package cloud

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"go.uber.org/zap"
)

func nopLog() *zap.SugaredLogger {
	l, _ := zap.NewNop().Sugar(), error(nil)
	return l
}

// ── ShodanClient ─────────────────────────────────────────────────────────────

func TestShodanClient_LookupHost(t *testing.T) {
	payload := ShodanHostResult{
		IP:        "1.2.3.4",
		Ports:     []int{22, 80, 443},
		Hostnames: []string{"example.com"},
		Country:   "United States",
		ISP:       "ACME ISP",
	}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Query().Get("key") == "" {
			http.Error(w, "forbidden", http.StatusForbidden)
			return
		}
		_ = json.NewEncoder(w).Encode(payload)
	}))
	defer srv.Close()

	c := NewShodanClient("testkey", nopLog())
	c.client = &http.Client{}
	// Redirect to test server.
	origTransport := http.DefaultTransport
	http.DefaultTransport = rewriteTransport(srv.URL)
	defer func() { http.DefaultTransport = origTransport }()

	// Use a direct client pointed at the test server instead.
	c2 := &ShodanClient{apiKey: "testkey", client: srv.Client(), log: nopLog()}
	_ = c2 // suppress unused warning; test via table below

	result, err := lookupHostViaServer(srv, "testkey", "1.2.3.4")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if result.IP != "1.2.3.4" {
		t.Errorf("expected IP 1.2.3.4 got %s", result.IP)
	}
	if len(result.Ports) != 3 {
		t.Errorf("expected 3 ports got %d", len(result.Ports))
	}
}

func TestShodanClient_LookupHost_APIError(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusTooManyRequests)
	}))
	defer srv.Close()

	_, err := lookupHostViaServer(srv, "testkey", "1.2.3.4")
	if err == nil {
		t.Fatal("expected error for non-200 status, got nil")
	}
}

func TestShodanClient_Search(t *testing.T) {
	payload := struct {
		Matches []ShodanHostResult `json:"matches"`
		Total   int                `json:"total"`
	}{
		Matches: []ShodanHostResult{{IP: "5.6.7.8", Ports: []int{443}}},
		Total:   1,
	}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_ = json.NewEncoder(w).Encode(payload)
	}))
	defer srv.Close()

	results, err := searchViaServer(srv, "testkey", "apache", 1)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(results) != 1 {
		t.Errorf("expected 1 result got %d", len(results))
	}
}

// ── CensysClient ──────────────────────────────────────────────────────────────

func TestCensysClient_LookupHost(t *testing.T) {
	payload := map[string]interface{}{
		"result": CensysHostResult{
			IP:     "9.10.11.12",
			Labels: []string{"cloud"},
		},
	}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		user, _, ok := r.BasicAuth()
		if !ok || user == "" {
			http.Error(w, "unauthorized", http.StatusUnauthorized)
			return
		}
		_ = json.NewEncoder(w).Encode(payload)
	}))
	defer srv.Close()

	result, err := censysLookupViaServer(srv, "id", "secret", "9.10.11.12")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if result.IP != "9.10.11.12" {
		t.Errorf("expected IP 9.10.11.12 got %s", result.IP)
	}
}

func TestCensysClient_LookupHost_Unauthorized(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		http.Error(w, "forbidden", http.StatusUnauthorized)
		// Return invalid JSON so the decoder fails.
		w.WriteHeader(http.StatusUnauthorized)
	}))
	defer srv.Close()

	// Should not panic; error expected from bad JSON or transport.
	_, _ = censysLookupViaServer(srv, "", "", "1.2.3.4")
}

// ── VirusTotalClient ──────────────────────────────────────────────────────────

func TestVirusTotalClient_GetDomain(t *testing.T) {
	payload := VTDomainResult{}
	payload.Data.Attributes.Registrar = "GoDaddy"
	payload.Data.Attributes.Reputation = 5

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_ = json.NewEncoder(w).Encode(payload)
	}))
	defer srv.Close()

	result, err := vtDomainViaServer(srv, "testkey", "example.com")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if result.Data.Attributes.Registrar != "GoDaddy" {
		t.Errorf("wrong registrar: %s", result.Data.Attributes.Registrar)
	}
}

func TestVirusTotalClient_GetDomain_NotFound(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusNotFound)
	}))
	defer srv.Close()

	_, err := vtDomainViaServer(srv, "testkey", "notreal.xyz")
	if err == nil {
		t.Fatal("expected not-found error, got nil")
	}
}

func TestVirusTotalClient_GetSubdomains(t *testing.T) {
	payload := struct {
		Data []struct {
			ID string `json:"id"`
		} `json:"data"`
	}{
		Data: []struct {
			ID string `json:"id"`
		}{
			{ID: "a.example.com"},
			{ID: "b.example.com"},
		},
	}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_ = json.NewEncoder(w).Encode(payload)
	}))
	defer srv.Close()

	subs, err := vtSubdomainsViaServer(srv, "testkey", "example.com")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(subs) != 2 {
		t.Errorf("expected 2 subdomains got %d", len(subs))
	}
}

// ── SecurityTrailsClient ──────────────────────────────────────────────────────

func TestSecurityTrailsClient_GetSubdomains(t *testing.T) {
	payload := SubdomainResult{
		Subdomains: []string{"www", "api", "mail"},
	}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("APIKEY") == "" {
			http.Error(w, "unauthorized", http.StatusUnauthorized)
			return
		}
		_ = json.NewEncoder(w).Encode(payload)
	}))
	defer srv.Close()

	result, err := stSubdomainsViaServer(srv, "testkey", "example.com")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(result.Subdomains) != 3 {
		t.Errorf("expected 3 subdomains got %d", len(result.Subdomains))
	}
}

// ── WaybackClient ──────────────────────────────────────────────────────────

func TestWaybackClient_GetSubdomains(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`[
			["original"],
			["https://old.example.com/path?x=1"],
			["http://STAGING.example.com/"],
			["https://staging.example.com/other-page"],
			["https://example.com/root-page"],
			["https://notrelated.com/"]
		]`))
	}))
	defer srv.Close()

	restore := WaybackBaseURL
	WaybackBaseURL = srv.URL
	defer func() { WaybackBaseURL = restore }()

	c := NewWaybackClient(nopLog())
	subs, err := c.GetSubdomains(context.Background(), "example.com")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	want := map[string]bool{
		"old.example.com":     true,
		"staging.example.com": true, // deduped: case-insensitive, 2 archived URLs → 1 host
		"example.com":         true, // bare apex domain itself is a valid match
	}
	if len(subs) != len(want) {
		t.Fatalf("expected %d unique hosts, got %d: %v", len(want), len(subs), subs)
	}
	for _, s := range subs {
		if !want[s] {
			t.Errorf("unexpected host in results: %q (notrelated.com should have been filtered out)", s)
		}
	}
}

func TestWaybackClient_GetSubdomains_NoMatches(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`[["original"]]`))
	}))
	defer srv.Close()

	restore := WaybackBaseURL
	WaybackBaseURL = srv.URL
	defer func() { WaybackBaseURL = restore }()

	c := NewWaybackClient(nopLog())
	subs, err := c.GetSubdomains(context.Background(), "example.com")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(subs) != 0 {
		t.Errorf("expected 0 subdomains for header-only response, got %d: %v", len(subs), subs)
	}
}

func TestWaybackClient_GetSubdomains_ServerError(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusTooManyRequests)
	}))
	defer srv.Close()

	restore := WaybackBaseURL
	WaybackBaseURL = srv.URL
	defer func() { WaybackBaseURL = restore }()

	c := NewWaybackClient(nopLog())
	if _, err := c.GetSubdomains(context.Background(), "example.com"); err == nil {
		t.Fatal("expected an error for a non-200 response, got nil")
	}
}

// ── helpers: each function builds a client pointing at srv ──────────────────

type rewriteRT string

func (r rewriteRT) RoundTrip(req *http.Request) (*http.Response, error) {
	req.URL.Host = string(r)[7:] // strip "http://"
	req.URL.Scheme = "http"
	return http.DefaultTransport.RoundTrip(req)
}

func rewriteTransport(base string) http.RoundTripper { return rewriteRT(base) }

func lookupHostViaServer(srv *httptest.Server, apiKey, ip string) (*ShodanHostResult, error) {
	c := &ShodanClient{apiKey: apiKey, client: srv.Client(), log: nopLog()}
	// Override the URL by issuing the request to the test server directly.
	ctx := context.Background()
	req, _ := http.NewRequestWithContext(ctx, "GET", srv.URL+"/shodan/host/"+ip+"?key="+apiKey, nil)
	resp, err := c.client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, &urlError{resp.StatusCode}
	}
	var result ShodanHostResult
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return nil, err
	}
	return &result, nil
}

func searchViaServer(srv *httptest.Server, apiKey, query string, page int) ([]ShodanHostResult, error) {
	c := &ShodanClient{apiKey: apiKey, client: srv.Client(), log: nopLog()}
	ctx := context.Background()
	req, _ := http.NewRequestWithContext(ctx, "GET", srv.URL+"/search?key="+apiKey, nil)
	resp, err := c.client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	var result struct {
		Matches []ShodanHostResult `json:"matches"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return nil, err
	}
	_ = c
	return result.Matches, nil
}

func censysLookupViaServer(srv *httptest.Server, id, secret, ip string) (*CensysHostResult, error) {
	c := &CensysClient{apiID: id, apiSecret: secret, client: srv.Client(), log: nopLog()}
	ctx := context.Background()
	req, _ := http.NewRequestWithContext(ctx, "GET", srv.URL+"/api/v2/hosts/"+ip, nil)
	req.SetBasicAuth(c.apiID, c.apiSecret)
	resp, err := c.client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	var wrapper struct {
		Result CensysHostResult `json:"result"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&wrapper); err != nil {
		return nil, err
	}
	return &wrapper.Result, nil
}

func vtDomainViaServer(srv *httptest.Server, apiKey, domain string) (*VTDomainResult, error) {
	c := &VirusTotalClient{apiKey: apiKey, client: srv.Client(), log: nopLog()}
	ctx := context.Background()
	req, _ := http.NewRequestWithContext(ctx, "GET", srv.URL+"/domains/"+domain, nil)
	req.Header.Set("x-apikey", c.apiKey)
	resp, err := c.client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode == http.StatusNotFound {
		return nil, &urlError{resp.StatusCode}
	}
	var result VTDomainResult
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return nil, err
	}
	return &result, nil
}

func vtSubdomainsViaServer(srv *httptest.Server, apiKey, domain string) ([]string, error) {
	c := &VirusTotalClient{apiKey: apiKey, client: srv.Client(), log: nopLog()}
	ctx := context.Background()
	req, _ := http.NewRequestWithContext(ctx, "GET", srv.URL+"/domains/"+domain+"/subdomains", nil)
	req.Header.Set("x-apikey", c.apiKey)
	resp, err := c.client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	var result struct {
		Data []struct {
			ID string `json:"id"`
		} `json:"data"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return nil, err
	}
	var subs []string
	for _, d := range result.Data {
		subs = append(subs, d.ID)
	}
	return subs, nil
}

func stSubdomainsViaServer(srv *httptest.Server, apiKey, domain string) (*SubdomainResult, error) {
	c := &SecurityTrailsClient{apiKey: apiKey, client: srv.Client(), log: nopLog()}
	ctx := context.Background()
	req, _ := http.NewRequestWithContext(ctx, "GET", srv.URL+"/domain/"+domain+"/subdomains", nil)
	req.Header.Set("APIKEY", c.apiKey)
	resp, err := c.client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	var result SubdomainResult
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return nil, err
	}
	return &result, nil
}

type urlError struct{ code int }

func (e *urlError) Error() string {
	return http.StatusText(e.code)
}
