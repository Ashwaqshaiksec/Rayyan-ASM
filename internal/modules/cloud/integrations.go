package cloud

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"

	"go.uber.org/zap"
)

type ShodanClient struct {
	apiKey string
	client *http.Client
	log    *zap.SugaredLogger
}

func NewShodanClient(apiKey string, log *zap.SugaredLogger) *ShodanClient {
	return &ShodanClient{
		apiKey: apiKey,
		client: &http.Client{Timeout: 30 * time.Second},
		log:    log,
	}
}

type ShodanHostResult struct {
	IP        string          `json:"ip_str"`
	Ports     []int           `json:"ports"`
	Hostnames []string        `json:"hostnames"`
	Country   string          `json:"country_name"`
	City      string          `json:"city"`
	ISP       string          `json:"isp"`
	ASN       string          `json:"asn"`
	Org       string          `json:"org"`
	OS        string          `json:"os"`
	Data      []ShodanService `json:"data"`
}

type ShodanService struct {
	Port      int    `json:"port"`
	Transport string `json:"transport"`
	Product   string `json:"product"`
	Version   string `json:"version"`
	Banner    string `json:"data"`
}

func (c *ShodanClient) LookupHost(ctx context.Context, ip string) (*ShodanHostResult, error) {
	url := fmt.Sprintf("https://api.shodan.io/shodan/host/%s?key=%s", ip, c.apiKey)

	req, err := http.NewRequestWithContext(ctx, "GET", url, nil)
	if err != nil {
		return nil, err
	}

	resp, err := c.client.Do(req)
	if err != nil {
		return nil, err
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("shodan API error: %d", resp.StatusCode)
	}

	var result ShodanHostResult
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return nil, err
	}

	return &result, nil
}

func (c *ShodanClient) Search(ctx context.Context, query string, page int) ([]ShodanHostResult, error) {
	url := fmt.Sprintf("https://api.shodan.io/shodan/host/search?key=%s&query=%s&page=%d",
		c.apiKey, query, page)

	req, _ := http.NewRequestWithContext(ctx, "GET", url, nil)
	resp, err := c.client.Do(req)
	if err != nil {
		return nil, err
	}
	defer func() { _ = resp.Body.Close() }()

	var result struct {
		Matches []ShodanHostResult `json:"matches"`
		Total   int                `json:"total"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return nil, err
	}
	return result.Matches, nil
}

// WaybackBaseURL is the Internet Archive CDX API host. Exported (not just a
// lowercase package var) for the same reason as VirusTotalBaseURL above:
// tests that drive WaybackClient indirectly through the dispatcher need to
// swap it to an httptest.Server URL, and a same-package export_test.go seam
// doesn't work across package boundaries.
var WaybackBaseURL = "https://web.archive.org"

// WaybackClient queries the Internet Archive's CDX API for every URL it has
// ever crawled under a domain. This is a free, no-API-key passive
// discovery source — unlike Shodan/Censys/SecurityTrails/VirusTotal above,
// it requires no account or key at all, so it runs unconditionally for
// every scan the same way crt.sh does, rather than being gated behind an
// operator-configured credential. It frequently surfaces subdomains that
// were live years ago and never appear in current certificate-transparency
// logs (crt.sh) or DNS-brute-force wordlists, e.g. decommissioned staging
// or marketing subdomains that still resolve.
type WaybackClient struct {
	client *http.Client
	log    *zap.SugaredLogger
}

func NewWaybackClient(log *zap.SugaredLogger) *WaybackClient {
	return &WaybackClient{
		client: &http.Client{Timeout: 30 * time.Second},
		log:    log,
	}
}

// GetSubdomains returns every unique subdomain of domain that the Internet
// Archive has ever crawled, derived from the host portion of each archived
// URL. collapse=urlkey de-duplicates near-identical URLs on the server side
// so the response stays small even for domains with a long crawl history.
func (c *WaybackClient) GetSubdomains(ctx context.Context, domain string) ([]string, error) {
	url := fmt.Sprintf("%s/cdx/search/cdx?url=*.%s&output=json&fl=original&collapse=urlkey&limit=10000",
		WaybackBaseURL, domain)

	req, err := http.NewRequestWithContext(ctx, "GET", url, nil)
	if err != nil {
		return nil, err
	}

	resp, err := c.client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("wayback request failed: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("wayback returned status %d", resp.StatusCode)
	}

	// The CDX JSON API returns a header row (["urlkey","timestamp",...])
	// followed by one array-of-strings row per match, not an array of
	// objects — a quirk of the endpoint's original plain-text CDX format
	// carried over into its "json" output mode.
	var rows [][]string
	if err := json.NewDecoder(resp.Body).Decode(&rows); err != nil {
		return nil, fmt.Errorf("decoding wayback response: %w", err)
	}
	if len(rows) < 2 {
		return nil, nil // header only (or empty) — no matches
	}

	seen := make(map[string]bool)
	var subs []string
	for _, row := range rows[1:] { // skip header row
		if len(row) == 0 {
			continue
		}
		raw := row[0] // "original" column: the full archived URL
		host := extractHost(raw)
		if host == "" || !strings.HasSuffix(host, "."+domain) && host != domain {
			continue
		}
		if !seen[host] {
			seen[host] = true
			subs = append(subs, host)
		}
	}
	return subs, nil
}

// extractHost pulls the bare host out of a URL without a full net/url
// parse, since archived URLs are sometimes malformed enough (stray
// whitespace, missing scheme) that url.Parse rejects them outright when a
// simple string trim would do.
func extractHost(rawURL string) string {
	s := strings.TrimSpace(rawURL)
	s = strings.TrimPrefix(s, "https://")
	s = strings.TrimPrefix(s, "http://")
	if i := strings.IndexAny(s, "/:?#"); i >= 0 {
		s = s[:i]
	}
	return strings.ToLower(s)
}

type CensysClient struct {
	apiID     string
	apiSecret string
	client    *http.Client
	log       *zap.SugaredLogger
}

func NewCensysClient(apiID, apiSecret string, log *zap.SugaredLogger) *CensysClient {
	return &CensysClient{
		apiID:     apiID,
		apiSecret: apiSecret,
		client:    &http.Client{Timeout: 30 * time.Second},
		log:       log,
	}
}

type CensysHostResult struct {
	IP       string `json:"ip"`
	Services []struct {
		Port           int    `json:"port"`
		TransportProto string `json:"transport_protocol"`
		ServiceName    string `json:"service_name"`
	} `json:"services"`
	Labels []string `json:"labels"`
}

func (c *CensysClient) LookupHost(ctx context.Context, ip string) (*CensysHostResult, error) {
	url := fmt.Sprintf("https://search.censys.io/api/v2/hosts/%s", ip)

	req, _ := http.NewRequestWithContext(ctx, "GET", url, nil)
	req.SetBasicAuth(c.apiID, c.apiSecret)

	resp, err := c.client.Do(req)
	if err != nil {
		return nil, err
	}
	defer func() { _ = resp.Body.Close() }()

	var wrapper struct {
		Result CensysHostResult `json:"result"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&wrapper); err != nil {
		return nil, err
	}
	return &wrapper.Result, nil
}

type SecurityTrailsClient struct {
	apiKey string
	client *http.Client
	log    *zap.SugaredLogger
}

func NewSecurityTrailsClient(apiKey string, log *zap.SugaredLogger) *SecurityTrailsClient {
	return &SecurityTrailsClient{
		apiKey: apiKey,
		client: &http.Client{Timeout: 30 * time.Second},
		log:    log,
	}
}

type SubdomainResult struct {
	Subdomains []string `json:"subdomains"`
	Endpoint   string   `json:"endpoint"`
}

func (c *SecurityTrailsClient) GetSubdomains(ctx context.Context, domain string) (*SubdomainResult, error) {
	url := fmt.Sprintf("https://api.securitytrails.com/v1/domain/%s/subdomains", domain)

	req, _ := http.NewRequestWithContext(ctx, "GET", url, nil)
	req.Header.Set("APIKEY", c.apiKey)
	req.Header.Set("Accept", "application/json")

	resp, err := c.client.Do(req)
	if err != nil {
		return nil, err
	}
	defer func() { _ = resp.Body.Close() }()

	var result SubdomainResult
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return nil, err
	}
	return &result, nil
}

func (c *SecurityTrailsClient) GetDNSHistory(ctx context.Context, domain, recordType string) (map[string]interface{}, error) {
	url := fmt.Sprintf("https://api.securitytrails.com/v1/history/%s/dns/%s", domain, recordType)

	req, _ := http.NewRequestWithContext(ctx, "GET", url, nil)
	req.Header.Set("APIKEY", c.apiKey)

	resp, err := c.client.Do(req)
	if err != nil {
		return nil, err
	}
	defer func() { _ = resp.Body.Close() }()

	var result map[string]interface{}
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return nil, err
	}
	return result, nil
}

// VirusTotalBaseURL is the VirusTotal API host. Exported (not just a
// lowercase package var) so tests in other packages — e.g.
// internal/modules, which drives VirusTotalClient indirectly through
// Dispatcher.chainExtraSubdomainSources — can swap it to an
// httptest.Server URL. A same-package export_test.go seam (the pattern
// used in internal/modules/intelligence) doesn't work across package
// boundaries: Go only compiles a package's _test.go files into that
// package's own test binary, not into other packages that import it.
var VirusTotalBaseURL = "https://www.virustotal.com"

type VirusTotalClient struct {
	apiKey string
	client *http.Client
	log    *zap.SugaredLogger
}

func NewVirusTotalClient(apiKey string, log *zap.SugaredLogger) *VirusTotalClient {
	return &VirusTotalClient{
		apiKey: apiKey,
		client: &http.Client{Timeout: 30 * time.Second},
		log:    log,
	}
}

type VTDomainResult struct {
	Data struct {
		Attributes struct {
			LastAnalysisStats map[string]int    `json:"last_analysis_stats"`
			Subdomains        []string          `json:"subdomains"`
			Categories        map[string]string `json:"categories"`
			CreationDate      int64             `json:"creation_date"`
			ExpirationDate    int64             `json:"expiration_date"`
			Registrar         string            `json:"registrar"`
			Reputation        int               `json:"reputation"`
		} `json:"attributes"`
	} `json:"data"`
}

func (c *VirusTotalClient) GetDomain(ctx context.Context, domain string) (*VTDomainResult, error) {
	url := fmt.Sprintf("%s/api/v3/domains/%s", VirusTotalBaseURL, domain)

	req, _ := http.NewRequestWithContext(ctx, "GET", url, nil)
	req.Header.Set("x-apikey", c.apiKey)

	resp, err := c.client.Do(req)
	if err != nil {
		return nil, err
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode == http.StatusNotFound {
		return nil, fmt.Errorf("domain not found in VirusTotal")
	}

	var result VTDomainResult
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}
	if err := json.Unmarshal(body, &result); err != nil {
		return nil, err
	}
	return &result, nil
}

func (c *VirusTotalClient) GetSubdomains(ctx context.Context, domain string) ([]string, error) {
	url := fmt.Sprintf("%s/api/v3/domains/%s/subdomains?limit=40", VirusTotalBaseURL, domain)

	req, _ := http.NewRequestWithContext(ctx, "GET", url, nil)
	req.Header.Set("x-apikey", c.apiKey)

	resp, err := c.client.Do(req)
	if err != nil {
		return nil, err
	}
	defer func() { _ = resp.Body.Close() }()

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
