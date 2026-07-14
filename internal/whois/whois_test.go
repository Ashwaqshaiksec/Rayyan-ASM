package whois

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestBootstrapURL_KnownTLDs(t *testing.T) {
	cases := map[string]string{
		"example.com": "https://rdap.verisign.com/com/v1",
		"example.io":  "https://rdap.nic.io",
		"example.dev": "https://rdap.nic.google",
	}
	for domain, want := range cases {
		if got := bootstrapURL(domain); got != want {
			t.Errorf("bootstrapURL(%q) = %q, want %q", domain, got, want)
		}
	}
}

func TestBootstrapURL_NoTLD(t *testing.T) {
	// A single-label "domain" has no dot at all — must not panic or index
	// out of range, just fall back to a sane default.
	if got := bootstrapURL("localhost"); got == "" {
		t.Error("bootstrapURL(\"localhost\"): expected a non-empty fallback URL")
	}
}

func TestFetchData_NetworkFailure(t *testing.T) {
	// Point at a closed port so the request fails immediately rather than
	// hitting a real network — deterministic and fast.
	result := fetchData("http://127.0.0.1:1", "example.com")
	if !strings.Contains(result["raw"], "RDAP lookup failed") {
		t.Errorf(`result["raw"] = %q, want it to describe a lookup failure`, result["raw"])
	}
}

func TestFetchData_404(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNotFound)
	}))
	defer srv.Close()

	result := fetchData(srv.URL, "notregistered.example")
	if result["raw"] != "domain not found in RDAP" {
		t.Errorf(`result["raw"] = %q, want "domain not found in RDAP"`, result["raw"])
	}
}

func TestFetchData_FullResponse(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		fmt.Fprint(w, `{
			"ldhName": "example.com",
			"nameservers": [{"ldhName": "ns1.example.com"}, {"ldhName": "ns2.example.com"}],
			"events": [
				{"eventAction": "registration", "eventDate": "2020-01-01T00:00:00Z"},
				{"eventAction": "expiration", "eventDate": "2030-01-01T00:00:00Z"}
			],
			"entities": [
				{
					"roles": ["registrar"],
					"vcardArray": ["vcard", [["fn", {}, "text", "Test Registrar Inc."]]],
					"publicIds": [{"type": "IANA Registrar ID", "identifier": "1234"}]
				}
			]
		}`)
	}))
	defer srv.Close()

	result := fetchData(srv.URL, "example.com")

	if result["registrar"] != "Test Registrar Inc." {
		t.Errorf(`result["registrar"] = %q, want "Test Registrar Inc."`, result["registrar"])
	}
	if result["registrar_iana_id"] != "1234" {
		t.Errorf(`result["registrar_iana_id"] = %q, want "1234"`, result["registrar_iana_id"])
	}
	if result["registration_date"] != "2020-01-01T00:00:00Z" {
		t.Errorf(`result["registration_date"] = %q, want "2020-01-01T00:00:00Z"`, result["registration_date"])
	}
	if result["expiry_date"] != "2030-01-01T00:00:00Z" {
		t.Errorf(`result["expiry_date"] = %q, want "2030-01-01T00:00:00Z"`, result["expiry_date"])
	}
	if result["nameservers"] != "ns1.example.com,ns2.example.com" {
		t.Errorf(`result["nameservers"] = %q, want "ns1.example.com,ns2.example.com"`, result["nameservers"])
	}
	if result["tld"] != "com" {
		t.Errorf(`result["tld"] = %q, want "com"`, result["tld"])
	}
	if result["raw"] == "" {
		t.Error(`result["raw"] should contain the raw response body`)
	}
}

func TestFetchData_MalformedJSON(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		fmt.Fprint(w, `not json at all`)
	}))
	defer srv.Close()

	// Must not panic — malformed JSON is silently ignored (matches the
	// original handler's behavior: `_ = json.Unmarshal(body, &rdap)`),
	// leaving result with just "raw" and "tld" set.
	result := fetchData(srv.URL, "example.com")
	if result["raw"] != "not json at all" {
		t.Errorf(`result["raw"] = %q, want the raw malformed body`, result["raw"])
	}
}
