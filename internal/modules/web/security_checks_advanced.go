package web

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"
)

// checkOAuthOIDC detects common OAuth 2.0 / OIDC misconfigurations.
func (sc *SecurityChecker) checkOAuthOIDC(ctx context.Context, targetURL string) []SecurityFinding {
	var findings []SecurityFinding

	// 1. Well-known OIDC discovery endpoint
	base := strings.TrimRight(targetURL, "/")
	oidcURL := base + "/.well-known/openid-configuration"
	resp, body, err := sc.fetch(ctx, oidcURL, "GET", map[string]string{"User-Agent": "Mozilla/5.0"})
	if err == nil && resp != nil && resp.StatusCode == 200 && strings.Contains(body, "issuer") {
		// Check for implicit flow enabled (deprecated, insecure)
		if strings.Contains(body, "\"implicit\"") || strings.Contains(body, "token id_token") {
			findings = append(findings, SecurityFinding{
				Title:       "OAuth: Implicit Flow Enabled in OIDC Discovery",
				Description: "The OIDC discovery document advertises support for the implicit grant flow. Implicit flow returns access tokens in URLs and is deprecated in OAuth 2.1 due to token leakage risks.",
				Severity:    SevMedium,
				Category:    "OAuth/OIDC",
				URL:         oidcURL,
				Evidence:    "openid-configuration lists implicit/token response types",
				Remediation: "Remove implicit flow from supported response types. Migrate all clients to the Authorization Code flow with PKCE.",
			})
		}
		// Check for password grant enabled
		if strings.Contains(body, "\"password\"") {
			findings = append(findings, SecurityFinding{
				Title:       "OAuth: Resource Owner Password Credentials Grant Enabled",
				Description: "The OIDC discovery document advertises the password grant. This grant type exposes user credentials to the client application and bypasses MFA.",
				Severity:    SevHigh,
				Category:    "OAuth/OIDC",
				URL:         oidcURL,
				Evidence:    "openid-configuration grant_types_supported includes 'password'",
				Remediation: "Disable the resource owner password credentials grant. Use Authorization Code + PKCE instead.",
			})
		}
		// Check JWKS is present (informational — means we can try key confusion)
		if strings.Contains(body, "jwks_uri") {
			findings = append(findings, SecurityFinding{
				Title:       "OAuth: JWKS Endpoint Publicly Accessible",
				Description: "The JWKS (JSON Web Key Set) endpoint is publicly accessible. While this is standard, it should be audited to confirm no private key material is exposed.",
				Severity:    SevInfo,
				Category:    "OAuth/OIDC",
				URL:         oidcURL,
				Evidence:    "jwks_uri present in OIDC discovery document",
				Remediation: "Ensure only public keys are exposed in the JWKS endpoint. Verify the signing key rotation policy.",
			})
		}
	}

	// 2. OAuth callback with open redirect probe
	callbackPaths := []string{"/oauth/callback", "/auth/callback", "/callback", "/login/oauth/callback", "/oidc/callback"}
	externalRedirect := "https://evil.rayyan-asm-probe.invalid"
	for _, path := range callbackPaths {
		testURL := base + path + "?code=test&state=test&redirect_uri=" + externalRedirect
		resp2, _, err2 := sc.fetch(ctx, testURL, "GET", map[string]string{"User-Agent": "Mozilla/5.0"})
		if err2 != nil || resp2 == nil {
			continue
		}
		location := resp2.Header.Get("Location")
		if resp2.StatusCode >= 300 && resp2.StatusCode < 400 && strings.Contains(location, "evil.rayyan-asm-probe.invalid") {
			findings = append(findings, SecurityFinding{
				Title:       "OAuth: Open Redirect via redirect_uri Parameter",
				Description: "The OAuth callback endpoint follows an externally-supplied redirect_uri without validation. Attackers can steal authorization codes or tokens by injecting a malicious redirect.",
				Severity:    SevHigh,
				Category:    "OAuth/OIDC",
				URL:         testURL,
				Evidence:    fmt.Sprintf("HTTP %d Location: %s", resp2.StatusCode, location),
				Remediation: "Validate redirect_uri against an exact-match allowlist registered per client. Never accept dynamic redirect URIs.",
				CVSS:        8.1,
			})
			break
		}
	}

	return findings
}

// checkHTTP2RapidReset probes for HTTP/2 Rapid Reset vulnerability (CVE-2023-44487).
// True exploitation requires a raw TCP+TLS connection; this check detects servers
// that advertise HTTP/2 and lack evidence of patching via response headers/server version.
func (sc *SecurityChecker) checkHTTP2RapidReset(ctx context.Context, targetURL string) []SecurityFinding {
	var findings []SecurityFinding
	if !strings.HasPrefix(targetURL, "https://") {
		return findings
	}

	resp, _, err := sc.fetch(ctx, targetURL, "GET", map[string]string{"User-Agent": "Mozilla/5.0"})
	if err != nil || resp == nil || resp.TLS == nil {
		return findings
	}

	// Check if server negotiated HTTP/2 (Go's http.Client does this transparently)
	if resp.Proto != "HTTP/2.0" && resp.Proto != "HTTP/2" {
		return findings
	}

	// Check server header for known-vulnerable versions
	server := resp.Header.Get("Server")
	serverLower := strings.ToLower(server)
	vulnerable := false
	var hint string

	switch {
	case strings.Contains(serverLower, "nginx/1.24") || strings.Contains(serverLower, "nginx/1.23") ||
		strings.Contains(serverLower, "nginx/1.22") || strings.Contains(serverLower, "nginx/1.20"):
		vulnerable = true
		hint = fmt.Sprintf("Server: %s (check if ngx_http_v2_module is patched)", server)
	case strings.Contains(serverLower, "apache/2.4.5") || strings.Contains(serverLower, "apache/2.4.4") ||
		strings.Contains(serverLower, "apache/2.4.3") || strings.Contains(serverLower, "apache/2.4.2"):
		vulnerable = true
		hint = fmt.Sprintf("Server: %s (Apache mod_http2 may be unpatched)", server)
	case server == "" || serverLower == "cloudflare" || strings.Contains(serverLower, "litespeed"):
		// Cloudflare and LiteSpeed patched early; skip
		return findings
	}

	if !vulnerable && server != "" {
		return findings
	}

	findings = append(findings, SecurityFinding{
		Title:       "Potential HTTP/2 Rapid Reset (CVE-2023-44487)",
		Description: "The server uses HTTP/2 and may be vulnerable to the Rapid Reset attack (CVE-2023-44487). A malicious client can open and immediately cancel thousands of HTTP/2 streams per second, causing CPU exhaustion without triggering rate limits.",
		Severity:    SevHigh,
		Category:    "Denial of Service",
		URL:         targetURL,
		Evidence:    fmt.Sprintf("Protocol: %s | %s", resp.Proto, hint),
		Remediation: "Upgrade nginx ≥1.25.3, Apache httpd ≥2.4.58, or your load balancer to a version patched for CVE-2023-44487. Set http2_max_concurrent_streams to a low value (e.g. 128).",
		CVE:         "CVE-2023-44487",
		CVSS:        7.5,
	})
	return findings
}

// checkSubdomainTakeoverBody rescans the response body for takeover fingerprints
// that the header-only check in checkSubdomainTakeover may miss.
func (sc *SecurityChecker) checkSubdomainTakeoverBody(ctx context.Context, targetURL string) []SecurityFinding {
	var findings []SecurityFinding

	resp, body, err := sc.fetch(ctx, targetURL, "GET", map[string]string{"User-Agent": "Mozilla/5.0"})
	if err != nil || resp == nil {
		return findings
	}
	if resp.StatusCode != 200 && resp.StatusCode != 404 {
		return findings
	}

	type fp struct {
		service  string
		patterns []string
		severity string
	}
	fingerprints := []fp{
		{"GitHub Pages", []string{"There isn't a GitHub Pages site here", "github.io"}, SevHigh},
		{"Heroku", []string{"No such app", "herokucdn.com/error-pages/no-such-app"}, SevHigh},
		{"AWS S3", []string{"NoSuchBucket", "The specified bucket does not exist"}, SevHigh},
		{"AWS CloudFront", []string{"ERROR: The request could not be satisfied", "Generated by cloudfront"}, SevMedium},
		{"Fastly", []string{"Fastly error: unknown domain"}, SevHigh},
		{"Shopify", []string{"Sorry, this shop is currently unavailable", "myshopify.com"}, SevMedium},
		{"Tumblr", []string{"Whatever you were looking for doesn't currently exist at this address"}, SevMedium},
		{"Azure App Service", []string{"404 Web Site not found", "azurewebsites.net"}, SevHigh},
		{"Azure CDN", []string{"Endpoint doesn't exist in this Azure region"}, SevHigh},
		{"Zendesk", []string{"Help Center Closed", "zendesk.com"}, SevMedium},
		{"Pantheon", []string{"The gods are wise, but do not know of the site"}, SevMedium},
		{"WordPress.com", []string{"Do you want to register"}, SevLow},
		{"Bitbucket", []string{"Repository not found"}, SevHigh},
		{"Ghost", []string{"The thing you were looking for is no longer here"}, SevMedium},
		{"Surge.sh", []string{"project not found"}, SevMedium},
		{"Netlify", []string{"Not Found - Request ID:"}, SevMedium},
		{"Vercel", []string{"The deployment could not be found"}, SevMedium},
	}

	bodyLower := strings.ToLower(body)
	for _, f := range fingerprints {
		for _, pat := range f.patterns {
			if strings.Contains(bodyLower, strings.ToLower(pat)) {
				findings = append(findings, SecurityFinding{
					Title:       fmt.Sprintf("Subdomain Takeover: Unclaimed %s Resource", f.service),
					Description: fmt.Sprintf("The response body matches the fingerprint for an unclaimed %s resource. An attacker can register the dangling resource and serve arbitrary content from this domain.", f.service),
					Severity:    f.severity,
					Category:    "Subdomain Takeover",
					URL:         targetURL,
					Evidence:    fmt.Sprintf("Pattern %q found in HTTP %d response body", pat, resp.StatusCode),
					Remediation: "Remove the dangling DNS CNAME record, or re-register the cloud resource at the provider before an attacker does.",
					CVSS:        8.1,
				})
				goto nextFingerprint
			}
		}
	nextFingerprint:
	}
	return findings
}

// checkTimingBlindSQLi uses response time differences to detect blind SQL injection.
// It injects sleep/delay payloads and flags when the response takes significantly longer.
func (sc *SecurityChecker) checkTimingBlindSQLi(ctx context.Context, targetURL string) []SecurityFinding {
	var findings []SecurityFinding

	type timingProbe struct {
		param   string
		payload string // the delay payload — 3 second sleep
	}
	probes := []timingProbe{
		{"id", "1' AND SLEEP(3)--"},
		{"id", "1; SELECT pg_sleep(3)--"},
		{"id", "1 WAITFOR DELAY '0:0:3'--"},
		{"q", "1' AND SLEEP(3)--"},
		{"search", "' OR SLEEP(3)--"},
		{"user", "admin' AND SLEEP(3)--"},
	}

	// Establish baseline response time
	baseline := sc.measureResponseTime(ctx, targetURL)
	if baseline <= 0 {
		return findings
	}

	for _, p := range probes {
		sep := "?"
		if strings.Contains(targetURL, "?") {
			sep = "&"
		}
		testURL := targetURL + sep + p.param + "=" + p.payload
		elapsed := sc.measureResponseTime(ctx, testURL)
		if elapsed <= 0 {
			continue
		}
		// Flag if response took ≥2.5s longer than baseline
		if elapsed >= baseline+2500 {
			findings = append(findings, SecurityFinding{
				Title:       "Blind SQL Injection (Time-Based)",
				Description: fmt.Sprintf("Parameter %q caused a ~%dms response delay when injected with a sleep payload, indicating time-based blind SQL injection.", p.param, elapsed-baseline),
				Severity:    SevCritical,
				Category:    "Injection",
				URL:         testURL,
				Evidence:    fmt.Sprintf("Baseline: %dms | With payload %q: %dms (+%dms delay)", baseline, p.payload, elapsed, elapsed-baseline),
				Remediation: "Use parameterized queries or prepared statements. Never concatenate user input into SQL. Deploy a WAF as an additional layer.",
				CVSS:        9.8,
			})
			return findings // one confirmed is enough
		}
	}
	return findings
}

// measureResponseTime returns the round-trip time in milliseconds for a GET request.
// Returns -1 on error.
func (sc *SecurityChecker) measureResponseTime(ctx context.Context, url string) int64 {
	req, err := http.NewRequestWithContext(ctx, "GET", url, nil)
	if err != nil {
		return -1
	}
	req.Header.Set("User-Agent", "Mozilla/5.0")

	start := time.Now()
	resp, err := sc.client.Do(req)
	elapsed := time.Since(start).Milliseconds()
	if err != nil || resp == nil {
		return -1
	}
	io.Copy(io.Discard, resp.Body) //nolint:errcheck
	_ = resp.Body.Close()
	return elapsed
}

// checkAPIVersioning probes for older, potentially unpatched API versions.
func (sc *SecurityChecker) checkAPIVersioning(ctx context.Context, targetURL string) []SecurityFinding {
	var findings []SecurityFinding
	base := strings.TrimRight(targetURL, "/")

	versionPaths := []string{
		"/api/v0", "/api/v1", "/api/v2",
		"/v0", "/v1", "/v2",
		"/api/1.0", "/api/2.0",
	}
	// First find which version is "current" (returns 200)
	var currentVersion string
	for _, path := range versionPaths {
		resp, _, err := sc.fetch(ctx, base+path, "GET", map[string]string{"User-Agent": "Mozilla/5.0"})
		if err == nil && resp != nil && resp.StatusCode == 200 {
			currentVersion = path
			break
		}
	}
	if currentVersion == "" {
		return findings
	}

	// Now probe older versions
	for _, path := range versionPaths {
		if path == currentVersion {
			continue
		}
		// Only test versions "before" the current one (v0 is older than v1)
		if strings.Compare(path, currentVersion) >= 0 {
			continue
		}
		resp, body, err := sc.fetch(ctx, base+path, "GET", map[string]string{"User-Agent": "Mozilla/5.0"})
		if err != nil || resp == nil {
			continue
		}
		if resp.StatusCode == 200 && len(body) > 50 {
			findings = append(findings, SecurityFinding{
				Title:       fmt.Sprintf("Legacy API Version Accessible: %s", path),
				Description: fmt.Sprintf("An older API version (%s) is still accessible. Legacy API versions often lack security patches, input validation improvements, and authentication updates applied to current versions.", path),
				Severity:    SevMedium,
				Category:    "API Security",
				URL:         base + path,
				Evidence:    fmt.Sprintf("GET %s returned HTTP %d (current version: %s)", base+path, resp.StatusCode, base+currentVersion),
				Remediation: "Deprecate and sunset old API versions. Redirect legacy version traffic to the current version or return 410 Gone.",
			})
		}
	}
	return findings
}
