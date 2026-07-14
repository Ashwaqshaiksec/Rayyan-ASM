package web

import (
	"context"
	"crypto/tls"
	"fmt"
	"net/http"
	"regexp"
	"strings"
	"sync"
	"time"
)

// checkReflectedXSS actively probes query parameters for reflected XSS.
func (sc *SecurityChecker) checkReflectedXSS(ctx context.Context, targetURL string) []SecurityFinding {
	var findings []SecurityFinding

	probeToken := "rayyan-xss-" + fmt.Sprintf("%d", time.Now().UnixNano()%99999)
	xssPayloads := []string{
		`<script>alert('` + probeToken + `')</script>`,
		`"><img src=x onerror=alert('` + probeToken + `')>`,
		`javascript:alert('` + probeToken + `')`,
		`';alert('` + probeToken + `')//`,
	}

	commonParams := []string{"q", "search", "query", "s", "name", "id", "input", "term", "text", "msg", "message", "data", "value", "page"}

	for _, param := range commonParams {
		for _, payload := range xssPayloads {
			sep := "?"
			if strings.Contains(targetURL, "?") {
				sep = "&"
			}
			testURL := targetURL + sep + param + "=" + payload
			_, body, err := sc.fetch(ctx, testURL, "GET", map[string]string{"User-Agent": "Mozilla/5.0"})
			if err != nil {
				continue
			}
			if strings.Contains(body, payload) || strings.Contains(body, probeToken) {
				findings = append(findings, SecurityFinding{
					Title:       "Reflected XSS",
					Description: fmt.Sprintf("Parameter %q reflects unsanitized input in the HTML response. Script injection may be possible.", param),
					Severity:    SevHigh,
					Category:    "XSS",
					URL:         testURL,
					Evidence:    fmt.Sprintf("Payload %q found in response body for param %s", payload, param),
					Remediation: "HTML-encode all user-supplied input before rendering it in the page. Implement a strict Content-Security-Policy.",
					CVSS:        7.2,
				})
				return findings // one confirmed XSS is sufficient per URL
			}
		}
	}
	return findings
}

// checkCSRF checks for missing CSRF protection on forms.
func (sc *SecurityChecker) checkCSRF(ctx context.Context, targetURL string) []SecurityFinding {
	var findings []SecurityFinding

	_, body, err := sc.fetch(ctx, targetURL, "GET", map[string]string{"User-Agent": "Mozilla/5.0"})
	if err != nil || body == "" {
		return findings
	}

	bodyLower := strings.ToLower(body)
	hasForm := strings.Contains(bodyLower, "<form")
	hasCSRFToken := strings.Contains(bodyLower, "csrf") ||
		strings.Contains(bodyLower, "_token") ||
		strings.Contains(bodyLower, "authenticity_token") ||
		strings.Contains(bodyLower, "__requestverificationtoken")

	if hasForm && !hasCSRFToken {
		findings = append(findings, SecurityFinding{
			Title:       "Missing CSRF Token in Form",
			Description: "One or more HTML forms on this page do not appear to contain a CSRF token. State-changing operations may be exploitable via cross-site request forgery.",
			Severity:    SevHigh,
			Category:    "CSRF",
			URL:         targetURL,
			Evidence:    "<form> tag found but no csrf/token hidden field detected in response body.",
			Remediation: "Add a per-session, per-form CSRF token to all state-changing forms. Validate the token server-side on every submission.",
			CVSS:        8.0,
		})
	}

	// Check SameSite=None cookies without CSRF token as extra signal
	return findings
}

// checkRateLimiting sends rapid sequential requests and checks for 429 / throttling.
func (sc *SecurityChecker) checkRateLimiting(ctx context.Context, targetURL string) []SecurityFinding {
	var findings []SecurityFinding

	// Send 15 rapid requests and check if any 429 is received
	var got429 bool
	var mu sync.Mutex

	var wg sync.WaitGroup
	for i := 0; i < 15; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			resp, _, err := sc.fetch(ctx, targetURL, "GET", map[string]string{
				"User-Agent": "Mozilla/5.0",
			})
			if err != nil || resp == nil {
				return
			}
			if resp.StatusCode == 429 {
				mu.Lock()
				got429 = true
				mu.Unlock()
			}
		}()
	}
	wg.Wait()

	if !got429 {
		loginPaths := []string{"/login", "/signin", "/auth", "/api/login", "/api/auth"}
		base := strings.TrimRight(targetURL, "/")
		for _, lp := range loginPaths {
			resp, _, err := sc.fetch(ctx, base+lp, "POST", map[string]string{
				"User-Agent":   "Mozilla/5.0",
				"Content-Type": "application/json",
			})
			if err != nil || resp == nil {
				continue
			}
			if resp.StatusCode == 200 || resp.StatusCode == 401 {
				// Login endpoint found, probe rate limit
				limited := false
				for i := 0; i < 10; i++ {
					r, _, _ := sc.fetch(ctx, base+lp, "POST", map[string]string{"User-Agent": "Mozilla/5.0"})
					if r != nil && r.StatusCode == 429 {
						limited = true
						break
					}
				}
				if !limited {
					findings = append(findings, SecurityFinding{
						Title:       "No Rate Limiting on Login Endpoint",
						Description: fmt.Sprintf("The login endpoint at %s does not appear to enforce rate limiting. It may be vulnerable to brute-force or credential stuffing attacks.", base+lp),
						Severity:    SevHigh,
						Category:    "Authentication",
						URL:         base + lp,
						Evidence:    "10 rapid POST requests returned no HTTP 429 or lockout response.",
						Remediation: "Implement rate limiting (e.g. 5 attempts per minute per IP), account lockout, and CAPTCHA on authentication endpoints.",
						CVSS:        7.5,
					})
					break
				}
			}
		}
	}
	return findings
}

// checkDefaultCredentials attempts common default credential pairs on discovered admin panels.
func (sc *SecurityChecker) checkDefaultCredentials(ctx context.Context, targetURL string) []SecurityFinding {
	var findings []SecurityFinding

	type credSet struct {
		username string
		password string
	}

	commonCreds := []credSet{
		{"admin", "admin"},
		{"admin", "password"},
		{"admin", "123456"},
		{"admin", "admin123"},
		{"root", "root"},
		{"root", "toor"},
		{"administrator", "administrator"},
		{"test", "test"},
		{"guest", "guest"},
	}

	adminPaths := []string{"/admin", "/wp-admin", "/administrator", "/login", "/signin"}
	base := strings.TrimRight(targetURL, "/")

	for _, path := range adminPaths {
		testURL := base + path
		// Check if the path exists first
		resp, body, err := sc.fetch(ctx, testURL, "GET", map[string]string{"User-Agent": "Mozilla/5.0"})
		if err != nil || resp == nil || resp.StatusCode == 404 {
			continue
		}
		if resp.StatusCode != 200 && resp.StatusCode != 401 && resp.StatusCode != 403 {
			continue
		}

		// Only probe if it looks like a login form
		if !strings.Contains(strings.ToLower(body), "password") {
			continue
		}

		for _, cred := range commonCreds {
			// Try form POST
			formBody := fmt.Sprintf("username=%s&password=%s&log=%s&pwd=%s", cred.username, cred.password, cred.username, cred.password)
			req, err := http.NewRequestWithContext(ctx, "POST", testURL, strings.NewReader(formBody))
			if err != nil {
				continue
			}
			req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
			req.Header.Set("User-Agent", "Mozilla/5.0")

			postResp, err := sc.client.Do(req)
			if err != nil || postResp == nil {
				continue
			}
			_ = postResp.Body.Close()

			// Heuristic: 302 redirect away from login = success, or 200 without error keywords
			if postResp.StatusCode == 302 {
				loc := postResp.Header.Get("Location")
				if loc != "" && !strings.Contains(strings.ToLower(loc), "login") &&
					!strings.Contains(strings.ToLower(loc), "error") {
					findings = append(findings, SecurityFinding{
						Title:       "Default Credentials Accepted",
						Description: fmt.Sprintf("The login at %s accepted the credential pair %s:%s (redirected to %s).", testURL, cred.username, cred.password, loc),
						Severity:    SevCritical,
						Category:    "Authentication",
						URL:         testURL,
						Evidence:    fmt.Sprintf("POST %s with %s:%s → HTTP 302 Location: %s", testURL, cred.username, cred.password, loc),
						Remediation: "Change all default credentials immediately. Enforce strong password policies and MFA on admin interfaces.",
						CVSS:        9.8,
					})
					return findings
				}
			}
		}
	}
	return findings
}

// checkDirectoryListing detects if directory listing is enabled on common paths.
func (sc *SecurityChecker) checkDirectoryListing(ctx context.Context, targetURL string) []SecurityFinding {
	var findings []SecurityFinding

	dirPaths := []string{"/", "/images/", "/assets/", "/uploads/", "/files/", "/static/", "/media/", "/backup/", "/logs/", "/tmp/"}
	base := strings.TrimRight(targetURL, "/")

	for _, path := range dirPaths {
		url := base + path
		_, body, err := sc.fetch(ctx, url, "GET", map[string]string{"User-Agent": "Mozilla/5.0"})
		if err != nil {
			continue
		}
		bodyLower := strings.ToLower(body)
		if strings.Contains(bodyLower, "index of /") ||
			strings.Contains(bodyLower, "directory listing") ||
			strings.Contains(bodyLower, "parent directory") ||
			(strings.Contains(bodyLower, "<pre>") && strings.Contains(bodyLower, "last modified")) {
			findings = append(findings, SecurityFinding{
				Title:       "Directory Listing Enabled",
				Description: fmt.Sprintf("Directory listing is enabled at %s, exposing the full file/folder structure to unauthenticated users.", url),
				Severity:    SevMedium,
				Category:    "Information Disclosure",
				URL:         url,
				Evidence:    "Response contains 'Index of /' or directory listing markers.",
				Remediation: "Disable directory listing in your web server config (Options -Indexes for Apache; autoindex off for Nginx).",
				CVSS:        5.3,
			})
		}
	}
	return findings
}

// checkWebSocketEndpoints scans the response for WebSocket upgrade hints.
func (sc *SecurityChecker) checkWebSocketEndpoints(ctx context.Context, targetURL string) []SecurityFinding {
	var findings []SecurityFinding

	// Try WS upgrade request
	wsPaths := []string{"/ws", "/websocket", "/socket", "/chat", "/live", "/stream", "/events", "/api/ws"}
	base := strings.TrimRight(targetURL, "/")

	wsClient := &http.Client{
		Transport: &http.Transport{TLSClientConfig: &tls.Config{InsecureSkipVerify: true}},
		Timeout:   6 * time.Second,
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}

	for _, path := range wsPaths {
		url := base + path
		req, err := http.NewRequestWithContext(ctx, "GET", url, nil)
		if err != nil {
			continue
		}
		req.Header.Set("Upgrade", "websocket")
		req.Header.Set("Connection", "Upgrade")
		req.Header.Set("Sec-WebSocket-Key", "dGhlIHNhbXBsZSBub25jZQ==")
		req.Header.Set("Sec-WebSocket-Version", "13")
		req.Header.Set("User-Agent", "Mozilla/5.0")

		resp, err := wsClient.Do(req)
		if err != nil {
			continue
		}
		_ = resp.Body.Close()

		if resp.StatusCode == 101 || strings.Contains(resp.Header.Get("Upgrade"), "websocket") {
			// Check for origin validation
			reqNoOrigin, _ := http.NewRequestWithContext(ctx, "GET", url, nil)
			if reqNoOrigin != nil {
				reqNoOrigin.Header.Set("Upgrade", "websocket")
				reqNoOrigin.Header.Set("Connection", "Upgrade")
				reqNoOrigin.Header.Set("Origin", "https://evil.attacker.com")
				reqNoOrigin.Header.Set("Sec-WebSocket-Key", "dGhlIHNhbXBsZSBub25jZQ==")
				reqNoOrigin.Header.Set("Sec-WebSocket-Version", "13")
				r2, err2 := wsClient.Do(reqNoOrigin)
				if err2 == nil && r2 != nil {
					_ = r2.Body.Close()
					if r2.StatusCode == 101 {
						findings = append(findings, SecurityFinding{
							Title:       "WebSocket Cross-Origin Access (Missing Origin Validation)",
							Description: fmt.Sprintf("WebSocket endpoint at %s accepts connections from arbitrary origins. This may allow cross-site WebSocket hijacking (CSWH).", url),
							Severity:    SevHigh,
							Category:    "WebSocket",
							URL:         url,
							Evidence:    "101 Switching Protocols returned for hostile Origin: https://evil.attacker.com",
							Remediation: "Validate the Origin header on WebSocket handshake and reject unknown origins. Require authentication tokens in the WS handshake.",
							CVSS:        8.1,
						})
						continue
					}
				}
			}
			// Report discovery regardless
			findings = append(findings, SecurityFinding{
				Title:       "WebSocket Endpoint Discovered",
				Description: fmt.Sprintf("A WebSocket endpoint is available at %s. Review its authentication and input handling.", url),
				Severity:    SevInfo,
				Category:    "WebSocket",
				URL:         url,
				Evidence:    fmt.Sprintf("HTTP %d with Upgrade: websocket", resp.StatusCode),
				Remediation: "Ensure WebSocket endpoints validate Origin, require authentication, and sanitize all incoming messages.",
			})
		}
	}
	return findings
}

// secretPattern holds a regex pattern and label for secret detection.
type secretPattern struct {
	name     string
	re       *regexp.Regexp
	severity string
}

var secretPatterns = []secretPattern{
	{"AWS Access Key", regexp.MustCompile(`AKIA[0-9A-Z]{16}`), SevCritical},
	{"AWS Secret Key", regexp.MustCompile(`(?i)aws.{0,20}secret.{0,20}['\"][0-9a-zA-Z/+]{40}['\"]`), SevCritical},
	{"Google API Key", regexp.MustCompile(`AIza[0-9A-Za-z\\-_]{35}`), SevHigh},
	{"GitHub Token", regexp.MustCompile(`gh[pousr]_[A-Za-z0-9_]{36,}`), SevCritical},
	{"Slack Token", regexp.MustCompile(`xox[baprs]-[0-9A-Za-z\-]{10,}`), SevHigh},
	{"Stripe Key", regexp.MustCompile(`(?:sk|pk)_(live|test)_[0-9a-zA-Z]{24,}`), SevCritical},
	{"Twilio Account SID", regexp.MustCompile(`AC[a-z0-9]{32}`), SevHigh},
	{"Private Key", regexp.MustCompile(`-----BEGIN (RSA|EC|DSA|OPENSSH) PRIVATE KEY-----`), SevCritical},
	{"Bearer Token", regexp.MustCompile(`(?i)bearer\s+[a-zA-Z0-9\-_]{32,}`), SevMedium},
	{"Basic Auth in URL", regexp.MustCompile(`https?://[^:]+:[^@]+@`), SevHigh},
	{"Database URI", regexp.MustCompile(`(?i)(mysql|postgres|mongodb|redis):\/\/[^:]+:[^@]+@`), SevCritical},
	{"Hardcoded Password", regexp.MustCompile(`(?i)(password|passwd|pwd)\s*[=:]\s*['"][^'"]{6,}['"]`), SevHigh},
	{"SendGrid Key", regexp.MustCompile(`SG\.[a-zA-Z0-9\-_]{22}\.[a-zA-Z0-9\-_]{43}`), SevHigh},
	{"Cloudinary URL", regexp.MustCompile(`cloudinary://[0-9]+:[A-Za-z0-9\-]+@`), SevHigh},
}

// checkSecretsInResponse scans the response body for leaked secrets and API keys.
func (sc *SecurityChecker) checkSecretsInResponse(ctx context.Context, targetURL string) []SecurityFinding {
	var findings []SecurityFinding

	// Scan main page + common JS/config paths
	urlsToScan := []string{targetURL}
	base := strings.TrimRight(targetURL, "/")
	extraPaths := []string{"/config.js", "/app.js", "/main.js", "/bundle.js", "/env.js", "/settings.js", "/.env", "/config.json", "/api/config"}
	for _, p := range extraPaths {
		urlsToScan = append(urlsToScan, base+p)
	}

	seen := make(map[string]bool)

	for _, url := range urlsToScan {
		_, body, err := sc.fetch(ctx, url, "GET", map[string]string{"User-Agent": "Mozilla/5.0"})
		if err != nil || len(body) == 0 {
			continue
		}

		for _, sp := range secretPatterns {
			match := sp.re.FindString(body)
			if match == "" {
				continue
			}
			// Mask the secret in evidence
			masked := maskSecret(match)
			key := sp.name + ":" + url
			if seen[key] {
				continue
			}
			seen[key] = true

			findings = append(findings, SecurityFinding{
				Title:       fmt.Sprintf("Secret Leaked in HTTP Response: %s", sp.name),
				Description: fmt.Sprintf("A %s was found in the HTTP response body of %s. This credential may be usable by attackers.", sp.name, url),
				Severity:    sp.severity,
				Category:    "Credentials Exposure",
				URL:         url,
				Evidence:    fmt.Sprintf("Pattern matched: %s", masked),
				Remediation: "Remove secrets from all client-facing files. Use server-side environment variables. Rotate the exposed credential immediately.",
				CVSS:        9.1,
			})
		}
	}
	return findings
}

func maskSecret(s string) string {
	runes := []rune(s)
	n := len(runes)
	if n <= 8 {
		return strings.Repeat("*", n)
	}
	visible := 4
	masked := make([]rune, n)
	for i, r := range runes {
		if i < visible || i >= n-visible {
			masked[i] = r
		} else {
			masked[i] = '*'
		}
	}
	return string(masked)
}

// techCVE holds known-vulnerable version patterns for detected technologies.
type techCVE struct {
	technology  string
	versionHint string
	cve         string
	cvss        float64
	description string
	severity    string
}

var knownVulnTechs = []techCVE{
	{"WordPress", "wp-login.php", "CVE-2023-2745", 8.1, "WordPress Core path traversal (≤6.2) allows arbitrary file read.", SevHigh},
	{"Drupal", "drupal", "CVE-2022-25270", 7.2, "Drupal input validation bypass leading to XSS in older versions.", SevHigh},
	{"Joomla", "joomla", "CVE-2023-23752", 7.5, "Joomla improper access control allows unauthenticated API access (≤4.2.7).", SevHigh},
	{"jQuery", "jquery/1.", "CVE-2019-11358", 6.1, "jQuery ≤3.3.1 prototype pollution vulnerability.", SevMedium},
	{"jQuery", "jquery/2.", "CVE-2020-11023", 6.1, "jQuery ≤3.4.x XSS via HTML manipulation.", SevMedium},
	{"Angular", "angular.js/1.", "CVE-2023-26116", 7.5, "AngularJS 1.x sandbox bypass for template injection.", SevHigh},
	{"Apache", "Apache/2.4.49", "CVE-2021-41773", 7.5, "Apache 2.4.49 path traversal (zero-day Proxyshell surface).", SevHigh},
	{"Apache", "Apache/2.4.50", "CVE-2021-42013", 9.8, "Apache 2.4.50 RCE via path traversal.", SevCritical},
	{"Nginx", "nginx/1.18", "CVE-2021-23017", 7.7, "Nginx ≤1.20.0 resolver overflow.", SevHigh},
	{"PHP", "PHP/7.", "CVE-2022-31625", 9.8, "PHP 7.x use-after-free vulnerability.", SevCritical},
	{"Laravel", "laravel", "CVE-2021-3129", 9.8, "Laravel debug mode RCE via Ignition (PHAR deserialization).", SevCritical},
	{"Django", "csrfmiddlewaretoken", "CVE-2021-45116", 7.5, "Django potential info leak in URL patterns.", SevHigh},
	{"ASP.NET", "ASP.NET", "CVE-2021-34473", 9.8, "ProxyShell RCE via ASP.NET Exchange path confusion.", SevCritical},
	{"Spring", "spring", "CVE-2022-22965", 9.8, "Spring4Shell — Spring Framework RCE via data binding.", SevCritical},
	{"Tomcat", "Tomcat/8.", "CVE-2020-1938", 9.8, "Apache Tomcat AJP Ghostcat file disclosure (≤8.5.50).", SevCritical},
	{"Bootstrap", "bootstrap/3.", "CVE-2019-8331", 6.1, "Bootstrap 3.x XSS in tooltip/popover data-template.", SevMedium},
	{"OpenSSL", "OpenSSL", "CVE-2022-0778", 7.5, "OpenSSL infinite loop in BN_mod_sqrt() — DoS.", SevHigh},
}

// checkTechVulnerabilities cross-references detected technologies with known CVEs.
func (sc *SecurityChecker) checkTechVulnerabilities(_ context.Context, targetURL string, _ []string, headers map[string]string, body string) []SecurityFinding {
	var findings []SecurityFinding
	seen := make(map[string]bool)

	allText := strings.ToLower(body)
	for _, h := range headers {
		allText += " " + strings.ToLower(h)
	}

	for _, vuln := range knownVulnTechs {
		key := vuln.cve + ":" + targetURL
		if seen[key] {
			continue
		}
		if strings.Contains(allText, strings.ToLower(vuln.versionHint)) {
			seen[key] = true
			findings = append(findings, SecurityFinding{
				Title:       fmt.Sprintf("Known Vulnerable Technology: %s (%s)", vuln.technology, vuln.cve),
				Description: vuln.description,
				Severity:    vuln.severity,
				Category:    "Vulnerable Components",
				URL:         targetURL,
				Evidence:    fmt.Sprintf("Version hint %q found in response. %s", vuln.versionHint, vuln.cve),
				Remediation: fmt.Sprintf("Update %s to the latest stable version and apply all security patches. Reference: https://nvd.nist.gov/vuln/detail/%s", vuln.technology, vuln.cve),
				CVE:         vuln.cve,
				CVSS:        vuln.cvss,
			})
		}
	}
	return findings
}

// checkSQLInjection performs lightweight Go-native SQLi detection.
func (sc *SecurityChecker) checkSQLInjection(ctx context.Context, targetURL string) []SecurityFinding {
	var findings []SecurityFinding

	sqliPayloads := []struct {
		payload    string
		errorHints []string
	}{
		{"'", []string{"sql syntax", "mysql_fetch", "pg_query", "sqlite3_", "ora-", "microsoft ole db", "odbc drivers", "syntax error", "unclosed quotation"}},
		{"1 OR 1=1--", []string{"sql syntax", "mysql_fetch", "unexpected result"}},
		{"1; DROP TABLE users--", []string{"sql syntax", "error"}},
		{"' OR 'a'='a", []string{"sql syntax", "mysql_fetch", "pg_query"}},
		{`" OR "1"="1`, []string{"sql syntax", "error"}},
	}

	commonParams := []string{"id", "user", "username", "search", "q", "page", "cat", "category", "item", "product", "order"}

	for _, param := range commonParams {
		for _, test := range sqliPayloads {
			sep := "?"
			if strings.Contains(targetURL, "?") {
				sep = "&"
			}
			testURL := targetURL + sep + param + "=" + test.payload
			_, body, err := sc.fetch(ctx, testURL, "GET", map[string]string{"User-Agent": "Mozilla/5.0"})
			if err != nil {
				continue
			}
			bodyLower := strings.ToLower(body)
			for _, hint := range test.errorHints {
				if strings.Contains(bodyLower, hint) {
					findings = append(findings, SecurityFinding{
						Title:       "SQL Injection (Error-Based)",
						Description: fmt.Sprintf("Parameter %q appears to cause a SQL error when injected with %q, indicating SQL injection vulnerability.", param, test.payload),
						Severity:    SevCritical,
						Category:    "Injection",
						URL:         testURL,
						Evidence:    fmt.Sprintf("Payload %q triggered SQL error pattern %q in response", test.payload, hint),
						Remediation: "Use parameterized queries or prepared statements. Never concatenate user input into SQL queries.",
						CVSS:        9.8,
					})
					return findings
				}
			}
		}
	}
	return findings
}

// checkCommandInjection probes for OS command injection via timing and output.
func (sc *SecurityChecker) checkCommandInjection(ctx context.Context, targetURL string) []SecurityFinding {
	var findings []SecurityFinding

	cmdPayloads := []struct {
		payload  string
		evidence string
	}{
		{";id", "uid="},
		{"&&id", "uid="},
		{"|id", "uid="},
		{"`id`", "uid="},
		{"$(id)", "uid="},
		{";cat /etc/passwd", "root:x:"},
		{"&&cat /etc/passwd", "root:x:"},
	}

	commonParams := []string{"host", "ip", "url", "server", "domain", "ping", "exec", "cmd", "command", "run"}

	for _, param := range commonParams {
		for _, test := range cmdPayloads {
			sep := "?"
			if strings.Contains(targetURL, "?") {
				sep = "&"
			}
			testURL := targetURL + sep + param + "=" + test.payload
			_, body, err := sc.fetch(ctx, testURL, "GET", map[string]string{"User-Agent": "Mozilla/5.0"})
			if err != nil {
				continue
			}
			if strings.Contains(body, test.evidence) {
				findings = append(findings, SecurityFinding{
					Title:       "OS Command Injection",
					Description: fmt.Sprintf("Parameter %q appears to execute OS commands. The payload %q produced command output in the response.", param, test.payload),
					Severity:    SevCritical,
					Category:    "Injection",
					URL:         testURL,
					Evidence:    fmt.Sprintf("Payload %q produced system output %q", test.payload, test.evidence),
					Remediation: "Never pass user input to shell commands. Use safe language APIs. If shell execution is required, use strict allowlists and escaping.",
					CVSS:        10.0,
				})
				return findings
			}
		}
	}
	return findings
}

// checkCRLFInjection tests for CRLF injection in HTTP headers via query parameters.
func (sc *SecurityChecker) checkCRLFInjection(ctx context.Context, targetURL string) []SecurityFinding {
	var findings []SecurityFinding

	crlfPayloads := []string{
		"%0d%0aX-Injected: rayyan-crlf-probe",
		"%0aX-Injected: rayyan-crlf-probe",
		"\r\nX-Injected: rayyan-crlf-probe",
	}
	params := []string{"url", "redirect", "return", "next", "page", "ref", "lang"}

	for _, param := range params {
		for _, payload := range crlfPayloads {
			sep := "?"
			if strings.Contains(targetURL, "?") {
				sep = "&"
			}
			testURL := targetURL + sep + param + "=" + payload
			resp, _, err := sc.fetch(ctx, testURL, "GET", map[string]string{"User-Agent": "Mozilla/5.0"})
			if err != nil || resp == nil {
				continue
			}
			if resp.Header.Get("X-Injected") != "" {
				findings = append(findings, SecurityFinding{
					Title:       "CRLF Injection",
					Description: fmt.Sprintf("Parameter %q allows CRLF injection into HTTP response headers. This can enable HTTP response splitting and header injection attacks.", param),
					Severity:    SevHigh,
					Category:    "Injection",
					URL:         testURL,
					Evidence:    fmt.Sprintf("X-Injected header appeared in response via payload: %s", payload),
					Remediation: "Strip or encode CR (\\r) and LF (\\n) characters from all values used in HTTP response headers.",
					CVSS:        7.2,
				})
				return findings
			}
		}
	}
	return findings
}

// checkXXE probes XML endpoints for XXE vulnerability.
func (sc *SecurityChecker) checkXXE(ctx context.Context, targetURL string) []SecurityFinding {
	var findings []SecurityFinding

	xxePayload := `<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE test [<!ENTITY xxe SYSTEM "file:///etc/passwd">]>
<test>&xxe;</test>`

	xmlEndpoints := []string{"/api", "/soap", "/xml", "/upload", "/import", "/parse", "/rpc"}
	base := strings.TrimRight(targetURL, "/")

	for _, ep := range xmlEndpoints {
		url := base + ep
		req, err := http.NewRequestWithContext(ctx, "POST", url, strings.NewReader(xxePayload))
		if err != nil {
			continue
		}
		req.Header.Set("Content-Type", "application/xml")
		req.Header.Set("User-Agent", "Mozilla/5.0")

		resp, err := sc.client.Do(req)
		if err != nil || resp == nil {
			continue
		}
		buf := make([]byte, 8192)
		n, _ := resp.Body.Read(buf)
		_ = resp.Body.Close()
		body := string(buf[:n])

		if strings.Contains(body, "root:x:") || strings.Contains(body, "/bin/bash") {
			findings = append(findings, SecurityFinding{
				Title:       "XML External Entity (XXE) Injection",
				Description: fmt.Sprintf("The XML endpoint at %s processed an external entity reference and returned /etc/passwd content.", url),
				Severity:    SevCritical,
				Category:    "Injection",
				URL:         url,
				Evidence:    "XXE payload with file:///etc/passwd returned system file content.",
				Remediation: "Disable external entity processing in your XML parser. Use a safe XML library and enable FEATURE_DISALLOW_DOCTYPE_DECL.",
				CVE:         "CWE-611",
				CVSS:        9.1,
			})
			break
		}
	}
	return findings
}

// checkSecurityDisclosurePolicy checks for presence of security.txt and responsible disclosure policy.
func (sc *SecurityChecker) checkSecurityDisclosurePolicy(ctx context.Context, targetURL string) []SecurityFinding {
	var findings []SecurityFinding
	base := strings.TrimRight(targetURL, "/")

	paths := []string{"/.well-known/security.txt", "/security.txt"}
	found := false
	for _, p := range paths {
		resp, body, err := sc.fetch(ctx, base+p, "GET", map[string]string{"User-Agent": "Mozilla/5.0"})
		if err == nil && resp != nil && resp.StatusCode == 200 && len(body) > 10 {
			found = true
			break
		}
	}

	if !found {
		findings = append(findings, SecurityFinding{
			Title:       "Missing security.txt (No Vulnerability Disclosure Policy)",
			Description: "The site does not have a security.txt file at /.well-known/security.txt. This makes it harder for security researchers to report vulnerabilities responsibly.",
			Severity:    SevInfo,
			Category:    "Security Policy",
			URL:         targetURL,
			Evidence:    "/.well-known/security.txt returned non-200 or empty.",
			Remediation: "Create a security.txt at /.well-known/security.txt per RFC 9116. Include contact, policy, and encryption fields.",
		})
	}
	return findings
}

// checkMIMEConfusion tests for MIME-type confusion attacks via file upload endpoints.
func (sc *SecurityChecker) checkMIMEConfusion(ctx context.Context, targetURL string) []SecurityFinding {
	var findings []SecurityFinding

	resp, _, err := sc.fetch(ctx, targetURL, "GET", map[string]string{"User-Agent": "Mozilla/5.0"})
	if err != nil || resp == nil {
		return findings
	}

	xcto := resp.Header.Get("X-Content-Type-Options")
	ct := resp.Header.Get("Content-Type")

	if xcto == "" && !strings.Contains(strings.ToLower(ct), "text/html") {
		findings = append(findings, SecurityFinding{
			Title:       "MIME Sniffing Risk: Missing X-Content-Type-Options on Non-HTML Response",
			Description: "The server returns a non-HTML Content-Type without the X-Content-Type-Options: nosniff header. Browsers may MIME-sniff the content and execute it as a different type.",
			Severity:    SevLow,
			Category:    "MIME Confusion",
			URL:         targetURL,
			Evidence:    fmt.Sprintf("Content-Type: %s | X-Content-Type-Options: absent", ct),
			Remediation: "Add X-Content-Type-Options: nosniff to all responses. Ensure uploaded file Content-Types are validated server-side.",
		})
	}
	return findings
}

// checkSubresourceIntegrity checks if external scripts/styles use SRI attributes.
func (sc *SecurityChecker) checkSubresourceIntegrity(ctx context.Context, targetURL string) []SecurityFinding {
	var findings []SecurityFinding

	_, body, err := sc.fetch(ctx, targetURL, "GET", map[string]string{"User-Agent": "Mozilla/5.0"})
	if err != nil {
		return findings
	}

	// Find external scripts without integrity attribute
	scriptRe := regexp.MustCompile(`(?i)<script[^>]+src=["']https?://[^"']+["'][^>]*>`)
	linkRe := regexp.MustCompile(`(?i)<link[^>]+href=["']https?://[^"']+["'][^>]*(stylesheet)[^>]*>`)

	scripts := scriptRe.FindAllString(body, -1)
	links := linkRe.FindAllString(body, -1)

	for _, tag := range append(scripts, links...) {
		if !strings.Contains(tag, "integrity=") {
			srcRe := regexp.MustCompile(`(?i)(?:src|href)=["']([^"']+)["']`)
			match := srcRe.FindStringSubmatch(tag)
			src := ""
			if len(match) > 1 {
				src = match[1]
			}
			findings = append(findings, SecurityFinding{
				Title:       "Missing Subresource Integrity (SRI)",
				Description: "An external script or stylesheet is loaded without an integrity attribute. If the CDN is compromised, malicious code could be injected.",
				Severity:    SevMedium,
				Category:    "Supply Chain",
				URL:         targetURL,
				Evidence:    fmt.Sprintf("External resource without SRI: %s", src),
				Remediation: "Add integrity and crossorigin attributes to all external <script> and <link> tags. Generate hashes at https://www.srihash.org/",
			})
			break // report once per URL
		}
	}
	return findings
}

// end of security_checks_extended.go
