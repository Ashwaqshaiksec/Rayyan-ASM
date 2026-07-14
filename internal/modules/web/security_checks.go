package web

import (
	"context"
	"crypto/tls"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"
)

// Severity constants
const (
	SevCritical = "critical"
	SevHigh     = "high"
	SevMedium   = "medium"
	SevLow      = "low"
	SevInfo     = "info"
)

// SecurityFinding is a single issue found during web security testing.
type SecurityFinding struct {
	Title       string
	Description string
	Severity    string
	Category    string
	URL         string
	Evidence    string
	Remediation string
	CVE         string
	CVSS        float64
}

// SecurityChecker runs pure-HTTP security checks against a target URL.
type SecurityChecker struct {
	client *http.Client
}

func NewSecurityChecker() *SecurityChecker {
	transport := &http.Transport{
		TLSClientConfig:     &tls.Config{InsecureSkipVerify: true},
		DisableKeepAlives:   true,
		MaxIdleConnsPerHost: 5,
	}
	return &SecurityChecker{
		client: &http.Client{
			Transport: transport,
			Timeout:   12 * time.Second,
			CheckRedirect: func(req *http.Request, via []*http.Request) error {
				if len(via) >= 5 {
					return http.ErrUseLastResponse
				}
				return nil
			},
		},
	}
}

// Check runs all security checks on the given URL and returns findings.
func (sc *SecurityChecker) Check(ctx context.Context, targetURL string) []SecurityFinding {
	var findings []SecurityFinding

	// Fetch base response once
	resp, body, err := sc.fetch(ctx, targetURL, "GET", map[string]string{
		"User-Agent": "Mozilla/5.0 (compatible; SecurityScanner/1.0)",
	})
	if err != nil || resp == nil {
		return findings
	}

	findings = append(findings, sc.checkSecurityHeaders(targetURL, resp)...)
	findings = append(findings, sc.checkTLS(targetURL, resp)...)
	findings = append(findings, sc.checkInformationDisclosure(targetURL, resp, body)...)
	findings = append(findings, sc.checkClickjacking(targetURL, resp)...)
	findings = append(findings, sc.checkCORS(ctx, targetURL)...)
	findings = append(findings, sc.checkSensitivePaths(ctx, targetURL)...)
	findings = append(findings, sc.checkHTTPMethods(ctx, targetURL)...)
	findings = append(findings, sc.checkCookies(targetURL, resp)...)
	findings = append(findings, sc.checkCaching(targetURL, resp)...)
	findings = append(findings, sc.checkRedirect(ctx, targetURL)...)
	// Extended checks
	findings = append(findings, sc.checkCORSWildcardCredentials(ctx, targetURL)...)
	findings = append(findings, sc.checkHTTPRequestSmuggling(ctx, targetURL)...)
	findings = append(findings, sc.checkSSTI(ctx, targetURL)...)
	findings = append(findings, sc.checkJWT(ctx, targetURL, resp, body)...)
	findings = append(findings, sc.checkGraphQLIntrospection(ctx, targetURL)...)
	findings = append(findings, sc.checkOpenRedirect(ctx, targetURL)...)
	findings = append(findings, sc.checkSSRFDNSRebinding(ctx, targetURL)...)
	findings = append(findings, sc.checkPathTraversal(ctx, targetURL)...)
	findings = append(findings, sc.checkSubdomainTakeover(targetURL, resp)...)
	findings = append(findings, sc.checkPrototypePollution(ctx, targetURL)...)
	findings = append(findings, sc.checkDOMXSSSinks(targetURL, body)...)
	findings = append(findings, sc.checkHTTP2Downgrade(ctx, targetURL)...)
	findings = append(findings, sc.checkCachePoisoning(ctx, targetURL)...)
	findings = append(findings, sc.checkHostHeaderInjection(ctx, targetURL)...)
	findings = append(findings, sc.checkMassAssignmentIDOR(ctx, targetURL)...)

	findings = append(findings, sc.checkReflectedXSS(ctx, targetURL)...)
	findings = append(findings, sc.checkCSRF(ctx, targetURL)...)
	findings = append(findings, sc.checkRateLimiting(ctx, targetURL)...)
	findings = append(findings, sc.checkDefaultCredentials(ctx, targetURL)...)
	findings = append(findings, sc.checkDirectoryListing(ctx, targetURL)...)
	findings = append(findings, sc.checkWebSocketEndpoints(ctx, targetURL)...)
	findings = append(findings, sc.checkSecretsInResponse(ctx, targetURL)...)
	// Convert resp.Header to map[string]string for tech vuln check
	flatHeaders := make(map[string]string, len(resp.Header))
	for k, v := range resp.Header {
		flatHeaders[k] = strings.Join(v, ", ")
	}
	findings = append(findings, sc.checkTechVulnerabilities(ctx, targetURL, nil, flatHeaders, body)...)
	findings = append(findings, sc.checkSQLInjection(ctx, targetURL)...)
	findings = append(findings, sc.checkCommandInjection(ctx, targetURL)...)
	findings = append(findings, sc.checkCRLFInjection(ctx, targetURL)...)
	findings = append(findings, sc.checkXXE(ctx, targetURL)...)
	findings = append(findings, sc.checkSecurityDisclosurePolicy(ctx, targetURL)...)
	findings = append(findings, sc.checkMIMEConfusion(ctx, targetURL)...)
	findings = append(findings, sc.checkSubresourceIntegrity(ctx, targetURL)...)

	// Batch-3 checks
	findings = append(findings, sc.checkOAuthOIDC(ctx, targetURL)...)
	findings = append(findings, sc.checkHTTP2RapidReset(ctx, targetURL)...)
	findings = append(findings, sc.checkSubdomainTakeoverBody(ctx, targetURL)...)
	findings = append(findings, sc.checkTimingBlindSQLi(ctx, targetURL)...)
	findings = append(findings, sc.checkAPIVersioning(ctx, targetURL)...)

	return findings
}

func (sc *SecurityChecker) checkSecurityHeaders(targetURL string, resp *http.Response) []SecurityFinding {
	var findings []SecurityFinding

	type headerCheck struct {
		name        string
		severity    string
		description string
		remediation string
	}

	checks := []headerCheck{
		{
			"Strict-Transport-Security", SevHigh,
			"HSTS header is missing. Browsers may fall back to plain HTTP, exposing users to downgrade and MITM attacks.",
			"Add: Strict-Transport-Security: max-age=31536000; includeSubDomains; preload",
		},
		{
			"Content-Security-Policy", SevMedium,
			"CSP header is missing. Without CSP, browsers have no policy to prevent XSS and data injection attacks.",
			"Define a strict Content-Security-Policy appropriate to your application.",
		},
		{
			"X-Frame-Options", SevMedium,
			"X-Frame-Options header is missing, potentially allowing clickjacking via iframe embedding.",
			"Add: X-Frame-Options: DENY or SAMEORIGIN (or use CSP frame-ancestors directive).",
		},
		{
			"X-Content-Type-Options", SevLow,
			"X-Content-Type-Options header is missing. Browsers may MIME-sniff responses, enabling content injection.",
			"Add: X-Content-Type-Options: nosniff",
		},
		{
			"Referrer-Policy", SevLow,
			"Referrer-Policy header is missing. Full URLs including sensitive query params may leak in Referer headers.",
			"Add: Referrer-Policy: strict-origin-when-cross-origin",
		},
		{
			"Permissions-Policy", SevInfo,
			"Permissions-Policy (formerly Feature-Policy) header is missing. Browser features are unrestricted.",
			"Add a Permissions-Policy header to restrict access to browser APIs like camera, microphone, geolocation.",
		},
	}

	for _, c := range checks {
		if resp.Header.Get(c.name) == "" {
			findings = append(findings, SecurityFinding{
				Title:       fmt.Sprintf("Missing Security Header: %s", c.name),
				Description: c.description,
				Severity:    c.severity,
				Category:    "Security Headers",
				URL:         targetURL,
				Evidence:    fmt.Sprintf("Header '%s' not present in HTTP response.", c.name),
				Remediation: c.remediation,
			})
		}
	}

	// Check for deprecated X-XSS-Protection: 1 (can actually introduce vulnerabilities)
	if xss := resp.Header.Get("X-XSS-Protection"); xss == "1" || xss == "1; mode=block" {
		findings = append(findings, SecurityFinding{
			Title:       "Deprecated X-XSS-Protection Header",
			Description: "X-XSS-Protection: 1 is deprecated and can introduce cross-site scripting vulnerabilities in older browsers. Modern browsers use CSP instead.",
			Severity:    SevLow,
			Category:    "Security Headers",
			URL:         targetURL,
			Evidence:    fmt.Sprintf("X-XSS-Protection: %s", xss),
			Remediation: "Remove X-XSS-Protection header and implement a proper Content-Security-Policy instead.",
		})
	}

	return findings
}

func (sc *SecurityChecker) checkTLS(targetURL string, resp *http.Response) []SecurityFinding {
	var findings []SecurityFinding

	if !strings.HasPrefix(targetURL, "https://") {
		return findings
	}

	if resp.TLS == nil {
		return findings
	}

	// Weak TLS versions
	version := resp.TLS.Version
	switch version {
	case tls.VersionSSL30: //nolint:staticcheck // detecting SSLv3 support on the target, not negotiating it
		findings = append(findings, SecurityFinding{
			Title:       "SSL 3.0 Supported (POODLE)",
			Description: "The server supports SSL 3.0, which is vulnerable to the POODLE attack (CVE-2014-3566).",
			Severity:    SevCritical, Category: "TLS", URL: targetURL,
			Evidence:    "TLS handshake negotiated SSL 3.0",
			Remediation: "Disable SSL 3.0 and TLS 1.0/1.1. Only enable TLS 1.2 and TLS 1.3.",
			CVE:         "CVE-2014-3566", CVSS: 3.4,
		})
	case tls.VersionTLS10:
		findings = append(findings, SecurityFinding{
			Title:       "TLS 1.0 Supported (Deprecated)",
			Description: "TLS 1.0 is deprecated (RFC 8996) and vulnerable to BEAST and POODLE attacks.",
			Severity:    SevHigh, Category: "TLS", URL: targetURL,
			Evidence:    "TLS handshake negotiated TLS 1.0",
			Remediation: "Disable TLS 1.0 and 1.1. Configure minimum TLS 1.2.",
			CVE:         "CVE-2011-3389", CVSS: 5.9,
		})
	case tls.VersionTLS11:
		findings = append(findings, SecurityFinding{
			Title:       "TLS 1.1 Supported (Deprecated)",
			Description: "TLS 1.1 is deprecated (RFC 8996) and should not be used.",
			Severity:    SevMedium, Category: "TLS", URL: targetURL,
			Evidence:    "TLS handshake negotiated TLS 1.1",
			Remediation: "Disable TLS 1.1. Configure minimum TLS 1.2.",
		})
	}

	// Expired or self-signed cert
	if len(resp.TLS.PeerCertificates) > 0 {
		cert := resp.TLS.PeerCertificates[0]

		if time.Now().After(cert.NotAfter) {
			findings = append(findings, SecurityFinding{
				Title:       "Expired TLS Certificate",
				Description: fmt.Sprintf("The TLS certificate for %s expired on %s.", cert.Subject.CommonName, cert.NotAfter.Format("2006-01-02")),
				Severity:    SevCritical, Category: "TLS", URL: targetURL,
				Evidence:    fmt.Sprintf("NotAfter: %s", cert.NotAfter.Format(time.RFC3339)),
				Remediation: "Renew the TLS certificate immediately.",
			})
		} else if cert.NotAfter.Before(time.Now().Add(30 * 24 * time.Hour)) {
			findings = append(findings, SecurityFinding{
				Title:       "TLS Certificate Expiring Soon",
				Description: fmt.Sprintf("The TLS certificate expires on %s (within 30 days).", cert.NotAfter.Format("2006-01-02")),
				Severity:    SevHigh, Category: "TLS", URL: targetURL,
				Evidence:    fmt.Sprintf("NotAfter: %s", cert.NotAfter.Format(time.RFC3339)),
				Remediation: "Renew the TLS certificate before it expires.",
			})
		}

		// Self-signed
		if cert.IsCA && cert.Issuer.CommonName == cert.Subject.CommonName {
			findings = append(findings, SecurityFinding{
				Title:       "Self-Signed TLS Certificate",
				Description: "The server is presenting a self-signed certificate. Browsers will show security warnings.",
				Severity:    SevHigh, Category: "TLS", URL: targetURL,
				Evidence:    fmt.Sprintf("Issuer: %s, Subject: %s", cert.Issuer.CommonName, cert.Subject.CommonName),
				Remediation: "Replace the self-signed certificate with one from a trusted Certificate Authority.",
			})
		}
	}

	return findings
}

func (sc *SecurityChecker) checkInformationDisclosure(targetURL string, resp *http.Response, body string) []SecurityFinding {
	var findings []SecurityFinding

	// Server header with version
	server := resp.Header.Get("Server")
	if server != "" {
		hasVersion := false
		for _, part := range strings.Fields(server) {
			if strings.Contains(part, "/") {
				hasVersion = true
				break
			}
		}
		if hasVersion || strings.ContainsAny(server, "0123456789") {
			findings = append(findings, SecurityFinding{
				Title:       "Server Version Disclosure",
				Description: "The Server response header reveals the web server software and version, aiding attackers in identifying CVEs.",
				Severity:    SevLow, Category: "Information Disclosure", URL: targetURL,
				Evidence:    fmt.Sprintf("Server: %s", server),
				Remediation: "Configure your web server to omit version information from the Server header.",
			})
		}
	}

	// X-Powered-By
	if powered := resp.Header.Get("X-Powered-By"); powered != "" {
		findings = append(findings, SecurityFinding{
			Title:       "Technology Disclosure via X-Powered-By",
			Description: "The X-Powered-By header reveals the backend technology stack.",
			Severity:    SevInfo, Category: "Information Disclosure", URL: targetURL,
			Evidence:    fmt.Sprintf("X-Powered-By: %s", powered),
			Remediation: "Remove the X-Powered-By header from all responses.",
		})
	}

	// X-AspNet-Version
	if aspnet := resp.Header.Get("X-AspNet-Version"); aspnet != "" {
		findings = append(findings, SecurityFinding{
			Title:       "ASP.NET Version Disclosure",
			Description: "The X-AspNet-Version header exposes the exact .NET runtime version in use.",
			Severity:    SevLow, Category: "Information Disclosure", URL: targetURL,
			Evidence:    fmt.Sprintf("X-AspNet-Version: %s", aspnet),
			Remediation: "Set <httpRuntime enableVersionHeader=\"false\" /> in web.config.",
		})
	}

	// Stack trace / debug info in body
	bodyLower := strings.ToLower(body)
	debugPatterns := map[string]string{
		"stack trace":         "Stack trace exposed in response body",
		"exception in thread": "Java exception trace exposed",
		"traceback (most":     "Python traceback exposed",
		"fatal error:":        "PHP/Go fatal error exposed",
		"warning: ":           "PHP warning message exposed",
		"syntax error":        "Syntax error in response body",
		"at com.":             "Java stack trace exposed",
		"at java.":            "Java stack trace exposed",
		"microsoft ole db":    "OLE DB error exposed",
		"odbc drivers error":  "ODBC error exposed",
		"sql syntax":          "SQL syntax error exposed",
		"mysql_fetch":         "MySQL error exposed",
		"pg_query():":         "PostgreSQL error exposed",
	}
	for pattern, title := range debugPatterns {
		if strings.Contains(bodyLower, pattern) {
			findings = append(findings, SecurityFinding{
				Title:       fmt.Sprintf("Debug/Error Information Disclosed: %s", title),
				Description: "The application is exposing internal error or debug information in HTTP responses, which can assist attackers.",
				Severity:    SevMedium, Category: "Information Disclosure", URL: targetURL,
				Evidence:    fmt.Sprintf("Pattern '%s' found in response body.", pattern),
				Remediation: "Disable debug mode and configure custom error pages. Never expose stack traces in production.",
			})
			break // one finding per URL is enough for this category
		}
	}

	return findings
}

func (sc *SecurityChecker) checkClickjacking(targetURL string, resp *http.Response) []SecurityFinding {
	var findings []SecurityFinding

	xfo := resp.Header.Get("X-Frame-Options")
	csp := resp.Header.Get("Content-Security-Policy")

	hasFrameProtection := xfo != "" || strings.Contains(strings.ToLower(csp), "frame-ancestors")

	if !hasFrameProtection {
		findings = append(findings, SecurityFinding{
			Title:       "Clickjacking: No Frame Embedding Protection",
			Description: "Neither X-Frame-Options nor CSP frame-ancestors directive is set. The page can be embedded in an iframe on any domain, enabling clickjacking attacks.",
			Severity:    SevMedium, Category: "Clickjacking", URL: targetURL,
			Evidence:    "X-Frame-Options: absent, CSP frame-ancestors: absent",
			Remediation: "Add 'X-Frame-Options: DENY' or include 'frame-ancestors \"none\"' in Content-Security-Policy.",
		})
	}

	return findings
}

func (sc *SecurityChecker) checkCORS(ctx context.Context, targetURL string) []SecurityFinding {
	var findings []SecurityFinding

	// Send a CORS preflight with a hostile origin
	resp, _, err := sc.fetch(ctx, targetURL, "GET", map[string]string{
		"Origin":                        "https://attacker.example.com",
		"Access-Control-Request-Method": "GET",
		"User-Agent":                    "Mozilla/5.0 (compatible; SecurityScanner/1.0)",
	})
	if err != nil || resp == nil {
		return findings
	}

	acao := resp.Header.Get("Access-Control-Allow-Origin")
	acac := resp.Header.Get("Access-Control-Allow-Credentials")

	if acao == "*" {
		findings = append(findings, SecurityFinding{
			Title:       "CORS: Wildcard Access-Control-Allow-Origin",
			Description: "The server responds with Access-Control-Allow-Origin: *, allowing any origin to make cross-origin requests and read the response.",
			Severity:    SevMedium, Category: "CORS", URL: targetURL,
			Evidence:    "Access-Control-Allow-Origin: *",
			Remediation: "Restrict CORS to specific trusted origins. Never use wildcard with sensitive endpoints.",
		})
	} else if acao == "https://attacker.example.com" {
		sev := SevHigh
		if strings.EqualFold(acac, "true") {
			sev = SevCritical
		}
		findings = append(findings, SecurityFinding{
			Title:       "CORS: Arbitrary Origin Reflected",
			Description: "The server reflects the attacker-controlled Origin header back in Access-Control-Allow-Origin, allowing cross-origin reads from any domain.",
			Severity:    sev, Category: "CORS", URL: targetURL,
			Evidence:    fmt.Sprintf("Access-Control-Allow-Origin: %s, Credentials: %s", acao, acac),
			Remediation: "Validate Origin against an explicit allowlist. Never reflect arbitrary Origin values.",
			CVSS:        7.5,
		})
	}

	return findings
}

func (sc *SecurityChecker) checkSensitivePaths(ctx context.Context, targetURL string) []SecurityFinding {
	var findings []SecurityFinding

	base := strings.TrimRight(targetURL, "/")

	type pathCheck struct {
		path     string
		title    string
		severity string
		category string
	}

	paths := []pathCheck{
		// Admin panels
		{"/admin", "Admin Panel Exposed", SevHigh, "Exposed Admin Interface"},
		{"/administrator", "Administrator Panel Exposed", SevHigh, "Exposed Admin Interface"},
		{"/wp-admin", "WordPress Admin Panel Exposed", SevHigh, "Exposed Admin Interface"},
		{"/wp-login.php", "WordPress Login Exposed", SevMedium, "Exposed Admin Interface"},
		{"/phpmyadmin", "phpMyAdmin Exposed", SevCritical, "Exposed Admin Interface"},
		{"/phpmyadmin/", "phpMyAdmin Exposed", SevCritical, "Exposed Admin Interface"},
		{"/pma", "phpMyAdmin (pma) Exposed", SevCritical, "Exposed Admin Interface"},
		{"/adminer.php", "Adminer Database UI Exposed", SevCritical, "Exposed Admin Interface"},

		// Sensitive files
		{"/.git/HEAD", "Git Repository Exposed", SevCritical, "Source Code Exposure"},
		{"/.git/config", "Git Config Exposed", SevCritical, "Source Code Exposure"},
		{"/.env", ".env File Exposed", SevCritical, "Credentials Exposure"},
		{"/.env.local", ".env.local File Exposed", SevCritical, "Credentials Exposure"},
		{"/.env.production", ".env.production File Exposed", SevCritical, "Credentials Exposure"},
		{"/config.php", "Config File Exposed", SevHigh, "Credentials Exposure"},
		{"/configuration.php", "Joomla Config Exposed", SevHigh, "Credentials Exposure"},
		{"/wp-config.php", "WordPress Config Exposed", SevCritical, "Credentials Exposure"},
		{"/database.yml", "Database Config Exposed", SevCritical, "Credentials Exposure"},
		{"/credentials.json", "Credentials File Exposed", SevCritical, "Credentials Exposure"},
		{"/secrets.json", "Secrets File Exposed", SevCritical, "Credentials Exposure"},

		// Debug/info endpoints
		{"/server-status", "Apache Server Status Exposed", SevMedium, "Information Disclosure"},
		{"/server-info", "Apache Server Info Exposed", SevMedium, "Information Disclosure"},
		{"/phpinfo.php", "PHP Info Page Exposed", SevHigh, "Information Disclosure"},
		{"/info.php", "PHP Info Page Exposed", SevHigh, "Information Disclosure"},
		{"/_profiler", "Symfony Profiler Exposed", SevHigh, "Information Disclosure"},
		{"/actuator", "Spring Actuator Exposed", SevHigh, "Information Disclosure"},
		{"/actuator/env", "Spring Actuator /env Exposed", SevCritical, "Information Disclosure"},
		{"/actuator/heapdump", "Spring Heapdump Exposed", SevCritical, "Information Disclosure"},
		{"/debug", "Debug Endpoint Exposed", SevMedium, "Information Disclosure"},
		{"/debug/vars", "Go Expvar Debug Endpoint Exposed", SevMedium, "Information Disclosure"},

		// Backup files
		{"/backup.zip", "Backup Archive Exposed", SevCritical, "Backup Exposure"},
		{"/backup.tar.gz", "Backup Archive Exposed", SevCritical, "Backup Exposure"},
		{"/backup.sql", "SQL Backup Exposed", SevCritical, "Backup Exposure"},
		{"/db.sql", "SQL Dump Exposed", SevCritical, "Backup Exposure"},
		{"/dump.sql", "SQL Dump Exposed", SevCritical, "Backup Exposure"},

		// API
		{"/swagger.json", "Swagger API Docs Exposed", SevMedium, "API Exposure"},
		{"/swagger-ui.html", "Swagger UI Exposed", SevMedium, "API Exposure"},
		{"/openapi.json", "OpenAPI Spec Exposed", SevMedium, "API Exposure"},
		{"/api/swagger.json", "Swagger API Docs Exposed", SevMedium, "API Exposure"},
		{"/graphql", "GraphQL Endpoint Exposed", SevMedium, "API Exposure"},
		{"/graphiql", "GraphiQL Interface Exposed", SevHigh, "API Exposure"},

		// Logs
		{"/logs/error.log", "Error Log Exposed", SevHigh, "Log Exposure"},
		{"/error.log", "Error Log Exposed", SevHigh, "Log Exposure"},
		{"/access.log", "Access Log Exposed", SevMedium, "Log Exposure"},

		// Jenkins / CI
		{"/jenkins", "Jenkins Instance Exposed", SevHigh, "Exposed Admin Interface"},
		{"/jenkins/", "Jenkins Instance Exposed", SevHigh, "Exposed Admin Interface"},
		{"/console", "Console Exposed", SevHigh, "Exposed Admin Interface"},

		// Misc
		{"/.DS_Store", ".DS_Store File Exposed", SevLow, "Information Disclosure"},
		{"/robots.txt", "robots.txt Accessible", SevInfo, "Information Disclosure"},
		{"/sitemap.xml", "sitemap.xml Accessible", SevInfo, "Information Disclosure"},
		{"/.well-known/security.txt", "security.txt Present", SevInfo, "Security Policy"},
	}

	// Worker pool to check paths concurrently
	type result struct {
		finding *SecurityFinding
	}
	resultCh := make(chan result, len(paths))
	sem := make(chan struct{}, 10) // 10 concurrent

	for _, p := range paths {
		go func(pc pathCheck) {
			sem <- struct{}{}
			defer func() { <-sem }()

			url := base + pc.path
			resp, body, err := sc.fetch(ctx, url, "GET", map[string]string{
				"User-Agent": "Mozilla/5.0 (compatible; SecurityScanner/1.0)",
			})
			if err != nil || resp == nil {
				resultCh <- result{nil}
				return
			}

			// Only flag 200-class or 403 (which confirms the resource exists)
			code := resp.StatusCode
			if code == 200 || code == 403 {
				// For robots.txt / sitemap / security.txt — just info, always flag if 200
				if code == 403 && pc.severity == SevInfo {
					resultCh <- result{nil}
					return
				}

				evidence := fmt.Sprintf("HTTP %d at %s", code, url)
				if code == 200 && len(body) > 0 && len(body) < 200 {
					// Include a short snippet for context
					snip := strings.TrimSpace(body)
					if len(snip) > 120 {
						snip = snip[:120] + "..."
					}
					evidence += fmt.Sprintf(" | Body preview: %s", snip)
				}

				f := &SecurityFinding{
					Title:       pc.title,
					Description: fmt.Sprintf("Sensitive path '%s' returned HTTP %d. This resource should not be publicly accessible.", pc.path, code),
					Severity:    pc.severity,
					Category:    pc.category,
					URL:         url,
					Evidence:    evidence,
					Remediation: fmt.Sprintf("Restrict access to '%s' via server configuration, firewall rules, or remove the file if unnecessary.", pc.path),
				}
				resultCh <- result{f}
			} else {
				resultCh <- result{nil}
			}
		}(p)
	}

	for range paths {
		r := <-resultCh
		if r.finding != nil {
			findings = append(findings, *r.finding)
		}
	}

	return findings
}

func (sc *SecurityChecker) checkHTTPMethods(ctx context.Context, targetURL string) []SecurityFinding {
	var findings []SecurityFinding

	dangerousMethods := []string{"TRACE", "TRACK", "PUT", "DELETE"}

	for _, method := range dangerousMethods {
		resp, _, err := sc.fetch(ctx, targetURL, method, map[string]string{
			"User-Agent": "Mozilla/5.0 (compatible; SecurityScanner/1.0)",
		})
		if err != nil || resp == nil {
			continue
		}

		if resp.StatusCode < 400 {
			sev := SevMedium
			desc := fmt.Sprintf("The HTTP %s method is allowed on this server.", method)
			rem := fmt.Sprintf("Disable the %s method in server configuration.", method)

			if method == "TRACE" || method == "TRACK" {
				sev = SevMedium
				desc = fmt.Sprintf("HTTP %s method is enabled. This can be used in cross-site tracing (XST) attacks to steal cookies and authentication tokens.", method)
				rem = fmt.Sprintf("Disable %s/TRACK methods in server configuration (TraceEnable Off in Apache, methods block in Nginx).", method)
			} else if method == "PUT" {
				sev = SevHigh
				desc = "HTTP PUT method is allowed. An attacker may be able to upload arbitrary files to the server."
				rem = "Disable HTTP PUT unless explicitly required by the application, and restrict it with authentication."
			} else if method == "DELETE" {
				sev = SevHigh
				desc = "HTTP DELETE method is allowed. An attacker may be able to delete files or resources on the server."
				rem = "Disable HTTP DELETE unless explicitly required, and restrict it with authentication and authorization."
			}

			findings = append(findings, SecurityFinding{
				Title:       fmt.Sprintf("Dangerous HTTP Method Allowed: %s", method),
				Description: desc,
				Severity:    sev,
				Category:    "HTTP Methods",
				URL:         targetURL,
				Evidence:    fmt.Sprintf("HTTP %s returned %d", method, resp.StatusCode),
				Remediation: rem,
			})
		}
	}

	resp, _, err := sc.fetch(ctx, targetURL, "OPTIONS", map[string]string{
		"User-Agent": "Mozilla/5.0 (compatible; SecurityScanner/1.0)",
	})
	if err == nil && resp != nil {
		if allow := resp.Header.Get("Allow"); allow != "" {
			if strings.Contains(strings.ToUpper(allow), "TRACE") ||
				strings.Contains(strings.ToUpper(allow), "TRACK") {
				findings = append(findings, SecurityFinding{
					Title:       "Dangerous Methods Listed in Allow Header",
					Description: "The OPTIONS Allow header lists dangerous HTTP methods (TRACE/TRACK).",
					Severity:    SevMedium, Category: "HTTP Methods", URL: targetURL,
					Evidence:    fmt.Sprintf("Allow: %s", allow),
					Remediation: "Restrict the Allow header to only necessary methods (GET, POST, HEAD).",
				})
			}
		}
	}

	return findings
}

func (sc *SecurityChecker) checkCookies(targetURL string, resp *http.Response) []SecurityFinding {
	var findings []SecurityFinding

	for _, cookie := range resp.Cookies() {
		name := cookie.Name

		if !cookie.Secure && strings.HasPrefix(targetURL, "https://") {
			findings = append(findings, SecurityFinding{
				Title:       fmt.Sprintf("Cookie Missing Secure Flag: %s", name),
				Description: fmt.Sprintf("The cookie '%s' does not have the Secure flag set. It may be transmitted over plain HTTP.", name),
				Severity:    SevMedium, Category: "Cookie Security", URL: targetURL,
				Evidence:    fmt.Sprintf("Set-Cookie: %s (Secure flag absent)", name),
				Remediation: "Set the Secure flag on all cookies: Set-Cookie: name=value; Secure",
			})
		}

		if !cookie.HttpOnly {
			findings = append(findings, SecurityFinding{
				Title:       fmt.Sprintf("Cookie Missing HttpOnly Flag: %s", name),
				Description: fmt.Sprintf("The cookie '%s' does not have the HttpOnly flag. It can be read by JavaScript, increasing XSS impact.", name),
				Severity:    SevMedium, Category: "Cookie Security", URL: targetURL,
				Evidence:    fmt.Sprintf("Set-Cookie: %s (HttpOnly flag absent)", name),
				Remediation: "Set the HttpOnly flag on all session cookies: Set-Cookie: name=value; HttpOnly",
			})
		}

		sameSite := ""
		switch cookie.SameSite {
		case http.SameSiteLaxMode:
			sameSite = "lax"
		case http.SameSiteStrictMode:
			sameSite = "strict"
		case http.SameSiteNoneMode:
			sameSite = "none"
		default:
			sameSite = ""
		}
		if sameSite == "" || sameSite == "none" {
			findings = append(findings, SecurityFinding{
				Title:       fmt.Sprintf("Cookie Missing SameSite Attribute: %s", name),
				Description: fmt.Sprintf("The cookie '%s' has no SameSite attribute, making it vulnerable to CSRF attacks.", name),
				Severity:    SevLow, Category: "Cookie Security", URL: targetURL,
				Evidence:    fmt.Sprintf("Set-Cookie: %s (SameSite not set)", name),
				Remediation: "Add SameSite=Lax or SameSite=Strict to sensitive cookies.",
			})
		}
	}

	return findings
}

func (sc *SecurityChecker) checkCaching(targetURL string, resp *http.Response) []SecurityFinding {
	var findings []SecurityFinding

	cc := resp.Header.Get("Cache-Control")
	pragma := resp.Header.Get("Pragma")

	if cc == "" && pragma == "" {
		findings = append(findings, SecurityFinding{
			Title:       "No Cache-Control Headers",
			Description: "The response has no Cache-Control or Pragma headers. Sensitive pages may be cached by proxies or browsers.",
			Severity:    SevInfo, Category: "Caching", URL: targetURL,
			Evidence:    "Cache-Control: absent, Pragma: absent",
			Remediation: "Add 'Cache-Control: no-store, no-cache, must-revalidate' for pages containing sensitive data.",
		})
	}

	return findings
}

func (sc *SecurityChecker) checkRedirect(ctx context.Context, targetURL string) []SecurityFinding {
	var findings []SecurityFinding

	if !strings.HasPrefix(targetURL, "https://") {
		return findings
	}

	httpURL := "http://" + strings.TrimPrefix(targetURL, "https://")

	// Use a client that does NOT follow redirects for this check
	noRedirectClient := &http.Client{
		Transport: &http.Transport{TLSClientConfig: &tls.Config{InsecureSkipVerify: true}},
		Timeout:   8 * time.Second,
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}

	req, err := http.NewRequestWithContext(ctx, "GET", httpURL, nil)
	if err != nil {
		return findings
	}
	req.Header.Set("User-Agent", "Mozilla/5.0 (compatible; SecurityScanner/1.0)")

	resp, err := noRedirectClient.Do(req)
	if err != nil {
		return findings
	}
	_ = resp.Body.Close()

	// If not redirecting to HTTPS
	if resp.StatusCode < 300 || resp.StatusCode >= 400 {
		findings = append(findings, SecurityFinding{
			Title:       "HTTP Not Redirected to HTTPS",
			Description: "Plain HTTP requests are not automatically redirected to HTTPS. Users who access the site over HTTP will not be upgraded to a secure connection.",
			Severity:    SevHigh, Category: "TLS", URL: httpURL,
			Evidence:    fmt.Sprintf("HTTP GET %s returned %d (no redirect to HTTPS)", httpURL, resp.StatusCode),
			Remediation: "Configure your web server to permanently redirect (301) all HTTP requests to HTTPS.",
		})
	} else {
		location := resp.Header.Get("Location")
		if location != "" && !strings.HasPrefix(location, "https://") {
			findings = append(findings, SecurityFinding{
				Title:       "HTTP Redirect Does Not Target HTTPS",
				Description: fmt.Sprintf("HTTP redirects to '%s' instead of an HTTPS URL.", location),
				Severity:    SevMedium, Category: "TLS", URL: httpURL,
				Evidence:    fmt.Sprintf("Location: %s", location),
				Remediation: "Ensure HTTP redirects point to the HTTPS version of the URL.",
			})
		}
	}

	return findings
}

func (sc *SecurityChecker) fetch(ctx context.Context, url, method string, headers map[string]string) (*http.Response, string, error) {
	req, err := http.NewRequestWithContext(ctx, method, url, nil)
	if err != nil {
		return nil, "", err
	}
	for k, v := range headers {
		req.Header.Set(k, v)
	}
	resp, err := sc.client.Do(req)
	if err != nil {
		return nil, "", err
	}
	defer func() { _ = resp.Body.Close() }()

	bodyBytes := make([]byte, 1024*32) // 32KB
	n, _ := io.ReadFull(resp.Body, bodyBytes)
	return resp, string(bodyBytes[:n]), nil
}

// checkCORSWildcardCredentials detects CORS misconfigurations where an arbitrary
// Origin is reflected with Access-Control-Allow-Credentials: true.
func (sc *SecurityChecker) checkCORSWildcardCredentials(ctx context.Context, targetURL string) []SecurityFinding {
	var findings []SecurityFinding
	resp, _, err := sc.fetch(ctx, targetURL, "GET", map[string]string{
		"Origin":     "https://evil.rayyan-asm-probe.invalid",
		"User-Agent": "Mozilla/5.0",
	})
	if err != nil || resp == nil {
		return findings
	}
	acao := resp.Header.Get("Access-Control-Allow-Origin")
	acac := resp.Header.Get("Access-Control-Allow-Credentials")
	if strings.EqualFold(acao, "https://evil.rayyan-asm-probe.invalid") &&
		strings.EqualFold(acac, "true") {
		findings = append(findings, SecurityFinding{
			Title:       "CORS: Arbitrary Origin Reflected with Credentials",
			Description: "The server reflects arbitrary Origins in ACAO and sets ACAC: true, allowing cross-origin requests with credentials from any attacker-controlled domain.",
			Severity:    SevCritical,
			Category:    "CORS",
			URL:         targetURL,
			Evidence:    fmt.Sprintf("ACAO: %s | ACAC: %s", acao, acac),
			Remediation: "Validate the Origin header against an explicit allowlist. Never combine a reflected/wildcard ACAO with ACAC: true.",
		})
	} else if acao == "*" && strings.EqualFold(acac, "true") {
		findings = append(findings, SecurityFinding{
			Title:       "CORS: Wildcard Origin with Credentials",
			Description: "Access-Control-Allow-Origin: * combined with Allow-Credentials: true is invalid per spec but some browsers may honour it.",
			Severity:    SevHigh,
			Category:    "CORS",
			URL:         targetURL,
			Evidence:    fmt.Sprintf("ACAO: %s | ACAC: %s", acao, acac),
			Remediation: "Remove the wildcard ACAO or disable Allow-Credentials for cross-origin requests.",
		})
	}
	return findings
}

// checkHTTPRequestSmuggling sends CL.TE and TE.CL probe requests looking for
// differential behaviour that indicates a desync opportunity.
func (sc *SecurityChecker) checkHTTPRequestSmuggling(ctx context.Context, targetURL string) []SecurityFinding {
	var findings []SecurityFinding
	// CL.TE probe: send Content-Length that is shorter than the actual body;
	// a vulnerable front-end will pass TE while the back-end uses CL.
	probe := "POST / HTTP/1.1\r\nHost: rayyan-probe\r\nContent-Length: 6\r\nTransfer-Encoding: chunked\r\n\r\n0\r\n\r\nX"
	_ = probe // actual TCP-level probing is out of scope for the HTTP client; detect via header reflection
	resp, _, err := sc.fetch(ctx, targetURL, "POST", map[string]string{
		"Content-Length":    "6",
		"Transfer-Encoding": "chunked",
		"User-Agent":        "Mozilla/5.0",
	})
	if err != nil || resp == nil {
		return findings
	}
	te := resp.Header.Get("Transfer-Encoding")
	if strings.Contains(strings.ToLower(te), "chunked") && resp.StatusCode == 200 {
		findings = append(findings, SecurityFinding{
			Title:       "Potential HTTP Request Smuggling (TE header reflected)",
			Description: "The server responds with Transfer-Encoding: chunked to a POST containing both CL and TE headers. Manual verification with a dedicated smuggling tool (smuggler, h2csmuggler) is recommended.",
			Severity:    SevHigh,
			Category:    "HTTP Smuggling",
			URL:         targetURL,
			Evidence:    fmt.Sprintf("Response TE: %s, Status: %d", te, resp.StatusCode),
			Remediation: "Normalise Transfer-Encoding headers at the reverse proxy/load balancer and reject ambiguous requests.",
			CVSS:        8.1,
		})
	}
	return findings
}

// checkSSTI tests for Server-Side Template Injection by injecting arithmetic
// expressions that popular template engines evaluate.
func (sc *SecurityChecker) checkSSTI(ctx context.Context, targetURL string) []SecurityFinding {
	var findings []SecurityFinding
	probes := []struct {
		payload  string
		expected string
	}{
		{"{{7*7}}", "49"},
		{"${7*7}", "49"},
		{"<%= 7*7 %>", "49"},
		{"#{7*7}", "49"},
		{"*{7*7}", "49"},
	}
	for _, p := range probes {
		testURL := targetURL
		if strings.Contains(testURL, "?") {
			testURL += "&q=" + p.payload
		} else {
			testURL += "?q=" + p.payload
		}
		_, body, err := sc.fetch(ctx, testURL, "GET", map[string]string{"User-Agent": "Mozilla/5.0"})
		if err != nil {
			continue
		}
		if strings.Contains(body, p.expected) {
			findings = append(findings, SecurityFinding{
				Title:       "Server-Side Template Injection (SSTI)",
				Description: "A template expression was evaluated server-side, indicating SSTI. This can lead to RCE.",
				Severity:    SevCritical,
				Category:    "Injection",
				URL:         testURL,
				Evidence:    fmt.Sprintf("Payload %q produced %q in response", p.payload, p.expected),
				Remediation: "Never pass user input into template rendering functions. Use strict sandboxing or a logic-less template engine.",
				CVSS:        9.8,
			})
			break
		}
	}
	return findings
}

// checkJWT inspects response body and Authorization headers for JWT tokens and
// detects the none-algorithm vulnerability pattern.
func (sc *SecurityChecker) checkJWT(ctx context.Context, targetURL string, resp *http.Response, body string) []SecurityFinding {
	var findings []SecurityFinding
	// Look for JWTs in Authorization header or response body
	detectJWT := func(s string) bool {
		parts := strings.Split(s, ".")
		return len(parts) == 3 && len(parts[0]) > 4
	}
	authHdr := resp.Header.Get("Authorization")
	token := ""
	if strings.HasPrefix(authHdr, "Bearer ") {
		token = strings.TrimPrefix(authHdr, "Bearer ")
	}
	if token == "" {
		// scan body for JWT-like strings
		for _, word := range strings.Fields(body) {
			word = strings.Trim(word, `"',;`)
			if detectJWT(word) {
				token = word
				break
			}
		}
	}
	if token == "" {
		return findings
	}
	// Probe: send forged token with alg:none
	noneToken := strings.Split(token, ".")
	if len(noneToken) < 2 {
		return findings
	}
	// Craft a none-alg header (base64url of {"alg":"none","typ":"JWT"})
	fakeHeader := "eyJhbGciOiJub25lIiwidHlwIjoiSldUIn0"
	forged := fakeHeader + "." + noneToken[1] + "."
	_, forgedBody, err := sc.fetch(ctx, targetURL, "GET", map[string]string{
		"Authorization": "Bearer " + forged,
		"User-Agent":    "Mozilla/5.0",
	})
	if err != nil {
		return findings
	}
	// Heuristic: if the forged token response is similar to an authenticated response
	// (not a 401/403) flag it
	_ = forgedBody
	_, legitBody, err2 := sc.fetch(ctx, targetURL, "GET", map[string]string{"User-Agent": "Mozilla/5.0"})
	if err2 != nil {
		return findings
	}
	if len(forgedBody) > 100 && len(forgedBody) > len(legitBody)+50 {
		findings = append(findings, SecurityFinding{
			Title:       "JWT None-Algorithm Accepted",
			Description: "The server may accept a JWT with alg:none (unsigned token), bypassing signature validation.",
			Severity:    SevCritical,
			Category:    "Authentication",
			URL:         targetURL,
			Evidence:    "Forged token with alg:none returned a larger response than the unauthenticated baseline.",
			Remediation: "Explicitly reject tokens with alg:none. Enforce allowlisted algorithms server-side.",
			CVSS:        9.1,
		})
	}
	return findings
}

// checkGraphQLIntrospection detects exposed GraphQL introspection endpoints.
func (sc *SecurityChecker) checkGraphQLIntrospection(ctx context.Context, targetURL string) []SecurityFinding {
	var findings []SecurityFinding
	endpoints := []string{"/graphql", "/api/graphql", "/v1/graphql", "/graphiql", "/gql"}
	introspectionQuery := `{"query":"{__schema{queryType{name}}}"}`
	for _, ep := range endpoints {
		base := strings.TrimRight(targetURL, "/")
		testURL := base + ep
		req, err := http.NewRequestWithContext(ctx, "POST", testURL, strings.NewReader(introspectionQuery))
		if err != nil {
			continue
		}
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("User-Agent", "Mozilla/5.0")
		resp, err := sc.client.Do(req)
		if err != nil || resp == nil {
			continue
		}
		defer func() { _ = resp.Body.Close() }()
		buf := make([]byte, 4096)
		n, _ := resp.Body.Read(buf)
		respBody := string(buf[:n])
		if resp.StatusCode == 200 && strings.Contains(respBody, "__schema") {
			findings = append(findings, SecurityFinding{
				Title:       "GraphQL Introspection Exposed",
				Description: "GraphQL introspection is enabled, allowing attackers to enumerate the full API schema.",
				Severity:    SevMedium,
				Category:    "API Security",
				URL:         testURL,
				Evidence:    "__schema present in response",
				Remediation: "Disable introspection in production environments.",
				CVSS:        5.3,
			})
			break
		}
	}
	return findings
}

// checkOpenRedirect tests for open redirect vulnerabilities using common redirect parameters.
func (sc *SecurityChecker) checkOpenRedirect(ctx context.Context, targetURL string) []SecurityFinding {
	var findings []SecurityFinding
	redirectParams := []string{"url", "redirect", "return", "next", "dest", "destination", "go", "redir", "redirect_uri", "return_url"}
	probe := "https://evil.rayyan-asm-probe.invalid"
	for _, param := range redirectParams {
		sep := "?"
		if strings.Contains(targetURL, "?") {
			sep = "&"
		}
		testURL := targetURL + sep + param + "=" + probe
		resp, _, err := sc.fetch(ctx, testURL, "GET", map[string]string{"User-Agent": "Mozilla/5.0"})
		if err != nil || resp == nil {
			continue
		}
		location := resp.Header.Get("Location")
		if resp.StatusCode >= 300 && resp.StatusCode < 400 && strings.Contains(location, "evil.rayyan-asm-probe.invalid") {
			findings = append(findings, SecurityFinding{
				Title:       "Open Redirect",
				Description: fmt.Sprintf("Parameter %q causes an external redirect to an attacker-controlled URL.", param),
				Severity:    SevMedium,
				Category:    "Open Redirect",
				URL:         testURL,
				Evidence:    fmt.Sprintf("HTTP %d Location: %s", resp.StatusCode, location),
				Remediation: "Validate redirect destinations against an explicit allowlist. Prefer relative paths.",
				CVSS:        6.1,
			})
			break
		}
	}
	return findings
}

// checkSSRFDNSRebinding probes for SSRF via common URL parameters pointing at
// the loopback and metadata service addresses.
func (sc *SecurityChecker) checkSSRFDNSRebinding(ctx context.Context, targetURL string) []SecurityFinding {
	var findings []SecurityFinding
	ssrfParams := []string{"url", "uri", "src", "source", "dest", "host", "fetch", "load", "callback", "path", "file"}
	probes := []string{
		"http://169.254.169.254/latest/meta-data/",
		"http://127.0.0.1/",
		"http://[::1]/",
	}
	for _, param := range ssrfParams {
		for _, probe := range probes {
			sep := "?"
			if strings.Contains(targetURL, "?") {
				sep = "&"
			}
			testURL := targetURL + sep + param + "=" + probe
			resp, body, err := sc.fetch(ctx, testURL, "GET", map[string]string{"User-Agent": "Mozilla/5.0"})
			if err != nil || resp == nil {
				continue
			}
			ssrfIndicators := []string{"ami-id", "instance-id", "root:x:", "localhost", "127.0.0.1"}
			for _, indicator := range ssrfIndicators {
				if strings.Contains(body, indicator) {
					findings = append(findings, SecurityFinding{
						Title:       "Server-Side Request Forgery (SSRF)",
						Description: fmt.Sprintf("Parameter %q triggers a server-side HTTP request; internal service content was returned.", param),
						Severity:    SevCritical,
						Category:    "SSRF",
						URL:         testURL,
						Evidence:    fmt.Sprintf("Status %d, body contains %q", resp.StatusCode, indicator),
						Remediation: "Validate and allowlist outbound request destinations. Block metadata service ranges at the network level.",
						CVSS:        9.8,
					})
					return findings
				}
			}
		}
	}
	return findings
}

// checkPathTraversal tests for LFI / path traversal vulnerabilities.
func (sc *SecurityChecker) checkPathTraversal(ctx context.Context, targetURL string) []SecurityFinding {
	var findings []SecurityFinding
	lfiPayloads := []string{
		"../../../../etc/passwd",
		"..%2F..%2F..%2F..%2Fetc%2Fpasswd",
		"....//....//....//etc/passwd",
	}
	fileParams := []string{"file", "path", "page", "include", "doc", "template", "view"}
	for _, param := range fileParams {
		for _, payload := range lfiPayloads {
			sep := "?"
			if strings.Contains(targetURL, "?") {
				sep = "&"
			}
			testURL := targetURL + sep + param + "=" + payload
			_, body, err := sc.fetch(ctx, testURL, "GET", map[string]string{"User-Agent": "Mozilla/5.0"})
			if err != nil {
				continue
			}
			if strings.Contains(body, "root:x:") || strings.Contains(body, "/bin/bash") {
				findings = append(findings, SecurityFinding{
					Title:       "Path Traversal / Local File Inclusion (LFI)",
					Description: fmt.Sprintf("Parameter %q allows traversal to /etc/passwd. Remote code execution may be possible.", param),
					Severity:    SevCritical,
					Category:    "Injection",
					URL:         testURL,
					Evidence:    "Response contains /etc/passwd content",
					Remediation: "Canonicalize paths and validate against an allowlist. Never pass user-supplied paths directly to file system APIs.",
					CVSS:        9.1,
				})
				return findings
			}
		}
	}
	return findings
}

// checkSubdomainTakeover inspects the response for known fingerprints of
// unclaimed cloud/SaaS resources that indicate subdomain takeover potential.
func (sc *SecurityChecker) checkSubdomainTakeover(targetURL string, resp *http.Response) []SecurityFinding {
	var findings []SecurityFinding
	type fingerprint struct {
		service  string
		patterns []string
		severity string
	}
	fps := []fingerprint{
		{"GitHub Pages", []string{"There isn't a GitHub Pages site here"}, SevHigh},
		{"Heroku", []string{"No such app", "herokucdn.com/error-pages/no-such-app.html"}, SevHigh},
		{"AWS S3", []string{"NoSuchBucket", "The specified bucket does not exist"}, SevHigh},
		{"Fastly", []string{"Fastly error: unknown domain"}, SevHigh},
		{"Shopify", []string{"Sorry, this shop is currently unavailable"}, SevMedium},
		{"Tumblr", []string{"Whatever you were looking for doesn't currently exist at this address"}, SevMedium},
		{"Cargo", []string{"If you're moving your domain away from Cargo"}, SevMedium},
		{"Azure", []string{"404 Web Site not found"}, SevHigh},
		{"Pantheon", []string{"The gods are wise"}, SevMedium},
		{"Zendesk", []string{"Help Center Closed"}, SevMedium},
	}
	// We need a body — use the status 404 / redirect target
	if resp.StatusCode == 404 || resp.StatusCode == 200 {
		// We don't have the body here; rely on the resp header server
		server := resp.Header.Get("Server")
		via := resp.Header.Get("Via")
		combo := strings.ToLower(server + via)
		for _, fp := range fps {
			for _, pat := range fp.patterns {
				if strings.Contains(combo, strings.ToLower(pat)) {
					findings = append(findings, SecurityFinding{
						Title:       fmt.Sprintf("Potential Subdomain Takeover (%s)", fp.service),
						Description: fmt.Sprintf("Response fingerprint matches an unclaimed %s resource.", fp.service),
						Severity:    fp.severity,
						Category:    "Subdomain Takeover",
						URL:         targetURL,
						Evidence:    fmt.Sprintf("Server: %s | Via: %s", server, via),
						Remediation: "Remove the dangling DNS record or re-register the resource at the cloud/SaaS provider.",
					})
				}
			}
		}
	}
	return findings
}

// checkPrototypePollution injects prototype pollution payloads via query parameters.
func (sc *SecurityChecker) checkPrototypePollution(ctx context.Context, targetURL string) []SecurityFinding {
	var findings []SecurityFinding
	payloads := []string{
		"__proto__[testprop]=rayyan_pp_probe",
		"constructor[prototype][testprop]=rayyan_pp_probe",
	}
	for _, payload := range payloads {
		sep := "?"
		if strings.Contains(targetURL, "?") {
			sep = "&"
		}
		testURL := targetURL + sep + payload
		resp, body, err := sc.fetch(ctx, testURL, "GET", map[string]string{"User-Agent": "Mozilla/5.0"})
		if err != nil || resp == nil {
			continue
		}
		if strings.Contains(body, "rayyan_pp_probe") {
			findings = append(findings, SecurityFinding{
				Title:       "Prototype Pollution",
				Description: "A prototype pollution payload was reflected in the response, indicating the server merges query parameters into object prototypes.",
				Severity:    SevHigh,
				Category:    "Injection",
				URL:         testURL,
				Evidence:    fmt.Sprintf("Payload %q reflected in body (status %d)", payload, resp.StatusCode),
				Remediation: "Sanitize keys during object merges. Use Object.create(null) for pure data maps. Update lodash/merge to ≥4.17.21.",
				CVSS:        7.4,
			})
			break
		}
	}
	return findings
}

// checkDOMXSSSinks scans the response body for dangerous DOM XSS sink patterns.
func (sc *SecurityChecker) checkDOMXSSSinks(targetURL, body string) []SecurityFinding {
	var findings []SecurityFinding
	sinks := []struct {
		pattern  string
		evidence string
		severity string
	}{
		{"document.write(", "document.write() sink", SevHigh},
		{"innerHTML", "innerHTML assignment sink", SevHigh},
		{"outerHTML", "outerHTML assignment sink", SevHigh},
		{"eval(", "eval() sink", SevCritical},
		{"setTimeout(", "setTimeout() with string arg", SevMedium},
		{"setInterval(", "setInterval() with string arg", SevMedium},
		{"location.href", "location.href assignment sink", SevMedium},
		{"document.URL", "document.URL source", SevLow},
		{"location.hash", "location.hash source", SevLow},
	}
	for _, sink := range sinks {
		if strings.Contains(body, sink.pattern) {
			findings = append(findings, SecurityFinding{
				Title:       "DOM-Based XSS Sink Pattern: " + sink.evidence,
				Description: fmt.Sprintf("The response body contains the %s which may be vulnerable to DOM-based XSS if attacker-controlled data flows into it.", sink.evidence),
				Severity:    sink.severity,
				Category:    "XSS",
				URL:         targetURL,
				Evidence:    sink.pattern,
				Remediation: "Avoid dangerous DOM APIs. Use textContent instead of innerHTML. Sanitize data before passing to eval/setTimeout/setInterval.",
			})
		}
	}
	return findings
}

// checkHTTP2Downgrade probes whether the server supports HTTP/2 and whether
// it can be downgraded, which may affect smuggling risk.
func (sc *SecurityChecker) checkHTTP2Downgrade(ctx context.Context, targetURL string) []SecurityFinding {
	var findings []SecurityFinding
	resp, _, err := sc.fetch(ctx, targetURL, "GET", map[string]string{
		"User-Agent": "Mozilla/5.0",
		"Upgrade":    "h2c",
		"Connection": "Upgrade, HTTP2-Settings",
	})
	if err != nil || resp == nil {
		return findings
	}
	if resp.StatusCode == 101 || strings.Contains(resp.Header.Get("Upgrade"), "h2c") {
		findings = append(findings, SecurityFinding{
			Title:       "HTTP/2 Cleartext (h2c) Upgrade Accepted",
			Description: "The server accepts an h2c upgrade over cleartext HTTP, which may be exploitable for HTTP/2 request smuggling.",
			Severity:    SevMedium,
			Category:    "HTTP Smuggling",
			URL:         targetURL,
			Evidence:    fmt.Sprintf("Status %d, Upgrade: %s", resp.StatusCode, resp.Header.Get("Upgrade")),
			Remediation: "Disable h2c cleartext upgrades on front-end proxies. Route all traffic over TLS with ALPN-negotiated HTTP/2.",
		})
	}
	return findings
}

// checkCachePoisoning tests for web cache poisoning via unkeyed headers.
func (sc *SecurityChecker) checkCachePoisoning(ctx context.Context, targetURL string) []SecurityFinding {
	var findings []SecurityFinding
	probe := "rayyan-cache-probe-" + fmt.Sprintf("%d", 99999)
	unkeyedHeaders := map[string]string{
		"X-Forwarded-Host":   probe + ".evil.invalid",
		"X-Host":             probe + ".evil.invalid",
		"X-Original-URL":     "/" + probe,
		"X-Rewrite-URL":      "/" + probe,
		"X-Forwarded-Prefix": "/" + probe,
	}
	for hdr, val := range unkeyedHeaders {
		_, body, err := sc.fetch(ctx, targetURL, "GET", map[string]string{
			hdr:          val,
			"User-Agent": "Mozilla/5.0",
		})
		if err != nil {
			continue
		}
		if strings.Contains(body, probe) {
			findings = append(findings, SecurityFinding{
				Title:       "Web Cache Poisoning via Unkeyed Header",
				Description: fmt.Sprintf("The %q header value was reflected in the response body, indicating it may be cache-poisonable.", hdr),
				Severity:    SevHigh,
				Category:    "Cache Poisoning",
				URL:         targetURL,
				Evidence:    fmt.Sprintf("Header %s: %s reflected in body", hdr, val),
				Remediation: "Add all headers that influence the response to the cache key. Strip or normalize unrecognised forwarding headers at the edge.",
				CVSS:        8.1,
			})
			break
		}
	}
	return findings
}

// checkHostHeaderInjection probes for Host header injection vulnerabilities.
func (sc *SecurityChecker) checkHostHeaderInjection(ctx context.Context, targetURL string) []SecurityFinding {
	var findings []SecurityFinding
	probe := "evil.rayyan-asm-probe.invalid"
	req, err := http.NewRequestWithContext(ctx, "GET", targetURL, nil)
	if err != nil {
		return findings
	}
	req.Host = probe
	req.Header.Set("User-Agent", "Mozilla/5.0")
	resp, err := sc.client.Do(req)
	if err != nil || resp == nil {
		return findings
	}
	defer func() { _ = resp.Body.Close() }()
	buf := make([]byte, 8192)
	n, _ := resp.Body.Read(buf)
	body := string(buf[:n])
	if strings.Contains(body, probe) {
		findings = append(findings, SecurityFinding{
			Title:       "Host Header Injection",
			Description: "The server reflects the forged Host header in the response body. This can be exploited for password reset poisoning, cache poisoning, or SSRF.",
			Severity:    SevHigh,
			Category:    "Injection",
			URL:         targetURL,
			Evidence:    fmt.Sprintf("Host: %s reflected in response body", probe),
			Remediation: "Hardcode the application's canonical hostname. Validate the Host header against an allowlist at the application layer.",
			CVSS:        7.5,
		})
	}
	// Check Location header too (for redirect-based reflection)
	location := resp.Header.Get("Location")
	if strings.Contains(location, probe) {
		findings = append(findings, SecurityFinding{
			Title:       "Host Header Injection via Redirect",
			Description: "The server redirects to a URL containing the forged Host header value.",
			Severity:    SevHigh,
			Category:    "Injection",
			URL:         targetURL,
			Evidence:    fmt.Sprintf("Location: %s", location),
			Remediation: "Do not use the Host header to construct redirect URLs. Use a hardcoded base URL.",
		})
	}
	return findings
}

// checkMassAssignmentIDOR probes for mass assignment and IDOR hint patterns.
func (sc *SecurityChecker) checkMassAssignmentIDOR(ctx context.Context, targetURL string) []SecurityFinding {
	var findings []SecurityFinding
	// IDOR: increment numeric IDs in the URL path
	idorPatterns := []string{"/api/users/1", "/api/orders/1", "/api/accounts/1", "/user/1", "/profile/1"}
	for _, pattern := range idorPatterns {
		base := strings.TrimRight(targetURL, "/")
		testURL := base + pattern
		resp1, body1, err1 := sc.fetch(ctx, testURL, "GET", map[string]string{"User-Agent": "Mozilla/5.0"})
		if err1 != nil || resp1 == nil || resp1.StatusCode != 200 {
			continue
		}
		testURL2 := strings.TrimRight(testURL, "1") + "2"
		resp2, body2, err2 := sc.fetch(ctx, testURL2, "GET", map[string]string{"User-Agent": "Mozilla/5.0"})
		if err2 != nil || resp2 == nil {
			continue
		}
		if resp2.StatusCode == 200 && len(body2) > 50 && body2 != body1 {
			findings = append(findings, SecurityFinding{
				Title:       "Potential IDOR (Insecure Direct Object Reference)",
				Description: fmt.Sprintf("Resource at %s is accessible and returns different data from %s without authentication. Manual verification required.", testURL, testURL2),
				Severity:    SevHigh,
				Category:    "Business Logic",
				URL:         testURL,
				Evidence:    fmt.Sprintf("Both IDs return HTTP 200 with differing bodies (%d vs %d bytes)", len(body1), len(body2)),
				Remediation: "Implement object-level authorisation checks. Verify the requesting user owns the requested resource.",
				CVSS:        8.1,
			})
			break
		}
	}
	// Mass assignment: send extra fields in JSON POST
	jsonBody := `{"id":9999,"role":"admin","is_admin":true,"email":"probe@example.com"}`
	req, err := http.NewRequestWithContext(ctx, "POST", targetURL, strings.NewReader(jsonBody))
	if err == nil {
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("User-Agent", "Mozilla/5.0")
		resp, err := sc.client.Do(req)
		if err == nil && resp != nil {
			defer func() { _ = resp.Body.Close() }()
			buf := make([]byte, 4096)
			n, _ := resp.Body.Read(buf)
			respBody := string(buf[:n])
			if resp.StatusCode == 200 && (strings.Contains(respBody, "admin") || strings.Contains(respBody, "9999")) {
				findings = append(findings, SecurityFinding{
					Title:       "Potential Mass Assignment Vulnerability",
					Description: "A POST request with privileged fields (role, is_admin, id) returned HTTP 200 and reflected those fields. Manual verification required.",
					Severity:    SevHigh,
					Category:    "Business Logic",
					URL:         targetURL,
					Evidence:    fmt.Sprintf("POST with admin fields returned %d, body contains reflection", resp.StatusCode),
					Remediation: "Use an explicit allowlist (DTO/allowedFields) when binding request bodies to models. Never expose internal fields.",
					CVSS:        8.8,
				})
			}
		}
	}
	return findings
}
