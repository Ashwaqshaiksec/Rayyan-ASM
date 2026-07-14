package tools

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"time"

	trtypes "github.com/ShadooowX/rayyan-asm/internal/modules/toolrunner/types"
)

// APIFinding holds a finding from an API-level audit.
type APIFinding struct {
	Type        string `json:"type"` // e.g. "graphql_batch_abuse", "verb_tampering", "schema_diff"
	Severity    string `json:"severity"`
	Title       string `json:"title"`
	Description string `json:"description"`
	URL         string `json:"url"`
	Evidence    string `json:"evidence"`
	Remediation string `json:"remediation"`
	Source      string `json:"source"`
}

// SwaggerDiffResult represents a discrepancy between the published schema and live behaviour.
type SwaggerDiffResult struct {
	Endpoint    string `json:"endpoint"`
	Method      string `json:"method"`
	Discrepancy string `json:"discrepancy"` // "undocumented", "extra_method", "schema_mismatch"
	Evidence    string `json:"evidence"`
	Source      string `json:"source"`
}

var apiHTTPClient = &http.Client{
	Transport: &http.Transport{TLSClientConfig: &tls.Config{InsecureSkipVerify: true}}, // #nosec G402
	Timeout:   15 * time.Second,
}

// GraphQL batch abuse

// CheckGraphQLBatchAbuse tests whether a GraphQL endpoint accepts batched
// queries, which can amplify rate-limit bypasses and brute-force attacks.
func CheckGraphQLBatchAbuse(ctx context.Context, targetURL string) []APIFinding {
	var findings []APIFinding
	endpoints := []string{"/graphql", "/api/graphql", "/v1/graphql", "/gql"}

	// Batched query: array of two introspection queries
	batchPayload := `[{"query":"{__typename}"},{"query":"{__typename}"}]`

	for _, ep := range endpoints {
		base := strings.TrimRight(targetURL, "/")
		url := base + ep
		req, err := http.NewRequestWithContext(ctx, "POST", url, strings.NewReader(batchPayload))
		if err != nil {
			continue
		}
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("User-Agent", "Mozilla/5.0 (RayyanASM-APIAudit/1.0)")

		resp, err := apiHTTPClient.Do(req)
		if err != nil || resp == nil {
			continue
		}
		buf := make([]byte, 8192)
		n, _ := resp.Body.Read(buf)
		_ = resp.Body.Close()
		body := string(buf[:n])

		// A batched response is a JSON array
		if resp.StatusCode == 200 && strings.HasPrefix(strings.TrimSpace(body), "[") {
			var results []map[string]interface{}
			if json.Unmarshal([]byte(body), &results) == nil && len(results) >= 2 {
				findings = append(findings, APIFinding{
					Type:        "graphql_batch_abuse",
					Severity:    "medium",
					Title:       "GraphQL Batched Queries Accepted",
					Description: "The GraphQL endpoint accepts batched query arrays. Attackers can use batching to bypass per-request rate limits on brute-force or enumeration operations.",
					URL:         url,
					Evidence:    fmt.Sprintf("POST with 2-query array returned HTTP 200 with %d results in response array", len(results)),
					Remediation: "Implement per-operation rate limiting at the resolver level. Consider disabling batching in production or limiting batch size to 1.",
					Source:      "rayyan-api-audit",
				})
				break
			}
		}
	}
	return findings
}

// HTTP verb tampering

// CheckVerbTampering probes REST-like paths for HTTP method confusion —
// accessing a resource with an unexpected verb that returns sensitive data.
func CheckVerbTampering(ctx context.Context, targetURL string) []APIFinding {
	var findings []APIFinding
	type probe struct {
		path   string
		method string
		expect string // keyword that should NOT appear in response
	}
	probes := []probe{
		{"/api/users", "DELETE", "id"},
		{"/api/admin", "GET", "admin"},
		{"/api/config", "PUT", "config"},
		{"/api/users/1", "PATCH", "email"},
	}
	base := strings.TrimRight(targetURL, "/")
	for _, p := range probes {
		url := base + p.path
		req, err := http.NewRequestWithContext(ctx, p.method, url, nil)
		if err != nil {
			continue
		}
		req.Header.Set("User-Agent", "Mozilla/5.0 (RayyanASM-APIAudit/1.0)")
		resp, err := apiHTTPClient.Do(req)
		if err != nil || resp == nil {
			continue
		}
		buf := make([]byte, 4096)
		n, _ := resp.Body.Read(buf)
		_ = resp.Body.Close()
		body := strings.ToLower(string(buf[:n]))

		if resp.StatusCode < 400 && strings.Contains(body, p.expect) {
			findings = append(findings, APIFinding{
				Type:        "verb_tampering",
				Severity:    "high",
				Title:       fmt.Sprintf("HTTP Verb Tampering: %s %s", p.method, p.path),
				Description: fmt.Sprintf("The endpoint %s responded successfully to %s with data that should require explicit authorisation.", p.path, p.method),
				URL:         url,
				Evidence:    fmt.Sprintf("HTTP %d from %s %s; response contains %q", resp.StatusCode, p.method, url, p.expect),
				Remediation: "Enforce explicit verb allowlists at the router level. Reject undocumented HTTP methods with 405 Method Not Allowed.",
				Source:      "rayyan-api-audit",
			})
		}
	}
	return findings
}

// Swagger/OpenAPI schema diff

// CheckSwaggerSchemaDiff fetches the OpenAPI/Swagger spec from common paths
// and probes for endpoints that exist live but are absent from the schema
// (shadow APIs), and schema endpoints returning unexpected methods.
func CheckSwaggerSchemaDiff(ctx context.Context, targetURL string) []SwaggerDiffResult {
	var results []SwaggerDiffResult
	specPaths := []string{"/swagger.json", "/openapi.json", "/api/swagger.json", "/api/openapi.json", "/v1/openapi.json"}
	base := strings.TrimRight(targetURL, "/")

	var spec map[string]interface{}
	var specURL string
	for _, p := range specPaths {
		url := base + p
		req, err := http.NewRequestWithContext(ctx, "GET", url, nil)
		if err != nil {
			continue
		}
		req.Header.Set("Accept", "application/json")
		resp, err := apiHTTPClient.Do(req)
		if err != nil || resp == nil || resp.StatusCode != 200 {
			continue
		}
		buf := make([]byte, 512*1024) // 512 KB max
		n, _ := resp.Body.Read(buf)
		_ = resp.Body.Close()
		if err := json.Unmarshal(buf[:n], &spec); err == nil {
			specURL = url
			break
		}
	}
	if spec == nil {
		return results // no spec found
	}

	// Extract documented paths from OpenAPI 3 or Swagger 2
	documentedPaths := extractOpenAPIPaths(spec)

	// Probe some common paths that are NOT in the spec — shadow API detection
	shadowCandidates := []string{
		"/api/internal", "/api/debug", "/api/admin", "/api/v0",
		"/api/test", "/internal/health", "/management", "/actuator/env",
	}
	for _, candidate := range shadowCandidates {
		if _, exists := documentedPaths[candidate]; exists {
			continue // documented — skip
		}
		url := base + candidate
		req, err := http.NewRequestWithContext(ctx, "GET", url, nil)
		if err != nil {
			continue
		}
		resp, err := apiHTTPClient.Do(req)
		if err != nil || resp == nil {
			continue
		}
		_ = resp.Body.Close()
		if resp.StatusCode == 200 || resp.StatusCode == 403 {
			results = append(results, SwaggerDiffResult{
				Endpoint:    candidate,
				Method:      "GET",
				Discrepancy: "undocumented",
				Evidence:    fmt.Sprintf("GET %s returned HTTP %d but path is absent from spec at %s", candidate, resp.StatusCode, specURL),
				Source:      "rayyan-api-audit",
			})
		}
	}

	// Check each documented endpoint for extra HTTP methods
	for path, methods := range documentedPaths {
		if path == "" {
			continue
		}
		url := base + path
		extraMethods := []string{"PUT", "DELETE", "PATCH", "HEAD"}
		for _, m := range extraMethods {
			if _, documented := methods[strings.ToLower(m)]; documented {
				continue
			}
			req, err := http.NewRequestWithContext(ctx, m, url, nil)
			if err != nil {
				continue
			}
			resp, err := apiHTTPClient.Do(req)
			if err != nil || resp == nil {
				continue
			}
			_ = resp.Body.Close()
			if resp.StatusCode < 400 {
				results = append(results, SwaggerDiffResult{
					Endpoint:    path,
					Method:      m,
					Discrepancy: "extra_method",
					Evidence:    fmt.Sprintf("%s %s returned HTTP %d but method is not in schema", m, url, resp.StatusCode),
					Source:      "rayyan-api-audit",
				})
			}
		}
	}
	return results
}

// extractOpenAPIPaths returns a map of path → set-of-methods from an OpenAPI/Swagger spec.
func extractOpenAPIPaths(spec map[string]interface{}) map[string]map[string]struct{} {
	result := make(map[string]map[string]struct{})
	paths, _ := spec["paths"].(map[string]interface{})
	for path, methodsRaw := range paths {
		methods, _ := methodsRaw.(map[string]interface{})
		result[path] = make(map[string]struct{})
		for method := range methods {
			result[path][strings.ToLower(method)] = struct{}{}
		}
	}
	return result
}

// nuclei API templates

// RunNucleiAPITemplates runs nuclei with the api-specific template tags.
func RunNucleiAPITemplates(target string, timeout time.Duration) ([]VulnResult, error) {
	info, ok := trtypes.DefaultRegistry.Get("nuclei")
	if !ok || info.Status != trtypes.StatusInstalled || !info.Enabled {
		return nil, toolNotAvailable("nuclei")
	}
	args := []string{
		"-u", target,
		"-json",
		"-silent",
		"-tags", "api,graphql,swagger,idor,ssrf",
		"-rate-limit", "50",
	}
	result := trtypes.Run(info.BinaryPath, args, trtypes.RunOptions{Timeout: timeout})
	trtypes.DefaultRegistry.RecordRun("nuclei", result.Error == nil)

	var out []VulnResult
	for _, line := range parseLines(result.Stdout) {
		var obj struct {
			TemplateID string `json:"template-id"`
			Info       struct {
				Name        string   `json:"name"`
				Severity    string   `json:"severity"`
				Description string   `json:"description"`
				Reference   []string `json:"reference"`
			} `json:"info"`
			Host string `json:"host"`
			URL  string `json:"matched-at"`
		}
		if err := parseJSONLine(line, &obj); err != nil {
			continue
		}
		ref := ""
		if len(obj.Info.Reference) > 0 {
			ref = obj.Info.Reference[0]
		}
		out = append(out, VulnResult{
			TemplateID:  obj.TemplateID,
			Name:        obj.Info.Name,
			Severity:    obj.Info.Severity,
			Host:        obj.Host,
			URL:         obj.URL,
			Description: obj.Info.Description,
			Reference:   ref,
			Source:      "nuclei-api",
		})
	}
	return out, nil
}
