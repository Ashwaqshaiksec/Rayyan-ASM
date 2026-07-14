package tools

import (
	"strings"
	"time"

	trtypes "github.com/ShadooowX/rayyan-asm/internal/modules/toolrunner/types"
)

// AuthResult holds a finding from an authentication/authorization test.
type AuthResult struct {
	Type        string `json:"type"` // "jwt_none_alg", "jwt_weak_secret", "cors_bypass", "oauth_issue"
	Target      string `json:"target"`
	Evidence    string `json:"evidence"`
	Severity    string `json:"severity"`
	Description string `json:"description"`
	Source      string `json:"source"`
}

// RunJWTTool runs jwt_tool to test JWT tokens for common vulnerabilities.
// token is a raw JWT string. target is the endpoint that accepts it.
func RunJWTTool(token, target string, timeout time.Duration) ([]AuthResult, error) {
	info, ok := trtypes.DefaultRegistry.Get("jwt_tool")
	if !ok || info.Status != trtypes.StatusInstalled || !info.Enabled {
		return nil, toolNotAvailable("jwt_tool")
	}
	if token == "" {
		token = "eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJzdWIiOiJ0ZXN0In0.test"
	}

	args := []string{
		token,
		"-t", target,
		"-M", "at", // all tests
		"--no-color",
	}
	result := trtypes.Run(info.BinaryPath, args, trtypes.RunOptions{Timeout: timeout})
	trtypes.DefaultRegistry.RecordRun("jwt_tool", result.Error == nil)

	var out []AuthResult
	for _, line := range parseLines(result.Stdout) {
		lower := strings.ToLower(line)
		if strings.Contains(lower, "[+]") || strings.Contains(lower, "vulnerability") || strings.Contains(lower, "exploit") {
			issueType := "jwt_issue"
			severity := "high"
			if strings.Contains(lower, "none") || strings.Contains(lower, "alg:none") {
				issueType = "jwt_none_alg"
				severity = "critical"
			} else if strings.Contains(lower, "weak") || strings.Contains(lower, "brute") || strings.Contains(lower, "crack") {
				issueType = "jwt_weak_secret"
				severity = "critical"
			} else if strings.Contains(lower, "rs256") || strings.Contains(lower, "algorithm confusion") {
				issueType = "jwt_alg_confusion"
				severity = "high"
			} else if strings.Contains(lower, "kid") {
				issueType = "jwt_kid_injection"
				severity = "high"
			}
			out = append(out, AuthResult{
				Type:        issueType,
				Target:      target,
				Evidence:    strings.TrimSpace(line),
				Severity:    severity,
				Description: strings.TrimSpace(line),
				Source:      "jwt_tool",
			})
		}
	}
	return out, nil
}

// RunCorsy runs corsy CORS misconfiguration scanner against the target URL.
func RunCorsy(target string, timeout time.Duration) ([]AuthResult, error) {
	info, ok := trtypes.DefaultRegistry.Get("corsy")
	if !ok || info.Status != trtypes.StatusInstalled || !info.Enabled {
		return nil, toolNotAvailable("corsy")
	}

	args := []string{
		"-u", target,
		"-t", "10",
		"--headers", "User-Agent: Mozilla/5.0",
	}
	result := trtypes.Run(info.BinaryPath, args, trtypes.RunOptions{Timeout: timeout})
	trtypes.DefaultRegistry.RecordRun("corsy", result.Error == nil)

	var out []AuthResult
	for _, line := range parseLines(result.Stdout) {
		lower := strings.ToLower(line)
		if strings.Contains(lower, "vulnerable") || strings.Contains(lower, "misconfigur") || strings.Contains(lower, "[+]") {
			issueType := "cors_bypass"
			severity := "high"
			if strings.Contains(lower, "credential") {
				severity = "critical"
				issueType = "cors_credentials_bypass"
			}
			out = append(out, AuthResult{
				Type:        issueType,
				Target:      target,
				Evidence:    strings.TrimSpace(line),
				Severity:    severity,
				Description: strings.TrimSpace(line),
				Source:      "corsy",
			})
		}
	}
	return out, nil
}
