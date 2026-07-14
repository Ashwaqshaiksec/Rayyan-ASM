package tools

import (
	"fmt"
	"strings"
	"time"

	trtypes "github.com/ShadooowX/rayyan-asm/internal/modules/toolrunner/types"
)

// InjectionResult holds a finding from an injection-class tool.
type InjectionResult struct {
	Type        string `json:"type"`      // e.g. "sqli", "xss", "ssti", "cmdi", "ssrf", "crlf", "smuggling"
	Parameter   string `json:"parameter"` // vulnerable parameter or vector
	Payload     string `json:"payload"`
	Severity    string `json:"severity"`
	URL         string `json:"url"`
	Evidence    string `json:"evidence"`
	Description string `json:"description"`
	Source      string `json:"source"`
}

// RunSQLMap runs sqlmap against the target URL for SQL injection discovery.
// Rate-limited to MaxConcurrent:1, MinIntervalSeconds:30 in the registry.
func RunSQLMap(target string, timeout time.Duration) ([]InjectionResult, error) {
	info, ok := trtypes.DefaultRegistry.Get("sqlmap")
	if !ok || info.Status != trtypes.StatusInstalled || !info.Enabled {
		return nil, toolNotAvailable("sqlmap")
	}

	release := trtypes.DefaultRegistry.Acquire("sqlmap")
	defer release()

	args := []string{
		"-u", target,
		"--batch",
		"--output-dir=/tmp/sqlmap-out",
		"--forms",
		"--level=2",
		"--risk=1",
		"--json-output=/dev/stdout",
		"-q",
	}
	result := trtypes.Run(info.BinaryPath, args, trtypes.RunOptions{Timeout: timeout})
	trtypes.DefaultRegistry.RecordRun("sqlmap", result.Error == nil)

	var out []InjectionResult
	for _, line := range parseLines(result.Stdout) {
		var obj struct {
			URL  string `json:"url"`
			Data []struct {
				Parameter string `json:"parameter"`
				Type      string `json:"type"`
				Data      string `json:"data"`
			} `json:"data"`
		}
		if err := parseJSONLine(line, &obj); err != nil {
			continue
		}
		for _, d := range obj.Data {
			out = append(out, InjectionResult{
				Type:        "sqli",
				Parameter:   d.Parameter,
				Payload:     d.Data,
				Severity:    "critical",
				URL:         obj.URL,
				Description: fmt.Sprintf("SQL injection via %s (%s)", d.Parameter, d.Type),
				Source:      "sqlmap",
			})
		}
	}
	// Fallback: parse text output for confirmation lines
	if len(out) == 0 {
		for _, line := range parseLines(result.Stdout) {
			if strings.Contains(line, "is vulnerable") || strings.Contains(line, "sqlmap identified") {
				out = append(out, InjectionResult{
					Type:        "sqli",
					Severity:    "critical",
					URL:         target,
					Description: strings.TrimSpace(line),
					Source:      "sqlmap",
				})
			}
		}
	}
	return out, nil
}

// RunDalfox runs dalfox XSS scanner against the target URL.
func RunDalfox(target string, timeout time.Duration) ([]InjectionResult, error) {
	info, ok := trtypes.DefaultRegistry.Get("dalfox")
	if !ok || info.Status != trtypes.StatusInstalled || !info.Enabled {
		return nil, toolNotAvailable("dalfox")
	}

	args := []string{
		"url", target,
		"--output-format", "json",
		"--silence",
		"--no-color",
	}
	result := trtypes.Run(info.BinaryPath, args, trtypes.RunOptions{Timeout: timeout})
	trtypes.DefaultRegistry.RecordRun("dalfox", result.Error == nil)

	var out []InjectionResult
	for _, line := range parseLines(result.Stdout) {
		var obj struct {
			Type      string `json:"type"`
			Parameter string `json:"param"`
			Payload   string `json:"payload"`
			Evidence  string `json:"evidence"`
			URL       string `json:"poc"`
		}
		if err := parseJSONLine(line, &obj); err != nil {
			continue
		}
		sev := "high"
		if strings.EqualFold(obj.Type, "R") {
			sev = "medium"
		}
		out = append(out, InjectionResult{
			Type:        "xss",
			Parameter:   obj.Parameter,
			Payload:     obj.Payload,
			Severity:    sev,
			URL:         obj.URL,
			Evidence:    obj.Evidence,
			Description: fmt.Sprintf("XSS (%s) in parameter %s", obj.Type, obj.Parameter),
			Source:      "dalfox",
		})
	}
	return out, nil
}

// RunXSStrike runs XSStrike XSS scanner against the target URL.
func RunXSStrike(target string, timeout time.Duration) ([]InjectionResult, error) {
	info, ok := trtypes.DefaultRegistry.Get("xsstrike")
	if !ok || info.Status != trtypes.StatusInstalled || !info.Enabled {
		return nil, toolNotAvailable("xsstrike")
	}

	args := []string{
		"-u", target,
		"--crawl",
		"--blind",
		"--skip-dom",
	}
	result := trtypes.Run(info.BinaryPath, args, trtypes.RunOptions{Timeout: timeout})
	trtypes.DefaultRegistry.RecordRun("xsstrike", result.Error == nil)

	var out []InjectionResult
	for _, line := range parseLines(result.Stdout) {
		lower := strings.ToLower(line)
		if strings.Contains(lower, "xss") && (strings.Contains(lower, "payload") || strings.Contains(lower, "vulnerable")) {
			out = append(out, InjectionResult{
				Type:        "xss",
				Severity:    "high",
				URL:         target,
				Description: strings.TrimSpace(line),
				Source:      "xsstrike",
			})
		}
	}
	return out, nil
}

// RunCommix runs commix command injection scanner against the target URL.
func RunCommix(target string, timeout time.Duration) ([]InjectionResult, error) {
	info, ok := trtypes.DefaultRegistry.Get("commix")
	if !ok || info.Status != trtypes.StatusInstalled || !info.Enabled {
		return nil, toolNotAvailable("commix")
	}

	release := trtypes.DefaultRegistry.Acquire("commix")
	defer release()

	args := []string{
		"--url", target,
		"--batch",
		"--output-dir=/tmp/commix-out",
		"--log-file=/dev/stdout",
		"--skip-empty",
	}
	result := trtypes.Run(info.BinaryPath, args, trtypes.RunOptions{Timeout: timeout})
	trtypes.DefaultRegistry.RecordRun("commix", result.Error == nil)

	var out []InjectionResult
	for _, line := range parseLines(result.Stdout) {
		lower := strings.ToLower(line)
		if strings.Contains(lower, "vulnerable") || strings.Contains(lower, "command injection") {
			param := ""
			if idx := strings.Index(line, "parameter '"); idx != -1 {
				rest := line[idx+len("parameter '"):]
				if end := strings.Index(rest, "'"); end != -1 {
					param = rest[:end]
				}
			}
			out = append(out, InjectionResult{
				Type:        "cmdi",
				Parameter:   param,
				Severity:    "critical",
				URL:         target,
				Description: strings.TrimSpace(line),
				Source:      "commix",
			})
		}
	}
	return out, nil
}

// RunTplmap runs tplmap SSTI scanner against the target URL.
func RunTplmap(target string, timeout time.Duration) ([]InjectionResult, error) {
	info, ok := trtypes.DefaultRegistry.Get("tplmap")
	if !ok || info.Status != trtypes.StatusInstalled || !info.Enabled {
		return nil, toolNotAvailable("tplmap")
	}

	args := []string{
		"-u", target,
		"--level", "3",
	}
	result := trtypes.Run(info.BinaryPath, args, trtypes.RunOptions{Timeout: timeout})
	trtypes.DefaultRegistry.RecordRun("tplmap", result.Error == nil)

	var out []InjectionResult
	engine := ""
	for _, line := range parseLines(result.Stdout) {
		lower := strings.ToLower(line)
		if strings.Contains(lower, "engine:") {
			parts := strings.SplitN(line, ":", 2)
			if len(parts) == 2 {
				engine = strings.TrimSpace(parts[1])
			}
		}
		if strings.Contains(lower, "vulnerable") || strings.Contains(lower, "server-side template injection") {
			out = append(out, InjectionResult{
				Type:        "ssti",
				Severity:    "critical",
				URL:         target,
				Description: fmt.Sprintf("SSTI confirmed (engine: %s)", engine),
				Source:      "tplmap",
			})
		}
	}
	return out, nil
}

// RunCRLFuzz runs crlfuzz CRLF injection scanner against the target URL.
func RunCRLFuzz(target string, timeout time.Duration) ([]InjectionResult, error) {
	info, ok := trtypes.DefaultRegistry.Get("crlfuzz")
	if !ok || info.Status != trtypes.StatusInstalled || !info.Enabled {
		return nil, toolNotAvailable("crlfuzz")
	}

	args := []string{
		"-u", target,
		"-s",
	}
	result := trtypes.Run(info.BinaryPath, args, trtypes.RunOptions{Timeout: timeout})
	trtypes.DefaultRegistry.RecordRun("crlfuzz", result.Error == nil)

	var out []InjectionResult
	for _, line := range parseLines(result.Stdout) {
		if strings.Contains(strings.ToLower(line), "vuln") || strings.HasPrefix(line, "[V]") {
			out = append(out, InjectionResult{
				Type:        "crlf",
				Severity:    "medium",
				URL:         target,
				Description: strings.TrimSpace(line),
				Source:      "crlfuzz",
			})
		}
	}
	return out, nil
}

// RunSmuggler runs smuggler HTTP request smuggling detector.
func RunSmuggler(target string, timeout time.Duration) ([]InjectionResult, error) {
	info, ok := trtypes.DefaultRegistry.Get("smuggler")
	if !ok || info.Status != trtypes.StatusInstalled || !info.Enabled {
		return nil, toolNotAvailable("smuggler")
	}

	args := []string{
		"-u", target,
		"--log", "/dev/stdout",
	}
	result := trtypes.Run(info.BinaryPath, args, trtypes.RunOptions{Timeout: timeout})
	trtypes.DefaultRegistry.RecordRun("smuggler", result.Error == nil)

	var out []InjectionResult
	for _, line := range parseLines(result.Stdout) {
		lower := strings.ToLower(line)
		if strings.Contains(lower, "vulnerable") || strings.Contains(lower, "issue found") {
			variant := "CL.TE"
			if strings.Contains(lower, "te.cl") {
				variant = "TE.CL"
			} else if strings.Contains(lower, "te.te") {
				variant = "TE.TE"
			}
			out = append(out, InjectionResult{
				Type:        "smuggling",
				Payload:     variant,
				Severity:    "high",
				URL:         target,
				Description: fmt.Sprintf("HTTP Request Smuggling (%s) detected", variant),
				Source:      "smuggler",
			})
		}
	}
	return out, nil
}

// RunH2CSmuggler runs h2csmuggler HTTP/2 cleartext upgrade smuggling detector.
func RunH2CSmuggler(target string, timeout time.Duration) ([]InjectionResult, error) {
	info, ok := trtypes.DefaultRegistry.Get("h2csmuggler")
	if !ok || info.Status != trtypes.StatusInstalled || !info.Enabled {
		return nil, toolNotAvailable("h2csmuggler")
	}

	args := []string{
		"--scan-list", "/dev/stdin",
		target,
	}
	result := trtypes.Run(info.BinaryPath, args, trtypes.RunOptions{Timeout: timeout})
	trtypes.DefaultRegistry.RecordRun("h2csmuggler", result.Error == nil)

	var out []InjectionResult
	for _, line := range parseLines(result.Stdout) {
		lower := strings.ToLower(line)
		if strings.Contains(lower, "vulnerable") || (strings.Contains(lower, "h2c") && strings.Contains(lower, "success")) {
			out = append(out, InjectionResult{
				Type:        "smuggling",
				Payload:     "H2C upgrade",
				Severity:    "high",
				URL:         target,
				Description: "HTTP/2 cleartext upgrade smuggling (h2c) detected",
				Source:      "h2csmuggler",
			})
		}
	}
	return out, nil
}

// RunSSRFMap runs ssrfmap SSRF vulnerability scanner.
func RunSSRFMap(target string, timeout time.Duration) ([]InjectionResult, error) {
	info, ok := trtypes.DefaultRegistry.Get("ssrfmap")
	if !ok || info.Status != trtypes.StatusInstalled || !info.Enabled {
		return nil, toolNotAvailable("ssrfmap")
	}

	args := []string{
		"-r", target,
		"-p", "url",
		"--lhost", "127.0.0.1",
		"--lport", "4242",
	}
	result := trtypes.Run(info.BinaryPath, args, trtypes.RunOptions{Timeout: timeout})
	trtypes.DefaultRegistry.RecordRun("ssrfmap", result.Error == nil)

	var out []InjectionResult
	for _, line := range parseLines(result.Stdout) {
		lower := strings.ToLower(line)
		if strings.Contains(lower, "vulnerable") || strings.Contains(lower, "[+] ssrf") {
			out = append(out, InjectionResult{
				Type:        "ssrf",
				Severity:    "critical",
				URL:         target,
				Description: strings.TrimSpace(line),
				Source:      "ssrfmap",
			})
		}
	}
	return out, nil
}

// RunGopherus generates SSRF Gopher payloads for a given target protocol.
// protocol examples: "mysql", "redis", "smtp", "fastcgi"
func RunGopherus(target, protocol string, timeout time.Duration) ([]InjectionResult, error) {
	info, ok := trtypes.DefaultRegistry.Get("gopherus")
	if !ok || info.Status != trtypes.StatusInstalled || !info.Enabled {
		return nil, toolNotAvailable("gopherus")
	}
	if protocol == "" {
		protocol = "redis"
	}

	args := []string{"--exploit", protocol}
	result := trtypes.Run(info.BinaryPath, args, trtypes.RunOptions{Timeout: timeout})
	trtypes.DefaultRegistry.RecordRun("gopherus", result.Error == nil)

	var out []InjectionResult
	for _, line := range parseLines(result.Stdout) {
		if strings.HasPrefix(line, "gopher://") || strings.Contains(line, "Payload") {
			out = append(out, InjectionResult{
				Type:        "ssrf",
				Payload:     strings.TrimSpace(line),
				Severity:    "high",
				URL:         target,
				Description: fmt.Sprintf("SSRF Gopher payload for %s", protocol),
				Source:      "gopherus",
			})
		}
	}
	return out, nil
}
