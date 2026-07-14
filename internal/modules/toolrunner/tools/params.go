package tools

import (
	"strings"
	"time"

	trtypes "github.com/ShadooowX/rayyan-asm/internal/modules/toolrunner/types"
)

// ParamResult holds a discovered parameter from a parameter discovery tool.
type ParamResult struct {
	URL       string `json:"url"`
	Parameter string `json:"parameter"`
	Method    string `json:"method"`
	Source    string `json:"source"`
}

// RunArjun runs arjun parameter discovery against the target URL.
func RunArjun(target string, timeout time.Duration) ([]ParamResult, error) {
	info, ok := trtypes.DefaultRegistry.Get("arjun")
	if !ok || info.Status != trtypes.StatusInstalled || !info.Enabled {
		return nil, toolNotAvailable("arjun")
	}

	args := []string{
		"-u", target,
		"--output-file", "/dev/stdout",
		"-oJ",
		"-t", "10",
		"-q",
	}
	result := trtypes.Run(info.BinaryPath, args, trtypes.RunOptions{Timeout: timeout})
	trtypes.DefaultRegistry.RecordRun("arjun", result.Error == nil)

	var out []ParamResult
	// arjun JSON output: {"url": "...", "params": {"GET": [...], "POST": [...]}}
	clean := extractJSON(result.Stdout)
	if clean != "" {
		var obj struct {
			URL    string              `json:"url"`
			Params map[string][]string `json:"params"`
		}
		if err := parseJSONObj(clean, &obj); err == nil {
			for method, params := range obj.Params {
				for _, p := range params {
					out = append(out, ParamResult{
						URL:       obj.URL,
						Parameter: p,
						Method:    method,
						Source:    "arjun",
					})
				}
			}
		}
	}
	// Fallback: text output parsing
	if len(out) == 0 {
		for _, line := range parseLines(result.Stdout) {
			line = strings.TrimSpace(line)
			if strings.HasPrefix(line, "[+]") || strings.HasPrefix(line, "Parameter:") {
				p := strings.TrimPrefix(line, "[+] ")
				p = strings.TrimPrefix(p, "Parameter: ")
				if p != "" {
					out = append(out, ParamResult{
						URL:       target,
						Parameter: strings.TrimSpace(p),
						Method:    "GET",
						Source:    "arjun",
					})
				}
			}
		}
	}
	return out, nil
}

// RunParamSpider runs paramspider to mine URL parameters from web archives.
func RunParamSpider(target string, timeout time.Duration) ([]ParamResult, error) {
	info, ok := trtypes.DefaultRegistry.Get("paramspider")
	if !ok || info.Status != trtypes.StatusInstalled || !info.Enabled {
		return nil, toolNotAvailable("paramspider")
	}

	args := []string{
		"--domain", target,
		"--quiet",
		"--output", "/dev/stdout",
	}
	result := trtypes.Run(info.BinaryPath, args, trtypes.RunOptions{Timeout: timeout})
	trtypes.DefaultRegistry.RecordRun("paramspider", result.Error == nil)

	var out []ParamResult
	for _, line := range parseLines(result.Stdout) {
		line = strings.TrimSpace(line)
		if !strings.HasPrefix(line, "http") {
			continue
		}
		// Extract param names from URL query string
		if qIdx := strings.Index(line, "?"); qIdx != -1 {
			query := line[qIdx+1:]
			for _, kv := range strings.Split(query, "&") {
				parts := strings.SplitN(kv, "=", 2)
				if len(parts) >= 1 && parts[0] != "" {
					out = append(out, ParamResult{
						URL:       line,
						Parameter: parts[0],
						Method:    "GET",
						Source:    "paramspider",
					})
				}
			}
		} else {
			out = append(out, ParamResult{
				URL:    line,
				Source: "paramspider",
			})
		}
	}
	return out, nil
}
