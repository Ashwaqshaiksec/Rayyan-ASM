package tools

import (
	"encoding/json"
	"strings"
	"time"

	trtypes "github.com/ShadooowX/rayyan-asm/internal/modules/toolrunner/types"
)

// SubdomainResult holds discovered subdomains from any subdomain tool.
type SubdomainResult struct {
	Subdomain string `json:"subdomain"`
	Source    string `json:"source"`
}

// parseLines splits output into trimmed, non-empty lines.
func parseLines(output string) []string {
	var lines []string
	for _, l := range strings.Split(output, "\n") {
		l = strings.TrimSpace(l)
		if l != "" && !strings.HasPrefix(l, "#") {
			lines = append(lines, l)
		}
	}
	return lines
}

// RunSubfinder runs subfinder against target and returns discovered subdomains.
// It uses -json output for structured parsing with safe fallback to line parsing.
func RunSubfinder(target string, timeout time.Duration) ([]SubdomainResult, error) {
	info, ok := trtypes.DefaultRegistry.Get("subfinder")
	if !ok || info.Status != trtypes.StatusInstalled || !info.Enabled {
		return nil, toolNotAvailable("subfinder")
	}

	args := []string{"-d", target, "-json", "-silent", "-all"}
	result := trtypes.Run(info.BinaryPath, args, trtypes.RunOptions{Timeout: timeout})
	trtypes.DefaultRegistry.RecordRun("subfinder", result.Error == nil)

	var out []SubdomainResult
	for _, line := range parseLines(result.Stdout) {
		var obj struct {
			Host string `json:"host"`
		}
		if err := json.Unmarshal([]byte(line), &obj); err == nil && obj.Host != "" {
			out = append(out, SubdomainResult{Subdomain: obj.Host, Source: "subfinder"})
		} else if !strings.HasPrefix(line, "{") {
			// plain line fallback
			out = append(out, SubdomainResult{Subdomain: line, Source: "subfinder"})
		}
	}
	return out, nil
}

// RunAmass runs amass enum in passive mode.
func RunAmass(target string, timeout time.Duration) ([]SubdomainResult, error) {
	info, ok := trtypes.DefaultRegistry.Get("amass")
	if !ok || info.Status != trtypes.StatusInstalled || !info.Enabled {
		return nil, toolNotAvailable("amass")
	}

	args := []string{"enum", "-passive", "-d", target, "-json", "/dev/stdout"}
	result := trtypes.Run(info.BinaryPath, args, trtypes.RunOptions{Timeout: timeout})
	trtypes.DefaultRegistry.RecordRun("amass", result.Error == nil)

	var out []SubdomainResult
	for _, line := range parseLines(result.Stdout) {
		var obj struct {
			Name string `json:"name"`
		}
		if err := json.Unmarshal([]byte(line), &obj); err == nil && obj.Name != "" {
			out = append(out, SubdomainResult{Subdomain: obj.Name, Source: "amass"})
		} else if !strings.HasPrefix(line, "{") && strings.Contains(line, ".") {
			out = append(out, SubdomainResult{Subdomain: line, Source: "amass"})
		}
	}
	return out, nil
}

// RunAssetfinder runs assetfinder for the given domain.
func RunAssetfinder(target string, timeout time.Duration) ([]SubdomainResult, error) {
	info, ok := trtypes.DefaultRegistry.Get("assetfinder")
	if !ok || info.Status != trtypes.StatusInstalled || !info.Enabled {
		return nil, toolNotAvailable("assetfinder")
	}

	args := []string{"--subs-only", target}
	result := trtypes.Run(info.BinaryPath, args, trtypes.RunOptions{Timeout: timeout})
	trtypes.DefaultRegistry.RecordRun("assetfinder", result.Error == nil)

	var out []SubdomainResult
	for _, line := range parseLines(result.Stdout) {
		out = append(out, SubdomainResult{Subdomain: line, Source: "assetfinder"})
	}
	return out, nil
}

// RunFindomain runs findomain for the given domain.
func RunFindomain(target string, timeout time.Duration) ([]SubdomainResult, error) {
	info, ok := trtypes.DefaultRegistry.Get("findomain")
	if !ok || info.Status != trtypes.StatusInstalled || !info.Enabled {
		return nil, toolNotAvailable("findomain")
	}

	args := []string{"-t", target, "-q"}
	result := trtypes.Run(info.BinaryPath, args, trtypes.RunOptions{Timeout: timeout})
	trtypes.DefaultRegistry.RecordRun("findomain", result.Error == nil)

	var out []SubdomainResult
	for _, line := range parseLines(result.Stdout) {
		out = append(out, SubdomainResult{Subdomain: line, Source: "findomain"})
	}
	return out, nil
}

// RunTheHarvester runs theHarvester with a set of local/offline data sources.
func RunTheHarvester(target string, timeout time.Duration) ([]SubdomainResult, error) {
	info, ok := trtypes.DefaultRegistry.Get("theHarvester")
	if !ok || info.Status != trtypes.StatusInstalled || !info.Enabled {
		return nil, toolNotAvailable("theHarvester")
	}

	args := []string{"-d", target, "-b", "bing,yahoo,baidu,dnsdumpster", "-f", "/dev/stdout"}
	result := trtypes.Run(info.BinaryPath, args, trtypes.RunOptions{Timeout: timeout})
	trtypes.DefaultRegistry.RecordRun("theHarvester", result.Error == nil)

	var out []SubdomainResult
	inHostSection := false
	for _, line := range parseLines(result.Stdout) {
		if strings.Contains(line, "Hosts found") || strings.Contains(line, "[*] Hosts found") {
			inHostSection = true
			continue
		}
		if strings.HasPrefix(line, "[") || strings.HasPrefix(line, "---") {
			inHostSection = false
		}
		if inHostSection && strings.Contains(line, "."+target) {
			// strip trailing IP if format is "host:ip"
			host := strings.SplitN(line, ":", 2)[0]
			host = strings.TrimSpace(host)
			if host != "" {
				out = append(out, SubdomainResult{Subdomain: host, Source: "theHarvester"})
			}
		}
	}
	return out, nil
}

// RunSublist3r runs sublist3r for the given domain.
func RunSublist3r(target string, timeout time.Duration) ([]SubdomainResult, error) {
	info, ok := trtypes.DefaultRegistry.Get("sublist3r")
	if !ok || info.Status != trtypes.StatusInstalled || !info.Enabled {
		return nil, toolNotAvailable("sublist3r")
	}

	args := []string{"-d", target, "-o", "/dev/stdout", "-n"}
	result := trtypes.Run(info.BinaryPath, args, trtypes.RunOptions{Timeout: timeout})
	trtypes.DefaultRegistry.RecordRun("sublist3r", result.Error == nil)

	var out []SubdomainResult
	for _, line := range parseLines(result.Stdout) {
		// filter out banner lines (contains "Sublist3r" or "Enumerating")
		if strings.ContainsAny(line, "[]|") {
			continue
		}
		if strings.Contains(line, ".") {
			out = append(out, SubdomainResult{Subdomain: line, Source: "sublist3r"})
		}
	}
	return out, nil
}

// RunSubbrute runs subbrute (Python script) for DNS brute-force.
func RunSubbrute(target string, timeout time.Duration) ([]SubdomainResult, error) {
	info, ok := trtypes.DefaultRegistry.Get("subbrute")
	if !ok || info.Status != trtypes.StatusInstalled || !info.Enabled {
		return nil, toolNotAvailable("subbrute")
	}

	args := []string{target}
	result := trtypes.Run(info.BinaryPath, args, trtypes.RunOptions{Timeout: timeout})
	trtypes.DefaultRegistry.RecordRun("subbrute", result.Error == nil)

	var out []SubdomainResult
	for _, line := range parseLines(result.Stdout) {
		if strings.Contains(line, ".") && !strings.HasPrefix(line, "#") {
			out = append(out, SubdomainResult{Subdomain: line, Source: "subbrute"})
		}
	}
	return out, nil
}

// RunSubDomainizer scans JS files for subdomains via SubDomainizer.
func RunSubDomainizer(target string, timeout time.Duration) ([]SubdomainResult, error) {
	info, ok := trtypes.DefaultRegistry.Get("SubDomainizer")
	if !ok || info.Status != trtypes.StatusInstalled || !info.Enabled {
		return nil, toolNotAvailable("SubDomainizer")
	}

	args := []string{"-u", target, "-o", "/dev/stdout"}
	result := trtypes.Run(info.BinaryPath, args, trtypes.RunOptions{Timeout: timeout})
	trtypes.DefaultRegistry.RecordRun("SubDomainizer", result.Error == nil)

	var out []SubdomainResult
	for _, line := range parseLines(result.Stdout) {
		if strings.Contains(line, ".") && !strings.ContainsAny(line, "[]|") {
			out = append(out, SubdomainResult{Subdomain: line, Source: "SubDomainizer"})
		}
	}
	return out, nil
}

// toolNotAvailable returns a standardised error for unavailable tools.
func toolNotAvailable(name string) error {
	return &ToolUnavailableError{Name: name}
}

// ToolUnavailableError is returned when a tool is missing, disabled, or not installed.
type ToolUnavailableError struct {
	Name string
}

func (e *ToolUnavailableError) Error() string {
	return "tool not available: " + e.Name + " (missing, disabled, or not installed)"
}
