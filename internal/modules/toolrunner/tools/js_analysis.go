package tools

import (
	"strings"
	"time"

	trtypes "github.com/ShadooowX/rayyan-asm/internal/modules/toolrunner/types"
)

// JSEndpointResult holds an endpoint discovered in a JavaScript file.
type JSEndpointResult struct {
	URL      string `json:"url"`
	Endpoint string `json:"endpoint"`
	Source   string `json:"source"`
}

// JSSecretResult holds a secret or sensitive value found in a JavaScript file.
type JSSecretResult struct {
	URL      string  `json:"url"`
	Key      string  `json:"key"`
	Value    string  `json:"value"`
	Entropy  float64 `json:"entropy,omitempty"`
	Severity string  `json:"severity"`
	Source   string  `json:"source"`
}

// DependencyVulnResult holds a vulnerable dependency finding.
type DependencyVulnResult struct {
	Library   string `json:"library"`
	Version   string `json:"version"`
	CVE       string `json:"cve"`
	Severity  string `json:"severity"`
	Title     string `json:"title"`
	Reference string `json:"reference"`
	Source    string `json:"source"`
}

// RunLinkFinder runs linkfinder to extract endpoints from JavaScript files.
func RunLinkFinder(target string, timeout time.Duration) ([]JSEndpointResult, error) {
	info, ok := trtypes.DefaultRegistry.Get("linkfinder")
	if !ok || info.Status != trtypes.StatusInstalled || !info.Enabled {
		return nil, toolNotAvailable("linkfinder")
	}

	args := []string{
		"-i", target,
		"-o", "cli",
		"-d",
	}
	result := trtypes.Run(info.BinaryPath, args, trtypes.RunOptions{Timeout: timeout})
	trtypes.DefaultRegistry.RecordRun("linkfinder", result.Error == nil)

	var out []JSEndpointResult
	for _, line := range parseLines(result.Stdout) {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "[") && strings.Contains(line, "Analyzing") {
			continue
		}
		if strings.HasPrefix(line, "/") || strings.HasPrefix(line, "http") || strings.Contains(line, "api") {
			out = append(out, JSEndpointResult{
				URL:      target,
				Endpoint: line,
				Source:   "linkfinder",
			})
		}
	}
	return out, nil
}

// RunSecretFinder runs secretfinder to detect secrets in JavaScript files.
func RunSecretFinder(target string, timeout time.Duration) ([]JSSecretResult, error) {
	info, ok := trtypes.DefaultRegistry.Get("secretfinder")
	if !ok || info.Status != trtypes.StatusInstalled || !info.Enabled {
		return nil, toolNotAvailable("secretfinder")
	}

	args := []string{
		"-i", target,
		"-o", "cli",
	}
	result := trtypes.Run(info.BinaryPath, args, trtypes.RunOptions{Timeout: timeout})
	trtypes.DefaultRegistry.RecordRun("secretfinder", result.Error == nil)

	var out []JSSecretResult
	for _, line := range parseLines(result.Stdout) {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		// SecretFinder output: [key] value
		if strings.HasPrefix(line, "[") {
			end := strings.Index(line, "]")
			if end != -1 {
				key := line[1:end]
				value := strings.TrimSpace(line[end+1:])
				sev := "high"
				lkey := strings.ToLower(key)
				if strings.Contains(lkey, "api_key") || strings.Contains(lkey, "secret") || strings.Contains(lkey, "token") {
					sev = "critical"
				}
				out = append(out, JSSecretResult{
					URL:      target,
					Key:      key,
					Value:    value,
					Severity: sev,
					Source:   "secretfinder",
				})
			}
		}
	}
	return out, nil
}

// RunRetireJS runs retire.js to detect vulnerable JavaScript libraries.
func RunRetireJS(target string, timeout time.Duration) ([]DependencyVulnResult, error) {
	info, ok := trtypes.DefaultRegistry.Get("retire")
	if !ok || info.Status != trtypes.StatusInstalled || !info.Enabled {
		return nil, toolNotAvailable("retire")
	}

	args := []string{
		"--outputformat", "json",
		"--outputpath", "/dev/stdout",
		"--js", target,
	}
	result := trtypes.Run(info.BinaryPath, args, trtypes.RunOptions{Timeout: timeout})
	trtypes.DefaultRegistry.RecordRun("retire", result.Error == nil)

	var out []DependencyVulnResult
	clean := extractJSON(result.Stdout)
	if clean == "" {
		return out, nil
	}
	var records []struct {
		File            string `json:"file"`
		Component       string `json:"component"`
		Version         string `json:"version"`
		Detection       string `json:"detection"`
		Vulnerabilities []struct {
			Info        []string `json:"info"`
			Severity    string   `json:"severity"`
			Identifiers struct {
				CVE []string `json:"CVE"`
			} `json:"identifiers"`
			Summary string `json:"summary"`
		} `json:"vulnerabilities"`
	}
	if err := parseJSONSlice(clean, &records); err != nil {
		return out, nil
	}
	for _, rec := range records {
		for _, v := range rec.Vulnerabilities {
			cve := ""
			if len(v.Identifiers.CVE) > 0 {
				cve = v.Identifiers.CVE[0]
			}
			ref := ""
			if len(v.Info) > 0 {
				ref = v.Info[0]
			}
			out = append(out, DependencyVulnResult{
				Library:   rec.Component,
				Version:   rec.Version,
				CVE:       cve,
				Severity:  strings.ToLower(v.Severity),
				Title:     v.Summary,
				Reference: ref,
				Source:    "retire.js",
			})
		}
	}
	return out, nil
}

// RunSnyk runs snyk dependency vulnerability test in the given project path.
func RunSnyk(projectPath string, timeout time.Duration) ([]DependencyVulnResult, error) {
	info, ok := trtypes.DefaultRegistry.Get("snyk")
	if !ok || info.Status != trtypes.StatusInstalled || !info.Enabled {
		return nil, toolNotAvailable("snyk")
	}

	args := []string{
		"test",
		"--json",
		"--severity-threshold=low",
	}
	if projectPath != "" {
		args = append(args, projectPath)
	}
	result := trtypes.Run(info.BinaryPath, args, trtypes.RunOptions{Timeout: timeout, WorkingDir: projectPath})
	trtypes.DefaultRegistry.RecordRun("snyk", result.Error == nil)

	var out []DependencyVulnResult
	clean := extractJSON(result.Stdout)
	if clean == "" {
		return out, nil
	}
	var resp struct {
		Vulnerabilities []struct {
			Title       string  `json:"title"`
			Severity    string  `json:"severity"`
			CVSSScore   float64 `json:"cvssScore"`
			Identifiers struct {
				CVE []string `json:"CVE"`
			} `json:"identifiers"`
			PackageName string `json:"packageName"`
			Version     string `json:"version"`
			References  []struct {
				URL string `json:"url"`
			} `json:"references"`
		} `json:"vulnerabilities"`
	}
	if err := parseJSONObj(clean, &resp); err != nil {
		return out, nil
	}
	for _, v := range resp.Vulnerabilities {
		cve := ""
		if len(v.Identifiers.CVE) > 0 {
			cve = v.Identifiers.CVE[0]
		}
		ref := ""
		if len(v.References) > 0 {
			ref = v.References[0].URL
		}
		out = append(out, DependencyVulnResult{
			Library:   v.PackageName,
			Version:   v.Version,
			CVE:       cve,
			Severity:  strings.ToLower(v.Severity),
			Title:     v.Title,
			Reference: ref,
			Source:    "snyk",
		})
	}
	return out, nil
}
