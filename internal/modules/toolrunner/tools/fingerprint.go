package tools

import (
	"strings"
	"time"

	trtypes "github.com/ShadooowX/rayyan-asm/internal/modules/toolrunner/types"
)

// TechFingerprintResult holds technology detection output.
type TechFingerprintResult struct {
	URL        string   `json:"url"`
	Technology string   `json:"technology"`
	Version    string   `json:"version"`
	Categories []string `json:"categories"`
	Confidence int      `json:"confidence"`
	Source     string   `json:"source"`
}

// RunWhatWeb runs whatweb to fingerprint technologies on the target URL.
func RunWhatWeb(target string, timeout time.Duration) ([]TechFingerprintResult, error) {
	info, ok := trtypes.DefaultRegistry.Get("whatweb")
	if !ok || info.Status != trtypes.StatusInstalled || !info.Enabled {
		return nil, toolNotAvailable("whatweb")
	}

	args := []string{
		target,
		"--log-json=/dev/stdout",
		"--color=never",
		"-q",
	}
	result := trtypes.Run(info.BinaryPath, args, trtypes.RunOptions{Timeout: timeout})
	trtypes.DefaultRegistry.RecordRun("whatweb", result.Error == nil)

	var out []TechFingerprintResult
	for _, line := range parseLines(result.Stdout) {
		var obj struct {
			Target string `json:"target"`
			HTTP   struct {
				Status int `json:"status"`
			} `json:"http_status"`
			Plugins map[string]struct {
				Version []string `json:"version"`
				String  []string `json:"string"`
			} `json:"plugins"`
		}
		if err := parseJSONLine(line, &obj); err != nil {
			continue
		}
		for tech, plugin := range obj.Plugins {
			ver := ""
			if len(plugin.Version) > 0 {
				ver = plugin.Version[0]
			}
			out = append(out, TechFingerprintResult{
				URL:        obj.Target,
				Technology: tech,
				Version:    ver,
				Confidence: 80,
				Source:     "whatweb",
			})
		}
	}
	return out, nil
}

// RunWappalyzerCLI runs wappalyzer-cli to identify technologies on the target URL.
func RunWappalyzerCLI(target string, timeout time.Duration) ([]TechFingerprintResult, error) {
	info, ok := trtypes.DefaultRegistry.Get("wappalyzer")
	if !ok || info.Status != trtypes.StatusInstalled || !info.Enabled {
		return nil, toolNotAvailable("wappalyzer")
	}

	args := []string{target}
	result := trtypes.Run(info.BinaryPath, args, trtypes.RunOptions{Timeout: timeout})
	trtypes.DefaultRegistry.RecordRun("wappalyzer", result.Error == nil)

	var out []TechFingerprintResult
	clean := extractJSON(result.Stdout)
	if clean == "" {
		return out, nil
	}
	var resp struct {
		Technologies []struct {
			Name       string   `json:"name"`
			Version    string   `json:"version"`
			Categories []string `json:"categories"`
			Confidence int      `json:"confidence"`
		} `json:"technologies"`
		URLs map[string]struct{} `json:"urls"`
	}
	if err := parseJSONObj(clean, &resp); err != nil {
		// Try flat array format
		var arr []struct {
			Name       string   `json:"name"`
			Version    string   `json:"version"`
			Categories []string `json:"categories"`
			Confidence int      `json:"confidence"`
		}
		if err2 := parseJSONSlice(clean, &arr); err2 == nil {
			for _, t := range arr {
				out = append(out, TechFingerprintResult{
					URL:        target,
					Technology: t.Name,
					Version:    t.Version,
					Categories: t.Categories,
					Confidence: t.Confidence,
					Source:     "wappalyzer",
				})
			}
		}
		return out, nil
	}
	for _, t := range resp.Technologies {
		cats := t.Categories
		if len(cats) == 0 {
			cats = []string{}
		}
		out = append(out, TechFingerprintResult{
			URL:        target,
			Technology: t.Name,
			Version:    strings.TrimSpace(t.Version),
			Categories: cats,
			Confidence: t.Confidence,
			Source:     "wappalyzer",
		})
	}
	return out, nil
}
