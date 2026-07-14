package tools

import (
	"strings"
	"time"

	trtypes "github.com/ShadooowX/rayyan-asm/internal/modules/toolrunner/types"
)

// CMSResult holds a finding from a CMS-specific scanner.
type CMSResult struct {
	CMS         string `json:"cms"`
	Component   string `json:"component"`
	Version     string `json:"version"`
	Severity    string `json:"severity"`
	Title       string `json:"title"`
	Description string `json:"description"`
	Reference   string `json:"reference"`
	Source      string `json:"source"`
}

// RunWPScan runs wpscan WordPress vulnerability scanner.
func RunWPScan(target string, timeout time.Duration) ([]CMSResult, error) {
	info, ok := trtypes.DefaultRegistry.Get("wpscan")
	if !ok || info.Status != trtypes.StatusInstalled || !info.Enabled {
		return nil, toolNotAvailable("wpscan")
	}

	args := []string{
		"--url", target,
		"--format", "json",
		"--no-banner",
		"--enumerate", "vp,vt,u",
		"--detection-mode", "passive",
	}
	result := trtypes.Run(info.BinaryPath, args, trtypes.RunOptions{Timeout: timeout})
	trtypes.DefaultRegistry.RecordRun("wpscan", result.Error == nil)

	var out []CMSResult
	clean := extractJSON(result.Stdout)
	if clean == "" {
		return out, nil
	}
	var resp struct {
		Version struct {
			Number string `json:"number"`
		} `json:"version"`
		Plugins map[string]struct {
			VersionNumber   string `json:"version"`
			Vulnerabilities []struct {
				Title      string `json:"title"`
				References struct {
					CVE []string `json:"cve"`
					URL []string `json:"url"`
				} `json:"references"`
			} `json:"vulnerabilities"`
		} `json:"plugins"`
		Themes map[string]struct {
			VersionNumber   string `json:"version"`
			Vulnerabilities []struct {
				Title      string `json:"title"`
				References struct {
					CVE []string `json:"cve"`
					URL []string `json:"url"`
				} `json:"references"`
			} `json:"vulnerabilities"`
		} `json:"themes"`
	}
	if err := parseJSONObj(clean, &resp); err != nil {
		return out, nil
	}

	if resp.Version.Number != "" {
		out = append(out, CMSResult{
			CMS:       "WordPress",
			Component: "core",
			Version:   resp.Version.Number,
			Severity:  "info",
			Title:     "WordPress version detected",
			Source:    "wpscan",
		})
	}
	for name, plugin := range resp.Plugins {
		for _, vuln := range plugin.Vulnerabilities {
			ref := ""
			if len(vuln.References.URL) > 0 {
				ref = vuln.References.URL[0]
			}
			out = append(out, CMSResult{
				CMS:       "WordPress",
				Component: "plugin:" + name,
				Version:   plugin.VersionNumber,
				Severity:  "high",
				Title:     vuln.Title,
				Reference: ref,
				Source:    "wpscan",
			})
		}
	}
	for name, theme := range resp.Themes {
		for _, vuln := range theme.Vulnerabilities {
			ref := ""
			if len(vuln.References.URL) > 0 {
				ref = vuln.References.URL[0]
			}
			out = append(out, CMSResult{
				CMS:       "WordPress",
				Component: "theme:" + name,
				Version:   theme.VersionNumber,
				Severity:  "medium",
				Title:     vuln.Title,
				Reference: ref,
				Source:    "wpscan",
			})
		}
	}
	return out, nil
}

// toTitle capitalises the first letter of s. Replaces deprecated strings.Title.
func toTitle(s string) string {
	if s == "" {
		return s
	}
	return strings.ToUpper(s[:1]) + s[1:]
}

// RunDroopeScan runs droopescan CMS detection and vulnerability scanner.
func RunDroopeScan(target string, timeout time.Duration) ([]CMSResult, error) {
	info, ok := trtypes.DefaultRegistry.Get("droopescan")
	if !ok || info.Status != trtypes.StatusInstalled || !info.Enabled {
		return nil, toolNotAvailable("droopescan")
	}

	args := []string{
		"scan", "--url", target,
		"-o", "json",
	}
	result := trtypes.Run(info.BinaryPath, args, trtypes.RunOptions{Timeout: timeout})
	trtypes.DefaultRegistry.RecordRun("droopescan", result.Error == nil)

	var out []CMSResult
	clean := extractJSON(result.Stdout)
	if clean == "" {
		// Fallback: detect CMS from text output
		for _, line := range parseLines(result.Stdout) {
			lower := strings.ToLower(line)
			for _, cms := range []string{"drupal", "wordpress", "joomla", "silverstripe", "moodle"} {
				if strings.Contains(lower, cms) {
					out = append(out, CMSResult{
						CMS:      toTitle(cms),
						Severity: "info",
						Title:    "CMS detected: " + toTitle(cms),
						Source:   "droopescan",
					})
				}
			}
		}
		return out, nil
	}

	var resp struct {
		CMS     string `json:"cms"`
		Plugins []struct {
			Name    string `json:"name"`
			Version string `json:"version"`
		} `json:"plugins"`
		Themes []struct {
			Name string `json:"name"`
		} `json:"themes"`
		Interesting []struct {
			URL         string `json:"url"`
			Description string `json:"description"`
		} `json:"interesting_urls"`
		Vulnerabilities []struct {
			Title    string `json:"title"`
			Severity string `json:"severity"`
		} `json:"vulnerabilities"`
	}
	if err := parseJSONObj(clean, &resp); err != nil {
		return out, nil
	}

	cms := resp.CMS
	if cms == "" {
		cms = "Unknown"
	}
	out = append(out, CMSResult{
		CMS:      cms,
		Severity: "info",
		Title:    "CMS detected: " + cms,
		Source:   "droopescan",
	})
	for _, p := range resp.Plugins {
		out = append(out, CMSResult{
			CMS:       cms,
			Component: "plugin:" + p.Name,
			Version:   p.Version,
			Severity:  "info",
			Title:     "Plugin detected: " + p.Name,
			Source:    "droopescan",
		})
	}
	for _, v := range resp.Vulnerabilities {
		sev := v.Severity
		if sev == "" {
			sev = "medium"
		}
		out = append(out, CMSResult{
			CMS:      cms,
			Severity: strings.ToLower(sev),
			Title:    v.Title,
			Source:   "droopescan",
		})
	}
	return out, nil
}
