package tools

import (
	"strings"
	"time"

	trtypes "github.com/ShadooowX/rayyan-asm/internal/modules/toolrunner/types"
)

// VulnResult holds a vulnerability finding from a scanner.
type VulnResult struct {
	TemplateID  string `json:"template_id"`
	Name        string `json:"name"`
	Severity    string `json:"severity"`
	Host        string `json:"host"`
	URL         string `json:"url"`
	Description string `json:"description"`
	Reference   string `json:"reference"`
	Source      string `json:"source"`
}

// WAFResult holds WAF detection output.
type WAFResult struct {
	Target     string `json:"target"`
	WAFName    string `json:"waf_name"`
	Detected   bool   `json:"detected"`
	Confidence string `json:"confidence"`
	Source     string `json:"source"`
}

// SMBResult holds SMB enumeration output.
type SMBResult struct {
	Host    string `json:"host"`
	Share   string `json:"share"`
	Type    string `json:"type"`
	Comment string `json:"comment"`
	Source  string `json:"source"`
}

// OriginIPResult holds a discovered origin IP behind a CDN.
type OriginIPResult struct {
	Domain   string `json:"domain"`
	OriginIP string `json:"origin_ip"`
	Source   string `json:"source"`
}

// RunNuclei runs nuclei template-based vulnerability scanning.
func RunNuclei(target string, severity string, timeout time.Duration) ([]VulnResult, error) {
	info, ok := trtypes.DefaultRegistry.Get("nuclei")
	if !ok || info.Status != trtypes.StatusInstalled || !info.Enabled {
		return nil, toolNotAvailable("nuclei")
	}
	if severity == "" {
		severity = "low,medium,high,critical"
	}

	args := []string{
		"-u", target,
		"-json",
		"-silent",
		"-severity", severity,
		"-rate-limit", "100",
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
			Source:      "nuclei",
		})
	}
	return out, nil
}

// NucleiTemplateGroup defines a named set of nuclei template tags/paths
// to run as a cohesive scan group.
type NucleiTemplateGroup struct {
	Name         string
	Tags         []string // -tags values; OR'd by nuclei
	TemplateDirs []string // -t paths (relative to nuclei template root)
	Severity     string   // comma-separated nuclei severity filter
}

// NucleiFullScanGroups returns the full set of template groups that together
// cover the complete Nuclei community template library.
var NucleiFullScanGroups = []NucleiTemplateGroup{
	{
		Name:     "exposed-panels",
		Tags:     []string{"panel", "login", "dashboard"},
		Severity: "low,medium,high,critical",
	},
	{
		Name:     "default-credentials",
		Tags:     []string{"default-login", "default-credentials"},
		Severity: "medium,high,critical",
	},
	{
		Name:     "misconfigurations",
		Tags:     []string{"misconfig", "misconfiguration", "exposure"},
		Severity: "low,medium,high,critical",
	},
	{
		Name:         "cves",
		TemplateDirs: []string{"cves/"},
		Severity:     "medium,high,critical",
	},
	{
		Name:     "exposed-files",
		Tags:     []string{"exposure", "file", "backup", "config"},
		Severity: "low,medium,high,critical",
	},
	{
		Name:         "vulnerabilities",
		TemplateDirs: []string{"vulnerabilities/"},
		Severity:     "low,medium,high,critical",
	},
	{
		Name:     "technologies",
		Tags:     []string{"tech", "detect"},
		Severity: "info,low",
	},
	{
		Name:         "network",
		TemplateDirs: []string{"network/"},
		Severity:     "medium,high,critical",
	},
	{
		Name:         "dns",
		TemplateDirs: []string{"dns/"},
		Severity:     "low,medium,high,critical",
	},
	{
		Name:     "ssl",
		Tags:     []string{"ssl", "tls"},
		Severity: "low,medium,high",
	},
	{
		Name:     "tokens-secrets",
		Tags:     []string{"token", "secret", "key", "api"},
		Severity: "medium,high,critical",
	},
	{
		Name:     "iot",
		Tags:     []string{"iot", "router", "camera", "scada"},
		Severity: "medium,high,critical",
	},
}

// RunNucleiWithTags runs nuclei against a specific template group using
// tag-based or directory-based template selection.
// Results carry the group name in the Source field for traceability.
func RunNucleiWithTags(target string, group NucleiTemplateGroup, timeout time.Duration) ([]VulnResult, error) {
	info, ok := trtypes.DefaultRegistry.Get("nuclei")
	if !ok || info.Status != trtypes.StatusInstalled || !info.Enabled {
		return nil, toolNotAvailable("nuclei")
	}

	sev := group.Severity
	if sev == "" {
		sev = "low,medium,high,critical"
	}

	args := []string{
		"-u", target,
		"-json",
		"-silent",
		"-severity", sev,
		"-rate-limit", "75",
		"-bulk-size", "25",
		"-retries", "1",
	}

	if len(group.Tags) > 0 {
		args = append(args, "-tags", strings.Join(group.Tags, ","))
	}
	for _, dir := range group.TemplateDirs {
		args = append(args, "-t", dir)
	}

	result := trtypes.Run(info.BinaryPath, args, trtypes.RunOptions{Timeout: timeout})
	trtypes.DefaultRegistry.RecordRun("nuclei", result.Error == nil)

	source := "nuclei/" + group.Name
	var out []VulnResult
	for _, line := range parseLines(result.Stdout) {
		var obj struct {
			TemplateID string `json:"template-id"`
			Info       struct {
				Name        string   `json:"name"`
				Severity    string   `json:"severity"`
				Description string   `json:"description"`
				Reference   []string `json:"reference"`
				Tags        string   `json:"tags"`
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
			Source:      source,
		})
	}
	return out, nil
}

// RunNucleiFullScan runs all NucleiFullScanGroups sequentially against the
// target and returns deduplicated findings. It is designed for the
// WorkflowNucleiFullScan workflow stage.
func RunNucleiFullScan(target string, timeout time.Duration) ([]VulnResult, error) {
	// Divide the total timeout evenly across groups so a slow group can't
	// starve the rest. Minimum 2 minutes per group.
	groupTimeout := timeout / time.Duration(len(NucleiFullScanGroups))
	if groupTimeout < 2*time.Minute {
		groupTimeout = 2 * time.Minute
	}

	seen := make(map[string]bool)
	var all []VulnResult

	for _, group := range NucleiFullScanGroups {
		results, err := RunNucleiWithTags(target, group, groupTimeout)
		if err != nil {
			// Non-fatal: log via Source field and continue other groups
			continue
		}
		for _, r := range results {
			key := r.TemplateID + "|" + r.URL
			if !seen[key] {
				seen[key] = true
				all = append(all, r)
			}
		}
	}
	return all, nil
}

func RunNikto(target string, timeout time.Duration) ([]VulnResult, error) {
	info, ok := trtypes.DefaultRegistry.Get("nikto")
	if !ok || info.Status != trtypes.StatusInstalled || !info.Enabled {
		return nil, toolNotAvailable("nikto")
	}

	args := []string{"-h", target, "-Format", "json", "-output", "/dev/stdout", "-nointeractive"}
	result := trtypes.Run(info.BinaryPath, args, trtypes.RunOptions{Timeout: timeout})
	trtypes.DefaultRegistry.RecordRun("nikto", result.Error == nil)

	var out []VulnResult
	clean := extractJSON(result.Stdout)
	if clean == "" {
		return out, nil
	}
	var resp struct {
		Vulnerabilities []struct {
			ID      string `json:"id"`
			Message string `json:"msg"`
			URL     string `json:"url"`
		} `json:"vulnerabilities"`
	}
	if err := parseJSONObj(clean, &resp); err != nil {
		return out, nil
	}
	for _, v := range resp.Vulnerabilities {
		out = append(out, VulnResult{
			TemplateID: v.ID,
			Name:       v.Message,
			URL:        v.URL,
			Host:       target,
			Severity:   "info",
			Source:     "nikto",
		})
	}
	return out, nil
}

// RunTestssl runs testssl.sh for TLS/SSL analysis.
func RunTestssl(target string, timeout time.Duration) ([]VulnResult, error) {
	info, ok := trtypes.DefaultRegistry.Get("testssl.sh")
	if !ok || info.Status != trtypes.StatusInstalled || !info.Enabled {
		return nil, toolNotAvailable("testssl.sh")
	}

	args := []string{"--json", "--severity", "LOW", "--quiet", target}
	result := trtypes.Run(info.BinaryPath, args, trtypes.RunOptions{Timeout: timeout})
	trtypes.DefaultRegistry.RecordRun("testssl.sh", result.Error == nil)

	var out []VulnResult
	clean := extractJSON(result.Stdout)
	if clean == "" {
		return out, nil
	}
	var records []struct {
		ID       string `json:"id"`
		Severity string `json:"severity"`
		Finding  string `json:"finding"`
	}
	if err := parseJSONSlice(clean, &records); err != nil {
		return out, nil
	}
	for _, r := range records {
		sev := strings.ToLower(r.Severity)
		if sev == "ok" || sev == "info" {
			continue
		}
		out = append(out, VulnResult{
			TemplateID: r.ID,
			Name:       r.ID + ": " + r.Finding,
			Severity:   sev,
			Host:       target,
			Source:     "testssl.sh",
		})
	}
	return out, nil
}

// RunWafw00f detects WAF presence on the target.
func RunWafw00f(target string, timeout time.Duration) ([]WAFResult, error) {
	info, ok := trtypes.DefaultRegistry.Get("wafw00f")
	if !ok || info.Status != trtypes.StatusInstalled || !info.Enabled {
		return nil, toolNotAvailable("wafw00f")
	}

	args := []string{target, "-o", "/dev/stdout", "-f", "json"}
	result := trtypes.Run(info.BinaryPath, args, trtypes.RunOptions{Timeout: timeout})
	trtypes.DefaultRegistry.RecordRun("wafw00f", result.Error == nil)

	var out []WAFResult
	clean := extractJSON(result.Stdout)
	if clean == "" {
		// Fallback: parse text output
		detected := strings.Contains(result.Stdout, "is behind")
		wafName := ""
		for _, line := range parseLines(result.Stdout) {
			if strings.Contains(line, "is behind") {
				parts := strings.SplitN(line, "is behind", 2)
				if len(parts) == 2 {
					wafName = strings.TrimSpace(parts[1])
					wafName = strings.Trim(wafName, " .")
				}
			}
		}
		out = append(out, WAFResult{
			Target:   target,
			WAFName:  wafName,
			Detected: detected,
			Source:   "wafw00f",
		})
		return out, nil
	}
	var records []struct {
		URL      string `json:"url"`
		Detected bool   `json:"detected"`
		Firewall string `json:"firewall"`
	}
	if err := parseJSONSlice(clean, &records); err != nil {
		return out, nil
	}
	for _, r := range records {
		out = append(out, WAFResult{
			Target:   r.URL,
			WAFName:  r.Firewall,
			Detected: r.Detected,
			Source:   "wafw00f",
		})
	}
	return out, nil
}

// RunSmbclient lists SMB shares on the target.
func RunSmbclient(target string, timeout time.Duration) ([]SMBResult, error) {
	info, ok := trtypes.DefaultRegistry.Get("smbclient")
	if !ok || info.Status != trtypes.StatusInstalled || !info.Enabled {
		return nil, toolNotAvailable("smbclient")
	}

	args := []string{"-L", target, "-N", "--no-pass"}
	result := trtypes.Run(info.BinaryPath, args, trtypes.RunOptions{Timeout: timeout})
	trtypes.DefaultRegistry.RecordRun("smbclient", result.Error == nil)

	var out []SMBResult
	for _, line := range parseLines(result.Stdout) {
		// smbclient -L output: "\tShareName  Type  Comment"
		if !strings.HasPrefix(line, "\t") && !strings.HasPrefix(line, " ") {
			continue
		}
		fields := strings.Fields(line)
		if len(fields) < 2 {
			continue
		}
		out = append(out, SMBResult{
			Host:    target,
			Share:   fields[0],
			Type:    fields[1],
			Comment: strings.Join(fields[2:], " "),
			Source:  "smbclient",
		})
	}
	return out, nil
}

// RunEnum4linuxNg runs enum4linux-ng with JSON output for SMB enumeration.
func RunEnum4linuxNg(target string, timeout time.Duration) ([]SMBResult, error) {
	info, ok := trtypes.DefaultRegistry.Get("enum4linux-ng")
	if !ok || info.Status != trtypes.StatusInstalled || !info.Enabled {
		return nil, toolNotAvailable("enum4linux-ng")
	}

	args := []string{"-A", "-oJ", "/dev/stdout", target}
	result := trtypes.Run(info.BinaryPath, args, trtypes.RunOptions{Timeout: timeout})
	trtypes.DefaultRegistry.RecordRun("enum4linux-ng", result.Error == nil)

	var out []SMBResult
	clean := extractJSON(result.Stdout)
	if clean == "" {
		return out, nil
	}
	var resp struct {
		Shares map[string]struct {
			Type    string `json:"type"`
			Comment string `json:"comment"`
		} `json:"shares"`
	}
	if err := parseJSONObj(clean, &resp); err != nil {
		return out, nil
	}
	for name, share := range resp.Shares {
		out = append(out, SMBResult{
			Host:    target,
			Share:   name,
			Type:    share.Type,
			Comment: share.Comment,
			Source:  "enum4linux-ng",
		})
	}
	return out, nil
}

// RunCrackMapExec runs crackmapexec for SMB enumeration (shares listing).
func RunCrackMapExec(target string, timeout time.Duration) ([]SMBResult, error) {
	info, ok := trtypes.DefaultRegistry.Get("crackmapexec")
	if !ok || info.Status != trtypes.StatusInstalled || !info.Enabled {
		return nil, toolNotAvailable("crackmapexec")
	}

	args := []string{"smb", target, "--shares", "-u", "", "-p", ""}
	result := trtypes.Run(info.BinaryPath, args, trtypes.RunOptions{Timeout: timeout})
	trtypes.DefaultRegistry.RecordRun("crackmapexec", result.Error == nil)

	var out []SMBResult
	for _, line := range parseLines(result.Stdout) {
		if !strings.Contains(line, "SMB") {
			continue
		}
		fields := strings.Fields(line)
		// CME line: "SMB  ip  port  hostname  ... SHARE  READ ..."
		for i, f := range fields {
			if f == "READ" || f == "WRITE" || f == "NO" {
				if i > 0 {
					out = append(out, SMBResult{
						Host:   target,
						Share:  fields[i-1],
						Type:   "Disk",
						Source: "crackmapexec",
					})
				}
			}
		}
	}
	return out, nil
}

// RunCloudflair discovers origin IPs behind CDN/Cloudflare.
func RunCloudflair(target string, timeout time.Duration) ([]OriginIPResult, error) {
	info, ok := trtypes.DefaultRegistry.Get("cloudflair")
	if !ok || info.Status != trtypes.StatusInstalled || !info.Enabled {
		return nil, toolNotAvailable("cloudflair")
	}

	args := []string{target}
	result := trtypes.Run(info.BinaryPath, args, trtypes.RunOptions{Timeout: timeout})
	trtypes.DefaultRegistry.RecordRun("cloudflair", result.Error == nil)

	var out []OriginIPResult
	for _, line := range parseLines(result.Stdout) {
		if strings.Contains(line, "Found origin") || strings.Contains(line, "origin IP") {
			// Extract IP from line
			fields := strings.Fields(line)
			for _, f := range fields {
				if isIPLike(f) {
					out = append(out, OriginIPResult{
						Domain: target, OriginIP: f, Source: "cloudflair",
					})
				}
			}
		}
	}
	return out, nil
}

// RunHakoriginfinder runs hakoriginfinder to discover origin IPs.
func RunHakoriginfinder(target string, timeout time.Duration) ([]OriginIPResult, error) {
	info, ok := trtypes.DefaultRegistry.Get("hakoriginfinder")
	if !ok || info.Status != trtypes.StatusInstalled || !info.Enabled {
		return nil, toolNotAvailable("hakoriginfinder")
	}

	args := []string{"-host", target}
	result := trtypes.Run(info.BinaryPath, args, trtypes.RunOptions{Timeout: timeout})
	trtypes.DefaultRegistry.RecordRun("hakoriginfinder", result.Error == nil)

	var out []OriginIPResult
	for _, line := range parseLines(result.Stdout) {
		fields := strings.Fields(line)
		for _, f := range fields {
			if isIPLike(f) {
				out = append(out, OriginIPResult{
					Domain: target, OriginIP: f, Source: "hakoriginfinder",
				})
			}
		}
	}
	return out, nil
}

// RunCloakquest3r runs CloakQuest3r to uncover origin IPs.
func RunCloakquest3r(target string, timeout time.Duration) ([]OriginIPResult, error) {
	info, ok := trtypes.DefaultRegistry.Get("cloakquest3r")
	if !ok || info.Status != trtypes.StatusInstalled || !info.Enabled {
		return nil, toolNotAvailable("cloakquest3r")
	}

	args := []string{target}
	result := trtypes.Run(info.BinaryPath, args, trtypes.RunOptions{Timeout: timeout})
	trtypes.DefaultRegistry.RecordRun("cloakquest3r", result.Error == nil)

	var out []OriginIPResult
	for _, line := range parseLines(result.Stdout) {
		if strings.Contains(line, "Origin") || strings.Contains(line, "IP:") {
			fields := strings.Fields(line)
			for _, f := range fields {
				f = strings.Trim(f, ":")
				if isIPLike(f) {
					out = append(out, OriginIPResult{
						Domain: target, OriginIP: f, Source: "cloakquest3r",
					})
				}
			}
		}
	}
	return out, nil
}

// isIPLike returns true if the string looks like an IPv4 address.
func isIPLike(s string) bool {
	parts := strings.Split(s, ".")
	if len(parts) != 4 {
		return false
	}
	for _, p := range parts {
		if len(p) == 0 || len(p) > 3 {
			return false
		}
		for _, c := range p {
			if c < '0' || c > '9' {
				return false
			}
		}
	}
	return true
}
