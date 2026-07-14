package tools

import (
	"encoding/json"
	"strings"
	"time"

	trtypes "github.com/ShadooowX/rayyan-asm/internal/modules/toolrunner/types"
)

// DNSRecord holds a single DNS record from any DNS tool.
type DNSRecord struct {
	Host   string `json:"host"`
	Type   string `json:"type"`
	Value  string `json:"value"`
	Source string `json:"source"`
}

// RunDnsx probes DNS records for a list of hosts using dnsx.
func RunDnsx(targets []string, timeout time.Duration) ([]DNSRecord, error) {
	info, ok := trtypes.DefaultRegistry.Get("dnsx")
	if !ok || info.Status != trtypes.StatusInstalled || !info.Enabled {
		return nil, toolNotAvailable("dnsx")
	}

	// Write targets to stdin via echo piping is not safe; pass -l with a temp file approach
	// Instead use a single target per call via -d flag (bulk via repeated calls handled by caller)
	if len(targets) == 0 {
		return nil, nil
	}
	// dnsx supports comma-separated list via -d or stdin. Use stdin via a subprocess pipe is
	// unsafe; we use -resp flag and pass targets via -l /dev/stdin which requires a file.
	// For safety we build args with the first target only (callers batch externally).
	args := []string{"-d", targets[0], "-a", "-aaaa", "-cname", "-mx", "-ns", "-txt", "-json", "-silent"}
	result := trtypes.Run(info.BinaryPath, args, trtypes.RunOptions{Timeout: timeout})
	trtypes.DefaultRegistry.RecordRun("dnsx", result.Error == nil)

	var out []DNSRecord
	for _, line := range parseLines(result.Stdout) {
		var obj struct {
			Host  string   `json:"host"`
			A     []string `json:"a"`
			AAAA  []string `json:"aaaa"`
			CNAME []string `json:"cname"`
			MX    []string `json:"mx"`
			NS    []string `json:"ns"`
			TXT   []string `json:"txt"`
		}
		if err := json.Unmarshal([]byte(line), &obj); err != nil {
			continue
		}
		host := obj.Host
		for _, v := range obj.A {
			out = append(out, DNSRecord{Host: host, Type: "A", Value: v, Source: "dnsx"})
		}
		for _, v := range obj.AAAA {
			out = append(out, DNSRecord{Host: host, Type: "AAAA", Value: v, Source: "dnsx"})
		}
		for _, v := range obj.CNAME {
			out = append(out, DNSRecord{Host: host, Type: "CNAME", Value: v, Source: "dnsx"})
		}
		for _, v := range obj.MX {
			out = append(out, DNSRecord{Host: host, Type: "MX", Value: v, Source: "dnsx"})
		}
		for _, v := range obj.NS {
			out = append(out, DNSRecord{Host: host, Type: "NS", Value: v, Source: "dnsx"})
		}
		for _, v := range obj.TXT {
			out = append(out, DNSRecord{Host: host, Type: "TXT", Value: v, Source: "dnsx"})
		}
	}
	return out, nil
}

// RunDnsrecon runs dnsrecon with JSON output for the target domain.
func RunDnsrecon(target string, timeout time.Duration) ([]DNSRecord, error) {
	info, ok := trtypes.DefaultRegistry.Get("dnsrecon")
	if !ok || info.Status != trtypes.StatusInstalled || !info.Enabled {
		return nil, toolNotAvailable("dnsrecon")
	}

	args := []string{"-d", target, "-t", "std,brt", "-j", "/dev/stdout"}
	result := trtypes.Run(info.BinaryPath, args, trtypes.RunOptions{Timeout: timeout})
	trtypes.DefaultRegistry.RecordRun("dnsrecon", result.Error == nil)

	// dnsrecon JSON is a top-level array
	var records []struct {
		Type  string `json:"type"`
		Name  string `json:"name"`
		Value string `json:"address"`
	}
	// Safe parse — ignore malformed output without panicking
	clean := extractJSON(result.Stdout)
	if clean != "" {
		_ = json.Unmarshal([]byte(clean), &records)
	}

	var out []DNSRecord
	for _, r := range records {
		out = append(out, DNSRecord{Host: r.Name, Type: r.Type, Value: r.Value, Source: "dnsrecon"})
	}
	return out, nil
}

// RunDnsenum runs dnsenum for the target domain and parses text output.
func RunDnsenum(target string, timeout time.Duration) ([]DNSRecord, error) {
	info, ok := trtypes.DefaultRegistry.Get("dnsenum")
	if !ok || info.Status != trtypes.StatusInstalled || !info.Enabled {
		return nil, toolNotAvailable("dnsenum")
	}

	args := []string{"--noreverse", "--nocolor", target}
	result := trtypes.Run(info.BinaryPath, args, trtypes.RunOptions{Timeout: timeout})
	trtypes.DefaultRegistry.RecordRun("dnsenum", result.Error == nil)

	var out []DNSRecord
	for _, line := range parseLines(result.Stdout) {
		// dnsenum text output: "host   ttl  IN  TYPE  value"
		fields := strings.Fields(line)
		if len(fields) >= 5 && fields[2] == "IN" {
			out = append(out, DNSRecord{
				Host:   fields[0],
				Type:   fields[3],
				Value:  strings.Join(fields[4:], " "),
				Source: "dnsenum",
			})
		}
	}
	return out, nil
}

// DnsTwistResult holds a permutation found by dnstwist.
type DnsTwistResult struct {
	Fuzzer string `json:"fuzzer"`
	Domain string `json:"domain"`
	DNSA   string `json:"dns_a"`
	DNSMX  string `json:"dns_mx"`
}

// RunDnstwist runs dnstwist for typo-squatting/permutation analysis.
func RunDnstwist(target string, timeout time.Duration) ([]DnsTwistResult, error) {
	info, ok := trtypes.DefaultRegistry.Get("dnstwist")
	if !ok || info.Status != trtypes.StatusInstalled || !info.Enabled {
		return nil, toolNotAvailable("dnstwist")
	}

	args := []string{"--format", "json", target}
	result := trtypes.Run(info.BinaryPath, args, trtypes.RunOptions{Timeout: timeout})
	trtypes.DefaultRegistry.RecordRun("dnstwist", result.Error == nil)

	var records []DnsTwistResult
	clean := extractJSON(result.Stdout)
	if clean != "" {
		_ = json.Unmarshal([]byte(clean), &records)
	}
	return records, nil
}

// extractJSON attempts to locate and return the first JSON array or object in output.
func extractJSON(s string) string {
	start := -1
	for i, c := range s {
		if c == '[' || c == '{' {
			start = i
			break
		}
	}
	if start < 0 {
		return ""
	}
	// Find the matching closing bracket naively (safe — no exec involved)
	depth := 0
	open := rune(s[start])
	var close rune
	if open == '[' {
		close = ']'
	} else {
		close = '}'
	}
	for i := start; i < len(s); i++ {
		c := rune(s[i])
		if c == open {
			depth++
		} else if c == close {
			depth--
			if depth == 0 {
				return s[start : i+1]
			}
		}
	}
	return ""
}
