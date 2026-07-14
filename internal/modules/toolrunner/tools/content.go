package tools

import (
	"strings"
	"time"

	trtypes "github.com/ShadooowX/rayyan-asm/internal/modules/toolrunner/types"
)

// ContentResult holds a discovered path/directory from a content discovery tool.
type ContentResult struct {
	URL        string `json:"url"`
	StatusCode int    `json:"status_code"`
	Length     int    `json:"length"`
	Words      int    `json:"words"`
	Lines      int    `json:"lines"`
	Source     string `json:"source"`
}

// DefaultWordlist is the fallback wordlist path when none is specified.
const DefaultWordlist = "/usr/share/wordlists/dirb/common.txt"

// RunFFUF runs ffuf for directory/file fuzzing with JSON output.
func RunFFUF(target, wordlist string, timeout time.Duration) ([]ContentResult, error) {
	info, ok := trtypes.DefaultRegistry.Get("ffuf")
	if !ok || info.Status != trtypes.StatusInstalled || !info.Enabled {
		return nil, toolNotAvailable("ffuf")
	}
	if wordlist == "" {
		wordlist = DefaultWordlist
	}

	// Ensure target ends with /FUZZ
	url := target
	if !strings.Contains(url, "FUZZ") {
		url = strings.TrimRight(url, "/") + "/FUZZ"
	}

	args := []string{
		"-u", url,
		"-w", wordlist,
		"-of", "json",
		"-o", "/dev/stdout",
		"-mc", "200,204,301,302,307,401,403,405",
		"-t", "50",
		"-s",
	}
	result := trtypes.Run(info.BinaryPath, args, trtypes.RunOptions{Timeout: timeout})
	trtypes.DefaultRegistry.RecordRun("ffuf", result.Error == nil)

	// ffuf JSON: {"results": [...]}
	var out []ContentResult
	clean := extractJSON(result.Stdout)
	if clean == "" {
		return out, nil
	}
	var resp struct {
		Results []struct {
			URL    string `json:"url"`
			Status int    `json:"status"`
			Length int    `json:"length"`
			Words  int    `json:"words"`
			Lines  int    `json:"lines"`
		} `json:"results"`
	}
	if err := parseJSONObj(clean, &resp); err != nil {
		return out, nil
	}
	for _, r := range resp.Results {
		out = append(out, ContentResult{
			URL:        r.URL,
			StatusCode: r.Status,
			Length:     r.Length,
			Words:      r.Words,
			Lines:      r.Lines,
			Source:     "ffuf",
		})
	}
	return out, nil
}

// RunFeroxbuster runs feroxbuster for recursive content discovery.
func RunFeroxbuster(target, wordlist string, timeout time.Duration) ([]ContentResult, error) {
	info, ok := trtypes.DefaultRegistry.Get("feroxbuster")
	if !ok || info.Status != trtypes.StatusInstalled || !info.Enabled {
		return nil, toolNotAvailable("feroxbuster")
	}
	if wordlist == "" {
		wordlist = DefaultWordlist
	}

	args := []string{
		"-u", target,
		"-w", wordlist,
		"--json",
		"--output", "/dev/stdout",
		"--no-state",
		"--quiet",
		"-t", "50",
		"-d", "3",
	}
	result := trtypes.Run(info.BinaryPath, args, trtypes.RunOptions{Timeout: timeout})
	trtypes.DefaultRegistry.RecordRun("feroxbuster", result.Error == nil)

	var out []ContentResult
	for _, line := range parseLines(result.Stdout) {
		// feroxbuster JSON lines: {"type":"response","url":"...","status":200,...}
		var obj struct {
			Type   string `json:"type"`
			URL    string `json:"url"`
			Status int    `json:"status"`
			Length int    `json:"content_length"`
			Words  int    `json:"word_count"`
			Lines  int    `json:"line_count"`
		}
		if err := parseJSONLine(line, &obj); err != nil {
			continue
		}
		if obj.Type != "response" {
			continue
		}
		out = append(out, ContentResult{
			URL:        obj.URL,
			StatusCode: obj.Status,
			Length:     obj.Length,
			Words:      obj.Words,
			Lines:      obj.Lines,
			Source:     "feroxbuster",
		})
	}
	return out, nil
}

// RunGobuster runs gobuster in dir mode.
func RunGobuster(target, wordlist string, timeout time.Duration) ([]ContentResult, error) {
	info, ok := trtypes.DefaultRegistry.Get("gobuster")
	if !ok || info.Status != trtypes.StatusInstalled || !info.Enabled {
		return nil, toolNotAvailable("gobuster")
	}
	if wordlist == "" {
		wordlist = DefaultWordlist
	}

	args := []string{
		"dir",
		"-u", target,
		"-w", wordlist,
		"-q",
		"--no-progress",
		"-o", "/dev/stdout",
	}
	result := trtypes.Run(info.BinaryPath, args, trtypes.RunOptions{Timeout: timeout})
	trtypes.DefaultRegistry.RecordRun("gobuster", result.Error == nil)

	var out []ContentResult
	for _, line := range parseLines(result.Stdout) {
		// gobuster text: "/path                (Status: 200) [Size: 1234]"
		if !strings.Contains(line, "(Status:") {
			continue
		}
		parts := strings.SplitN(line, "(Status:", 2)
		if len(parts) != 2 {
			continue
		}
		path := strings.TrimSpace(parts[0])
		statusStr := strings.TrimSpace(parts[1])
		statusStr = strings.TrimSuffix(statusStr, ")")
		// Strip trailing "[Size: NNN]" if present (not used in result)
		if idx := strings.Index(statusStr, "[Size:"); idx != -1 {
			statusStr = statusStr[:idx]
		}
		statusStr = strings.TrimSpace(statusStr)
		var code int
		if _, err := intParse(statusStr, &code); err != nil {
			continue
		}
		out = append(out, ContentResult{
			URL:        strings.TrimRight(target, "/") + path,
			StatusCode: code,
			Source:     "gobuster",
		})
	}
	return out, nil
}

// RunDirsearch runs dirsearch with JSON output.
func RunDirsearch(target, wordlist string, timeout time.Duration) ([]ContentResult, error) {
	info, ok := trtypes.DefaultRegistry.Get("dirsearch")
	if !ok || info.Status != trtypes.StatusInstalled || !info.Enabled {
		return nil, toolNotAvailable("dirsearch")
	}
	if wordlist == "" {
		wordlist = DefaultWordlist
	}

	args := []string{
		"-u", target,
		"-w", wordlist,
		"--format", "json",
		"-o", "/dev/stdout",
		"-q",
	}
	result := trtypes.Run(info.BinaryPath, args, trtypes.RunOptions{Timeout: timeout})
	trtypes.DefaultRegistry.RecordRun("dirsearch", result.Error == nil)

	var out []ContentResult
	clean := extractJSON(result.Stdout)
	if clean == "" {
		return out, nil
	}
	var resp struct {
		Results []struct {
			Path   string `json:"path"`
			Status int    `json:"status"`
			Length int    `json:"content_length"`
		} `json:"results"`
	}
	if err := parseJSONObj(clean, &resp); err != nil {
		return out, nil
	}
	for _, r := range resp.Results {
		out = append(out, ContentResult{
			URL:        strings.TrimRight(target, "/") + r.Path,
			StatusCode: r.Status,
			Length:     r.Length,
			Source:     "dirsearch",
		})
	}
	return out, nil
}

// intParse parses a decimal string into *out and returns (true, nil) on success.
func intParse(s string, out *int) (bool, error) {
	s = strings.TrimSpace(s)
	n := 0
	for _, c := range s {
		if c < '0' || c > '9' {
			return false, nil
		}
		n = n*10 + int(c-'0')
	}
	*out = n
	return true, nil
}
