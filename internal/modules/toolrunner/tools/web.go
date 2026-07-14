package tools

import (
	"fmt"
	"strings"
	"time"

	trtypes "github.com/ShadooowX/rayyan-asm/internal/modules/toolrunner/types"
)

// HTTPResult holds a probed HTTP endpoint result.
type HTTPResult struct {
	URL        string `json:"url"`
	StatusCode int    `json:"status_code"`
	Title      string `json:"title"`
	TechStack  string `json:"tech_stack"`
	WebServer  string `json:"web_server"`
	IP         string `json:"ip"`
	Source     string `json:"source"`
}

// CrawlResult holds a discovered URL from crawling.
type CrawlResult struct {
	URL    string `json:"url"`
	Source string `json:"source"`
}

// RunHTTPx probes HTTP/HTTPS services on the provided targets.
func RunHTTPx(targets []string, timeout time.Duration) ([]HTTPResult, error) {
	info, ok := trtypes.DefaultRegistry.Get("httpx")
	if !ok || info.Status != trtypes.StatusInstalled || !info.Enabled {
		return nil, toolNotAvailable("httpx")
	}
	if len(targets) == 0 {
		return nil, nil
	}

	args := []string{
		"-u", strings.Join(targets, ","),
		"-json", "-silent",
		"-title", "-tech-detect", "-status-code", "-web-server", "-ip",
		"-follow-redirects",
	}
	result := trtypes.Run(info.BinaryPath, args, trtypes.RunOptions{Timeout: timeout})
	trtypes.DefaultRegistry.RecordRun("httpx", result.Error == nil)

	var out []HTTPResult
	for _, line := range parseLines(result.Stdout) {
		var obj struct {
			URL        string   `json:"url"`
			StatusCode int      `json:"status_code"`
			Title      string   `json:"title"`
			Tech       []string `json:"tech"`
			WebServer  string   `json:"webserver"`
			Host       string   `json:"host"`
		}
		if err := parseJSONLine(line, &obj); err != nil {
			continue
		}
		out = append(out, HTTPResult{
			URL:        obj.URL,
			StatusCode: obj.StatusCode,
			Title:      obj.Title,
			TechStack:  strings.Join(obj.Tech, ", "),
			WebServer:  obj.WebServer,
			IP:         obj.Host,
			Source:     "httpx",
		})
	}
	return out, nil
}

// RunKatana crawls a target URL and returns discovered endpoints.
func RunKatana(target string, depth int, timeout time.Duration) ([]CrawlResult, error) {
	info, ok := trtypes.DefaultRegistry.Get("katana")
	if !ok || info.Status != trtypes.StatusInstalled || !info.Enabled {
		return nil, toolNotAvailable("katana")
	}
	if depth <= 0 {
		depth = 3
	}

	args := []string{"-u", target, "-d", fmt.Sprintf("%d", depth), "-silent", "-jc", "-kf", "all"}
	result := trtypes.Run(info.BinaryPath, args, trtypes.RunOptions{Timeout: timeout})
	trtypes.DefaultRegistry.RecordRun("katana", result.Error == nil)

	var out []CrawlResult
	for _, line := range parseLines(result.Stdout) {
		// katana outputs one URL per line
		if strings.HasPrefix(line, "http") {
			out = append(out, CrawlResult{URL: line, Source: "katana"})
		}
	}
	return out, nil
}

// RunHakrawler crawls a target URL using hakrawler.
func RunHakrawler(target string, timeout time.Duration) ([]CrawlResult, error) {
	info, ok := trtypes.DefaultRegistry.Get("hakrawler")
	if !ok || info.Status != trtypes.StatusInstalled || !info.Enabled {
		return nil, toolNotAvailable("hakrawler")
	}

	args := []string{"-url", target, "-depth", "3", "-plain"}
	result := trtypes.Run(info.BinaryPath, args, trtypes.RunOptions{Timeout: timeout})
	trtypes.DefaultRegistry.RecordRun("hakrawler", result.Error == nil)

	var out []CrawlResult
	for _, line := range parseLines(result.Stdout) {
		if strings.HasPrefix(line, "http") {
			out = append(out, CrawlResult{URL: line, Source: "hakrawler"})
		}
	}
	return out, nil
}

// RunGau fetches known URLs from open archives for the target domain.
// maxLines caps the number of output lines consumed (0 = trtypes default).
func RunGau(target string, timeout time.Duration, maxLines int) ([]CrawlResult, error) {
	info, ok := trtypes.DefaultRegistry.Get("gau")
	if !ok || info.Status != trtypes.StatusInstalled || !info.Enabled {
		return nil, toolNotAvailable("gau")
	}

	args := []string{"--providers", "wayback,commoncrawl,otx", target}
	result := trtypes.Run(info.BinaryPath, args, trtypes.RunOptions{Timeout: timeout, MaxLines: maxLines})
	trtypes.DefaultRegistry.RecordRun("gau", result.Error == nil)

	var out []CrawlResult
	for _, line := range parseLines(result.Stdout) {
		if strings.HasPrefix(line, "http") {
			out = append(out, CrawlResult{URL: line, Source: "gau"})
		}
	}
	return out, nil
}

// RunWaybackurls fetches archived URLs from the Wayback Machine for the target.
// maxLines caps the number of output lines consumed (0 = trtypes default).
func RunWaybackurls(target string, timeout time.Duration, maxLines int) ([]CrawlResult, error) {
	info, ok := trtypes.DefaultRegistry.Get("waybackurls")
	if !ok || info.Status != trtypes.StatusInstalled || !info.Enabled {
		return nil, toolNotAvailable("waybackurls")
	}

	args := []string{target}
	result := trtypes.Run(info.BinaryPath, args, trtypes.RunOptions{Timeout: timeout, MaxLines: maxLines})
	trtypes.DefaultRegistry.RecordRun("waybackurls", result.Error == nil)

	var out []CrawlResult
	for _, line := range parseLines(result.Stdout) {
		if strings.HasPrefix(line, "http") {
			out = append(out, CrawlResult{URL: line, Source: "waybackurls"})
		}
	}
	return out, nil
}
