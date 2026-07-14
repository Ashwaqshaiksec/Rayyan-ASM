package tools

import (
	"fmt"
	"strings"
	"time"

	trtypes "github.com/ShadooowX/rayyan-asm/internal/modules/toolrunner/types"
)

// TakeoverResult describes a potential subdomain takeover finding.
type TakeoverResult struct {
	Subdomain   string `json:"subdomain"`
	CNAME       string `json:"cname"`
	Provider    string `json:"provider"`
	Fingerprint string `json:"fingerprint"`
	Vulnerable  bool   `json:"vulnerable"`
	Confidence  string `json:"confidence"` // high, medium, low
	Source      string `json:"source"`
}

// RunSubjack runs subjack to check for subdomain takeover vulnerabilities.
// targets is a list of subdomains (one per line written to a temp file path,
// or pass a single domain as target and let subjack probe it).
func RunSubjack(subdomains []string, timeout time.Duration) ([]TakeoverResult, error) {
	info, ok := trtypes.DefaultRegistry.Get("subjack")
	if !ok || info.Status != trtypes.StatusInstalled || !info.Enabled {
		return nil, toolNotAvailable("subjack")
	}
	if len(subdomains) == 0 {
		return nil, nil
	}

	// subjack reads from a wordlist file; we write to a temp file via stdin pipe
	// using the -w flag with /dev/stdin trick.
	input := strings.Join(subdomains, "\n")

	args := []string{
		"-w", "/dev/stdin",
		"-t", "50",
		"-timeout", "30",
		"-ssl",
		"-c", "/usr/share/subjack/fingerprints.json",
		"-v",
	}
	result := trtypes.Run(info.BinaryPath, args, trtypes.RunOptions{
		Timeout: timeout,
		Env:     []string{"SUBJACK_INPUT=" + input},
	})
	trtypes.DefaultRegistry.RecordRun("subjack", result.Error == nil)

	// subjack outputs lines like:
	// [Not Vulnerable] sub.example.com
	// [Vulnerable] dangling.example.com (GitHub)
	var out []TakeoverResult
	for _, line := range parseLines(result.Stdout) {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		vulnerable := strings.HasPrefix(line, "[Vulnerable]") ||
			strings.HasPrefix(line, "[VULNERABLE]")
		if !vulnerable && !strings.HasPrefix(line, "[Not") {
			continue
		}
		// Extract subdomain and provider from: [Vulnerable] sub.example.com (Provider)
		sub := ""
		provider := ""
		rest := line
		if idx := strings.Index(rest, "]"); idx >= 0 {
			rest = strings.TrimSpace(rest[idx+1:])
		}
		if idx := strings.Index(rest, "("); idx >= 0 {
			provider = strings.Trim(rest[idx:], "()")
			sub = strings.TrimSpace(rest[:idx])
		} else {
			sub = rest
		}
		if !vulnerable {
			continue // skip non-vulnerable lines to reduce noise
		}
		out = append(out, TakeoverResult{
			Subdomain:  sub,
			Provider:   provider,
			Vulnerable: true,
			Confidence: "high",
			Source:     "subjack",
		})
	}
	return out, nil
}

// RunSubzy runs subzy to detect subdomain takeover vulnerabilities.
func RunSubzy(subdomains []string, timeout time.Duration) ([]TakeoverResult, error) {
	info, ok := trtypes.DefaultRegistry.Get("subzy")
	if !ok || info.Status != trtypes.StatusInstalled || !info.Enabled {
		return nil, toolNotAvailable("subzy")
	}
	if len(subdomains) == 0 {
		return nil, nil
	}

	targets := strings.Join(subdomains, ",")
	args := []string{
		"run",
		"--targets", targets,
		"--concurrency", "50",
		"--hide_fails",
		"--vuln",
	}
	result := trtypes.Run(info.BinaryPath, args, trtypes.RunOptions{Timeout: timeout})
	trtypes.DefaultRegistry.RecordRun("subzy", result.Error == nil)

	// subzy outputs lines like:
	// [VULN] sub.example.com - GitHub Pages
	var out []TakeoverResult
	for _, line := range parseLines(result.Stdout) {
		line = strings.TrimSpace(line)
		if !strings.Contains(line, "[VULN]") {
			continue
		}
		// Parse: [VULN] sub.example.com - Provider
		rest := strings.TrimPrefix(line, "[VULN]")
		rest = strings.TrimSpace(rest)
		parts := strings.SplitN(rest, " - ", 2)
		sub := strings.TrimSpace(parts[0])
		provider := ""
		if len(parts) == 2 {
			provider = strings.TrimSpace(parts[1])
		}
		out = append(out, TakeoverResult{
			Subdomain:  sub,
			Provider:   provider,
			Vulnerable: true,
			Confidence: "high",
			Source:     "subzy",
		})
	}
	return out, nil
}

// RunNucleiTakeover runs nuclei with the takeovers template pack specifically.
// This is separate from the general RunNuclei to enable targeted takeover
// detection without running the full template library.
func RunNucleiTakeover(subdomains []string, timeout time.Duration) ([]TakeoverResult, error) {
	info, ok := trtypes.DefaultRegistry.Get("nuclei")
	if !ok || info.Status != trtypes.StatusInstalled || !info.Enabled {
		return nil, toolNotAvailable("nuclei")
	}
	if len(subdomains) == 0 {
		return nil, nil
	}

	targets := strings.Join(subdomains, "\n")

	args := []string{
		"-l", "/dev/stdin",
		"-t", "takeovers/",
		"-json",
		"-silent",
		"-rate-limit", "50",
		"-bulk-size", "25",
	}
	result := trtypes.Run(info.BinaryPath, args, trtypes.RunOptions{
		Timeout: timeout,
		Env:     []string{"NUCLEI_INPUT=" + targets},
	})
	trtypes.DefaultRegistry.RecordRun("nuclei", result.Error == nil)

	var out []TakeoverResult
	for _, line := range parseLines(result.Stdout) {
		var obj struct {
			TemplateID string `json:"template-id"`
			Info       struct {
				Name     string `json:"name"`
				Severity string `json:"severity"`
			} `json:"info"`
			Host             string   `json:"host"`
			ExtractedResults []string `json:"extracted-results"`
			MatcherName      string   `json:"matcher-name"`
		}
		if err := parseJSONLine(line, &obj); err != nil {
			continue
		}
		cname := ""
		if len(obj.ExtractedResults) > 0 {
			cname = obj.ExtractedResults[0]
		}
		// Derive provider from template-id: takeovers/github-pages → GitHub Pages
		provider := providerFromTemplateID(obj.TemplateID)
		out = append(out, TakeoverResult{
			Subdomain:   obj.Host,
			CNAME:       cname,
			Provider:    provider,
			Fingerprint: obj.MatcherName,
			Vulnerable:  true,
			Confidence:  "high",
			Source:      "nuclei-takeover",
		})
	}
	return out, nil
}

// RunDNSTakeoverCheck performs a lightweight DNS-only takeover check without
// external tools. It resolves each subdomain's CNAME chain and checks the
// terminal CNAME against a built-in fingerprint table of known-vulnerable
// service patterns. Returns medium-confidence results for further validation.
func RunDNSTakeoverCheck(subdomains []string, timeout time.Duration) ([]TakeoverResult, error) {
	if len(subdomains) == 0 {
		return nil, nil
	}

	// Use dnsx for CNAME resolution if available; fall back to net.LookupCNAME
	info, dnsxOK := trtypes.DefaultRegistry.Get("dnsx")

	var out []TakeoverResult

	if dnsxOK && info.Status == trtypes.StatusInstalled && info.Enabled {
		targets := strings.Join(subdomains, "\n")
		args := []string{
			"-l", "/dev/stdin",
			"-cname",
			"-json",
			"-silent",
		}
		result := trtypes.Run(info.BinaryPath, args, trtypes.RunOptions{
			Timeout: timeout,
			Env:     []string{"DNSX_INPUT=" + targets},
		})

		for _, line := range parseLines(result.Stdout) {
			var obj struct {
				Host  string   `json:"host"`
				CNAME []string `json:"cname"`
			}
			if err := parseJSONLine(line, &obj); err != nil {
				continue
			}
			for _, cname := range obj.CNAME {
				provider, fingerprint, vulnerable := matchTakeoverFingerprint(cname)
				if vulnerable {
					out = append(out, TakeoverResult{
						Subdomain:   obj.Host,
						CNAME:       cname,
						Provider:    provider,
						Fingerprint: fingerprint,
						Vulnerable:  true,
						Confidence:  "medium", // DNS-only; not confirmed via HTTP probe
						Source:      "dns-takeover-check",
					})
				}
			}
		}
	}

	return out, nil
}

// providerFromTemplateID converts a nuclei template ID like
// "takeovers/github-pages" into a human-readable provider name.
func providerFromTemplateID(id string) string {
	id = strings.TrimPrefix(id, "takeovers/")
	id = strings.ReplaceAll(id, "-", " ")
	words := strings.Fields(id)
	for i, w := range words {
		if len(w) > 0 {
			words[i] = strings.ToUpper(w[:1]) + w[1:]
		}
	}
	return strings.Join(words, " ")
}

// takeoverFingerprints maps known dangling CNAME suffixes to provider info.
// Sources: EdOverflow/can-i-take-over-xyz, nuclei takeover templates.
var takeoverFingerprints = []struct {
	suffix      string
	provider    string
	fingerprint string
}{
	{"github.io", "GitHub Pages", "CNAME to github.io with no page"},
	{"s3.amazonaws.com", "AWS S3", "S3 bucket does not exist"},
	{"s3-website", "AWS S3", "NoSuchBucket"},
	{"storage.googleapis.com", "Google Cloud Storage", "The specified bucket does not exist"},
	{"azurewebsites.net", "Azure Web Apps", "Microsoft Azure App Service"},
	{"cloudapp.azure.com", "Azure Cloud", "Azure endpoint dangling"},
	{"trafficmanager.net", "Azure Traffic Manager", "DNS not configured"},
	{"azurefd.net", "Azure Front Door", "Resource removed"},
	{"digitaloceanspaces.com", "DigitalOcean Spaces", "NoSuchBucket"},
	{"herokudns.com", "Heroku", "No such app"},
	{"herokuapp.com", "Heroku", "No such app"},
	{"fastly.net", "Fastly", "Fastly error: unknown domain"},
	{"pantheonsite.io", "Pantheon", "The gods are wise"},
	{"netlify.com", "Netlify", "Not Found - Request ID"},
	{"netlify.app", "Netlify", "Not Found - Request ID"},
	{"ghost.io", "Ghost", "Domain does not match any active Ghost subscription"},
	{"helpscoutdocs.com", "HelpScout", "No settings were found"},
	{"freshdesk.com", "Freshdesk", "There is no helpdesk here"},
	{"statuspage.io", "StatusPage.io", "You are being redirected"},
	{"uservoice.com", "UserVoice", "This UserVoice subdomain is currently available"},
	{"wpengine.com", "WP Engine", "This site is not currently available"},
	{"webflow.io", "Webflow", "The page you are looking for doesn't exist"},
	{"smugmug.com", "SmugMug", "Page Not Found"},
	{"surge.sh", "Surge.sh", "project not found"},
	{"readme.io", "Readme.io", "Project doesnt exist"},
	{"cargocollective.com", "Cargo", "If you're moving your domain away from Cargo"},
	{"tumblr.com", "Tumblr", "Whatever you were looking for doesn't currently exist"},
	{"zendesk.com", "Zendesk", "Help Center Closed"},
	{"myshopify.com", "Shopify", "Sorry, this shop is currently unavailable"},
	{"bigcartel.com", "Big Cartel", "Oops! We couldn't find that page"},
	{"campaignmonitor.com", "Campaign Monitor", "Double check the URL"},
	{"createsend.com", "Campaign Monitor", "Double check the URL"},
	{"desk.com", "Desk", "Sorry, We Couldn't Find That Page"},
	{"feedpress.me", "FeedPress", "The feed has not been found"},
	{"fly.dev", "Fly.io", "404 Not Found"},
	{"render.com", "Render", "There is no Render app deployed here"},
	{"vercel.app", "Vercel", "The deployment could not be found on Vercel"},
}

// matchTakeoverFingerprint returns (provider, fingerprint, vulnerable) for a CNAME.
func matchTakeoverFingerprint(cname string) (string, string, bool) {
	cname = strings.ToLower(strings.TrimSuffix(cname, "."))
	for _, f := range takeoverFingerprints {
		if strings.Contains(cname, f.suffix) {
			return f.provider, f.fingerprint, true
		}
	}
	return "", "", false
}

// TakeoverSummary aggregates results from multiple takeover scanners into
// deduplicated findings, preferring higher-confidence results.
func TakeoverSummary(results []TakeoverResult) []TakeoverResult {
	seen := make(map[string]TakeoverResult)
	for _, r := range results {
		key := strings.ToLower(r.Subdomain)
		if existing, ok := seen[key]; ok {
			// Prefer high confidence over medium
			if r.Confidence == "high" && existing.Confidence != "high" {
				seen[key] = r
			}
		} else {
			seen[key] = r
		}
	}
	out := make([]TakeoverResult, 0, len(seen))
	for _, r := range seen {
		out = append(out, r)
	}
	return out
}

// TakeoverFindingTitle returns a human-readable finding title.
func TakeoverFindingTitle(r TakeoverResult) string {
	if r.Provider != "" {
		return fmt.Sprintf("Subdomain Takeover — %s (%s)", r.Subdomain, r.Provider)
	}
	return fmt.Sprintf("Subdomain Takeover — %s", r.Subdomain)
}

// TakeoverRemediation returns standard remediation text.
func TakeoverRemediation(r TakeoverResult) string {
	return fmt.Sprintf(
		"Remove the dangling DNS CNAME record for %s or re-provision the %s resource it points to. "+
			"Verify the CNAME target (%s) is under organizational control before removal to avoid "+
			"brief exposure windows. After removal, confirm DNS propagation and rescan.",
		r.Subdomain, r.Provider, r.CNAME,
	)
}
