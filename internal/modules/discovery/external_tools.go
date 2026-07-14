package discovery

// External Tool Integration: subfinder and amass
//
// Unlike the other providers in providers.go (crt.sh, Wayback, bgp.tools,
// ip-api.com), which are plain HTTP calls this package implements natively,
// subfinder (ProjectDiscovery) and amass (OWASP) are themselves aggregators
// that each fan out to 20-30+ passive sources (VirusTotal, Shodan, Censys,
// SecurityTrails, ThreatCrowd, and more), many of which need paid API keys
// to be useful. Reimplementing all of those natively is a large, ongoing
// maintenance surface; shelling out to the actual tools gets that coverage
// for free and stays current as they add sources.
//
// Both are strictly optional and off by default (Options.UseSubfinder /
// Options.UseAmass): if the binary isn't on PATH, the run logs one info
// line and continues exactly as if the source were disabled — a missing
// binary is never a hard failure for the discovery job.

import (
	"bufio"
	"context"
	"fmt"
	"os/exec"
	"strings"
	"time"

	"go.uber.org/zap"
)

// externalToolTimeout bounds how long a single subfinder/amass subprocess
// is allowed to run before being killed, independent of the parent job's
// overall context deadline. Both tools can otherwise run indefinitely
// against a domain with a huge footprint.
const externalToolTimeout = 3 * time.Minute

// runSubfinder shells out to `subfinder -d <domain> -silent` and returns
// one hostname per discovered line. Requires subfinder to be installed and
// on PATH (https://github.com/projectdiscovery/subfinder). If the binary
// isn't found, this is a no-op (nil, nil) — not an error — since the
// source is opt-in.
func runSubfinder(ctx context.Context, domain string, log *zap.SugaredLogger) ([]string, error) {
	path, err := exec.LookPath("subfinder")
	if err != nil {
		if log != nil {
			log.Infow("discovery: subfinder not found on PATH, skipping (optional external source)", "domain", domain)
		}
		return nil, nil
	}

	cctx, cancel := context.WithTimeout(ctx, externalToolTimeout)
	defer cancel()

	// -silent: hostnames only, no banner/stats noise on stdout.
	// -timeout: subfinder's own per-source timeout budget, in seconds.
	cmd := exec.CommandContext(cctx, path, "-d", domain, "-silent", "-timeout", "30")
	return runHostnameTool(cmd, domain, "subfinder", log)
}

// runAmass shells out to `amass enum -passive -d <domain>` and returns one
// hostname per discovered line. Requires amass to be installed and on PATH
// (https://github.com/owasp-amass/amass). Passive mode only — no active
// DNS brute force or zone walking from amass itself, since the engine
// already does its own brute force/permutation pass; this call is purely
// for amass's aggregated passive source coverage. If the binary isn't
// found, this is a no-op (nil, nil), same as runSubfinder.
func runAmass(ctx context.Context, domain string, log *zap.SugaredLogger) ([]string, error) {
	path, err := exec.LookPath("amass")
	if err != nil {
		if log != nil {
			log.Infow("discovery: amass not found on PATH, skipping (optional external source)", "domain", domain)
		}
		return nil, nil
	}

	cctx, cancel := context.WithTimeout(ctx, externalToolTimeout)
	defer cancel()

	// -passive: no active recon (no DNS brute force / zone walking from
	// amass itself — the engine already does its own). -timeout is in
	// minutes for amass, unlike subfinder's seconds.
	cmd := exec.CommandContext(cctx, path, "enum", "-passive", "-d", domain, "-timeout", "3")
	return runHostnameTool(cmd, domain, "amass", log)
}

// runHostnameTool runs cmd, expecting one hostname per line on stdout
// (both subfinder -silent and amass enum default output follow this
// format), and returns the filtered, deduplicated set of hostnames that
// actually belong to domain. Non-zero exit or a context deadline are
// logged and treated as "this source produced nothing this run" rather
// than failing the whole discovery job — same graceful-degradation
// philosophy as the crt.sh/Wayback/ASN providers.
func runHostnameTool(cmd *exec.Cmd, domain, toolName string, log *zap.SugaredLogger) ([]string, error) {
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		return nil, fmt.Errorf("%s: creating stdout pipe: %w", toolName, err)
	}
	if err := cmd.Start(); err != nil {
		if log != nil {
			log.Warnw("discovery: external tool failed to start, skipping", "tool", toolName, "domain", domain, "error", err)
		}
		return nil, nil
	}

	seen := make(map[string]bool)
	var hosts []string
	scanner := bufio.NewScanner(stdout)
	// subfinder/amass output is one hostname per line, but guard against
	// unexpectedly long lines rather than letting bufio.Scanner panic.
	scanner.Buffer(make([]byte, 0, 64*1024), 1024*1024)
	for scanner.Scan() {
		line := strings.TrimSpace(strings.ToLower(scanner.Text()))
		if line == "" || !strings.HasSuffix(line, "."+domain) && line != domain {
			continue
		}
		if !seen[line] {
			seen[line] = true
			hosts = append(hosts, line)
		}
	}

	// Wait() after fully draining stdout, or large outputs can deadlock
	// on a full pipe buffer.
	waitErr := cmd.Wait()
	if waitErr != nil && log != nil {
		// Non-fatal: a non-zero exit from these tools frequently just
		// means "no results for this target" or a transient upstream
		// source failure inside the tool itself, not a real error.
		log.Infow("discovery: external tool exited non-zero (treated as no additional results)",
			"tool", toolName, "domain", domain, "error", waitErr, "hosts_found", len(hosts))
	}

	return hosts, nil
}
