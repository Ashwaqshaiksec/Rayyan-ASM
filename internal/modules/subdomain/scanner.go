package subdomain

import (
	"context"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"strings"
	"sync"
	"time"

	"go.uber.org/zap"
)

// Result holds a confirmed subdomain with resolved IPs.
type Result struct {
	FQDN      string
	Domain    string
	IPs       []string
	Source    string // wordlist, crtsh, hackertarget
	ScannedAt time.Time
}

type Scanner struct {
	log         *zap.SugaredLogger
	resolver    *net.Resolver
	client      *http.Client
	crtshClient *http.Client
}

func NewScanner(log *zap.SugaredLogger) *Scanner {
	return &Scanner{
		log:      log,
		resolver: &net.Resolver{PreferGo: true},
		client: &http.Client{
			Timeout: 15 * time.Second,
		},
		// crt.sh is a free, single-maintainer service that is frequently
		// slow (20-60s+ for domains with heavy certificate history) or
		// briefly rate-limits/errors under load. The general 15s client
		// used for HackerTarget is far too short for it, which made
		// crt.sh silently fail on most real-world domains even though
		// the query logic itself was correct. Give it its own client
		// with a longer timeout; retryWithBackoff (below) handles the
		// transient-failure case on top of this.
		crtshClient: &http.Client{
			Timeout: 45 * time.Second,
		},
	}
}

type ScanOptions struct {
	Domain          string
	Wordlist        []string // nil = use built-in common wordlist
	Workers         int
	UseCRTSH        bool // query crt.sh certificate transparency logs
	UseHackerTarget bool // query hackertarget.com passive DNS
	ResolveDNS      bool // confirm found subdomains resolve
}

// Scan enumerates subdomains via wordlist brute-force and/or passive sources.
func (s *Scanner) Scan(ctx context.Context, opts ScanOptions) (<-chan Result, error) {
	if opts.Domain == "" {
		return nil, fmt.Errorf("domain is required")
	}

	// Defensive normalization: strip protocol/trailing-slash in case callers
	// pass a raw URL (e.g. "https://example.com").
	opts.Domain = strings.TrimSpace(opts.Domain)
	opts.Domain = strings.TrimPrefix(opts.Domain, "https://")
	opts.Domain = strings.TrimPrefix(opts.Domain, "http://")
	opts.Domain = strings.TrimSuffix(opts.Domain, "/")

	results := make(chan Result, 1000)

	wordlist := opts.Wordlist
	if len(wordlist) == 0 {
		wordlist = CommonWordlist
	}

	workers := opts.Workers
	if workers == 0 {
		workers = 50
	}

	go func() {
		defer close(results)

		var wg sync.WaitGroup
		seen := &sync.Map{}

		emit := func(r Result) {
			if _, loaded := seen.LoadOrStore(r.FQDN, true); loaded {
				return
			}
			select {
			case results <- r:
			case <-ctx.Done():
			}
		}

		// 1. Passive: crt.sh
		if opts.UseCRTSH {
			wg.Add(1)
			go func() {
				defer wg.Done()
				found, err := s.queryCRTSH(ctx, opts.Domain)
				if err != nil {
					s.log.Warnw("crt.sh query failed", "domain", opts.Domain, "error", err)
					return
				}
				for _, fqdn := range found {
					r := Result{FQDN: fqdn, Domain: opts.Domain, Source: "crtsh", ScannedAt: time.Now()}
					if opts.ResolveDNS {
						ips, err := s.resolve(ctx, fqdn)
						if err != nil {
							continue // doesn't resolve, skip
						}
						r.IPs = ips
					}
					emit(r)
				}
			}()
		}

		// 2. Passive: HackerTarget
		if opts.UseHackerTarget {
			wg.Add(1)
			go func() {
				defer wg.Done()
				found, err := s.queryHackerTarget(ctx, opts.Domain)
				if err != nil {
					s.log.Warnw("hackertarget query failed", "domain", opts.Domain, "error", err)
					return
				}
				for _, fqdn := range found {
					r := Result{FQDN: fqdn, Domain: opts.Domain, Source: "hackertarget", ScannedAt: time.Now()}
					if opts.ResolveDNS {
						ips, err := s.resolve(ctx, fqdn)
						if err != nil {
							continue
						}
						r.IPs = ips
					}
					emit(r)
				}
			}()
		}

		// 3. Active: wordlist brute-force
		wg.Add(1)
		go func() {
			defer wg.Done()

			wordCh := make(chan string, workers*2)
			var bruteWg sync.WaitGroup

			for i := 0; i < workers; i++ {
				bruteWg.Add(1)
				go func() {
					defer bruteWg.Done()
					for word := range wordCh {
						select {
						case <-ctx.Done():
							return
						default:
						}
						fqdn := word + "." + opts.Domain
						ips, err := s.resolve(ctx, fqdn)
						if err != nil {
							continue
						}
						emit(Result{
							FQDN:      fqdn,
							Domain:    opts.Domain,
							IPs:       ips,
							Source:    "wordlist",
							ScannedAt: time.Now(),
						})
					}
				}()
			}

			for _, word := range wordlist {
				select {
				case <-ctx.Done():
					goto bruteClose
				case wordCh <- word:
				}
			}
		bruteClose:
			close(wordCh)
			bruteWg.Wait()
		}()

		wg.Wait()
	}()

	return results, nil
}

// queryCRTSH queries crt.sh for certificate transparency records.
//
// crt.sh is notably slower and less reliable than HackerTarget: large
// domains routinely take 20-60s to return, and it occasionally serves a
// plain-text rate-limit/error page instead of JSON when under load. Both
// failure modes previously surfaced as a silent "crt.sh query failed"
// warning with no visible effect other than crt.sh results simply never
// showing up. This is now retried with backoff on transient failures
// (timeouts, 5xx, malformed JSON) before giving up.
func (s *Scanner) queryCRTSH(ctx context.Context, domain string) ([]string, error) {
	const maxAttempts = 3
	var lastErr error

	for attempt := 1; attempt <= maxAttempts; attempt++ {
		results, err := s.queryCRTSHOnce(ctx, domain)
		if err == nil {
			return results, nil
		}
		lastErr = err

		if attempt < maxAttempts {
			backoff := time.Duration(attempt) * 3 * time.Second
			select {
			case <-ctx.Done():
				return nil, ctx.Err()
			case <-time.After(backoff):
			}
		}
	}
	return nil, fmt.Errorf("crt.sh failed after %d attempts: %w", maxAttempts, lastErr)
}

// queryCRTSHOnce performs a single crt.sh request/decode attempt.
func (s *Scanner) queryCRTSHOnce(ctx context.Context, domain string) ([]string, error) {
	url := fmt.Sprintf("https://crt.sh/?q=%%.%s&output=json", domain)
	req, err := http.NewRequestWithContext(ctx, "GET", url, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("User-Agent", "RayyanASM/1.0")

	resp, err := s.crtshClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("crt.sh request failed: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("crt.sh returned status %d (likely rate-limited or under load)", resp.StatusCode)
	}

	var entries []struct {
		CommonName string `json:"common_name"`
		NameValue  string `json:"name_value"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&entries); err != nil {
		// crt.sh sometimes serves an HTML/plain-text error page (e.g. a
		// rate-limit notice) with a 200 status instead of JSON, which
		// fails decode rather than the status check above.
		return nil, fmt.Errorf("decoding crt.sh response (may be rate-limited): %w", err)
	}

	seen := make(map[string]bool)
	var results []string
	for _, e := range entries {
		for _, name := range []string{e.CommonName, e.NameValue} {
			// name_value can be multi-line
			for _, n := range strings.Split(name, "\n") {
				n = strings.TrimSpace(strings.ToLower(n))
				n = strings.TrimPrefix(n, "*.")
				if n == "" || !strings.HasSuffix(n, "."+domain) {
					continue
				}
				if !seen[n] {
					seen[n] = true
					results = append(results, n)
				}
			}
		}
	}
	return results, nil
}

// queryHackerTarget queries hackertarget.com passive DNS API (free tier).
func (s *Scanner) queryHackerTarget(ctx context.Context, domain string) ([]string, error) {
	url := fmt.Sprintf("https://api.hackertarget.com/hostsearch/?q=%s", domain)
	req, err := http.NewRequestWithContext(ctx, "GET", url, nil)
	if err != nil {
		return nil, err
	}

	resp, err := s.client.Do(req)
	if err != nil {
		return nil, err
	}
	defer func() { _ = resp.Body.Close() }()

	var buf strings.Builder
	buf.Grow(4096)
	b := make([]byte, 4096)
	for {
		n, err := resp.Body.Read(b)
		if n > 0 {
			_, _ = buf.Write(b[:n])
		}
		if err != nil {
			break
		}
		if buf.Len() > 512*1024 {
			break // safety cap
		}
	}

	body := buf.String()
	if strings.HasPrefix(body, "error") || strings.HasPrefix(body, "API") {
		return nil, fmt.Errorf("hackertarget: %s", strings.TrimSpace(body))
	}

	seen := make(map[string]bool)
	var results []string
	for _, line := range strings.Split(body, "\n") {
		parts := strings.SplitN(line, ",", 2)
		if len(parts) < 1 {
			continue
		}
		fqdn := strings.ToLower(strings.TrimSpace(parts[0]))
		if fqdn == "" || !strings.HasSuffix(fqdn, "."+domain) {
			continue
		}
		if !seen[fqdn] {
			seen[fqdn] = true
			results = append(results, fqdn)
		}
	}
	return results, nil
}

// resolve returns IPs for a hostname, or an error if it doesn't resolve.
func (s *Scanner) resolve(ctx context.Context, fqdn string) ([]string, error) {
	resolveCtx, cancel := context.WithTimeout(ctx, 3*time.Second)
	defer cancel()
	addrs, err := s.resolver.LookupHost(resolveCtx, fqdn)
	if err != nil {
		return nil, err
	}
	return addrs, nil
}

// ~200 highest-value subdomains from real-world enumeration data.

var CommonWordlist = []string{
	"www", "mail", "ftp", "smtp", "pop", "ns1", "ns2", "webmail", "admin",
	"secure", "vpn", "m", "shop", "blog", "dev", "staging", "api", "portal",
	"remote", "server", "mx", "email", "cdn", "cloud", "git", "gitlab",
	"github", "jira", "confluence", "wiki", "docs", "help", "support",
	"status", "monitor", "app", "apps", "test", "qa", "uat", "prod",
	"production", "development", "internal", "intranet", "extranet",
	"web", "web1", "web2", "www1", "www2", "ns", "dns", "dns1", "dns2",
	"ldap", "sso", "auth", "login", "accounts", "my", "dashboard",
	"panel", "cpanel", "whm", "plesk", "manage", "management",
	"download", "downloads", "upload", "uploads", "static", "assets",
	"media", "img", "images", "video", "videos", "files", "storage",
	"backup", "backups", "archive", "old", "new", "legacy",
	"db", "database", "mysql", "postgres", "redis", "mongo",
	"elastic", "kibana", "grafana", "prometheus", "jenkins", "ci",
	"deploy", "k8s", "kubernetes", "docker", "registry", "hub",
	"proxy", "gateway", "lb", "loadbalancer", "haproxy", "nginx",
	"dev1", "dev2", "staging1", "staging2", "uat1",
	"beta", "alpha", "demo", "preview", "sandbox",
	"api2", "api-v2", "v1", "v2", "v3",
	"mobile", "ios", "android",
	"office", "corp", "corporate", "hr", "finance", "marketing",
	"news", "events", "partner", "partners", "affiliates",
	"forum", "community", "chat", "irc", "slack",
	"ticket", "tickets", "helpdesk", "desk",
	"smtp1", "smtp2", "mail1", "mail2", "mx1", "mx2",
	"imap", "pop3", "exchange", "owa", "outlook",
	"build", "cd", "pipeline",
	"vault", "secret", "key", "cert",
	"metrics", "logs", "logging", "trace", "tracing",
}
