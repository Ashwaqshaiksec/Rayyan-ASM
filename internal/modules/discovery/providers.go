// Package discovery implements the External Attack Surface Discovery
// Engine: a multi-stage pipeline that starts from a small set of seed
// domains and recursively expands into subdomains, certificates, ASN/IP
// ranges, DNS records, open ports, and services — continuously maintaining
// a live attack-surface inventory in the existing asset tables.
package discovery

import (
	"context"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"go.uber.org/zap"
)

// httpClient is shared across providers that hit public HTTP APIs
// (bgp.tools, RDAP, ip-api.com). Kept short-timeout since these
// calls run inside a larger pipeline with many domains in flight.
var httpClient = &http.Client{Timeout: 20 * time.Second}

// crtshClient is used only for crt.sh. crt.sh is a free, single-maintainer
// service that is frequently slow (20-60s+ for domains with heavy
// certificate history) or briefly errors/rate-limits under load. The
// general 20s httpClient above is too short for it in practice, which
// made crt.sh silently fail on most real-world domains even though the
// query logic itself was correct. queryCTLogs also wraps calls in
// retryWithBackoff (see resilience.go) to ride out transient failures.
var crtshClient = &http.Client{Timeout: 45 * time.Second}

// InitHTTPClient replaces the shared httpClient with one that routes through
// the given proxy URL (e.g. "http://proxy:8080" or "socks5://proxy:1080").
// Call this once during server startup if a proxy is configured. Passing an
// empty string is a no-op so callers do not need to guard the call.
func InitHTTPClient(proxyURL string) {
	if proxyURL == "" {
		return
	}
	u, err := url.Parse(proxyURL)
	if err != nil {
		return
	}
	t := http.DefaultTransport.(*http.Transport).Clone()
	t.Proxy = http.ProxyURL(u)
	httpClient = &http.Client{Timeout: 20 * time.Second, Transport: t}
	crtshClient = &http.Client{Timeout: 45 * time.Second, Transport: t}
}

// Certificate Transparency / Certificate Discovery

// CTEntry is one raw row returned by crt.sh.
type CTEntry struct {
	NameValue string
	NotBefore time.Time
	NotAfter  time.Time
	IssuerCN  string
}

// queryCTLogs queries crt.sh certificate transparency logs for every
// hostname (including historical / expired certs) ever issued under the
// given domain. This is both the "Certificate Transparency Logs" and
// "Historical Certificate Collection" source from the discovery brief —
// crt.sh's index includes long-expired certificates by default.
//
// crt.sh is slow and occasionally rate-limits, so the request is retried
// with backoff (3 attempts) on transient failures before giving up.
func queryCTLogs(ctx context.Context, domain string, log *zap.SugaredLogger) ([]CTEntry, error) {
	var entries []CTEntry
	err := retryWithBackoff(ctx, 3, 3*time.Second, func() error {
		e, err := queryCTLogsOnce(ctx, domain)
		if err != nil {
			if log != nil {
				log.Debugw("crt.sh attempt failed, will retry if attempts remain", "domain", domain, "error", err)
			}
			return err
		}
		entries = e
		return nil
	})
	if err != nil {
		return nil, err
	}
	return entries, nil
}

// queryCTLogsOnce performs a single crt.sh request/decode attempt.
func queryCTLogsOnce(ctx context.Context, domain string) ([]CTEntry, error) {
	url := fmt.Sprintf("https://crt.sh/?q=%%.%s&output=json", domain)
	req, err := http.NewRequestWithContext(ctx, "GET", url, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("User-Agent", "RayyanASM-Discovery/1.0")

	resp, err := crtshClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("crt.sh request failed: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("crt.sh returned status %d (likely rate-limited or under load)", resp.StatusCode)
	}

	var raw []struct {
		NameValue string `json:"name_value"`
		NotBefore string `json:"not_before"`
		NotAfter  string `json:"not_after"`
		IssuerCN  string `json:"issuer_name"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&raw); err != nil {
		// crt.sh sometimes serves an HTML/plain-text error page (e.g. a
		// rate-limit notice) with a 200 status instead of JSON, which
		// fails decode rather than the status check above.
		return nil, fmt.Errorf("decoding crt.sh response (may be rate-limited): %w", err)
	}

	entries := make([]CTEntry, 0, len(raw))
	for _, r := range raw {
		nb, _ := time.Parse("2006-01-02T15:04:05", r.NotBefore)
		na, _ := time.Parse("2006-01-02T15:04:05", r.NotAfter)
		entries = append(entries, CTEntry{
			NameValue: r.NameValue,
			NotBefore: nb,
			NotAfter:  na,
			IssuerCN:  r.IssuerCN,
		})
	}
	return entries, nil
}

// hostnamesFromCT extracts a deduplicated, normalized set of hostnames
// (with wildcard SAN expansion) belonging to `domain` from raw CT entries.
// Returns the bare hostname set plus a map noting which entries had
// wildcard SANs, for wildcard certificate expansion downstream.
func hostnamesFromCT(entries []CTEntry, domain string) (hosts []string, wildcards []string) {
	seenHost := make(map[string]bool)
	seenWild := make(map[string]bool)

	for _, e := range entries {
		for _, line := range strings.Split(e.NameValue, "\n") {
			name := strings.ToLower(strings.TrimSpace(line))
			if name == "" {
				continue
			}
			isWildcard := strings.HasPrefix(name, "*.")
			bare := strings.TrimPrefix(name, "*.")
			if bare == "" || !strings.HasSuffix(bare, "."+domain) && bare != domain {
				continue
			}
			if isWildcard {
				if !seenWild[bare] {
					seenWild[bare] = true
					wildcards = append(wildcards, bare)
				}
				continue
			}
			if !seenHost[name] {
				seenHost[name] = true
				hosts = append(hosts, name)
			}
		}
	}
	sort.Strings(hosts)
	sort.Strings(wildcards)
	return hosts, wildcards
}

// Wayback Machine URL Discovery (second passive source beyond CT logs)

// waybackBaseURL is the Wayback Machine CDX API base, overridable in
// tests so queryWaybackURLs can be exercised against an httptest.Server
// instead of the real internet.archive.org — no network needed for the
// unit test (see TestQueryWaybackURLs_HermeticHTTPServer in
// providers_test.go). Production code never reassigns this.
var waybackBaseURL = "https://web.archive.org"

// queryWaybackURLs queries the Internet Archive's Wayback Machine CDX API
// for every URL ever archived under "*.domain", as a passive subdomain
// source independent of (and complementary to) certificate transparency:
// it surfaces hosts that were once live and crawled/archived but may never
// have had a logged TLS certificate (e.g. plain-HTTP-only legacy hosts).
//
// Like every other external lookup in this package, this is best-effort:
// callers are expected to log and continue on failure rather than treat it
// as fatal to the discovery run (see processHop's graceful-degradation
// pattern, already used for ASN/CIDR/GeoIP).
func queryWaybackURLs(ctx context.Context, domain string, log *zap.SugaredLogger) ([]string, error) {
	reqURL := fmt.Sprintf(
		"%s/cdx/search/cdx?url=*.%s&output=json&fl=original&collapse=urlkey&limit=10000",
		waybackBaseURL, domain,
	)
	req, err := http.NewRequestWithContext(ctx, "GET", reqURL, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("User-Agent", "RayyanASM-Discovery/1.0")

	resp, err := httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("wayback request failed: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("wayback returned status %d", resp.StatusCode)
	}

	// The CDX API returns a JSON array of arrays: a ["original"] header
	// row, then one ["http://host/path"] row per archived capture.
	var rows [][]string
	if err := json.NewDecoder(resp.Body).Decode(&rows); err != nil {
		return nil, fmt.Errorf("decoding wayback response: %w", err)
	}

	return hostnamesFromWaybackRows(rows, domain), nil
}

// hostnamesFromWaybackRows extracts a deduplicated, sorted set of in-scope
// hostnames from raw Wayback CDX rows (skipping the header row and anything
// outside the requested domain's scope).
func hostnamesFromWaybackRows(rows [][]string, domain string) []string {
	seen := make(map[string]bool)
	var hosts []string
	for i, row := range rows {
		if i == 0 || len(row) == 0 {
			continue // header row, e.g. ["original"]
		}
		raw := strings.TrimSpace(row[0])
		if raw == "" {
			continue
		}

		host := ""
		if u, err := url.Parse(raw); err == nil && u.Hostname() != "" {
			host = u.Hostname()
		} else if idx := strings.Index(raw, "/"); idx >= 0 {
			// Some captures lack a scheme; fall back to stripping the path.
			host = raw[:idx]
		} else {
			host = raw
		}

		host = strings.ToLower(strings.TrimSuffix(host, "."))
		if host == "" || (host != domain && !strings.HasSuffix(host, "."+domain)) {
			continue
		}
		if !seen[host] {
			seen[host] = true
			hosts = append(hosts, host)
		}
	}
	sort.Strings(hosts)
	return hosts
}

// FetchedCert is a parsed leaf certificate retrieved by directly dialing
// a live TLS service, used for SAN enumeration and risk indicators
// (expiry, self-signed, wildcard) on assets discovered via other sources.
type FetchedCert struct {
	Subject      string
	Issuer       string
	SANs         []string
	SerialNumber string
	NotBefore    time.Time
	NotAfter     time.Time
	Fingerprint  string
	IsWildcard   bool
	IsSelfSigned bool
	IsExpired    bool
	SignatureAlg string
	KeyAlg       string
	Version      int

	// TLSValid reports whether the certificate would pass standard OS/CA-pool
	// chain validation (the same check a browser or curl runs by default).
	// fetchLiveCert deliberately skips TLS verification on the initial probe
	// to ensure the cert can be retrieved and inspected regardless of chain
	// state, but also performs a separate standard-verification pass and
	// records the result here — turning "we ignore TLS errors" into "we
	// detect and flag broken TLS as a finding," which is the correct
	// ASM-aware behavior. See flagCertificate in risk.go for how this is
	// surfaced as a risk flag.
	TLSValid           bool
	TLSValidationError string
}

// fetchLiveCert dials host:port directly (no HTTP) and returns the leaf
// certificate presented during the TLS handshake. Used for SSL Certificate
// discovery and SAN enumeration against arbitrary ports, not just 443/HTTP.
//
// The initial connection always sets InsecureSkipVerify:true so the cert can
// be retrieved and examined regardless of chain/expiry/hostname state. A
// second, separate TLS dial is then performed with standard OS/CA-pool
// verification to capture whether the cert *would* pass a browser-grade
// check — recorded on FetchedCert.TLSValid / .TLSValidationError. This
// turns "we ignore TLS errors" into "we detect and flag broken TLS as a
// finding", which is the ASM-correct behavior.
//
// Both dials go through tls.Dialer.DialContext rather than the older
// tls.DialWithDialer(&net.Dialer{Timeout: ...}, ...) pattern: DialContext
// honors the caller's ctx (deadline AND cancellation) in addition to its
// own fixed timeout, so a caller bounding overall work via context.With-
// Timeout — as the discovery engine's per-run/per-hop context already
// does — actually shortens these dials instead of each one independently
// running its own multi-second timeout regardless of how much time the
// run has left. Previously ctx was accepted but never passed to either
// dial, so cancelling/timing out the run didn't stop calls already inside
// fetchLiveCert, and a caller with a shorter remaining deadline still
// waited the full 8s/5s per host.
func fetchLiveCert(ctx context.Context, host string, port int) (*FetchedCert, error) {
	dialer := &tls.Dialer{
		NetDialer: &net.Dialer{Timeout: 8 * time.Second},
		Config: &tls.Config{
			InsecureSkipVerify: true, // intentional: inspect cert, not validate trust
			ServerName:         host,
		},
	}
	addr := net.JoinHostPort(host, strconv.Itoa(port))

	// Pass 1: insecure – retrieve the cert regardless of validity. Bound
	// by whichever is shorter: the dialer's own 8s timeout or ctx's
	// remaining deadline/cancellation.
	dialCtx, cancelDial := context.WithTimeout(ctx, 8*time.Second)
	defer cancelDial()
	rawConn, err := dialer.DialContext(dialCtx, "tcp", addr)
	if err != nil {
		return nil, err
	}
	conn := rawConn.(*tls.Conn)
	defer func() { _ = conn.Close() }()

	_ = conn.SetDeadline(time.Now().Add(5 * time.Second))
	state := conn.ConnectionState()
	if len(state.PeerCertificates) == 0 {
		return nil, fmt.Errorf("no certificate presented by %s", addr)
	}

	cert := state.PeerCertificates[0]
	fp := sha256.Sum256(cert.Raw)

	fc := &FetchedCert{
		Subject:      cert.Subject.CommonName,
		Issuer:       cert.Issuer.CommonName,
		SerialNumber: cert.SerialNumber.String(),
		NotBefore:    cert.NotBefore,
		NotAfter:     cert.NotAfter,
		Fingerprint:  hex.EncodeToString(fp[:]),
		IsExpired:    time.Now().After(cert.NotAfter),
		IsSelfSigned: cert.IsCA && cert.Issuer.CommonName == cert.Subject.CommonName,
		SignatureAlg: cert.SignatureAlgorithm.String(),
		Version:      cert.Version,
	}
	fc.SANs = append(fc.SANs, cert.DNSNames...)
	for _, ip := range cert.IPAddresses {
		fc.SANs = append(fc.SANs, ip.String())
	}
	for _, san := range fc.SANs {
		if strings.HasPrefix(san, "*.") {
			fc.IsWildcard = true
			break
		}
	}
	switch cert.PublicKeyAlgorithm {
	case x509.RSA:
		fc.KeyAlg = "RSA"
	case x509.ECDSA:
		fc.KeyAlg = "ECDSA"
	case x509.Ed25519:
		fc.KeyAlg = "Ed25519"
	}

	// Pass 2: standard verification — short timeout, best-effort, non-fatal.
	// We use a separate dialer rather than re-using the already-open conn so
	// the OS TLS stack performs the full handshake + chain validation. A
	// failure here is a *finding* (surfaced via TLSValidationError), not an
	// error that prevents the cert record from being created.
	verifyCtx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	verifyDialer := &tls.Dialer{
		NetDialer: &net.Dialer{Timeout: 5 * time.Second},
		Config: &tls.Config{
			InsecureSkipVerify: false,
			ServerName:         host,
		},
	}
	verifyConn, verifyErr := verifyDialer.DialContext(verifyCtx, "tcp", addr)
	select {
	case <-verifyCtx.Done():
		fc.TLSValidationError = "verification timed out"
	default:
		if verifyErr != nil {
			fc.TLSValidationError = verifyErr.Error()
		} else {
			fc.TLSValid = true
			_ = verifyConn.Close()
		}
	}

	return fc, nil
}

// DNS Brute Force / Reverse DNS

var dnsResolver = &net.Resolver{PreferGo: true}

// Resolver abstracts the two DNS operations the discovery engine calls
// during subdomain brute-force / permutation expansion and reverse-DNS
// enrichment: forward A/AAAA lookups and PTR lookups. Production code
// always uses defaultResolver (a thin wrapper over Go's net.Resolver);
// tests inject a mock implementation so the bench/scale test can run
// fully hermetically — no real DNS, no network latency, no environment-
// dependent timing — while still exercising the exact same engine code
// path (runState.resolveHost / runState.reverseDNSLookup) that production
// uses, rather than a separate stub branch.
type Resolver interface {
	// ResolveHost resolves a hostname to its A/AAAA addresses.
	ResolveHost(ctx context.Context, fqdn string) ([]string, error)
	// ReverseDNSLookup performs a PTR lookup for an IP and returns the
	// lower-cased, trailing-dot-stripped hostnames it points to.
	ReverseDNSLookup(ctx context.Context, ip string) ([]string, error)
}

// defaultResolver is the production Resolver: a real DNS lookup through
// Go's net.Resolver, each call timeout-bounded so a single slow/unreachable
// name can't stall the worker pool that calls it.
type defaultResolver struct{}

func (defaultResolver) ResolveHost(ctx context.Context, fqdn string) ([]string, error) {
	rctx, cancel := context.WithTimeout(ctx, 4*time.Second)
	defer cancel()
	addrs, err := dnsResolver.LookupHost(rctx, fqdn)
	if err != nil {
		return nil, err
	}
	return addrs, nil
}

func (defaultResolver) ReverseDNSLookup(ctx context.Context, ip string) ([]string, error) {
	rctx, cancel := context.WithTimeout(ctx, 4*time.Second)
	defer cancel()
	names, err := dnsResolver.LookupAddr(rctx, ip)
	if err != nil {
		return nil, err
	}
	out := make([]string, 0, len(names))
	for _, n := range names {
		out = append(out, strings.ToLower(strings.TrimSuffix(n, ".")))
	}
	return out, nil
}

// dnsRecord mirrors the shape needed to populate models.DNSRecord without
// importing the api/db layer into this package.
type dnsRecord struct {
	Type     string
	Value    string
	TTL      int
	Priority int
}

// queryDNSIntelligence resolves A, AAAA, CNAME, MX, TXT, and NS records
// for a domain or subdomain using Go's net package (works against the
// system/Go resolver — no external binary required).
func queryDNSIntelligence(ctx context.Context, name string) []dnsRecord {
	var out []dnsRecord
	rctx, cancel := context.WithTimeout(ctx, 6*time.Second)
	defer cancel()

	if ips, err := dnsResolver.LookupIP(rctx, "ip4", name); err == nil {
		for _, ip := range ips {
			out = append(out, dnsRecord{Type: "A", Value: ip.String()})
		}
	}
	if ips, err := dnsResolver.LookupIP(rctx, "ip6", name); err == nil {
		for _, ip := range ips {
			out = append(out, dnsRecord{Type: "AAAA", Value: ip.String()})
		}
	}
	if cname, err := dnsResolver.LookupCNAME(rctx, name); err == nil {
		cname = strings.TrimSuffix(cname, ".")
		if cname != "" && cname != name {
			out = append(out, dnsRecord{Type: "CNAME", Value: cname})
		}
	}
	if mxs, err := dnsResolver.LookupMX(rctx, name); err == nil {
		for _, mx := range mxs {
			out = append(out, dnsRecord{
				Type:     "MX",
				Value:    strings.TrimSuffix(mx.Host, "."),
				Priority: int(mx.Pref),
			})
		}
	}
	if txts, err := dnsResolver.LookupTXT(rctx, name); err == nil {
		for _, txt := range txts {
			out = append(out, dnsRecord{Type: "TXT", Value: txt})
		}
	}
	if nss, err := dnsResolver.LookupNS(rctx, name); err == nil {
		for _, ns := range nss {
			out = append(out, dnsRecord{Type: "NS", Value: strings.TrimSuffix(ns.Host, ".")})
		}
	}
	return out
}

// ASN / CIDR Discovery

// asnInfo describes one IP's autonomous-system ownership, resolved via
// Team Cymru's IP-to-ASN DNS service — a single UDP-style DNS query, no
// API key, and reliable for "ASN Identification" / "IP Ownership
// Correlation" against arbitrary discovered IPs.
type asnInfo struct {
	ASN     string
	ASNOrg  string
	CIDR    string
	Country string
}

// lookupASNForIP resolves ASN ownership for a single IP using Cymru's
// origin lookup (the "<reversed-ip>.origin.asn.cymru.com" TXT convention).
// Wrapped with retry-with-backoff, a per-run TTL cache, and a circuit
// breaker (see resilience.go) since this is an external dependency called
// once per newly-discovered host. ps may be nil (falls back to a single
// attempt, no caching/short-circuiting) for callers outside a run context.
func lookupASNForIP(ctx context.Context, ip string, ps *providerState, log *zap.SugaredLogger) (*asnInfo, error) {
	if ps != nil {
		if cached, ok := ps.asnCache.Get(ip); ok {
			info, _ := cached.(*asnInfo)
			return info, nil
		}
		if !ps.asnBreaker.Allow() {
			return nil, fmt.Errorf("cymru ASN lookup circuit open, skipping %s", ip)
		}
	}

	var info *asnInfo
	err := retryWithBackoff(ctx, 3, 150*time.Millisecond, func() error {
		var lookupErr error
		info, lookupErr = lookupASNForIPOnce(ctx, ip)
		return lookupErr
	})

	if ps != nil {
		if err == nil {
			ps.asnBreaker.RecordSuccess()
			ps.asnCache.Set(ip, info)
		} else {
			ps.asnBreaker.RecordFailure(log)
		}
	}
	return info, err
}

// ASNInfo is the exported mirror of asnInfo for callers outside this
// package that need a single-shot ASN lookup without the discovery
// engine's run-scoped provider caching/circuit-breaker (see
// LookupASNForIP below).
type ASNInfo struct {
	ASN     string
	ASNOrg  string
	CIDR    string
	Country string
}

// LookupASNForIP is a single-attempt ASN lookup exported for callers that
// have no discovery-run providerState (e.g. the toolrunner workflow
// pipeline's nmap/naabu stage, which discovers hosts outside the
// discovery engine entirely and so has no other path to ASN enrichment).
func LookupASNForIP(ctx context.Context, ip string) (*ASNInfo, error) {
	info, err := lookupASNForIPOnce(ctx, ip)
	if err != nil {
		return nil, err
	}
	return &ASNInfo{ASN: info.ASN, ASNOrg: info.ASNOrg, CIDR: info.CIDR, Country: info.Country}, nil
}

// ExpandASNPrefixes is a single-attempt bgp.tools CIDR expansion, exported
// for the same reason as LookupASNForIP.
func ExpandASNPrefixes(ctx context.Context, asnNum string) ([]string, string) {
	return expandASNPrefixesOnce(ctx, asnNum)
}

// lookupASNForIPOnce is the single-attempt Cymru origin lookup that
// lookupASNForIP wraps with retry/cache/circuit-breaker behavior.
func lookupASNForIPOnce(ctx context.Context, ip string) (*asnInfo, error) {
	parsed := net.ParseIP(ip)
	if parsed == nil || parsed.To4() == nil {
		return nil, fmt.Errorf("only IPv4 supported for cymru lookup: %s", ip)
	}
	octets := strings.Split(parsed.To4().String(), ".")
	if len(octets) != 4 {
		return nil, fmt.Errorf("malformed IPv4: %s", ip)
	}
	reversed := fmt.Sprintf("%s.%s.%s.%s", octets[3], octets[2], octets[1], octets[0])
	query := reversed + ".origin.asn.cymru.com"

	rctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	txts, err := dnsResolver.LookupTXT(rctx, query)
	if err != nil || len(txts) == 0 {
		return nil, fmt.Errorf("cymru lookup failed for %s: %w", ip, err)
	}

	// Format: "ASN | CIDR | Country | Registry | Allocated"
	fields := strings.Split(txts[0], "|")
	for i := range fields {
		fields[i] = strings.TrimSpace(fields[i])
	}
	info := &asnInfo{}
	if len(fields) > 0 {
		info.ASN = "AS" + fields[0]
	}
	if len(fields) > 1 {
		info.CIDR = fields[1]
	}
	if len(fields) > 2 {
		info.Country = fields[2]
	}

	// A second query against asn.cymru.com resolves the ASN's org name.
	if info.ASN != "" {
		nameQuery := strings.TrimPrefix(info.ASN, "AS") + ".asn.cymru.com"
		if nameTxts, err := dnsResolver.LookupTXT(rctx, nameQuery); err == nil && len(nameTxts) > 0 {
			nameFields := strings.Split(nameTxts[0], "|")
			if len(nameFields) > 4 {
				info.ASNOrg = strings.TrimSpace(nameFields[4])
			}
		}
	}
	return info, nil
}

// bgpEntry is one row of bgp.tools' free, keyless prefix table — used to
// expand a known ASN into its full set of CIDR ranges ("ASN Prefix
// Enumeration" / "CIDR Collection").
type bgpEntry struct {
	CIDR    string `json:"CIDR"`
	ASNOrg  string `json:"Description"`
	Country string `json:"CC"`
}

// cidrExpansion bundles expandASNPrefixes' two return values so it can be
// stored as a single cache entry.
type cidrExpansion struct {
	CIDRs  []string
	ASNOrg string
}

// expandASNPrefixes queries bgp.tools for every CIDR block originated by
// the given ASN (numeric, no "AS" prefix). Falls back to an empty slice
// (not an error) if the lookup fails — ASN expansion is best-effort
// enrichment, not a hard dependency for the rest of the pipeline. Wrapped
// with retry-with-backoff, a per-run TTL cache keyed by ASN (many hosts in
// a run often share one ASN), and a circuit breaker. ps may be nil for
// callers outside a run context.
func expandASNPrefixes(ctx context.Context, asnNum string, ps *providerState, log *zap.SugaredLogger) ([]string, string) {
	if ps != nil {
		if cached, ok := ps.cidrCache.Get(asnNum); ok {
			if exp, ok := cached.(cidrExpansion); ok {
				return exp.CIDRs, exp.ASNOrg
			}
		}
		if !ps.cidrBreaker.Allow() {
			return nil, ""
		}
	}

	var cidrs []string
	var asnOrg string
	err := retryWithBackoff(ctx, 3, 150*time.Millisecond, func() error {
		c, org := expandASNPrefixesOnce(ctx, asnNum)
		if len(c) == 0 {
			return fmt.Errorf("bgp.tools returned no prefixes for AS%s", asnNum)
		}
		cidrs, asnOrg = c, org
		return nil
	})

	if ps != nil {
		if err == nil {
			ps.cidrBreaker.RecordSuccess()
			ps.cidrCache.Set(asnNum, cidrExpansion{CIDRs: cidrs, ASNOrg: asnOrg})
		} else {
			ps.cidrBreaker.RecordFailure(log)
		}
	}
	return cidrs, asnOrg
}

// expandASNPrefixesOnce is the single-attempt bgp.tools lookup that
// expandASNPrefixes wraps with retry/cache/circuit-breaker behavior.
func expandASNPrefixesOnce(ctx context.Context, asnNum string) ([]string, string) {
	url := fmt.Sprintf("https://bgp.tools/table.jsonl?origin=%s", asnNum)
	req, err := http.NewRequestWithContext(ctx, "GET", url, nil)
	if err != nil {
		return nil, ""
	}
	req.Header.Set("User-Agent", "RayyanASM-Discovery/1.0")

	resp, err := httpClient.Do(req)
	if err != nil {
		return nil, ""
	}
	defer func() { _ = resp.Body.Close() }()

	var cidrs []string
	asnOrg := ""
	decoder := json.NewDecoder(resp.Body)
	for {
		var entry bgpEntry
		if err := decoder.Decode(&entry); err != nil {
			break
		}
		if entry.CIDR == "" {
			continue
		}
		cidrs = append(cidrs, entry.CIDR)
		if asnOrg == "" && entry.ASNOrg != "" {
			asnOrg = entry.ASNOrg
		}
	}
	return cidrs, asnOrg
}

// Internet Exposure / Banner Discovery

// DefaultPorts are probed against every newly discovered host as part of
// "Open Port Enumeration" — kept intentionally compact since discovery
// runs frequently and recursively; a dedicated deep port scan remains
// available via the existing `port` scan module / "full" scan workflow.
var DefaultPorts = []int{21, 22, 25, 53, 80, 110, 143, 443, 465, 587, 993, 995,
	3306, 3389, 5432, 6379, 8000, 8080, 8443, 8888, 9000, 9200, 27017}

// probedService is one open-port finding from probePorts.
type probedService struct {
	Port     int
	Protocol string
	Banner   string
	TLS      bool
}

// probePorts performs a lightweight TCP connect scan against a host over
// a configurable port list with banner grabbing, the "Service Detection" /
// "Open Port Enumeration" discovery source. Ports are probed through a
// semaphore-bounded worker pool (concurrency, defaulting via
// portConcurrencyOrDefault) rather than one DialTimeout at a time, so the
// "top1000" and especially "full" (1-65535) port profiles complete in
// reasonable time instead of firing tens of thousands of sequential
// connect attempts. The engine separately parallelizes across hosts, so
// total in-flight sockets stays bounded by (hosts in flight) x concurrency.
func probePorts(ctx context.Context, host string, ports []int, concurrency int) []probedService {
	if len(ports) == 0 {
		ports = DefaultPorts
	}
	concurrency = portConcurrencyOrDefault(concurrency)
	concurrency = min(concurrency, len(ports))

	var mu sync.Mutex
	var found []probedService
	var wg sync.WaitGroup
	sem := make(chan struct{}, concurrency)

portLoop:
	for _, port := range ports {
		select {
		case <-ctx.Done():
			break portLoop
		default:
		}
		wg.Add(1)
		sem <- struct{}{}
		go func(port int) {
			defer wg.Done()
			defer func() { <-sem }()
			svc, ok := probeOnePort(ctx, host, port)
			if !ok {
				return
			}
			mu.Lock()
			found = append(found, svc)
			mu.Unlock()
		}(port)
	}
	wg.Wait()
	return found
}

// probeOnePort dials a single host:port with a short timeout, grabs a
// banner for non-TLS services, and reports whether the port was open.
func probeOnePort(ctx context.Context, host string, port int) (probedService, bool) {
	select {
	case <-ctx.Done():
		return probedService{}, false
	default:
	}
	addr := net.JoinHostPort(host, strconv.Itoa(port))
	conn, err := net.DialTimeout("tcp", addr, 800*time.Millisecond)
	if err != nil {
		return probedService{}, false
	}
	defer func() { _ = conn.Close() }()

	svc := probedService{Port: port, Protocol: "tcp"}
	svc.TLS = port == 443 || port == 8443 || port == 465 || port == 993 || port == 995
	if !svc.TLS {
		_ = conn.SetReadDeadline(time.Now().Add(500 * time.Millisecond))
		buf := make([]byte, 256)
		n, _ := conn.Read(buf)
		if n > 0 {
			svc.Banner = sanitizeBanner(buf[:n])
		}
	}
	return svc, true
}

// sanitizeBanner trims a raw banner read to a short, printable summary
// safe for storage and display.
func sanitizeBanner(b []byte) string {
	s := strings.Map(func(r rune) rune {
		if r < 32 || r > 126 {
			return -1
		}
		return r
	}, string(b))
	s = strings.TrimSpace(s)
	if len(s) > 200 {
		s = s[:200]
	}
	return s
}

// detectWebTitle does a lightweight HTTP(S) probe to grab the page title
// and status — used to flag admin panels / login pages / VPN portals
// among newly discovered web services, the "Web Application Detection"
// source plus an input to risk indicator flagging.
func detectWebTitle(ctx context.Context, scheme, host string, port int) (status int, title string, server string) {
	url := fmt.Sprintf("%s://%s:%d/", scheme, host, port)
	if (scheme == "http" && port == 80) || (scheme == "https" && port == 443) {
		url = fmt.Sprintf("%s://%s/", scheme, host)
	}
	req, err := http.NewRequestWithContext(ctx, "GET", url, nil)
	if err != nil {
		return 0, "", ""
	}
	req.Header.Set("User-Agent", "RayyanASM-Discovery/1.0")

	client := &http.Client{
		Timeout: 6 * time.Second,
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			if len(via) >= 3 {
				return http.ErrUseLastResponse
			}
			return nil
		},
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
		},
	}
	resp, err := client.Do(req)
	if err != nil {
		return 0, "", ""
	}
	defer func() { _ = resp.Body.Close() }()

	body := make([]byte, 8192)
	n, _ := io.ReadFull(resp.Body, body)
	body = body[:n]
	return resp.StatusCode, extractTitle(string(body)), resp.Header.Get("Server")
}

func extractTitle(html string) string {
	lower := strings.ToLower(html)
	start := strings.Index(lower, "<title>")
	if start == -1 {
		return ""
	}
	start += len("<title>")
	end := strings.Index(lower[start:], "</title>")
	if end == -1 {
		return ""
	}
	title := strings.TrimSpace(html[start : start+end])
	if len(title) > 200 {
		title = title[:200]
	}
	return title
}

// IP Geolocation (best-effort enrichment for newly discovered hosts)

type geoInfo struct {
	Country string
	City    string
	ISP     string
}

// lookupGeoIP enriches a discovered host with coarse geolocation via
// ip-api.com's free, keyless endpoint — mirrors the existing toolbox
// GeoIP handler's data source for consistency across the platform.
// Wrapped with retry-with-backoff, a per-run TTL cache, and a circuit
// breaker. ps may be nil for callers outside a run context.
func lookupGeoIP(ctx context.Context, ip string, ps *providerState, log *zap.SugaredLogger) *geoInfo {
	if ps != nil {
		if cached, ok := ps.geoCache.Get(ip); ok {
			geo, _ := cached.(*geoInfo)
			return geo
		}
		if !ps.geoBreaker.Allow() {
			return nil
		}
	}

	var geo *geoInfo
	err := retryWithBackoff(ctx, 3, 150*time.Millisecond, func() error {
		geo = lookupGeoIPOnce(ctx, ip)
		if geo == nil {
			return fmt.Errorf("ip-api geoip lookup failed for %s", ip)
		}
		return nil
	})

	if ps != nil {
		if err == nil {
			ps.geoBreaker.RecordSuccess()
			ps.geoCache.Set(ip, geo)
		} else {
			ps.geoBreaker.RecordFailure(log)
		}
	}
	return geo
}

// lookupGeoIPOnce is the single-attempt ip-api.com lookup that lookupGeoIP
// wraps with retry/cache/circuit-breaker behavior.
func lookupGeoIPOnce(ctx context.Context, ip string) *geoInfo {
	url := fmt.Sprintf("http://ip-api.com/json/%s?fields=status,country,city,isp", ip)
	req, err := http.NewRequestWithContext(ctx, "GET", url, nil)
	if err != nil {
		return nil
	}
	resp, err := httpClient.Do(req)
	if err != nil {
		return nil
	}
	defer func() { _ = resp.Body.Close() }()

	var result struct {
		Status  string `json:"status"`
		Country string `json:"country"`
		City    string `json:"city"`
		ISP     string `json:"isp"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil || result.Status != "success" {
		return nil
	}
	return &geoInfo{Country: result.Country, City: result.City, ISP: result.ISP}
}
