package discovery

import (
	"context"
	"encoding/json"
	"fmt"
	"net"
	"strings"
	"sync"
	"time"

	"github.com/ShadooowX/rayyan-asm/internal/models"
	"github.com/google/uuid"
	"go.uber.org/zap"
	"golang.org/x/net/publicsuffix"
	"gorm.io/gorm"
)

// WSHub is the minimal interface the engine needs to broadcast live
// progress. BroadcastToOrg scopes events to a single tenant so that
// discovery progress is never visible across organisation boundaries.
// BroadcastRaw is retained for backward-compatibility with the hub.
type WSHub interface {
	BroadcastRaw(message []byte)
	BroadcastToOrg(orgID string, data []byte)
}

// Engine runs the External Attack Surface Discovery pipeline:
//
//	seed domain -> subdomain discovery -> certificate discovery ->
//	ASN/IP discovery -> DNS intelligence -> port/service discovery ->
//	risk flagging -> (recurse on newly discovered domains/IPs)
//
// Every stage persists directly into the existing asset tables
// (domains, subdomains, hosts, services, certificates, dns_records) so
// the rest of the platform — correlation, change detection, risk
// scoring, exposure — picks up discovered assets with no extra wiring.
type Engine struct {
	db  *gorm.DB
	log *zap.SugaredLogger
	hub WSHub
}

func New(db *gorm.DB, log *zap.SugaredLogger, hub WSHub) *Engine {
	return &Engine{db: db, log: log, hub: hub}
}

// BoolPtr returns a pointer to b, for populating Options' pointer-typed
// fields (e.g. ProbeApexCert) inline — Go doesn't allow &false directly
// for a literal. discovery.BoolPtr(false) reads more clearly at the call
// site than introducing a local variable just to take its address.
func BoolPtr(b bool) *bool { return &b }

// Options configures one discovery run.
type Options struct {
	SeedDomains []string
	Depth       int  // recursive hop limit; 0 disables recursion beyond the seed pass
	ScanPorts   bool // whether to run port/service discovery (slower)
	Cadence     string
	CreatedBy   *uuid.UUID

	// WordlistTier selects subdomain brute-force breadth: "small" (default,
	// ~70 curated words), "medium" (~5k, SecLists subset), or "large"
	// (~110k, full SecLists list). Unrecognized/empty falls back to small.
	WordlistTier string

	// PortProfile selects the port set probed per host: "quick" (default,
	// today's compact 23-port list), "top1000" (Nmap's top-1000 TCP ports
	// by frequency), or "full" (1-65535). "full" requires
	// ConfirmFullPortScan=true — given the time and legal-authorization
	// implications of scanning every port — and otherwise silently falls
	// back to "top1000".
	PortProfile         string
	ConfirmFullPortScan bool

	// PortConcurrency bounds simultaneous port-probe goroutines per host
	// (worker-pool semaphore size). Defaults to 200 if <= 0.
	PortConcurrency int

	// ProbeApexCert controls the unconditional apex-domain TLS probe
	// (fetchLiveCert against <domain>:443) that runs once per frontier
	// domain regardless of ScanPorts, so root domains without any
	// CT-visible subdomains still get a certificate record. nil (the
	// zero value) means "use the default", which is true — today's
	// existing always-on behavior, so production callers that don't set
	// this field see no change. Set explicitly to a pointer to false to
	// skip it — e.g. a domain set known to have no live HTTPS endpoints,
	// or a hermetic test that wants no real network dials at all.
	ProbeApexCert *bool

	// SkipPassiveSources disables the CT-log (crt.sh) and Wayback Machine
	// passive-recon queries in processHop. nil (the zero value) means "use
	// the default", which is true (today's existing always-on behavior),
	// so production callers that don't set this field see no change. Set
	// explicitly to a pointer to true to skip both — e.g. a hermetic test
	// or scale benchmark that wants no real network dials at all. Without
	// this, tests using a real (non-mocked) root domain block for the
	// full HTTP client timeout on each external call before failing,
	// since these queries aren't gated behind the injectable Resolver
	// interface the way DNS lookups are.
	SkipPassiveSources *bool

	// MaxAssets hard-caps total assets (domains + subdomains + hosts +
	// certificates + services) persisted in a single run, so a
	// pathological recursive expansion can't run unbounded. Defaults to
	// 5000 if <= 0. When the cap is hit, the run stops early with stage
	// "capped" and a clear message rather than silently truncating.
	MaxAssets int

	// UseSubfinder / UseAmass enable shelling out to the subfinder and
	// amass binaries (see external_tools.go) as additional passive
	// hostname sources, alongside the built-in crt.sh/Wayback providers.
	// Both default to false (opt-in): unlike the built-in HTTP-based
	// providers, these require the actual binary to be installed on the
	// host running the scan. If enabled but the binary isn't found on
	// PATH, the run logs an info line and continues without that source
	// — it is never a hard failure.
	UseSubfinder bool
	UseAmass     bool
}

// wsEvent is the shape broadcast over the WebSocket hub for discovery
// progress, new assets, job status, and change events — matches the
// "Real-Time Updates" requirement without page refresh.
type wsEvent struct {
	Type      string      `json:"type"` // discovery_progress, discovery_asset, discovery_job_status, discovery_change
	OrgID     string      `json:"org_id"`
	JobID     string      `json:"job_id"`
	Data      interface{} `json:"data"`
	Timestamp time.Time   `json:"timestamp"`
}

func (e *Engine) broadcast(orgID, jobID uuid.UUID, eventType string, data interface{}) {
	if e.hub == nil {
		return
	}
	evt := wsEvent{Type: eventType, OrgID: orgID.String(), JobID: jobID.String(), Data: data, Timestamp: time.Now()}
	if msg, err := json.Marshal(evt); err == nil {
		e.hub.BroadcastToOrg(orgID.String(), msg)
	}
}

// recordEvent appends a row to the discovery_events feed and mirrors it
// over the WebSocket hub.
func (e *Engine) recordEvent(orgID, jobID uuid.UUID, eventType, assetType, assetLabel, source, severity, message string) {
	evt := models.DiscoveryEvent{
		ID: uuid.New(), OrgID: orgID, JobID: &jobID,
		EventType: eventType, AssetType: assetType, AssetLabel: assetLabel,
		Source: source, Severity: severity, Message: message, DetectedAt: time.Now(),
	}
	if err := e.db.Create(&evt).Error; err != nil {
		e.log.Warnw("discovery: failed to persist event", "error", err)
	}
	e.broadcast(orgID, jobID, "discovery_asset", evt)
}

// StartJob creates a DiscoveryJob row. Callers that want background
// execution (queue handler, scheduler) should enqueue a job and have the
// dispatcher invoke Run, matching how other engines in this codebase are
// invoked (e.g. riskscore.RecomputeOrg, correlation.RecomputeOrg).
func (e *Engine) StartJob(orgID uuid.UUID, opts Options) (*models.DiscoveryJob, error) {
	return e.createJob(context.Background(), orgID, opts)
}

func (e *Engine) createJob(_ context.Context, orgID uuid.UUID, opts Options) (*models.DiscoveryJob, error) {
	if len(opts.SeedDomains) == 0 {
		return nil, fmt.Errorf("at least one seed domain is required")
	}
	if opts.Depth <= 0 {
		opts.Depth = 2
	}
	cadence := opts.Cadence
	if cadence == "" {
		cadence = "manual"
	}

	job := models.DiscoveryJob{
		OrgID:       orgID,
		CreatedBy:   opts.CreatedBy,
		SeedDomains: models.StringArray(normalizeDomains(opts.SeedDomains)),
		Status:      "pending",
		Cadence:     cadence,
		Depth:       opts.Depth,
		Options: models.JSONB{
			"scan_ports":             opts.ScanPorts,
			"wordlist_tier":          opts.WordlistTier,
			"port_profile":           opts.PortProfile,
			"confirm_full_port_scan": opts.ConfirmFullPortScan,
			"port_concurrency":       opts.PortConcurrency,
			"max_assets":             opts.MaxAssets,
			"probe_apex_cert":        opts.ProbeApexCert,
			"skip_passive_sources":   opts.SkipPassiveSources,
			"use_subfinder":          opts.UseSubfinder,
			"use_amass":              opts.UseAmass,
		},
	}
	job.ID = uuid.New()
	if err := e.db.Create(&job).Error; err != nil {
		return nil, fmt.Errorf("creating discovery job: %w", err)
	}
	return &job, nil
}

// Run executes the discovery pipeline for an already-created job. Safe to
// call from a queue worker goroutine; updates job status/progress as it
// proceeds and never panics out of the caller (all stage errors are
// logged and treated as partial-success, matching the existing
// dispatcher's "partial results beat none" philosophy).
func (e *Engine) Run(ctx context.Context, jobID uuid.UUID) error {
	var job models.DiscoveryJob
	if err := e.db.First(&job, "id = ?", jobID).Error; err != nil {
		return fmt.Errorf("loading discovery job %s: %w", jobID, err)
	}

	now := time.Now()
	if err := e.db.Model(&job).Updates(map[string]any{"status": "running", "started_at": &now, "stage": "subdomain"}).Error; err != nil {
		e.log.Warnw("discovery: failed to mark job as running", "job_id", job.ID, "error", err)
	}
	job.StartedAt = &now
	e.broadcast(job.OrgID, job.ID, "discovery_job_status", map[string]any{"status": "running", "stage": "subdomain"})
	e.recordEvent(job.OrgID, job.ID, "job_started", "", "", "", "info",
		fmt.Sprintf("discovery started for %d seed domain(s)", len(job.SeedDomains)))

	run := newRunState(e, &job)
	for _, d := range job.SeedDomains {
		run.seedDomains[strings.ToLower(d)] = true
	}

	var runErr error
	frontier := append([]string{}, job.SeedDomains...)
	for hop := 0; hop <= job.Depth && len(frontier) > 0; hop++ {
		select {
		case <-ctx.Done():
			runErr = ctx.Err()
		default:
		}
		if runErr != nil {
			break
		}
		if run.capReached() {
			break
		}

		e.log.Infow("discovery: hop start", "job_id", job.ID, "hop", hop, "frontier_size", len(frontier))
		nextFrontier, err := run.processHop(ctx, frontier, hop)
		if err != nil {
			e.log.Warnw("discovery: hop error", "job_id", job.ID, "hop", hop, "error", err)
		}
		frontier = nextFrontier
	}

	// Final stage: persist counters, mark complete, then hand off to the
	// existing engines so the rest of the platform reflects the new
	// inventory immediately rather than waiting for their own cron.
	completedAt := time.Now()
	stage := "done"
	status := "completed"
	if run.capReached() {
		stage = "capped"
		e.log.Warnw("discovery: asset cap reached, run truncated",
			"job_id", job.ID, "max_assets", run.maxAssets)
		e.recordEvent(job.OrgID, job.ID, "job_capped", "", "", "", "warn",
			fmt.Sprintf("run stopped early: asset cap of %d reached — increase MaxAssets or narrow scope", run.maxAssets))
	}
	update := map[string]any{
		"completed_at":     &completedAt,
		"assets_found":     run.domainsFound + run.subdomainsFound + run.ipsFound + run.certsFound + run.servicesFound,
		"new_assets":       run.newAssets,
		"domains_found":    run.domainsFound,
		"subdomains_found": run.subdomainsFound,
		"ips_found":        run.ipsFound,
		"certs_found":      run.certsFound,
		"services_found":   run.servicesFound,
		"progress":         100,
		"stage":            stage,
	}
	if runErr != nil {
		update["status"] = "failed"
		update["error"] = runErr.Error()
	} else {
		update["status"] = status
	}
	if err := e.db.Model(&job).Updates(update).Error; err != nil {
		// job's DB row would otherwise be stuck at "running" forever even
		// though the job actually finished — the same silent-status-stall
		// risk fixed for scan jobs and reports.
		e.log.Warnw("discovery: failed to persist final job status", "job_id", job.ID, "error", err)
	}

	statusMsg := "completed"
	if runErr != nil {
		statusMsg = "failed"
	}
	e.recordEvent(job.OrgID, job.ID, "job_"+statusMsg, "", "", "", "info",
		fmt.Sprintf("discovery %s — %d new assets across %d domains, %d subdomains, %d IPs, %d certs, %d services",
			statusMsg, run.newAssets, run.domainsFound, run.subdomainsFound, run.ipsFound, run.certsFound, run.servicesFound))
	e.broadcast(job.OrgID, job.ID, "discovery_job_status", map[string]any{"status": statusMsg, "stage": "done"})

	return runErr
}

// newRunState constructs a runState for job, resolving every JSONB key in
// job.Options into its corresponding typed field. This is the single
// place that maps job.Options -> runState fields — both Run() and the
// test-only RunHopForBench (export_test.go) call this rather than each
// keeping their own copy of the option-parsing logic, so the mapping
// can't drift between production and test code paths.
func newRunState(e *Engine, job *models.DiscoveryJob) *runState {
	scanPorts, _ := job.Options["scan_ports"].(bool)

	// probeApexCert defaults to true (today's existing unconditional
	// behavior) unless the job's Options explicitly set ProbeApexCert to
	// false. job.Options["probe_apex_cert"] is nil when the option was
	// never set (Options.ProbeApexCert was a nil *bool at job-creation
	// time), or a bool when it was — see Options.ProbeApexCert's doc
	// comment.
	probeApexCert := true
	if v, ok := job.Options["probe_apex_cert"].(bool); ok {
		probeApexCert = v
	}

	// skipPassiveSources defaults to false (today's existing always-on
	// behavior) unless the job's Options explicitly set
	// SkipPassiveSources to true. See Options.SkipPassiveSources's doc
	// comment.
	skipPassiveSources := false
	if v, ok := job.Options["skip_passive_sources"].(bool); ok {
		skipPassiveSources = v
	}

	useSubfinder, _ := job.Options["use_subfinder"].(bool)
	useAmass, _ := job.Options["use_amass"].(bool)

	// Resolve numeric options from JSONB (JSON numbers decode as float64 in Go).
	toInt := func(v any) int {
		switch n := v.(type) {
		case float64:
			return int(n)
		case int:
			return n
		}
		return 0
	}
	maxAssets := toInt(job.Options["max_assets"])
	if maxAssets <= 0 {
		maxAssets = 5000
	}

	return &runState{
		engine:              e,
		job:                 job,
		visitedHost:         map[string]bool{},
		visitedIP:           map[string]bool{},
		seedDomains:         map[string]bool{},
		queriedRoot:         map[string]bool{},
		scanPorts:           scanPorts,
		probeApexCert:       probeApexCert,
		skipPassiveSources:  skipPassiveSources,
		useSubfinder:        useSubfinder,
		useAmass:            useAmass,
		providers:           newProviderState(),
		resolver:            defaultResolver{},
		wordlistTier:        func() string { s, _ := job.Options["wordlist_tier"].(string); return s }(),
		portProfile:         func() string { s, _ := job.Options["port_profile"].(string); return s }(),
		confirmFullPortScan: func() bool { b, _ := job.Options["confirm_full_port_scan"].(bool); return b }(),
		portConcurrency:     toInt(job.Options["port_concurrency"]),
		maxAssets:           maxAssets,
	}
}

// runState carries per-job mutable state across pipeline hops —
// deduplication sets and running counters — kept separate from the
// Engine itself since Engine is shared across concurrent jobs/orgs.
type runState struct {
	engine *Engine
	job    *models.DiscoveryJob

	mu          sync.Mutex
	visitedHost map[string]bool
	visitedIP   map[string]bool
	seedDomains map[string]bool
	scanPorts   bool

	// probeApexCert gates the unconditional apex-domain TLS probe in
	// processHop (fetchLiveCert against <domain>:443). See
	// Options.ProbeApexCert's doc comment; defaults true via newRunState.
	probeApexCert bool

	// skipPassiveSources gates the CT-log (crt.sh) and Wayback Machine
	// queries in processHop. See Options.SkipPassiveSources's doc
	// comment; defaults false (queries run) via newRunState.
	skipPassiveSources bool

	// useSubfinder / useAmass gate the optional external-binary sources
	// in external_tools.go. See Options.UseSubfinder/UseAmass's doc
	// comment; both default false (off) via newRunState.
	useSubfinder bool
	useAmass     bool

	// queriedRoot dedupes CT-log / Wayback queries per root domain within
	// a run: processHop iterates the frontier per-hostname, but many
	// hostnames in a hop typically share the same root (e.g. a hop full
	// of newly-discovered subdomains all rooted at the same domain), and
	// crt.sh / Wayback results are identical for all of them. Without
	// this, a frontier of N hostnames sharing one root fires N redundant
	// external API calls instead of one.
	queriedRoot map[string]bool

	// providers holds the per-run TTL cache + circuit breaker for ASN/
	// CIDR/GeoIP lookups (resilience.go). Always non-nil once Run()
	// constructs a runState.
	providers *providerState

	// resolver performs the forward/reverse DNS lookups used during
	// subdomain brute-force, permutation expansion, and reverse-DNS
	// enrichment (see resolveHost/reverseDNSLookup below). Defaults to
	// defaultResolver{} (real DNS); tests inject a mock so hermetic runs
	// never touch the network. Always non-nil once newRunState constructs
	// a runState.
	resolver Resolver

	wordlistTier        string
	portProfile         string
	confirmFullPortScan bool
	portConcurrency     int

	// maxAssets/assetCount/capHit implement the hard per-run asset cap:
	// once assetCount reaches maxAssets, capHit flips true and the run
	// stops persisting new assets / recursing further, with a clear
	// stage + message rather than a silent truncation.
	maxAssets  int
	assetCount int
	capHit     bool

	domainsFound    int
	subdomainsFound int
	ipsFound        int
	certsFound      int
	servicesFound   int
	newAssets       int
}

func (r *runState) markHostVisited(fqdn string) bool {
	r.mu.Lock()
	defer r.mu.Unlock()
	fqdn = strings.ToLower(fqdn)
	if r.visitedHost[fqdn] {
		return false
	}
	r.visitedHost[fqdn] = true
	return true
}

// addDomainsFound, addSubdomainsFound, addIPsFound, addCertsFound,
// addServicesFound, and addNewAssets are mutex-guarded increments for the
// run's summary counters. processHop runs concurrently across the hop's
// frontier (see hopConcurrency), so every counter mutation must go
// through one of these instead of a bare r.fooFound++ — a direct
// increment is a data race once more than one domain in the frontier is
// processed at the same time.
func (r *runState) addDomainsFound(n int) {
	r.mu.Lock()
	r.domainsFound += n
	r.mu.Unlock()
}

func (r *runState) addSubdomainsFound(n int) {
	r.mu.Lock()
	r.subdomainsFound += n
	r.mu.Unlock()
}

func (r *runState) addIPsFound(n int) {
	r.mu.Lock()
	r.ipsFound += n
	r.mu.Unlock()
}

func (r *runState) addCertsFound(n int) {
	r.mu.Lock()
	r.certsFound += n
	r.mu.Unlock()
}

func (r *runState) addServicesFound(n int) {
	r.mu.Lock()
	r.servicesFound += n
	r.mu.Unlock()
}

func (r *runState) addNewAssets(n int) {
	r.mu.Lock()
	r.newAssets += n
	r.mu.Unlock()
}

// markRootQueried reports whether rootDomain has already had its CT-log /
// Wayback passive-source queries fired this run, marking it queried if
// not. Used to dedupe repeated external API calls when many hostnames in
// a hop share the same registrable root (see queriedRoot).
func (r *runState) markRootQueried(rootDomain string) bool {
	r.mu.Lock()
	defer r.mu.Unlock()
	rootDomain = strings.ToLower(rootDomain)
	if r.queriedRoot[rootDomain] {
		return false
	}
	r.queriedRoot[rootDomain] = true
	return true
}

func (r *runState) markIPVisited(ip string) bool {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.visitedIP[ip] {
		return false
	}
	r.visitedIP[ip] = true
	return true
}

func (r *runState) isSeedOwned(fqdn string) bool {
	r.mu.Lock()
	defer r.mu.Unlock()
	fqdn = strings.ToLower(fqdn)
	for seed := range r.seedDomains {
		if fqdn == seed || strings.HasSuffix(fqdn, "."+seed) {
			return true
		}
	}
	return false
}

// reserveAsset claims one slot against the run's hard asset cap before
// persisting a genuinely new asset (domain, subdomain, host, certificate,
// or service). It returns true while there's still room; once the cap is
// reached it returns false from then on (capHit stays true for the rest
// of the run) so callers can stop creating new rows without silently
// truncating — the caller is responsible for surfacing the cap via the
// job's stage/message (see Run()).
func (r *runState) reserveAsset() bool {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.capHit {
		return false
	}
	if r.assetCount >= r.maxAssets {
		r.capHit = true
		return false
	}
	r.assetCount++
	return true
}

// capReached reports whether the run's asset cap has been hit, without
// claiming a slot — used to short-circuit further frontier expansion once
// the cap trips mid-hop.
func (r *runState) capReached() bool {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.capHit
}

// resolveHost resolves a hostname to its A/AAAA addresses through the
// run's injected Resolver — defaultResolver{} in production, a mock in
// tests (see Resolver in providers.go).
func (r *runState) resolveHost(ctx context.Context, fqdn string) ([]string, error) {
	return r.resolver.ResolveHost(ctx, fqdn)
}

// reverseDNSLookup performs a PTR lookup for an IP through the run's
// injected Resolver — the "Reverse DNS" discovery source, frequently
// surfacing internal-sounding hostnames (mail, vpn, etc.) that other
// passive sources miss.
func (r *runState) reverseDNSLookup(ctx context.Context, ip string) ([]string, error) {
	return r.resolver.ReverseDNSLookup(ctx, ip)
}

// hopConcurrency bounds how many frontier domains processHop works on at
// once. Each domain's own sub-stages (CT/wayback, brute-force, port scan)
// already run their own internally-bounded goroutine pools, so this is a
// second, outer level of concurrency — kept modest to avoid stacking too
// many nested worker pools and exhausting the DB connection pool under a
// large frontier.
const hopConcurrency = 32

// processHop runs one full stage sequence (subdomain -> certificate ->
// ASN/IP -> DNS -> port/service -> risk flagging) over the current
// frontier of domains, and returns the next hop's frontier — every newly
// discovered hostname not yet visited, per the brief's "every newly
// discovered asset must automatically trigger further discovery"
// requirement.
//
// Domains in the frontier are processed concurrently (bounded by
// hopConcurrency): they share no state beyond what runState already
// guards with its own mutex (visited sets, asset cap, counters — see
// markHostVisited/reserveAsset/addX above), so running them in parallel
// is safe and turns hop processing time from O(frontier size) serial
// round-trips into O(frontier size / hopConcurrency).
func (r *runState) processHop(ctx context.Context, frontier []string, hop int) ([]string, error) {
	e := r.engine
	job := r.job
	orgID := job.OrgID

	var nextFrontier []string
	var mu sync.Mutex
	addNext := func(fqdn string) {
		mu.Lock()
		nextFrontier = append(nextFrontier, fqdn)
		mu.Unlock()
	}

	var wg sync.WaitGroup
	sem := make(chan struct{}, hopConcurrency)

	for _, rawDomain := range frontier {
		if r.capReached() {
			break
		}
		domain := normalizeDomain(rawDomain)
		if domain == "" || !r.markHostVisited(domain) {
			continue
		}
		if !r.reserveAsset() {
			break
		}

		wg.Add(1)
		sem <- struct{}{}
		go func(domain string) {
			defer wg.Done()
			defer func() { <-sem }()

			rootDomain := rootOf(domain)

			// --- Stage 0: ensure a Domain row exists for the root ---
			var domainRec models.Domain
			startedAt := time.Now().Add(-1 * time.Hour)
			if job.StartedAt != nil {
				startedAt = *job.StartedAt
			}
			if err := e.db.Where("org_id = ? AND name = ?", orgID, rootDomain).
				Attrs(models.Domain{OrgID: orgID, Name: rootDomain, DiscoveryJobID: &job.ID}).
				FirstOrCreate(&domainRec).Error; err == nil && domainRec.CreatedAt.After(startedAt) {
				r.addDomainsFound(1)
				r.addNewAssets(1)
				e.recordEvent(orgID, job.ID, "asset_discovered", "domain", rootDomain, "seed", "info", "new root domain registered for discovery")
			}

			// --- Stage 1.5 (self): resolve the frontier item ITSELF (the
			// seed domain/IP or a previously-discovered subdomain) and run
			// the ASN/reverse-DNS/DNS-intel/port-scan pipeline on it.
			//
			// Previously this pipeline only ran for *newly discovered child*
			// subdomains (see the `for fqdn := range discovered` loop below),
			// so a seed that resolved straight to a host — or a bare IP
			// literal seed, which never produces any CT/brute "discovered"
			// children at all — got a Domain row and maybe a subdomain list,
			// but no host/ASN/port/DNS-intel records. That's why scans that
			// take a raw IP (or any domain with no further subdomains) only
			// ever produced subdomain/DNS output.
			isIPSeed := net.ParseIP(domain) != nil
			selfIPs := []string{domain}
			if !isIPSeed {
				selfIPs, _ = r.resolveHost(ctx, domain)
			}
			for _, ip := range selfIPs {
				if r.capReached() {
					break
				}
				if net.ParseIP(ip) == nil || !r.markIPVisited(ip) {
					continue
				}
				if !r.reserveAsset() {
					break
				}
				r.addIPsFound(1)
				hostRec, hostIsNew := e.upsertHost(orgID, job.ID, ip)
				if hostIsNew {
					r.addNewAssets(1)
					e.recordEvent(orgID, job.ID, "asset_discovered", "ip", ip, "dns_resolution", "info", "new IP address discovered")
				}
				e.enrichHostASNAndGeo(ctx, r, orgID, &hostRec)
				if ptrNames, err := r.reverseDNSLookup(ctx, ip); err == nil {
					for _, ptr := range ptrNames {
						if ptr != "" && strings.Contains(ptr, ".") && r.isSeedOwned(ptr) {
							addNext(ptr)
						}
					}
				}
				for _, rec := range queryDNSIntelligence(ctx, domain) {
					e.upsertDNSRecord(orgID, domainRec.ID, domain, rec)
				}
				if r.scanPorts {
					e.runPortAndServiceDiscovery(ctx, r, orgID, job.ID, hostRec.ID, ip, domain, startedAt)
				}
			}

			if err := e.db.Model(job).Update("stage", "subdomain").Error; err != nil {
				e.log.Warnw("discovery: failed to persist stage", "job_id", job.ID, "stage", "subdomain", "error", err)
			}
			e.broadcast(orgID, job.ID, "discovery_progress", map[string]any{"stage": "subdomain", "domain": domain, "hop": hop})

			// --- Stage 1: Subdomain & Certificate Transparency discovery ---
			// Skipped for literal IP seeds: CT/wayback/brute-force all key off
			// a registrable root domain, which doesn't exist for an IP — the
			// IP itself was already fully handled above.
			discovered := map[string]bool{}

			var ctHosts, waybackHosts []string
			if !isIPSeed && !r.skipPassiveSources && r.markRootQueried(rootDomain) {
				ctEntries, err := queryCTLogs(ctx, rootDomain, e.log)
				if err != nil {
					e.log.Warnw("discovery: crt.sh query failed", "domain", rootDomain, "error", err)
				}
				var wildcards []string
				ctHosts, wildcards = hostnamesFromCT(ctEntries, rootDomain)
				for _, h := range ctHosts {
					discovered[h] = true
				}
				// Wildcard Certificate Expansion: a wildcard SAN like *.api.example.com
				// implies the parent host itself is a live discovery target even
				// without its own CT log entry.
				for _, w := range wildcards {
					discovered[w] = true
				}

				// Second passive source beyond CT logs: Wayback Machine archived
				// URLs surface hosts that were once live and crawled but may never
				// have had a logged TLS certificate. Best-effort — log and continue
				// on failure, same graceful-degradation pattern as ASN/geo lookups.
				waybackHosts, err = queryWaybackURLs(ctx, rootDomain, e.log)
				if err != nil {
					e.log.Warnw("discovery: wayback machine query failed", "domain", rootDomain, "error", err)
				}
			}
			for _, h := range waybackHosts {
				discovered[h] = true
			}

			// Optional external-tool sources (subfinder/amass): opt-in via
			// Options.UseSubfinder/UseAmass since, unlike the HTTP-based
			// providers above, these require the actual binaries installed
			// on the host running the scan. Both no-op gracefully (nil,
			// nil) if the binary isn't on PATH — see external_tools.go.
			// Source attribution and asset_discovered event recording for
			// these hosts happens once, centrally, in the persistence loop
			// below (same as ctHosts/waybackHosts) — not here — so a host
			// found by more than one source doesn't fire duplicate events.
			var subfinderHosts, amassHosts []string
			if !isIPSeed && !r.skipPassiveSources && r.markRootQueried(rootDomain+"#external") {
				if r.useSubfinder {
					var err error
					subfinderHosts, err = runSubfinder(ctx, rootDomain, e.log)
					if err != nil {
						e.log.Warnw("discovery: subfinder query failed", "domain", rootDomain, "error", err)
					}
					for _, h := range subfinderHosts {
						discovered[h] = true
					}
				}
				if r.useAmass {
					var err error
					amassHosts, err = runAmass(ctx, rootDomain, e.log)
					if err != nil {
						e.log.Warnw("discovery: amass query failed", "domain", rootDomain, "error", err)
					}
					for _, h := range amassHosts {
						discovered[h] = true
					}
				}
			}

			// DNS Brute Force against the active wordlist tier (small/medium/
			// large, see wordlists.go); kept local to this package (see
			// bruteforceWordlist) to avoid a cross-module import cycle with
			// the existing subdomain scan module. Skipped for IP seeds —
			// "word.<ip>" is not a resolvable hostname.
			var ctHitWords []string
			if !isIPSeed {
				wordlist := wordlistForTier(r.wordlistTier)
				for _, h := range ctHosts {
					if label := strings.TrimSuffix(h, "."+rootDomain); label != h && !strings.Contains(label, ".") {
						ctHitWords = append(ctHitWords, label)
					}
				}

				var bruteWg sync.WaitGroup
				var bruteMu sync.Mutex
				sem := make(chan struct{}, 40)
				for _, word := range wordlist {
					bruteWg.Add(1)
					sem <- struct{}{}
					go func(word string) {
						defer bruteWg.Done()
						defer func() { <-sem }()
						candidate := word + "." + rootDomain
						if _, err := r.resolveHost(ctx, candidate); err == nil {
							bruteMu.Lock()
							discovered[candidate] = true
							ctHitWords = append(ctHitWords, word)
							bruteMu.Unlock()
						}
					}(word)
				}
				bruteWg.Wait()

				// Permutation-based generation: rather than relying solely on
				// static wordlist membership, expand discovered/wordlist-hit
				// base words into environment/numeric/version variants
				// (dev-2, api-v2, staging01) and probe those too.
				baseWords := permutationBaseWords(ctHitWords, discovered, rootDomain)
				permutations := generatePermutations(baseWords)
				var permWg sync.WaitGroup
				var permMu sync.Mutex
				permSem := make(chan struct{}, 40)
				for _, word := range permutations {
					permWg.Add(1)
					permSem <- struct{}{}
					go func(word string) {
						defer permWg.Done()
						defer func() { <-permSem }()
						candidate := word + "." + rootDomain
						if _, err := r.resolveHost(ctx, candidate); err == nil {
							permMu.Lock()
							discovered[candidate] = true
							permMu.Unlock()
						}
					}(word)
				}
				permWg.Wait()
			}

			// --- Persist subdomains, resolve IPs, recurse ---
			for fqdn := range discovered {
				if r.capReached() {
					break
				}
				if fqdn == rootDomain {
					continue
				}
				if !r.reserveAsset() {
					break
				}
				ips, _ := r.resolveHost(ctx, fqdn)
				// Precedence when a host is found by multiple sources:
				// ct_log/wayback (existing behavior, unchanged) take
				// priority over the newer external-tool sources, which in
				// turn take priority over the dns_brute fallback — brute
				// force is the least specific signal (any resolvable
				// label), so it should never override a named source.
				source := "ct_log"
				if !containsHost(ctHosts, fqdn) {
					source = "dns_brute"
				}
				if containsHost(waybackHosts, fqdn) && !containsHost(ctHosts, fqdn) {
					source = "wayback"
				}
				if containsHost(subfinderHosts, fqdn) && !containsHost(ctHosts, fqdn) && !containsHost(waybackHosts, fqdn) {
					source = "subfinder"
				}
				if containsHost(amassHosts, fqdn) && !containsHost(ctHosts, fqdn) && !containsHost(waybackHosts, fqdn) && !containsHost(subfinderHosts, fqdn) {
					source = "amass"
				}

				name := strings.TrimSuffix(fqdn, "."+rootDomain)
				now := time.Now()
				var subRec models.Subdomain
				err := e.db.Where("org_id = ? AND fqdn = ?", orgID, fqdn).
					Attrs(models.Subdomain{
						OrgID: orgID, DomainID: domainRec.ID, Name: name, FQDN: fqdn,
						IPs: models.StringArray(ips), Source: source, Status: "active",
						FirstSeenAt: now, LastSeenAt: now, LastScannedAt: &now,
						DiscoveryJobID: &job.ID,
					}).
					FirstOrCreate(&subRec).Error
				isNew := err == nil && subRec.CreatedAt.After(startedAt)
				if err == nil {
					if uerr := e.db.Model(&subRec).Updates(map[string]any{
						"ips": models.StringArray(ips), "last_seen_at": now, "last_scanned_at": &now, "status": "active",
					}).Error; uerr != nil {
						e.log.Warnw("discovery: failed to update subdomain last-seen", "job_id", job.ID, "fqdn", fqdn, "error", uerr)
					}
				}
				r.addSubdomainsFound(1)
				if isNew {
					r.addNewAssets(1)
					e.recordEvent(orgID, job.ID, "asset_discovered", "subdomain", fqdn, source, "info", "new subdomain discovered")
					for _, sig := range flagHostname(fqdn) {
						e.persistRiskFlag(orgID, "subdomain", subRec.ID, fqdn, sig)
					}
				}

				// Every newly discovered subdomain re-enters the frontier for
				// the next hop — satisfies "every newly discovered asset must
				// automatically trigger further discovery".
				if r.markHostVisited(fqdn) {
					addNext(fqdn)
				}

				// --- Stage 2: ASN / IP discovery for each resolved IP ---
				for _, ip := range ips {
					if r.capReached() {
						break
					}
					if net.ParseIP(ip) == nil || !r.markIPVisited(ip) {
						continue
					}
					if !r.reserveAsset() {
						break
					}
					r.addIPsFound(1)
					hostRec, hostIsNew := e.upsertHost(orgID, job.ID, ip)
					if hostIsNew {
						r.addNewAssets(1)
						e.recordEvent(orgID, job.ID, "asset_discovered", "ip", ip, "dns_resolution", "info", "new IP address discovered")
					}

					e.enrichHostASNAndGeo(ctx, r, orgID, &hostRec)

					// Reverse DNS: PTR records often surface infra hostnames
					// (mail, vpn gateways) other sources never see directly.
					// Only re-queue PTR names that fall under a seed domain,
					// so discovery doesn't wander into unrelated third-party
					// infrastructure sharing the same IP block.
					if ptrNames, err := r.reverseDNSLookup(ctx, ip); err == nil {
						for _, ptr := range ptrNames {
							if ptr != "" && strings.Contains(ptr, ".") && r.isSeedOwned(ptr) {
								addNext(ptr)
							}
						}
					}

					// --- Stage 3: DNS Intelligence for this hostname ---
					for _, rec := range queryDNSIntelligence(ctx, fqdn) {
						e.upsertDNSRecord(orgID, domainRec.ID, fqdn, rec)
					}

					// --- Stage 4: Internet Exposure / Port & Service Discovery ---
					if r.scanPorts {
						e.runPortAndServiceDiscovery(ctx, r, orgID, job.ID, hostRec.ID, ip, fqdn, startedAt)
					}
				}
			}

			// Certificate discovery against the apex domain's own HTTPS port,
			// independent of subdomain enumeration, so root domains without
			// any CT-visible subdomains still get a certificate record.
			// Gated by probeApexCert (defaults true; see Options.ProbeApexCert).
			if r.probeApexCert && !r.capReached() && r.reserveAsset() {
				if cert, err := fetchLiveCert(ctx, domain, 443); err == nil {
					e.persistCertificate(orgID, job.ID, nil, cert)
					r.addCertsFound(1)
					for _, sig := range flagCertificate(cert.Subject, cert.IsExpired, cert.TLSValid, cert.TLSValidationError) {
						e.persistRiskFlag(orgID, "domain", domainRec.ID, cert.Subject, sig)
					}
				}
			}
		}(domain)
	}

	wg.Wait()

	return dedupe(nextFrontier), nil
}

// runPortAndServiceDiscovery performs Open Port Enumeration, Service
// Detection, and Web Application Detection for a single resolved IP, and
// persists Certificate Discovery results for any TLS-fronted service
// found along the way. The port list and scan concurrency come from
// Options.PortProfile / Options.PortConcurrency (see ports.go); each
// discovered service still counts against the run's asset cap.
func (e *Engine) runPortAndServiceDiscovery(ctx context.Context, r *runState, orgID, jobID, hostID uuid.UUID, ip, hostname string, startedAt time.Time) {
	ports := portsForProfile(r.portProfile, r.confirmFullPortScan, e.log)
	services := probePorts(ctx, ip, ports, r.portConcurrency)
	for _, svc := range services {
		if r.capReached() {
			break
		}
		if !r.reserveAsset() {
			break
		}
		now := time.Now()
		var svcRec models.Service
		err := e.db.Where("org_id = ? AND host_ref = ? AND port = ? AND protocol = ?", orgID, ip, svc.Port, svc.Protocol).
			Attrs(models.Service{
				OrgID: orgID, HostID: hostID, HostRef: ip, Port: svc.Port, Protocol: svc.Protocol,
				Banner: svc.Banner, State: "open", FirstSeenAt: now, LastSeenAt: now,
				DiscoveryJobID: &jobID,
			}).
			FirstOrCreate(&svcRec).Error
		isNew := err == nil && svcRec.CreatedAt.After(startedAt)
		if err == nil {
			// host_id is included here (not just on create) so services
			// discovered before this field was wired in — or ever left
			// null by another code path — self-heal on the next scan
			// instead of staying permanently invisible on the host page.
			if uerr := e.db.Model(&svcRec).Updates(map[string]any{"last_seen_at": now, "state": "open", "banner": svc.Banner, "host_id": hostID}).Error; uerr != nil {
				e.log.Warnw("discovery: failed to update service last-seen", "job_id", jobID, "host", ip, "port", svc.Port, "error", uerr)
			}
		}
		r.addServicesFound(1)
		if isNew {
			r.addNewAssets(1)
			e.recordEvent(orgID, jobID, "asset_discovered", "service",
				fmt.Sprintf("%s:%d/%s", ip, svc.Port, svc.Protocol), "port_scan", "info", "new open service discovered")
		}

		if svc.TLS {
			if cert, err := fetchLiveCert(ctx, ip, svc.Port); err == nil {
				e.persistCertificate(orgID, jobID, &svcRec.ID, cert)
				r.addCertsFound(1)
				for _, sig := range flagCertificate(cert.Subject, cert.IsExpired, cert.TLSValid, cert.TLSValidationError) {
					e.persistRiskFlag(orgID, "certificate", svcRec.ID, cert.Subject, sig)
				}
			}
		}

		scheme := "http"
		if svc.TLS {
			scheme = "https"
		}
		switch svc.Port {
		case 80, 443, 8080, 8443, 8000, 8888:
			status, title, server := detectWebTitle(ctx, scheme, hostname, svc.Port)
			if status > 0 {
				url := fmt.Sprintf("%s://%s:%d/", scheme, hostname, svc.Port)
				for _, sig := range flagWebService(url, title, server, status) {
					e.persistRiskFlag(orgID, "service", svcRec.ID, hostname, sig)
				}
			}
		}
	}
}

// upsertHost creates or refreshes a Host row for a discovered IP,
// returning whether it was newly created during this run.
func (e *Engine) upsertHost(orgID, jobID uuid.UUID, ip string) (models.Host, bool) {
	now := time.Now()
	var host models.Host
	err := e.db.Where("org_id = ? AND ip = ?", orgID, ip).
		Attrs(models.Host{
			OrgID: orgID, IP: ip, IPVersion: ipVersion(ip), Status: "active",
			FirstSeenAt: now, LastSeenAt: now, DiscoveryJobID: &jobID,
		}).
		FirstOrCreate(&host).Error
	isNew := err == nil && host.CreatedAt.After(now.Add(-2*time.Second))
	if err == nil {
		if uerr := e.db.Model(&host).Updates(map[string]any{"last_seen_at": now, "status": "active"}).Error; uerr != nil {
			e.log.Warnw("discovery: failed to update host last-seen", "job_id", jobID, "ip", ip, "error", uerr)
		}
	}
	return host, isNew
}

// enrichHostASNAndGeo fills in ASN ownership and coarse geolocation for a
// host that doesn't have them yet, and writes any newly-seen ASN's full
// prefix list into asn_ranges so the correlation engine's existing
// "asn_range" edges pick it up automatically. ASN/CIDR/GeoIP lookups go
// through r.providers' retry/cache/circuit-breaker wrapping (resilience.go)
// since they're best-effort external dependencies called once per host.
func (e *Engine) enrichHostASNAndGeo(ctx context.Context, r *runState, orgID uuid.UUID, host *models.Host) {
	if host.ASN == "" {
		info, err := lookupASNForIP(ctx, host.IP, r.providers, e.log)
		if err != nil {
			e.log.Warnw("discovery: ASN lookup failed, host will have no ASN/geo data", "host_id", host.ID, "ip", host.IP, "error", err)
			return
		}
		if info.ASN == "" {
			e.log.Debugw("discovery: ASN lookup returned no data", "host_id", host.ID, "ip", host.IP)
			return
		}
		if uerr := e.db.Model(host).Updates(map[string]any{
			"asn": info.ASN, "asn_org": info.ASNOrg, "cidr": info.CIDR, "country": info.Country,
		}).Error; uerr != nil {
			e.log.Warnw("discovery: failed to persist host ASN/geo enrichment", "host_id", host.ID, "ip", host.IP, "asn", info.ASN, "error", uerr)
		}
		host.ASN, host.ASNOrg, host.CIDR, host.Country = info.ASN, info.ASNOrg, info.CIDR, info.Country

		var existing int64
		if cerr := e.db.Model(&models.ASNRange{}).Where("org_id = ? AND asn = ?", orgID, info.ASN).Count(&existing).Error; cerr != nil {
			// If this fails, `existing` stays at its zero value and the code
			// below would think no range is on record and try to insert one —
			// log so a spike in duplicate-insert warnings is traceable back
			// to this rather than looking like a data-quality issue.
			e.log.Warnw("discovery: failed to count existing ASN ranges", "org_id", orgID, "asn", info.ASN, "error", cerr)
		}
		if existing == 0 {
			asnNum := strings.TrimPrefix(info.ASN, "AS")
			if cidrs, asnOrg := expandASNPrefixes(ctx, asnNum, r.providers, e.log); len(cidrs) > 0 {
				if asnOrg == "" {
					asnOrg = info.ASNOrg
				}
				for _, cidr := range cidrs {
					rr := models.ASNRange{OrgID: orgID, ASN: info.ASN, ASNOrg: asnOrg, CIDR: cidr, Country: info.Country}
					rr.ID = uuid.New()
					rr.CreatedAt = time.Now()
					if err := e.db.Where("org_id = ? AND asn = ? AND cidr = ?", orgID, info.ASN, cidr).FirstOrCreate(&rr).Error; err != nil {
						e.log.Warnw("discovery: failed to persist ASN range", "org_id", orgID, "asn", info.ASN, "cidr", cidr, "error", err)
					}
				}
			}
		}
	}
	if host.City == "" && host.Country == "" {
		if geo := lookupGeoIP(ctx, host.IP, r.providers, e.log); geo != nil {
			if uerr := e.db.Model(host).Updates(map[string]any{"country": geo.Country, "city": geo.City, "isp": geo.ISP}).Error; uerr != nil {
				e.log.Warnw("discovery: failed to persist host geo enrichment", "host_id", host.ID, "ip", host.IP, "error", uerr)
			}
		}
	}
}

// upsertDNSRecord persists one DNS Intelligence finding (A/AAAA/CNAME/MX/TXT/NS).
func (e *Engine) upsertDNSRecord(orgID, domainID uuid.UUID, name string, rec dnsRecord) {
	now := time.Now()
	dr := models.DNSRecord{
		OrgID: orgID, DomainID: domainID, Name: name, Type: rec.Type, Value: rec.Value,
		TTL: rec.TTL, Priority: rec.Priority, FirstSeen: now, LastSeen: now,
	}
	if err := e.db.Where("org_id = ? AND name = ? AND type = ? AND value = ?", orgID, name, rec.Type, rec.Value).
		Attrs(dr).
		FirstOrCreate(&dr).Error; err != nil {
		e.log.Warnw("discovery: failed to persist DNS record", "org_id", orgID, "name", name, "type", rec.Type, "error", err)
		return
	}
	if err := e.db.Model(&models.DNSRecord{}).
		Where("org_id = ? AND name = ? AND type = ? AND value = ?", orgID, name, rec.Type, rec.Value).
		Update("last_seen", now).Error; err != nil {
		e.log.Warnw("discovery: failed to update DNS record last-seen", "org_id", orgID, "name", name, "type", rec.Type, "error", err)
	}
}

// persistCertificate stores a fetched TLS leaf certificate, matching the
// existing Certificate model's risk-relevant fields. TLSValid /
// TLSValidationError from the second verification pass are stored in
// Metadata rather than as first-class columns. The Metadata jsonb column
// itself is provisioned automatically by GORM AutoMigrate (it's a struct
// field on models.Certificate); see migrations/026_discovery_cert_metadata.sql
// for the matching SQL definition, kept for deployments/tooling that read
// the numbered migration files directly.
func (e *Engine) persistCertificate(orgID, jobID uuid.UUID, serviceID *uuid.UUID, cert *FetchedCert) {
	meta := models.JSONB{
		"tls_valid": cert.TLSValid,
	}
	if cert.TLSValidationError != "" {
		meta["tls_validation_error"] = cert.TLSValidationError
	}
	c := models.Certificate{
		OrgID: orgID, ServiceID: serviceID, Fingerprint: cert.Fingerprint,
		Subject: cert.Subject, Issuer: cert.Issuer, SubjectAltNames: models.StringArray(cert.SANs),
		SerialNumber: cert.SerialNumber, NotBefore: cert.NotBefore, NotAfter: cert.NotAfter,
		IsExpired: cert.IsExpired, IsWildcard: cert.IsWildcard, IsSelfSigned: cert.IsSelfSigned,
		SignatureAlg: cert.SignatureAlg, KeyAlg: cert.KeyAlg, Version: cert.Version,
		DiscoveryJobID: &jobID,
		Metadata:       meta,
	}
	if err := e.db.Where("org_id = ? AND fingerprint = ?", orgID, cert.Fingerprint).
		Attrs(c).
		FirstOrCreate(&c).Error; err != nil {
		e.log.Warnw("discovery: failed to persist certificate", "org_id", orgID, "fingerprint", cert.Fingerprint, "error", err)
		return
	}
	// Keep tls_valid / tls_validation_error fresh on subsequent runs so
	// a cert that failed validation before but got fixed is updated.
	if err := e.db.Model(&c).Update("metadata", meta).Error; err != nil {
		e.log.Warnw("discovery: failed to refresh certificate metadata", "org_id", orgID, "fingerprint", cert.Fingerprint, "error", err)
	}
}

// persistRiskFlag upserts a DiscoveryRiskFlag, deduplicated per
// (org, asset, flag_type) so re-running discovery doesn't spam duplicate
// flags for an already-known issue.
func (e *Engine) persistRiskFlag(orgID uuid.UUID, assetType string, assetID uuid.UUID, label string, sig riskSignal) {
	flag := models.DiscoveryRiskFlag{
		OrgID: orgID, AssetType: assetType, AssetID: assetID, AssetLabel: label,
		FlagType: sig.FlagType, Severity: sig.Severity, Evidence: sig.Evidence,
		Status: "open", DetectedAt: time.Now(),
	}
	flag.ID = uuid.New()
	if err := e.db.Where("org_id = ? AND asset_type = ? AND asset_id = ? AND flag_type = ?", orgID, assetType, assetID, sig.FlagType).
		Assign(models.DiscoveryRiskFlag{Evidence: sig.Evidence, Severity: sig.Severity, DetectedAt: time.Now()}).
		FirstOrCreate(&flag).Error; err != nil {
		e.log.Warnw("discovery: failed to persist risk flag", "org_id", orgID, "asset_type", assetType, "flag_type", sig.FlagType, "error", err)
	}
}

// helpers

// bruteforceWordlist mirrors the high-value subset of the existing
// subdomain module's wordlist, kept local to this package to avoid a
// cross-module import cycle.
var bruteforceWordlist = []string{
	"www", "mail", "ftp", "smtp", "ns1", "ns2", "webmail", "admin", "secure", "vpn",
	"shop", "blog", "dev", "staging", "api", "portal", "remote", "server", "cdn",
	"git", "gitlab", "jira", "confluence", "wiki", "docs", "help", "support",
	"status", "monitor", "app", "apps", "test", "qa", "uat", "prod",
	"internal", "intranet", "extranet", "ldap", "sso", "auth", "login",
	"dashboard", "panel", "cpanel", "manage", "backup", "db", "database",
	"jenkins", "ci", "deploy", "k8s", "registry", "proxy", "gateway", "lb",
	"beta", "demo", "sandbox", "v1", "v2", "mobile", "office", "owa", "exchange",
}

func ipVersion(ip string) int {
	if strings.Contains(ip, ":") {
		return 6
	}
	return 4
}

func normalizeDomain(d string) string {
	d = strings.TrimSpace(strings.ToLower(d))
	d = strings.TrimPrefix(d, "https://")
	d = strings.TrimPrefix(d, "http://")
	d = strings.TrimSuffix(d, "/")
	d = strings.TrimSuffix(d, ".")
	return d
}

func normalizeDomains(domains []string) []string {
	out := make([]string, 0, len(domains))
	for _, d := range domains {
		if n := normalizeDomain(d); n != "" {
			out = append(out, n)
		}
	}
	return out
}

// rootOf returns the registrable root domain ("effective TLD + 1") for a
// hostname using the real Public Suffix List (golang.org/x/net/publicsuffix)
// rather than a two-label heuristic. This correctly handles multi-level
// public suffixes that a naive "last two labels" approach gets wrong,
// e.g. private/registry suffixes like *.github.io, *.s3.amazonaws.com,
// *.herokuapp.com (where the registrable root is the third-from-last
// label, not the apex of the platform's own domain) as well as
// multi-label ccTLD suffixes like *.co.uk / *.com.au.
//
// publicsuffix.EffectiveTLDPlusOne returns an error for inputs that are
// themselves a public suffix (or otherwise have no valid eTLD+1, e.g. a
// bare TLD, an IP literal, or a single-label name like "localhost"); in
// that case we fall back to returning the input unchanged, matching the
// previous heuristic's behavior for those edge cases.
func rootOf(fqdn string) string {
	fqdn = strings.ToLower(strings.TrimSuffix(fqdn, "."))
	if fqdn == "" {
		return fqdn
	}
	root, err := publicsuffix.EffectiveTLDPlusOne(fqdn)
	if err != nil {
		return fqdn
	}
	return root
}

func containsHost(list []string, target string) bool {
	for _, h := range list {
		if h == target {
			return true
		}
	}
	return false
}

func dedupe(in []string) []string {
	seen := map[string]bool{}
	out := make([]string, 0, len(in))
	for _, v := range in {
		if v == "" || seen[v] {
			continue
		}
		seen[v] = true
		out = append(out, v)
	}
	return out
}
