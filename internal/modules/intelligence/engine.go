// Package intelligence integrates external threat-intelligence providers
// (Shodan, Censys, SecurityTrails) and exposes historical-DNS enrichment
// and continuous-monitoring capabilities on top of the existing ASM asset
// tables.  The design follows the same conventions already used in the
// correlation, riskscore and discovery modules: a stateless Engine struct
// that takes *gorm.DB + *zap.SugaredLogger, pure-Go HTTP calls to provider
// APIs, and GORM upserts back into the existing models package.
package intelligence

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/ShadooowX/rayyan-asm/internal/config"
	"github.com/ShadooowX/rayyan-asm/internal/models"
	"github.com/ShadooowX/rayyan-asm/pkg/httpclient"
	"github.com/google/uuid"
	"go.uber.org/zap"
	"gorm.io/gorm"
	"gorm.io/gorm/clause"
)

// ─── config injected at construction time ─────────────────────────────────

type Config struct {
	ShodanKey         string
	CensysID          string
	CensysSecret      string
	SecurityTrailsKey string
	Proxy             config.ProxyConfig
}

// ─── test-overridable provider base URLs ──────────────────────────────────
// These vars follow the same seam pattern used in internal/modules/discovery/
// providers.go (waybackBaseURL). Each points to the live API host and can be
// swapped to an httptest.Server URL in package tests, then restored via defer.

var (
	shodanBaseURL         = "https://api.shodan.io"
	censysBaseURL         = "https://search.censys.io"
	securityTrailsBaseURL = "https://api.securitytrails.com"
	hackerTargetBaseURL   = "https://api.hackertarget.com"
)

// ─── Engine ───────────────────────────────────────────────────────────────

type Engine struct {
	db     *gorm.DB
	log    *zap.SugaredLogger
	cfg    Config
	client *http.Client
}

func New(db *gorm.DB, log *zap.SugaredLogger, cfg Config) *Engine {
	return &Engine{
		db:     db,
		log:    log,
		cfg:    cfg,
		client: httpclient.New(30*time.Second, cfg.Proxy),
	}
}

// ─── public entry-points ──────────────────────────────────────────────────

// hostProviderNames lists every provider EnrichHost/RunDueMonitorJobs knows
// how to run against a host (IP) target.
var hostProviderNames = []string{"shodan", "censys"}

// domainProviderNames lists every provider EnrichDomain/RunDueMonitorJobs
// knows how to run against a domain target.
var domainProviderNames = []string{"securitytrails", "historical_dns"}

// EnrichHost queries all host intelligence providers (see hostProviderNames)
// for a single IP and persists the results as IntelResult rows.
func (e *Engine) EnrichHost(ctx context.Context, orgID uuid.UUID, ip string) ([]IntelResult, error) {
	return e.enrichHostWithProviders(ctx, orgID, ip, hostProviderNames)
}

// enrichHostWithProviders runs only the named host providers (any name not
// recognised for hosts is ignored). EnrichHost calls this with every known
// host provider so its external behaviour is unchanged; RunDueMonitorJobs
// calls this with job.Providers so monitor jobs only burn quota on the
// providers the user actually selected.
func (e *Engine) enrichHostWithProviders(ctx context.Context, orgID uuid.UUID, ip string, providerNames []string) ([]IntelResult, error) {
	var results []IntelResult
	var mu sync.Mutex
	var wg sync.WaitGroup
	var errs []string

	type providerFn func(context.Context, uuid.UUID, string) ([]IntelResult, error)
	available := map[string]providerFn{
		"shodan": e.enrichShodan,
		"censys": e.enrichCensys,
	}

	providers := map[string]providerFn{}
	for _, name := range providerNames {
		if fn, ok := available[name]; ok {
			providers[name] = fn
		}
	}

	for name, fn := range providers {
		wg.Add(1)
		go func(pname string, pfn providerFn) {
			defer wg.Done()
			res, err := pfn(ctx, orgID, ip)
			if err != nil {
				mu.Lock()
				errs = append(errs, fmt.Sprintf("%s: %v", pname, err))
				mu.Unlock()
				return
			}
			mu.Lock()
			results = append(results, res...)
			mu.Unlock()
		}(name, fn)
	}
	wg.Wait()

	if len(errs) > 0 {
		e.log.Warnw("intel.EnrichHost partial errors", "ip", ip, "errors", errs)
		if len(results) == 0 {
			return results, fmt.Errorf("all providers failed for host %s: %s", ip, strings.Join(errs, "; "))
		}
	}
	return results, nil
}

// EnrichDomain queries SecurityTrails and historical-DNS sources for a
// domain and its subdomains, persisting IntelResult rows.
func (e *Engine) EnrichDomain(ctx context.Context, orgID uuid.UUID, domain string) ([]IntelResult, error) {
	return e.enrichDomainWithProviders(ctx, orgID, domain, domainProviderNames)
}

// enrichDomainWithProviders runs only the named domain providers (any name
// not recognised for domains is ignored). EnrichDomain calls this with
// every known domain provider so its external behaviour is unchanged;
// RunDueMonitorJobs calls this with job.Providers so monitor jobs only run
// the providers the user actually selected.
func (e *Engine) enrichDomainWithProviders(ctx context.Context, orgID uuid.UUID, domain string, providerNames []string) ([]IntelResult, error) {
	run := map[string]bool{}
	for _, name := range providerNames {
		run[name] = true
	}

	var all []IntelResult
	var errs []string

	if run["securitytrails"] {
		stResults, err := e.enrichSecurityTrails(ctx, orgID, domain)
		if err != nil {
			e.log.Warnw("intel.EnrichDomain SecurityTrails error", "domain", domain, "error", err)
			errs = append(errs, fmt.Sprintf("securitytrails: %v", err))
		} else {
			all = append(all, stResults...)
		}
	}

	if run["historical_dns"] {
		histResults, err := e.enrichHistoricalDNS(ctx, orgID, domain)
		if err != nil {
			e.log.Warnw("intel.EnrichDomain HistoricalDNS error", "domain", domain, "error", err)
			errs = append(errs, fmt.Sprintf("historical_dns: %v", err))
		} else {
			all = append(all, histResults...)
		}
	}

	if len(errs) > 0 && len(all) == 0 {
		return all, fmt.Errorf("all providers failed for domain %s: %s", domain, strings.Join(errs, "; "))
	}
	return all, nil
}

// ListResults returns stored IntelResult rows for an org, optionally
// filtered by target and/or provider.
func (e *Engine) ListResults(orgID uuid.UUID, target, provider string, limit, offset int) ([]IntelResult, int64, error) {
	q := e.db.Where("org_id = ?", orgID)
	if target != "" {
		q = q.Where("target = ?", target)
	}
	if provider != "" {
		q = q.Where("provider = ?", provider)
	}
	var total int64
	if err := q.Model(&IntelResult{}).Count(&total).Error; err != nil {
		return nil, 0, err
	}
	var rows []IntelResult
	err := q.Order("fetched_at DESC").Limit(limit).Offset(offset).Find(&rows).Error
	return rows, total, err
}

// ListMonitorJobs returns continuous-monitoring jobs for an org.
func (e *Engine) ListMonitorJobs(orgID uuid.UUID) ([]MonitorJob, error) {
	var jobs []MonitorJob
	err := e.db.Where("org_id = ?", orgID).Order("created_at DESC").Find(&jobs).Error
	return jobs, err
}

// CreateMonitorJob persists a new monitoring job.
func (e *Engine) CreateMonitorJob(job *MonitorJob) error {
	if job.ID == uuid.Nil {
		job.ID = uuid.New()
	}
	return e.db.Create(job).Error
}

// ToggleMonitorJob enables/disables a monitoring job.
func (e *Engine) ToggleMonitorJob(orgID, jobID uuid.UUID, enabled bool) error {
	return e.db.Model(&MonitorJob{}).
		Where("id = ? AND org_id = ?", jobID, orgID).
		Update("enabled", enabled).Error
}

// DeleteMonitorJob deletes a monitoring job.
func (e *Engine) DeleteMonitorJob(orgID, jobID uuid.UUID) error {
	return e.db.Where("id = ? AND org_id = ?", jobID, orgID).Delete(&MonitorJob{}).Error
}

// maxConcurrentMonitorJobs caps how many monitor jobs run at once. Without
// this, a scheduler tick that finds a large batch of due jobs (e.g. after
// downtime, or many jobs sharing the same cadence) fires one goroutine per
// job with no limit — flooding Shodan/Censys/SecurityTrails simultaneously
// and risking rate-limit bans, plus unbounded memory/socket use under load.
const maxConcurrentMonitorJobs = 8

// RunDueMonitorJobs is called by the scheduler; it runs every enabled job
// whose next_run_at <= now, up to maxConcurrentMonitorJobs at a time.
//
// ctx is accepted for API stability with the scheduler's call site but is
// intentionally not threaded into individual jobs — each job gets its own
// context.Background() (see below) so one job's lifetime is independent
// of the others and of the caller's context.
func (e *Engine) RunDueMonitorJobs(ctx context.Context) {
	now := time.Now()
	var jobs []MonitorJob
	if err := e.db.
		Where("enabled = true AND next_run_at <= ?", now).
		Find(&jobs).Error; err != nil {
		e.log.Warnw("intel.RunDueMonitorJobs query error", "error", err)
		return
	}

	sem := make(chan struct{}, maxConcurrentMonitorJobs)
	var wg sync.WaitGroup

	for _, job := range jobs {
		j := job // capture
		wg.Add(1)
		sem <- struct{}{} // blocks once maxConcurrentMonitorJobs are in flight
		go func() {
			defer wg.Done()
			defer func() { <-sem }()
			// Recover from a panic in a single job so it can't take down
			// the scheduler loop or any other in-flight job.
			defer func() {
				if r := recover(); r != nil {
					e.log.Warnw("intel: monitor job panicked", "job_id", j.ID, "target", j.Target, "panic", r)
				}
			}()

			// Use a fresh Background context, not the scheduler's ctx —
			// that ctx is tied to the scheduler tick/process lifecycle and
			// could be cancelled out from under a still-running enrichment
			// call, especially under the new bounded concurrency where a
			// job may now wait in the semaphore queue before it even starts.
			jobCtx := context.Background()
			e.log.Infow("intel: running monitor job", "job_id", j.ID, "target", j.Target, "type", j.TargetType)
			switch j.TargetType {
			case "host":
				providers := []string(j.Providers)
				if len(providers) == 0 {
					providers = hostProviderNames
				}
				if _, err := e.enrichHostWithProviders(jobCtx, j.OrgID, j.Target, providers); err != nil {
					e.log.Warnw("intel monitor job host error", "job_id", j.ID, "error", err)
				}
			case "domain":
				providers := []string(j.Providers)
				if len(providers) == 0 {
					providers = domainProviderNames
				}
				if _, err := e.enrichDomainWithProviders(jobCtx, j.OrgID, j.Target, providers); err != nil {
					e.log.Warnw("intel monitor job domain error", "job_id", j.ID, "error", err)
				}
			}
			// Advance next_run_at
			next := now.Add(intervalFor(j.Cadence))
			if err := e.db.Model(&MonitorJob{}).Where("id = ?", j.ID).Updates(map[string]interface{}{
				"last_run_at": now,
				"next_run_at": next,
				"run_count":   gorm.Expr("run_count + 1"),
			}).Error; err != nil {
				e.log.Warnw("intel: failed to advance monitor job schedule", "job_id", j.ID, "error", err)
			}
		}()
	}

	wg.Wait()
}

// ─── provider implementations ─────────────────────────────────────────────

// --- Shodan ---

type shodanHostResponse struct {
	IP        string   `json:"ip_str"`
	Hostnames []string `json:"hostnames"`
	Org       string   `json:"org"`
	ISP       string   `json:"isp"`
	Country   string   `json:"country_name"`
	City      string   `json:"city"`
	ASN       string   `json:"asn"`
	OS        string   `json:"os"`
	Ports     []int    `json:"ports"`
	Tags      []string `json:"tags"`
	Data      []struct {
		Port      int      `json:"port"`
		Transport string   `json:"transport"`
		Banner    string   `json:"data"`
		Product   string   `json:"product"`
		Version   string   `json:"version"`
		CPE       []string `json:"cpe"`
	} `json:"data"`
	Vulns map[string]struct {
		CVSS    float64  `json:"cvss"`
		Summary string   `json:"summary"`
		Refs    []string `json:"references"`
	} `json:"vulns"`
}

func (e *Engine) enrichShodan(ctx context.Context, orgID uuid.UUID, ip string) ([]IntelResult, error) {
	if e.cfg.ShodanKey == "" {
		return nil, fmt.Errorf("shodan API key not configured")
	}
	// NOTE: Shodan's REST API only accepts the key as a `?key=` query
	// parameter — there is no documented header-based auth. The real risk
	// isn't the URL shape itself, it's letting that URL reach logs. e.get()
	// never logs the request URL (see below), so the key is not written to
	// application logs; just be careful not to log `url` if this function
	// is ever modified.
	url := fmt.Sprintf("%s/shodan/host/%s?key=%s", shodanBaseURL, ip, e.cfg.ShodanKey)
	body, status, err := e.get(ctx, url, nil)
	if err != nil {
		return nil, err
	}
	if status == 404 {
		return nil, nil // host not in Shodan index
	}
	if status != 200 {
		return nil, fmt.Errorf("shodan returned status %d", status)
	}

	var resp shodanHostResponse
	if err := json.Unmarshal(body, &resp); err != nil {
		return nil, fmt.Errorf("decoding shodan response: %w", err)
	}

	// Build summary
	var vulnIDs []string
	for cve := range resp.Vulns {
		vulnIDs = append(vulnIDs, cve)
	}
	summary := fmt.Sprintf("Shodan: %s (%s) | Org: %s | Ports: %v | CVEs: %s",
		ip, resp.Country, resp.Org,
		resp.Ports,
		strings.Join(vulnIDs, ", "),
	)

	raw, _ := json.Marshal(resp)
	result := IntelResult{
		ID:         uuid.New(),
		OrgID:      orgID,
		Provider:   "shodan",
		Target:     ip,
		TargetType: "host",
		Summary:    summary,
		RawData:    RawJSON(raw),
		Severity:   severityFromVulns(resp.Vulns),
		FetchedAt:  time.Now(),
		Tags:       models.StringArray(resp.Tags),
	}

	if err := e.upsertResult(&result); err != nil {
		e.log.Warnw("intel: shodan upsert error", "error", err)
	}

	// resp.ASN/resp.Org were already being parsed out of Shodan's response
	// above but never used anywhere except this throwaway summary string —
	// the actual Host row never got this data. Best-effort: only updates a
	// Host row that already exists (created by the network scan step),
	// never creates one, and only touches ASN/ASNOrg so it can't clobber
	// anything else on that row.
	if resp.ASN != "" || resp.Org != "" {
		updates := map[string]any{}
		if resp.ASN != "" {
			updates["asn"] = resp.ASN
		}
		if resp.Org != "" {
			updates["asn_org"] = resp.Org
		}
		if err := e.db.Model(&models.Host{}).
			Where("org_id = ? AND ip = ?", orgID, ip).
			Updates(updates).Error; err != nil {
			e.log.Warnw("intel: shodan ASN update error", "ip", ip, "error", err)
		}
	}

	// Upsert any CVEs as Findings
	for cveID, vuln := range resp.Vulns {
		e.upsertFinding(orgID, ip, cveID, vuln.Summary, vuln.CVSS)
	}

	return []IntelResult{result}, nil
}

// --- Censys ---

type censysHostResponse struct {
	Result struct {
		IP  string `json:"ip"`
		ASN struct {
			ASNS int `json:"asns"`
		} `json:"autonomous_system"`
		Services []struct {
			Port        int    `json:"port"`
			Transport   string `json:"transport_protocol"`
			ServiceName string `json:"service_name"`
			Software    []struct {
				Product string `json:"product"`
			} `json:"software"`
		} `json:"services"`
	} `json:"result"`
}

func (e *Engine) enrichCensys(ctx context.Context, orgID uuid.UUID, ip string) ([]IntelResult, error) {
	if e.cfg.CensysID == "" || e.cfg.CensysSecret == "" {
		return nil, fmt.Errorf("censys credentials not configured")
	}
	url := fmt.Sprintf("%s/api/v2/hosts/%s", censysBaseURL, ip)
	req, err := http.NewRequestWithContext(ctx, "GET", url, nil)
	if err != nil {
		return nil, err
	}
	req.SetBasicAuth(e.cfg.CensysID, e.cfg.CensysSecret)
	req.Header.Set("Accept", "application/json")

	resp, err := e.client.Do(req)
	if err != nil {
		return nil, err
	}
	defer func() { _ = resp.Body.Close() }()
	bodyBytes, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("reading censys response body: %w", err)
	}

	if resp.StatusCode == 404 {
		return nil, nil
	}
	if resp.StatusCode != 200 {
		return nil, fmt.Errorf("censys returned status %d", resp.StatusCode)
	}

	var cr censysHostResponse
	if err := json.Unmarshal(bodyBytes, &cr); err != nil {
		return nil, fmt.Errorf("decoding censys response: %w", err)
	}

	var svcList []string
	for _, svc := range cr.Result.Services {
		svcList = append(svcList, fmt.Sprintf("%d/%s(%s)", svc.Port, svc.Transport, svc.ServiceName))
	}
	summary := fmt.Sprintf("Censys: %s | Services: %s", ip, strings.Join(svcList, ", "))

	result := IntelResult{
		ID:         uuid.New(),
		OrgID:      orgID,
		Provider:   "censys",
		Target:     ip,
		TargetType: "host",
		Summary:    summary,
		RawData:    RawJSON(bodyBytes),
		Severity:   "info",
		FetchedAt:  time.Now(),
	}
	if err := e.upsertResult(&result); err != nil {
		e.log.Warnw("intel: censys upsert error", "error", err)
	}

	// Same gap as enrichShodan above: cr.Result.ASN.ASNS was parsed but
	// never used anywhere. Only update if Censys actually returned a
	// nonzero ASN, and only touch a Host row that already exists.
	if cr.Result.ASN.ASNS != 0 {
		asn := fmt.Sprintf("AS%d", cr.Result.ASN.ASNS)
		if err := e.db.Model(&models.Host{}).
			Where("org_id = ? AND ip = ?", orgID, ip).
			Update("asn", asn).Error; err != nil {
			e.log.Warnw("intel: censys ASN update error", "ip", ip, "error", err)
		}
	}
	return []IntelResult{result}, nil
}

// --- SecurityTrails ---

type stSubdomainsResponse struct {
	Subdomains []string `json:"subdomains"`
	Endpoint   string   `json:"endpoint"`
}

func (e *Engine) enrichSecurityTrails(ctx context.Context, orgID uuid.UUID, domain string) ([]IntelResult, error) {
	if e.cfg.SecurityTrailsKey == "" {
		return nil, fmt.Errorf("securitytrails API key not configured")
	}

	url := fmt.Sprintf("%s/v1/domain/%s/subdomains?children_only=false&include_inactive=true", securityTrailsBaseURL, domain)
	body, status, err := e.get(ctx, url, map[string]string{"APIKEY": e.cfg.SecurityTrailsKey})
	if err != nil {
		return nil, err
	}
	if status != 200 {
		return nil, fmt.Errorf("securitytrails returned status %d", status)
	}

	var resp stSubdomainsResponse
	if err := json.Unmarshal(body, &resp); err != nil {
		return nil, fmt.Errorf("decoding securitytrails response: %w", err)
	}

	summary := fmt.Sprintf("SecurityTrails: %d subdomains for %s", len(resp.Subdomains), domain)
	result := IntelResult{
		ID:         uuid.New(),
		OrgID:      orgID,
		Provider:   "securitytrails",
		Target:     domain,
		TargetType: "domain",
		Summary:    summary,
		RawData:    RawJSON(body),
		Severity:   "info",
		FetchedAt:  time.Now(),
	}
	if err := e.upsertResult(&result); err != nil {
		e.log.Warnw("intel: securitytrails upsert error", "error", err)
	}

	// Surface any new subdomains not already in the DB
	for _, sub := range resp.Subdomains {
		fqdn := strings.ToLower(sub) + "." + domain
		var existing models.Subdomain
		// errors.Is (not ==) because GORM v2 wraps ErrRecordNotFound, so a
		// direct equality check silently fails to match and this branch
		// would never fire — every subdomain would be treated as "already
		// exists" or as a DB error, depending on what == happens to compare
		// against. Also scope by org_id so a subdomain belonging to another
		// org with the same FQDN doesn't block (or get conflated with) this
		// org's record.
		tx := e.db.Where("fqdn = ? AND org_id = ?", fqdn, orgID).First(&existing)
		if errors.Is(tx.Error, gorm.ErrRecordNotFound) {
			// Find the domain row to get domain_id
			var dom models.Domain
			if err := e.db.Where("org_id = ? AND name = ?", orgID, domain).First(&dom).Error; err == nil {
				now := time.Now()
				newSub := models.Subdomain{
					OrgID:       orgID,
					DomainID:    dom.ID,
					Name:        strings.ToLower(sub),
					FQDN:        fqdn,
					Status:      "active",
					Source:      "securitytrails",
					FirstSeenAt: now,
					LastSeenAt:  now,
				}
				if err := e.db.Create(&newSub).Error; err != nil {
					e.log.Warnw("intel: failed to create subdomain", "fqdn", fqdn, "error", err)
				}
			}
		}
	}

	return []IntelResult{result}, nil
}

// --- Historical DNS (SecurityTrails history endpoint + fallback to HackerTarget) ---

type stDNSHistoryResponse struct {
	Type    string `json:"type"`
	Records []struct {
		FirstSeen string `json:"first_seen"`
		LastSeen  string `json:"last_seen"`
		Values    []struct {
			IP string `json:"ip"`
		} `json:"values"`
	} `json:"records"`
}

func (e *Engine) enrichHistoricalDNS(ctx context.Context, orgID uuid.UUID, domain string) ([]IntelResult, error) {
	var results []IntelResult

	for _, recType := range []string{"a", "mx", "ns"} {
		var body []byte
		var status int
		var err error

		if e.cfg.SecurityTrailsKey != "" {
			url := fmt.Sprintf("%s/v1/history/%s/dns/%s", securityTrailsBaseURL, domain, recType)
			body, status, err = e.get(ctx, url, map[string]string{"APIKEY": e.cfg.SecurityTrailsKey})
		} else {
			// Fallback: HackerTarget free DNS history (A records only)
			if recType != "a" {
				continue
			}
			url := fmt.Sprintf("%s/hostsearch/?q=%s", hackerTargetBaseURL, domain)
			body, status, err = e.get(ctx, url, nil)
			if err == nil && status == 200 {
				// HackerTarget returns rate-limit/error messages as a plain
				// HTTP 200 body (e.g. "API count exceeded..." or "error
				// check your search parameter..."). Treating that text as
				// real DNS data would silently poison the stored results,
				// so detect the known error prefixes and skip storing.
				trimmed := strings.TrimSpace(string(body))
				if strings.HasPrefix(trimmed, "API count exceeded") || strings.HasPrefix(trimmed, "error check your") {
					e.log.Warnw("intel: hackertarget returned an error/rate-limit body, skipping", "domain", domain, "body", trimmed)
					continue
				}
				// HackerTarget returns CSV text — wrap in JSON so Postgres
				// can store it as jsonb without a cast error.
				summary := fmt.Sprintf("Historical DNS (HackerTarget): %s | %d bytes", domain, len(body))
				r := IntelResult{
					ID:         uuid.New(),
					OrgID:      orgID,
					Provider:   "historical_dns",
					Target:     domain,
					TargetType: "domain",
					Summary:    summary,
					RawData:    TextToRawJSON(string(body)),
					Severity:   "info",
					FetchedAt:  time.Now(),
				}
				if err2 := e.upsertResult(&r); err2 != nil {
					e.log.Warnw("intel: hackertarget upsert error", "error", err2)
				}
				results = append(results, r)
			}
			continue
		}

		if err != nil || status != 200 {
			continue
		}

		var histResp stDNSHistoryResponse
		if err := json.Unmarshal(body, &histResp); err != nil {
			continue
		}

		summary := fmt.Sprintf("Historical DNS (%s): %s %s records — %d entries", "securitytrails", domain, strings.ToUpper(recType), len(histResp.Records))
		r := IntelResult{
			ID:         uuid.New(),
			OrgID:      orgID,
			Provider:   "historical_dns",
			Target:     domain,
			TargetType: "domain",
			Summary:    summary,
			RawData:    RawJSON(body),
			Severity:   "info",
			FetchedAt:  time.Now(),
			Tags:       models.StringArray{recType},
		}
		if err2 := e.upsertResult(&r); err2 != nil {
			e.log.Warnw("intel: historical dns upsert error", "rectype", recType, "error", err2)
		}
		results = append(results, r)
	}

	return results, nil
}

// ─── helpers ──────────────────────────────────────────────────────────────

func (e *Engine) get(ctx context.Context, url string, headers map[string]string) ([]byte, int, error) {
	req, err := http.NewRequestWithContext(ctx, "GET", url, nil)
	if err != nil {
		return nil, 0, err
	}
	req.Header.Set("Accept", "application/json")
	for k, v := range headers {
		req.Header.Set(k, v)
	}
	resp, err := e.client.Do(req)
	if err != nil {
		return nil, 0, err
	}
	defer func() { _ = resp.Body.Close() }()
	body, err := io.ReadAll(resp.Body)
	return body, resp.StatusCode, err
}

func (e *Engine) upsertResult(r *IntelResult) error {
	return e.db.Clauses(clause.OnConflict{
		Columns: []clause.Column{{Name: "org_id"}, {Name: "provider"}, {Name: "target"}},
		// target_type is included so that if a target's classification is
		// ever corrected (e.g. re-run with the right host/domain type),
		// the conflict update actually reflects it instead of leaving the
		// original (possibly wrong) value frozen in place.
		DoUpdates: clause.AssignmentColumns([]string{"summary", "raw_data", "severity", "fetched_at", "tags", "target_type"}),
	}).Create(r).Error
}

func (e *Engine) upsertFinding(orgID uuid.UUID, ip, cveID, summary string, cvss float64) {
	sev := "low"
	if cvss >= 9.0 {
		sev = "critical"
	} else if cvss >= 7.0 {
		sev = "high"
	} else if cvss >= 4.0 {
		sev = "medium"
	}
	var existing models.Finding
	// errors.Is, not == — see comment in enrichSecurityTrails for why a
	// direct equality check against a wrapped GORM error doesn't work.
	if err := e.db.Where("org_id = ? AND title = ?", orgID, cveID).First(&existing).Error; errors.Is(err, gorm.ErrRecordNotFound) {
		// Finding does not exist yet — create it.
		if err2 := e.db.Create(&models.Finding{
			OrgID:       orgID,
			Title:       cveID,
			Description: summary,
			Severity:    sev,
			Status:      "open",
			Category:    "vulnerability",
			CVE:         cveID,
			CVSS:        cvss,
			// A bare IP isn't a valid URL for UI rendering / link-out; give
			// it a scheme so it round-trips through url.Parse cleanly.
			URL: "http://" + ip,
		}).Error; err2 != nil {
			e.log.Warnw("intel: failed to create finding", "cve", cveID, "ip", ip, "error", err2)
		}
	} else if err == nil {
		// Finding already exists — update CVSS/severity if the new score is higher.
		// This handles re-scans where the same CVE appears with an updated score.
		if cvss > existing.CVSS {
			if err2 := e.db.Model(&existing).Updates(map[string]interface{}{
				"cvss":        cvss,
				"severity":    sev,
				"description": summary,
			}).Error; err2 != nil {
				e.log.Warnw("intel: failed to update finding", "cve", cveID, "error", err2)
			}
		}
	}
}

func severityFromVulns(vulns map[string]struct {
	CVSS    float64  `json:"cvss"`
	Summary string   `json:"summary"`
	Refs    []string `json:"references"`
}) string {
	max := 0.0
	for _, v := range vulns {
		if v.CVSS > max {
			max = v.CVSS
		}
	}
	if max >= 9.0 {
		return "critical"
	} else if max >= 7.0 {
		return "high"
	} else if max >= 4.0 {
		return "medium"
	} else if max > 0 {
		return "low"
	}
	return "info"
}

func intervalFor(cadence string) time.Duration {
	switch cadence {
	case "hourly":
		return time.Hour
	case "daily":
		return 24 * time.Hour
	case "weekly":
		return 7 * 24 * time.Hour
	default:
		return 24 * time.Hour
	}
}
