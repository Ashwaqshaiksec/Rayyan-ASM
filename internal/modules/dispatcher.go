package modules

import (
	"archive/zip"
	"bytes"
	"context"
	"encoding/csv"
	"encoding/json"
	"fmt"
	"net"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/ShadooowX/rayyan-asm/internal/models"
	"github.com/ShadooowX/rayyan-asm/internal/modules/changedetect"
	"github.com/ShadooowX/rayyan-asm/internal/modules/cloud"
	"github.com/ShadooowX/rayyan-asm/internal/modules/correlation"
	"github.com/ShadooowX/rayyan-asm/internal/modules/discovery"
	"github.com/ShadooowX/rayyan-asm/internal/modules/dns"
	"github.com/ShadooowX/rayyan-asm/internal/modules/executive"
	"github.com/ShadooowX/rayyan-asm/internal/modules/intelligence"
	"github.com/ShadooowX/rayyan-asm/internal/modules/network"
	"github.com/ShadooowX/rayyan-asm/internal/modules/port"
	"github.com/ShadooowX/rayyan-asm/internal/modules/riskscore"
	"github.com/ShadooowX/rayyan-asm/internal/modules/subdomain"
	"github.com/ShadooowX/rayyan-asm/internal/modules/toolrunner"
	"github.com/ShadooowX/rayyan-asm/internal/modules/toolrunner/tools"
	"github.com/ShadooowX/rayyan-asm/internal/modules/web"
	"github.com/ShadooowX/rayyan-asm/internal/queue"
	"github.com/ShadooowX/rayyan-asm/internal/whois"
	"github.com/ShadooowX/rayyan-asm/pkg/metrics"
	"github.com/google/uuid"
	"go.uber.org/zap"
	"gorm.io/gorm"
)

// WSHub is the minimal interface required by the workflow dispatcher.
// BroadcastToOrg is required so that scan progress events are scoped
// to the requesting tenant and not leaked to other organisations.
type WSHub interface {
	BroadcastRaw(message []byte)
	BroadcastToOrg(orgID string, data []byte)
}

// Dispatcher wires all scan modules to the job queue.
type Dispatcher struct {
	db             *gorm.DB
	log            *zap.SugaredLogger
	hub            WSHub
	workflowEngine *toolrunner.WorkflowEngine
	network        *network.Scanner
	port           *port.Scanner
	dns            *dns.Scanner
	web            *web.Scanner
	subdomain      *subdomain.Scanner
	discovery      *discovery.Engine
	// credKey is the AES-256 key (32 bytes) for stored tool credentials, nil if unconfigured.
	credKey []byte
	// intel and vtAPIKey chain SecurityTrails/Shodan/Censys and VirusTotal
	// into the subdomain scan step (see runSubdomain). Both are optional —
	// nil/empty means those sources are silently skipped, same as any
	// other not-configured provider. Injected via SetIntelEngine /
	// SetVirusTotalKey after construction rather than added as NewDispatcher
	// parameters, so existing call sites and tests don't need to change.
	intel    *intelligence.Engine
	vtAPIKey string
}

// SetIntelEngine wires the shared intelligence engine (Shodan/Censys/
// SecurityTrails) into the dispatcher so runSubdomain can chain
// SecurityTrails' subdomain enumeration into every Full/subdomain scan,
// not just manual Intelligence-page lookups. Safe to leave unset — a nil
// engine means that source is skipped, same as a tool that isn't installed.
// resolveHostID returns the Host row's ID for an IP target, creating a bare
// Host record if none exists yet. Returns the zero UUID for anything that
// isn't a literal IP (e.g. a bare hostname from a web-scan URL) — the hosts
// table is IP-keyed, so there's no natural row to link to without a DNS
// resolution step this isn't the place to do.
func (d *Dispatcher) resolveHostID(orgID uuid.UUID, ipOrHost string) uuid.UUID {
	if net.ParseIP(ipOrHost) == nil {
		return uuid.UUID{}
	}
	var h models.Host
	if err := d.db.Where("org_id = ? AND ip = ?", orgID, ipOrHost).
		Attrs(models.Host{OrgID: orgID, IP: ipOrHost, Status: "active"}).
		FirstOrCreate(&h).Error; err != nil {
		d.log.Warnw("failed to resolve host for service linking", "ip", ipOrHost, "error", err)
		return uuid.UUID{}
	}
	return h.ID
}

func (d *Dispatcher) SetIntelEngine(e *intelligence.Engine) {
	d.intel = e
}

// SetVirusTotalKey wires a VirusTotal API key into the dispatcher so
// runSubdomain can chain VirusTotal's subdomain enumeration in too. Safe to
// leave empty — that source is then skipped, same as a missing API key
// anywhere else in this codebase.
func (d *Dispatcher) SetVirusTotalKey(key string) {
	d.vtAPIKey = key
}

// NewDispatcher creates a Dispatcher with all scanner modules initialised.
// credKey is the decoded AES-256 key (32 bytes) used to load stored tool
// credentials for authenticated SMB scans; pass nil to disable.
func NewDispatcher(db *gorm.DB, hub WSHub, log *zap.SugaredLogger, credKey []byte) *Dispatcher {
	return &Dispatcher{
		db:             db,
		log:            log,
		hub:            hub,
		workflowEngine: toolrunner.NewWorkflowEngine(toolrunner.DefaultRegistry, log),
		network:        network.NewScanner(log),
		port:           port.NewScanner(log),
		dns:            dns.NewScanner(log, nil), // nil = use default public resolvers
		web:            web.NewScanner(log),
		subdomain:      subdomain.NewScanner(log),
		discovery:      discovery.New(db, log, hub),
		credKey:        credKey,
	}
}

// RegisterAll registers queue handlers for scan and report jobs.
func (d *Dispatcher) RegisterAll(q *queue.Queue) {
	q.Register("scan", d.handleScan)
	q.Register("report_generate", d.handleReportGenerate)
	q.Register("subdomain_scan", d.handleSubdomainScan)
	q.Register("discovery_run", d.handleDiscoveryRun)
}

// handleDiscoveryRun executes one External Attack Surface Discovery
// pipeline run. The job row already exists (created by the API handler
// or scheduler) — this just invokes the engine, which owns all status
// transitions, progress broadcasts, and asset persistence itself.
func (d *Dispatcher) handleDiscoveryRun(ctx context.Context, job queue.Job) error {
	jobIDStr, _ := job.Payload["job_id"].(string)
	if jobIDStr == "" {
		return fmt.Errorf("discovery_run job missing job_id in payload")
	}
	jobID, err := uuid.Parse(jobIDStr)
	if err != nil {
		return fmt.Errorf("invalid job_id %q: %w", jobIDStr, err)
	}
	return d.discovery.Run(ctx, jobID)
}

func (d *Dispatcher) handleScan(ctx context.Context, job queue.Job) error {
	jobIDStr, _ := job.Payload["job_id"].(string)
	if jobIDStr == "" {
		return fmt.Errorf("scan job missing job_id in payload")
	}
	jobID, err := uuid.Parse(jobIDStr)
	if err != nil {
		return fmt.Errorf("invalid job_id %q: %w", jobIDStr, err)
	}

	// Wrap context so DELETE /scans/:id can cancel the running goroutine.
	scanCtx, scanCancel := context.WithCancel(ctx)
	defer scanCancel()
	GlobalCancelRegistry.Register(jobID, scanCancel)
	defer GlobalCancelRegistry.Deregister(jobID)

	var scanJob models.ScanJob
	if err := d.db.First(&scanJob, "id = ?", jobID).Error; err != nil {
		return fmt.Errorf("loading scan job %s: %w", jobID, err)
	}

	now := time.Now()
	scanStart := now
	if err := d.db.Model(&scanJob).Updates(map[string]any{
		"status":     "running",
		"started_at": &now,
	}).Error; err != nil {
		d.log.Warnw("scan: failed to mark job as running", "job_id", scanJob.ID, "error", err)
	}
	metrics.ActiveScans.Inc()

	d.log.Infow("scan started",
		"job_id", scanJob.ID,
		"type", scanJob.Type,
		"org_id", scanJob.OrgID,
	)

	// Check if already cancelled before we start.
	if scanCtx.Err() != nil {
		return fmt.Errorf("scan %s was cancelled before execution", jobID)
	}

	var runErr error
	if scanJob.Workflow != "" {
		wfType, err := toolrunner.ValidateWorkflow(scanJob.Workflow)
		if err != nil {
			runErr = fmt.Errorf("invalid workflow %q: %w", scanJob.Workflow, err)
		} else {
			result := toolrunner.RunWorkflowForScan(scanCtx, d.db, d.hub, d.workflowEngine, wfType, scanJob.ID, scanJob.OrgID, firstTarget(scanJob), d.credKey, d.log)
			// Treat any stage with an error as a partial failure; we log but don't abort.
			for _, stage := range result.Stages {
				if stage.Error != "" {
					d.log.Warnw("workflow stage error", "stage", stage.Stage, "error", stage.Error)
				}
			}
		}
	} else {
		switch scanJob.Type {
		case "network":
			runErr = d.runNetwork(scanCtx, &scanJob)
		case "port":
			runErr = d.runPort(scanCtx, &scanJob)
		case "dns":
			runErr = d.runDNS(scanCtx, &scanJob)
		case "web":
			runErr = d.runWeb(scanCtx, &scanJob)
		case "subdomain":
			runErr = d.runSubdomain(scanCtx, &scanJob)
		case "full":
			runErr = d.runFull(scanCtx, &scanJob)
		default:
			runErr = fmt.Errorf("unknown scan type: %s", scanJob.Type)
		}
	}

	completedAt := time.Now()
	metrics.ActiveScans.Dec()
	update := map[string]any{"completed_at": &completedAt}
	finalStatus := "completed"
	if runErr != nil {
		if scanCtx.Err() != nil {
			finalStatus = "cancelled"
			update["status"] = "cancelled"
			d.log.Infow("scan cancelled", "job_id", scanJob.ID)
		} else {
			finalStatus = "failed"
			update["status"] = "failed"
			update["error"] = runErr.Error()
			d.log.Warnw("scan failed", "job_id", scanJob.ID, "error", runErr)
		}
	} else {
		update["status"] = "completed"
		update["progress"] = 100
	}
	metrics.RecordScanComplete(scanJob.Type, finalStatus, time.Since(scanStart))
	if err := d.db.Model(&scanJob).Updates(update).Error; err != nil {
		d.log.Warnw("scan: failed to persist final job status", "job_id", scanJob.ID, "status", finalStatus, "error", err)
	}

	// refresh risk scores and the asset relationship graph in the
	// background, doesn't block job completion
	if runErr == nil {
		go func(orgID uuid.UUID) {
			if _, err := riskscore.New(d.db, d.log).RecomputeOrg(orgID); err != nil {
				d.log.Warnw("riskscore: post-scan recompute failed", "org_id", orgID, "error", err)
			}
		}(scanJob.OrgID)
		go func(orgID uuid.UUID) {
			if _, err := correlation.New(d.db, d.log).RecomputeOrg(orgID); err != nil {
				d.log.Warnw("correlation: post-scan graph recompute failed", "org_id", orgID, "error", err)
			}
		}(scanJob.OrgID)
		go func(orgID uuid.UUID) {
			if _, err := changedetect.New(d.db, d.log).RunDetection(orgID); err != nil {
				d.log.Warnw("changedetect: post-scan detection failed", "org_id", orgID, "error", err)
			}
		}(scanJob.OrgID)
	}

	return runErr
}

func targetsFromPayload(scanJob *models.ScanJob) []string {
	raw, ok := scanJob.Targets["targets"]
	if !ok {
		return nil
	}
	switch v := raw.(type) {
	case []string:
		return v
	case []interface{}:
		var out []string
		for _, item := range v {
			if s, ok := item.(string); ok {
				out = append(out, s)
			}
		}
		return out
	case string:
		return []string{v}
	}
	return nil
}

// firstTarget returns the first target from the scan job payload, used as
// the workflow's primary target (domain / IP range).
func firstTarget(scanJob models.ScanJob) string {
	targets := targetsFromPayload(&scanJob)
	if len(targets) == 0 {
		return ""
	}
	return targets[0]
}

func (d *Dispatcher) runNetwork(ctx context.Context, scanJob *models.ScanJob) error {
	targets := targetsFromPayload(scanJob)
	if len(targets) == 0 {
		return fmt.Errorf("no targets specified")
	}

	opts := network.ScanOptions{
		Targets:    targets,
		Workers:    100,
		Timeout:    3 * time.Second,
		RateLimit:  500,
		ResolveDNS: true,
	}

	resultCh, err := d.network.Scan(ctx, opts)
	if err != nil {
		return err
	}

	count := 0
	for host := range resultCh {
		if !host.IsUp {
			continue
		}
		h := models.Host{
			OrgID:      scanJob.OrgID,
			IP:         host.IP,
			Hostname:   host.Hostname,
			ReverseDNS: host.ReverseDNS,
			Status:     "active",
		}
		if err := d.db.Where("org_id = ? AND ip = ?", scanJob.OrgID, host.IP).
			Assign(models.Host{
				Hostname:   host.Hostname,
				ReverseDNS: host.ReverseDNS,
				Status:     "active",
			}).
			FirstOrCreate(&h).Error; err != nil {
			d.log.Warnw("network scan: failed to persist host", "job_id", scanJob.ID, "ip", host.IP, "error", err)
			continue
		}

		d.saveResult(scanJob, host.IP, "network", map[string]any{
			"ip":          host.IP,
			"hostname":    host.Hostname,
			"reverse_dns": host.ReverseDNS,
			"method":      host.Method,
			"latency_ms":  host.Latency.Milliseconds(),
		})
		count++

		// Best-effort ASN/org/CVE enrichment via Shodan/Censys, same
		// "skip silently if not configured, never fail the scan"
		// philosophy as chainExtraSubdomainSources. d.intel is nil unless
		// SetIntelEngine was called (see NewDispatcher call sites), and
		// EnrichHost itself no-ops per-provider when its API key isn't set.
		if d.intel != nil {
			if _, err := d.intel.EnrichHost(ctx, scanJob.OrgID, host.IP); err != nil {
				d.log.Debugw("host enrichment skipped or failed", "ip", host.IP, "error", err)
			}
		}
	}

	d.log.Infow("network scan complete", "job_id", scanJob.ID, "hosts_found", count)
	return nil
}

func (d *Dispatcher) runPort(ctx context.Context, scanJob *models.ScanJob) error {
	targets := targetsFromPayload(scanJob)
	if len(targets) == 0 {
		return fmt.Errorf("no targets specified")
	}

	opts := port.ScanOptions{
		Hosts:      targets,
		Workers:    500,
		Timeout:    1 * time.Second,
		BannerGrab: true,
	}

	resultCh, err := d.port.Scan(ctx, opts)
	if err != nil {
		return err
	}

	// Resolve each numeric target to its Host row up front so every
	// Service found below can be linked by host_id — the host-detail
	// page's service list filters strictly on that FK, not on host_ref.
	hostIDs := map[string]uuid.UUID{}
	for _, t := range targets {
		hostIDs[t] = d.resolveHostID(scanJob.OrgID, t)
	}

	count := 0
	for openPort := range resultCh {
		svcNow := time.Now()
		svc := models.Service{
			OrgID:       scanJob.OrgID,
			HostID:      hostIDs[openPort.Host],
			HostRef:     openPort.Host,
			Port:        openPort.Port,
			Protocol:    openPort.Protocol,
			Service:     openPort.Service,
			Banner:      openPort.Banner,
			State:       "open",
			FirstSeenAt: svcNow,
			LastSeenAt:  svcNow,
		}
		if err := d.db.Where("org_id = ? AND host_ref = ? AND port = ? AND protocol = ?",
			scanJob.OrgID, openPort.Host, openPort.Port, openPort.Protocol).
			Assign(models.Service{
				Service:    openPort.Service,
				Banner:     openPort.Banner,
				State:      "open",
				LastSeenAt: svcNow,
				HostID:     hostIDs[openPort.Host],
			}).
			FirstOrCreate(&svc).Error; err != nil {
			d.log.Warnw("port scan: failed to persist service", "job_id", scanJob.ID,
				"host", openPort.Host, "port", openPort.Port, "error", err)
			continue
		}

		models.RecordServiceHistory(d.db, svc, &scanJob.ID)

		d.saveResult(scanJob, openPort.Host, "port", map[string]any{
			"host":       openPort.Host,
			"port":       openPort.Port,
			"protocol":   openPort.Protocol,
			"service":    openPort.Service,
			"banner":     openPort.Banner,
			"latency_ms": openPort.Latency.Milliseconds(),
		})
		count++
	}

	d.log.Infow("port scan complete", "job_id", scanJob.ID, "ports_found", count)
	return nil
}

func (d *Dispatcher) runDNS(ctx context.Context, scanJob *models.ScanJob) error {
	targets := targetsFromPayload(scanJob)
	if len(targets) == 0 {
		return fmt.Errorf("no targets specified")
	}

	opts := dns.ScanOptions{
		Domains:     targets,
		Workers:     20,
		RecordTypes: []string{"A", "AAAA", "MX", "TXT", "NS", "SOA"},
	}

	resultCh, err := d.dns.Scan(ctx, opts)
	if err != nil {
		return err
	}

	count := 0
	for info := range resultCh {
		// Every DNSRecord below needs a valid DomainID: the column is
		// NOT NULL with a foreign-key constraint to domains(id). Without
		// this lookup, DomainID was left at its zero value (all-zero
		// UUID), which has no matching row in domains — every insert
		// below failed the FK constraint and was silently dropped, since
		// FirstOrCreate's error was never checked. Confirmed directly:
		// a real scan logged "18 records found" while `SELECT count(*)
		// FROM dns_records` on the same database returned 0. Same
		// resolve-or-create-domain pattern already used in runSubdomain
		// a few hundred lines down, applied here for consistency.
		var domainRec models.Domain
		if err := d.db.Where("org_id = ? AND name = ?", scanJob.OrgID, info.Domain).
			FirstOrCreate(&domainRec, models.Domain{OrgID: scanJob.OrgID, Name: info.Domain}).Error; err != nil {
			d.log.Warnw("dns scan: domain lookup failed, skipping records for this domain",
				"job_id", scanJob.ID, "domain", info.Domain, "error", err)
			continue
		}

		now := time.Now()
		for _, rec := range info.Records {
			dnsRec := models.DNSRecord{
				OrgID:     scanJob.OrgID,
				DomainID:  domainRec.ID,
				Name:      rec.Name,
				Type:      rec.Type,
				Value:     rec.Value,
				TTL:       int(rec.TTL),
				Priority:  int(rec.Priority),
				FirstSeen: now,
				LastSeen:  now,
			}
			if err := d.db.Where("org_id = ? AND name = ? AND type = ? AND value = ?",
				scanJob.OrgID, rec.Name, rec.Type, rec.Value).
				FirstOrCreate(&dnsRec).Error; err != nil {
				d.log.Warnw("dns scan: failed to persist record", "job_id", scanJob.ID,
					"domain", info.Domain, "name", rec.Name, "type", rec.Type, "error", err)
				continue
			}
			count++
		}

		d.saveResult(scanJob, info.Domain, "dns", map[string]any{
			"domain":      info.Domain,
			"records":     info.Records,
			"nameservers": info.Nameservers,
			"errors":      info.Errors,
		})
	}

	d.log.Infow("DNS scan complete", "job_id", scanJob.ID, "records_found", count)
	return nil
}

func (d *Dispatcher) runWeb(ctx context.Context, scanJob *models.ScanJob) error {
	targets := targetsFromPayload(scanJob)
	if len(targets) == 0 {
		return fmt.Errorf("no targets specified")
	}

	opts := web.ScanOptions{
		Targets:         targets,
		Workers:         50,
		Timeout:         15 * time.Second,
		FollowRedirects: true,
		ParseTLS:        true,
		GrabBanners:     true,
	}

	resultCh, err := d.web.Scan(ctx, opts)
	if err != nil {
		return err
	}

	count := 0
	var screenshotURLs []string
	for asset := range resultCh {
		if asset.ScanError != "" {
			continue
		}
		screenshotURLs = append(screenshotURLs, asset.URL)

		// Resolve ServiceID — look up port 80/443 service for this URL's host
		var serviceID uuid.UUID
		if parsedURL, err := url.Parse(asset.URL); err == nil {
			host := parsedURL.Hostname()
			port := 80
			if parsedURL.Scheme == "https" {
				port = 443
			}
			if p := parsedURL.Port(); p != "" {
				_, _ = fmt.Sscanf(p, "%d", &port)
			}
			var svc models.Service
			if d.db.Where("org_id = ? AND host_ref = ? AND port = ?",
				scanJob.OrgID, host, port).First(&svc).Error == nil {
				serviceID = svc.ID
			} else {
				// Create a placeholder service record so the FK is satisfied
				now := time.Now()
				svc = models.Service{
					OrgID:       scanJob.OrgID,
					HostID:      d.resolveHostID(scanJob.OrgID, host),
					HostRef:     host,
					Port:        port,
					Protocol:    "tcp",
					Service:     parsedURL.Scheme,
					State:       "open",
					FirstSeenAt: now,
					LastSeenAt:  now,
				}
				svc.ID = uuid.New()
				if err := d.db.FirstOrCreate(&svc, models.Service{
					OrgID:    scanJob.OrgID,
					HostRef:  host,
					Port:     port,
					Protocol: "tcp",
				}).Error; err != nil {
					d.log.Warnw("web scan: failed to create placeholder service, WebAsset will have zero ServiceID",
						"job_id", scanJob.ID, "url", asset.URL, "host", host, "error", err)
				}
				serviceID = svc.ID
			}
		}

		waScannedAt := asset.ScannedAt
		wa := models.WebAsset{
			OrgID:         scanJob.OrgID,
			ServiceID:     serviceID,
			URL:           asset.URL,
			FinalURL:      asset.FinalURL,
			Title:         asset.Title,
			StatusCode:    asset.StatusCode,
			Server:        asset.Server,
			ContentType:   asset.ContentType,
			ContentLength: asset.ContentLength,
			ScannedAt:     waScannedAt,
		}
		if err := d.db.Where("org_id = ? AND url = ?", scanJob.OrgID, asset.URL).
			Assign(models.WebAsset{
				FinalURL:      asset.FinalURL,
				Title:         asset.Title,
				StatusCode:    asset.StatusCode,
				Server:        asset.Server,
				ContentType:   asset.ContentType,
				ContentLength: asset.ContentLength,
				ScannedAt:     waScannedAt,
			}).
			FirstOrCreate(&wa).Error; err != nil {
			d.log.Warnw("web scan: failed to persist web asset", "job_id", scanJob.ID, "url", asset.URL, "error", err)
			// No continue here: certificate/alert/finding/technology
			// extraction below doesn't reference wa.ID, so a WebAsset
			// persistence failure shouldn't also throw away otherwise-
			// good, independent data for the same asset.
		}

		if asset.TLSInfo != nil {
			tls := asset.TLSInfo
			cert := models.Certificate{
				OrgID:           scanJob.OrgID,
				Fingerprint:     tls.Fingerprint,
				Subject:         tls.Subject,
				Issuer:          tls.Issuer,
				NotBefore:       tls.NotBefore,
				NotAfter:        tls.NotAfter,
				IsExpired:       tls.IsExpired,
				IsWildcard:      tls.IsWildcard,
				IsSelfSigned:    tls.IsSelfSigned,
				KeyAlg:          tls.KeyAlg,
				SignatureAlg:    tls.SignatureAlg,
				SubjectAltNames: models.StringArray(tls.SANs),
				SerialNumber:    tls.SerialNumber,
				Version:         tls.Version,
			}
			if err := d.db.Where("org_id = ? AND fingerprint = ?", scanJob.OrgID, tls.Fingerprint).
				Assign(cert).
				FirstOrCreate(&cert).Error; err != nil {
				d.log.Warnw("web scan: failed to persist certificate", "job_id", scanJob.ID,
					"url", asset.URL, "fingerprint", tls.Fingerprint, "error", err)
			}

			if tls.NotAfter.Before(time.Now().Add(30 * 24 * time.Hour)) {
				alert := models.Alert{
					OrgID:    scanJob.OrgID,
					Type:     "cert_expiry",
					Severity: "high",
					Title:    fmt.Sprintf("Certificate expiring soon: %s", tls.Subject),
					Message:  fmt.Sprintf("Certificate for %s expires on %s", asset.URL, tls.NotAfter.Format("2006-01-02")),
				}
				if err := d.db.Where("org_id = ? AND type = ? AND title = ?",
					scanJob.OrgID, "cert_expiry", alert.Title).
					FirstOrCreate(&alert).Error; err != nil {
					d.log.Warnw("web scan: failed to persist cert-expiry alert", "job_id", scanJob.ID,
						"url", asset.URL, "error", err)
				}
			}
		}

		checker := web.NewSecurityChecker()
		secFindings := checker.Check(ctx, asset.FinalURL)
		for _, sf := range secFindings {
			f := models.Finding{
				OrgID:       scanJob.OrgID,
				ScanJobID:   &scanJob.ID,
				Title:       sf.Title,
				Description: sf.Description,
				Severity:    sf.Severity,
				Category:    sf.Category,
				URL:         sf.URL,
				Evidence:    sf.Evidence,
				Remediation: sf.Remediation,
				CVE:         sf.CVE,
				CVSS:        sf.CVSS,
				Status:      "open",
			}
			if err := d.db.Where("org_id = ? AND title = ? AND url = ?", scanJob.OrgID, sf.Title, sf.URL).
				FirstOrCreate(&f).Error; err != nil {
				d.log.Warnw("web scan: failed to persist finding", "job_id", scanJob.ID,
					"url", sf.URL, "title", sf.Title, "error", err)
			}
		}

		for _, techName := range asset.Technologies {
			tech := models.Technology{
				OrgID:      scanJob.OrgID,
				ServiceID:  &serviceID,
				Name:       techName,
				Source:     "web_scan",
				Confidence: 80,
			}
			if err := d.db.Where("org_id = ? AND service_id = ? AND name = ?", scanJob.OrgID, serviceID, techName).
				Assign(models.Technology{ServiceID: &serviceID, Source: "web_scan", Confidence: 80}).
				FirstOrCreate(&tech).Error; err != nil {
				d.log.Warnw("web scan: failed to persist technology", "job_id", scanJob.ID,
					"url", asset.URL, "technology", techName, "error", err)
			}
		}

		d.saveResult(scanJob, asset.URL, "web", map[string]any{
			"url":          asset.URL,
			"final_url":    asset.FinalURL,
			"status_code":  asset.StatusCode,
			"title":        asset.Title,
			"server":       asset.Server,
			"technologies": asset.Technologies,
		})
		count++
	}

	d.captureScreenshots(ctx, scanJob, screenshotURLs)

	d.log.Infow("web scan complete", "job_id", scanJob.ID, "assets_found", count)
	return nil
}

// screenshotBaseDir mirrors ScreenshotHandler's screenshotDir in
// internal/api/handlers/screenshots.go — same on-disk convention, so
// screenshots taken automatically during a scan and ones taken manually via
// the Toolbox/Screenshots page land in the same place and are servable the
// same way (ScreenshotHandler.Get just reads WebAsset.ScreenshotPath).
const screenshotBaseDir = "/var/rayyan-asm/screenshots"

// captureScreenshots runs gowitness once for every URL discovered by this
// web scan and updates the matching WebAsset rows with the resulting file
// path. Previously screenshots only ever happened via the manual
// Toolbox/Screenshots page (ScreenshotHandler.Capture) — a Full scan never
// took any at all. Best-effort: a missing gowitness binary (or any other
// failure) skips this step entirely rather than failing the scan, same
// philosophy as every other chained tool in this file.
func (d *Dispatcher) captureScreenshots(ctx context.Context, scanJob *models.ScanJob, urls []string) {
	if len(urls) == 0 {
		return
	}
	outDir := filepath.Join(screenshotBaseDir, scanJob.OrgID.String(), scanJob.ID.String())
	results, err := tools.RunGowitness(urls, outDir, 5*time.Minute)
	if err != nil {
		d.log.Debugw("screenshot capture skipped or failed", "job_id", scanJob.ID, "error", err)
		return
	}
	for _, r := range results {
		if r.FilePath == "" {
			continue
		}
		if err := d.db.Model(&models.WebAsset{}).
			Where("org_id = ? AND url = ?", scanJob.OrgID, r.URL).
			Updates(map[string]any{
				"screenshotted":   true,
				"screenshot_path": r.FilePath,
			}).Error; err != nil {
			d.log.Warnw("web scan: failed to record screenshot", "job_id", scanJob.ID, "url", r.URL, "error", err)
		}
	}
}

func (d *Dispatcher) runFull(ctx context.Context, scanJob *models.ScanJob) error {
	steps := []struct {
		name string
		fn   func(context.Context, *models.ScanJob) error
	}{
		{"network", d.runNetwork},
		{"subdomain", d.runSubdomain},
		{"port", d.runPort},
		{"dns", d.runDNS},
		{"web", d.runWeb},
	}

	total := len(steps)
	for i, step := range steps {
		select {
		case <-ctx.Done():
			return ctx.Err()
		default:
		}

		d.log.Infow("full scan step", "job_id", scanJob.ID, "step", step.name, "progress", i*100/total)
		if err := d.db.Model(scanJob).Update("progress", i*100/total).Error; err != nil {
			d.log.Warnw("full scan: failed to persist progress", "job_id", scanJob.ID, "step", step.name, "error", err)
		}

		if err := step.fn(ctx, scanJob); err != nil {
			// Log but don't abort — partial results are better than none
			d.log.Warnw("scan step failed", "step", step.name, "error", err)
		}

		// After subdomain discovery, expand this scan's in-memory target list so
		// the remaining steps (port/dns/web) actually probe what was just found,
		// not just the original root target(s). Without this, runPort/runDNS/
		// runWeb each independently call targetsFromPayload(scanJob), which
		// reads the static list typed in at scan creation — crt.sh/hackertarget/
		// wordlist results from the subdomain step above never reached them, so
		// e.g. Services stayed empty even when dozens of subdomains were found.
		if step.name == "subdomain" {
			d.expandTargetsWithDiscoveredSubdomains(scanJob)
		}
	}
	return nil
}

// expandTargetsWithDiscoveredSubdomains merges every known subdomain for this
// scan's original root domain(s) into scanJob.Targets["targets"], in memory
// only — the scan_jobs row on disk is left untouched so the original payload
// stays accurate for audit/rerun purposes; only the copy the remaining steps
// in this runFull call see is expanded.
//
// Deliberately not scoped to only *this run's* newly-discovered subdomains:
// it pulls every subdomain on record for the domain (org-scoped), including
// ones found by earlier scans. For an attack-surface-management tool that's
// the useful behavior — a "full" scan should sweep the whole known surface,
// not just whatever crt.sh/hackertarget happened to return this time. The
// maxExpanded cap below exists so a domain with a very large subdomain
// history doesn't turn one "full" scan into an unbounded port sweep.
func (d *Dispatcher) expandTargetsWithDiscoveredSubdomains(scanJob *models.ScanJob) {
	const maxExpanded = 500

	original := targetsFromPayload(scanJob)
	if len(original) == 0 {
		return
	}

	seen := make(map[string]bool, len(original))
	merged := make([]string, 0, len(original))
	for _, t := range original {
		key := normalizeDomain(t)
		if !seen[key] {
			seen[key] = true
			merged = append(merged, t)
		}
	}

	for _, root := range original {
		if len(merged) >= maxExpanded {
			break
		}
		normRoot := normalizeDomain(root)
		var domainRec models.Domain
		if err := d.db.Where("org_id = ? AND name = ?", scanJob.OrgID, normRoot).First(&domainRec).Error; err != nil {
			// No Domain row yet — the subdomain step may have failed for this
			// target (e.g. crt.sh/hackertarget both errored). Nothing to expand.
			continue
		}
		var subs []models.Subdomain
		if err := d.db.Where("org_id = ? AND domain_id = ?", scanJob.OrgID, domainRec.ID).
			Order("last_seen_at DESC").
			Limit(maxExpanded).
			Find(&subs).Error; err != nil {
			d.log.Warnw("full scan: failed to load discovered subdomains for target expansion",
				"job_id", scanJob.ID, "domain", normRoot, "error", err)
			continue
		}
		for _, s := range subs {
			if len(merged) >= maxExpanded {
				break
			}
			key := normalizeDomain(s.FQDN)
			if !seen[key] {
				seen[key] = true
				merged = append(merged, s.FQDN)
			}
		}
	}

	if len(merged) > len(original) {
		d.log.Infow("full scan: expanded targets with discovered subdomains",
			"job_id", scanJob.ID, "original_count", len(original), "expanded_count", len(merged))
	}
	scanJob.Targets["targets"] = merged
}

func (d *Dispatcher) saveResult(scanJob *models.ScanJob, target, resultType string, data map[string]any) {
	b, err := json.Marshal(data)
	if err != nil {
		d.log.Warnw("failed to marshal scan result data", "error", err)
		return
	}
	var payload models.JSONB
	if err := json.Unmarshal(b, &payload); err != nil {
		d.log.Warnw("failed to unmarshal scan result data", "error", err)
		return
	}

	result := models.ScanResult{
		OrgID:  scanJob.OrgID,
		JobID:  scanJob.ID,
		Target: target,
		Type:   resultType,
		Status: "completed",
		Data:   payload,
	}
	result.ID = uuid.New()
	if err := d.db.Create(&result).Error; err != nil {
		d.log.Warnw("failed to save scan result", "error", err)
	}
}

func (d *Dispatcher) handleReportGenerate(ctx context.Context, job queue.Job) error {
	reportIDStr, _ := job.Payload["report_id"].(string)
	if reportIDStr == "" {
		return fmt.Errorf("report job missing report_id")
	}
	reportID, err := uuid.Parse(reportIDStr)
	if err != nil {
		return fmt.Errorf("invalid report_id %q: %w", reportIDStr, err)
	}

	var report models.Report
	if err := d.db.First(&report, "id = ?", reportID).Error; err != nil {
		return fmt.Errorf("loading report %s: %w", reportID, err)
	}

	if err := d.db.Model(&report).Update("status", "generating").Error; err != nil {
		d.log.Warnw("report: failed to mark as generating", "report_id", report.ID, "error", err)
	}

	jsonContent, err := d.buildReport(ctx, &report)
	if err != nil {
		if uerr := d.db.Model(&report).Updates(map[string]any{"status": "failed"}).Error; uerr != nil {
			d.log.Warnw("report: failed to mark as failed", "report_id", report.ID, "error", uerr)
		}
		return err
	}
	content, err := d.convertReportContent(jsonContent, report.Format)
	if err != nil {
		if uerr := d.db.Model(&report).Updates(map[string]any{"status": "failed"}).Error; uerr != nil {
			d.log.Warnw("report: failed to mark as failed", "report_id", report.ID, "error", uerr)
		}
		return fmt.Errorf("converting report to %s: %w", report.Format, err)
	}

	dir := filepath.Join("data", "reports")
	if err := os.MkdirAll(dir, 0o750); err != nil {
		if uerr := d.db.Model(&report).Updates(map[string]any{"status": "failed"}).Error; uerr != nil {
			d.log.Warnw("report: failed to mark as failed", "report_id", report.ID, "error", uerr)
		}
		return fmt.Errorf("creating reports dir: %w", err)
	}

	ext := report.Format
	if ext == "" {
		ext = "json"
	}
	filePath := filepath.Join(dir, report.ID.String()+"."+ext)
	if err := os.WriteFile(filePath, content, 0o640); err != nil {
		if uerr := d.db.Model(&report).Updates(map[string]any{"status": "failed"}).Error; uerr != nil {
			d.log.Warnw("report: failed to mark as failed", "report_id", report.ID, "error", uerr)
		}
		return fmt.Errorf("writing report file: %w", err)
	}

	now := time.Now()
	expiry := now.Add(7 * 24 * time.Hour)
	if err := d.db.Model(&report).Updates(map[string]any{
		"status":       "completed",
		"file_path":    filePath,
		"file_size":    int64(len(content)),
		"generated_at": &now,
		"expires_at":   &expiry,
	}).Error; err != nil {
		// The report file is already written to disk at this point — if this
		// update fails the row is stuck at "generating" forever even though
		// generation actually succeeded, with nothing in the UI to explain why.
		d.log.Warnw("report: generated successfully but failed to mark as completed",
			"report_id", report.ID, "file_path", filePath, "error", err)
	}

	d.log.Infow("report generated", "report_id", report.ID, "type", report.Type, "bytes", len(content), "path", filePath)
	return nil
}

// convertReportContent takes the canonical JSON output from buildReport and
// converts it to the format the user requested (csv, html, pdf, xlsx, or
// falls back to json).

// flattenScalarFields walks payload in sorted key order and returns parallel
// headers/values slices. Sorting makes output deterministic across calls
// (Go map iteration order is randomized), which keeps repeated exports of
// the same report byte-identical and prevents the csv/xlsx column order
// from shuffling between runs.
func flattenScalarFields(payload map[string]any) (headers, values []string) {
	keys := make([]string, 0, len(payload))
	for k := range payload {
		keys = append(keys, k)
	}
	sort.Strings(keys)

	headers = make([]string, 0, len(keys))
	values = make([]string, 0, len(keys))
	for _, k := range keys {
		v := payload[k]
		switch tv := v.(type) {
		case []any:
			// Arrays are flattened to a JSON string cell rather than
			// expanded into extra rows/sheets.
			b, _ := json.Marshal(tv)
			headers = append(headers, k)
			values = append(values, string(b))
		default:
			headers = append(headers, k)
			values = append(values, fmt.Sprintf("%v", v))
		}
	}
	return headers, values
}

// excelColumnName converts a zero-based column index into its Excel-style
// column letter (0 -> "A", 25 -> "Z", 26 -> "AA", 701 -> "ZZ", ...).
// A single rune('A'+i) only works for i in [0,25]; beyond that it must wrap
// using the same base-26 (bijective) scheme spreadsheets use.
func excelColumnName(index int) string {
	var col []byte
	for index >= 0 {
		col = append([]byte{byte('A' + index%26)}, col...)
		index = index/26 - 1
	}
	return string(col)
}

// xlsxFileOrder is the fixed write order for the in-memory OOXML zip.
// The OPC/OOXML spec expects [Content_Types].xml to be the first entry in
// the archive; ranging over a map (random iteration order) can write it
// anywhere, which some strict readers reject. xlsxFileOrder below preserves
// this slice order when writing entries.
var xlsxFileOrder = []string{
	"[Content_Types].xml",
	"_rels/.rels",
	"xl/workbook.xml",
	"xl/_rels/workbook.xml.rels",
	"xl/worksheets/sheet1.xml",
}

func (d *Dispatcher) convertReportContent(jsonData []byte, format string) ([]byte, error) {
	switch format {
	case "pdf":
		// Build the HTML body first, then attempt to convert via wkhtmltopdf.
		// If wkhtmltopdf is not installed we fall back to returning the HTML
		// with a Content-Type that browsers render correctly (the file is saved
		// with a .pdf extension by the Download handler so the UI shows it as a
		// PDF; most browsers will still display it as HTML, which is acceptable
		// for environments without a headless renderer).
		htmlBytes, err := d.convertReportContent(jsonData, "html")
		if err != nil {
			return nil, fmt.Errorf("building html for pdf: %w", err)
		}
		// Try wkhtmltopdf if available.
		if _, lookErr := os.LookupEnv("RAYYAN_SKIP_WKHTMLTOPDF"); lookErr {
			// Opt-out env var set — return HTML.
			return htmlBytes, nil
		}
		wkPath, _ := exec.LookPath("wkhtmltopdf")
		if wkPath == "" {
			d.log.Warn("wkhtmltopdf not found; serving HTML as PDF fallback")
			return htmlBytes, nil
		}
		// Write HTML to a temp file, convert to PDF, read result.
		tmp, err := os.CreateTemp("", "rayyan-report-*.html")
		if err != nil {
			return htmlBytes, nil // non-fatal fallback
		}
		defer os.Remove(tmp.Name())
		if _, err := tmp.Write(htmlBytes); err != nil {
			_ = tmp.Close()
			return htmlBytes, nil
		}
		_ = tmp.Close()

		outFile := tmp.Name() + ".pdf"
		defer os.Remove(outFile)

		cmd := exec.Command(wkPath, "--quiet", "--disable-javascript",
			"--margin-top", "10mm", "--margin-bottom", "10mm",
			"--margin-left", "10mm", "--margin-right", "10mm",
			tmp.Name(), outFile)
		if out, err := cmd.CombinedOutput(); err != nil {
			d.log.Warnw("wkhtmltopdf failed; serving HTML as PDF fallback",
				"error", err, "output", string(out))
			return htmlBytes, nil
		}
		pdfBytes, err := os.ReadFile(outFile)
		if err != nil {
			return htmlBytes, nil
		}
		return pdfBytes, nil

	case "csv":
		var payload map[string]any
		if err := json.Unmarshal(jsonData, &payload); err != nil {
			return nil, err
		}
		var buf bytes.Buffer
		w := csv.NewWriter(&buf)
		// Write a flat key=value header + one data row. Keys are sorted so
		// headers and values stay aligned and column order is stable across
		// repeated exports (see flattenScalarFields).
		headers, values := flattenScalarFields(payload)
		if err := w.Write(headers); err != nil {
			return nil, err
		}
		if err := w.Write(values); err != nil {
			return nil, err
		}
		w.Flush()
		return buf.Bytes(), w.Error()
	case "html":
		var payload map[string]any
		if err := json.Unmarshal(jsonData, &payload); err != nil {
			return nil, err
		}
		if rt, _ := payload["report_type"].(string); rt == "executive" {
			return buildExecutiveReportHTML(jsonData)
		}
		var buf bytes.Buffer
		buf.WriteString("<!DOCTYPE html><html><head><meta charset=\"UTF-8\">")
		buf.WriteString("<title>Rayyan ASM Report</title>")
		buf.WriteString("<style>body{font-family:sans-serif;padding:2rem}pre{background:#f4f4f4;padding:1rem;border-radius:4px}</style>")
		buf.WriteString("</head><body><h1>Rayyan ASM Report</h1><pre>")
		prettyJSON, err := json.MarshalIndent(json.RawMessage(jsonData), "", "  ")
		if err != nil {
			return nil, err
		}
		_, _ = buf.Write(prettyJSON)
		buf.WriteString("</pre></body></html>")
		return buf.Bytes(), nil
	case "xlsx":
		// Build a minimal but valid OOXML workbook without external dependencies.
		// Structure: [Content_Types].xml, _rels/.rels, xl/workbook.xml,
		// xl/_rels/workbook.xml.rels, xl/worksheets/sheet1.xml.
		var payload map[string]any
		if err := json.Unmarshal(jsonData, &payload); err != nil {
			return nil, err
		}

		// Sorted headers/values keep columns aligned and stable across runs
		// (see flattenScalarFields).
		headers, values := flattenScalarFields(payload)

		// xmlEsc escapes characters that are illegal in XML text nodes.
		xmlEsc := func(s string) string {
			s = strings.ReplaceAll(s, "&", "&amp;")
			s = strings.ReplaceAll(s, "<", "&lt;")
			s = strings.ReplaceAll(s, ">", "&gt;")
			s = strings.ReplaceAll(s, "\"", "&quot;")
			return s
		}

		// Build sheet1.xml row by row (inline strings, type="inlineStr").
		// excelColumnName supports arbitrarily many columns (AA, AB, ... ZZ,
		// AAA, ...), unlike a bare rune('A'+i) which overflows past column 26.
		var sheetBuf bytes.Buffer
		sheetBuf.WriteString(`<?xml version="1.0" encoding="UTF-8" standalone="yes"?>`)
		sheetBuf.WriteString(`<worksheet xmlns="http://schemas.openxmlformats.org/spreadsheetml/2006/main">`)
		sheetBuf.WriteString(`<sheetData>`)
		// Header row
		sheetBuf.WriteString(`<row r="1">`)
		for i, h := range headers {
			col := excelColumnName(i)
			sheetBuf.WriteString(fmt.Sprintf(`<c r="%s1" t="inlineStr"><is><t>%s</t></is></c>`, col, xmlEsc(h)))
		}
		sheetBuf.WriteString(`</row>`)
		// Values row
		sheetBuf.WriteString(`<row r="2">`)
		for i, v := range values {
			col := excelColumnName(i)
			sheetBuf.WriteString(fmt.Sprintf(`<c r="%s2" t="inlineStr"><is><t>%s</t></is></c>`, col, xmlEsc(v)))
		}
		sheetBuf.WriteString(`</row>`)
		sheetBuf.WriteString(`</sheetData></worksheet>`)

		// Assemble the zip archive in memory.
		var zipBuf bytes.Buffer
		zw := zip.NewWriter(&zipBuf)

		files := map[string]string{
			"[Content_Types].xml": `<?xml version="1.0" encoding="UTF-8" standalone="yes"?>` +
				`<Types xmlns="http://schemas.openxmlformats.org/package/2006/content-types">` +
				`<Default Extension="rels" ContentType="application/vnd.openxmlformats-package.relationships+xml"/>` +
				`<Default Extension="xml" ContentType="application/xml"/>` +
				`<Override PartName="/xl/workbook.xml" ContentType="application/vnd.openxmlformats-officedocument.spreadsheetml.sheet.main+xml"/>` +
				`<Override PartName="/xl/worksheets/sheet1.xml" ContentType="application/vnd.openxmlformats-officedocument.spreadsheetml.worksheet+xml"/>` +
				`</Types>`,
			"_rels/.rels": `<?xml version="1.0" encoding="UTF-8" standalone="yes"?>` +
				`<Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships">` +
				`<Relationship Id="rId1" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/officeDocument" Target="xl/workbook.xml"/>` +
				`</Relationships>`,
			"xl/workbook.xml": `<?xml version="1.0" encoding="UTF-8" standalone="yes"?>` +
				`<workbook xmlns="http://schemas.openxmlformats.org/spreadsheetml/2006/main" xmlns:r="http://schemas.openxmlformats.org/officeDocument/2006/relationships">` +
				`<sheets><sheet name="Report" sheetId="1" r:id="rId1"/></sheets>` +
				`</workbook>`,
			"xl/_rels/workbook.xml.rels": `<?xml version="1.0" encoding="UTF-8" standalone="yes"?>` +
				`<Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships">` +
				`<Relationship Id="rId1" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/worksheet" Target="worksheets/sheet1.xml"/>` +
				`</Relationships>`,
			"xl/worksheets/sheet1.xml": sheetBuf.String(),
		}
		// Write entries in xlsxFileOrder (not by ranging over the map) so
		// [Content_Types].xml is always first, per the OPC/OOXML spec.
		for _, name := range xlsxFileOrder {
			content, ok := files[name]
			if !ok {
				return nil, fmt.Errorf("xlsx: missing expected entry %s", name)
			}
			w, err := zw.Create(name)
			if err != nil {
				return nil, fmt.Errorf("xlsx: creating entry %s: %w", name, err)
			}
			if _, err := w.Write([]byte(content)); err != nil {
				return nil, fmt.Errorf("xlsx: writing entry %s: %w", name, err)
			}
		}
		if err := zw.Close(); err != nil {
			return nil, fmt.Errorf("xlsx: closing zip: %w", err)
		}
		return zipBuf.Bytes(), nil

	default:
		// json or any unrecognised format — return as-is (pretty-printed)
		return json.MarshalIndent(json.RawMessage(jsonData), "", "  ")
	}
}

// buildExecutiveReportHTML renders the executive report payload (see the
// "executive" case in buildReport) as a formatted document instead of a raw
// JSON dump — KPI cards, a severity breakdown table, a top-10 findings
// table, and the narrative summary sentence. wkhtmltopdf (see the "pdf"
// case above) converts this same HTML to PDF, so improving this one
// template upgrades both the HTML and PDF exports at once.
func buildExecutiveReportHTML(jsonData []byte) ([]byte, error) {
	var payload struct {
		Generated   time.Time        `json:"generated"`
		OrgName     string           `json:"org_name"`
		Summary     string           `json:"summary"`
		RiskScore   float64          `json:"risk_score"`
		RiskTier    string           `json:"risk_tier"`
		KPIs        executive.Live   `json:"kpis"`
		TopFindings []models.Finding `json:"top_findings"`
	}
	if err := json.Unmarshal(jsonData, &payload); err != nil {
		return nil, err
	}

	tierColor := map[string]string{
		"critical": "#C81E3A", "high": "#A75709", "medium": "#8D6608", "low": "#147D3B",
	}[payload.RiskTier]
	if tierColor == "" {
		tierColor = "#565D6D"
	}
	sevColor := func(sev string) string {
		switch sev {
		case "critical":
			return "#C81E3A"
		case "high":
			return "#A75709"
		case "medium":
			return "#8D6608"
		case "low":
			return "#147D3B"
		default:
			return "#565D6D"
		}
	}

	esc := func(s string) string {
		s = strings.ReplaceAll(s, "&", "&amp;")
		s = strings.ReplaceAll(s, "<", "&lt;")
		s = strings.ReplaceAll(s, ">", "&gt;")
		return s
	}

	orgName := payload.OrgName
	if orgName == "" {
		orgName = "Attack Surface"
	}

	var buf bytes.Buffer
	buf.WriteString("<!DOCTYPE html><html><head><meta charset=\"UTF-8\"><title>Executive Summary</title><style>")
	buf.WriteString(`
		body{font-family:-apple-system,'Segoe UI',Helvetica,Arial,sans-serif;color:#12151C;padding:0;margin:0;background:#fff}
		.page{max-width:900px;margin:0 auto;padding:40px}
		.header{display:flex;justify-content:space-between;align-items:baseline;border-bottom:2px solid #12151C;padding-bottom:16px;margin-bottom:24px}
		.header h1{font-size:22px;margin:0}
		.header .meta{color:#636873;font-size:13px}
		.summary{background:#F4F5F7;border-radius:8px;padding:20px 24px;margin-bottom:28px;font-size:14px;line-height:1.6}
		.score-row{display:flex;align-items:center;gap:16px;margin-bottom:28px}
		.score-badge{font-size:32px;font-weight:700;color:#fff;border-radius:8px;padding:10px 22px;background:` + tierColor + `}
		.score-label{font-size:13px;color:#636873;text-transform:uppercase;letter-spacing:0.04em}
		.kpi-grid{display:grid;grid-template-columns:repeat(4,1fr);gap:12px;margin-bottom:32px}
		.kpi-card{border:1px solid #DDE1E8;border-radius:8px;padding:14px}
		.kpi-card .n{font-size:22px;font-weight:700}
		.kpi-card .l{font-size:12px;color:#636873;margin-top:2px}
		h2{font-size:16px;border-bottom:1px solid #DDE1E8;padding-bottom:8px;margin-top:32px}
		table{width:100%;border-collapse:collapse;font-size:13px;margin-top:12px}
		th{text-align:left;color:#636873;font-weight:600;padding:8px;border-bottom:1px solid #DDE1E8}
		td{padding:8px;border-bottom:1px solid #E9EBEF;vertical-align:top}
		.sev-pill{display:inline-block;padding:2px 8px;border-radius:12px;color:#fff;font-size:11px;font-weight:600;text-transform:uppercase}
		.empty{color:#636873;font-size:13px;padding:16px 0}
	`)
	buf.WriteString("</style></head><body><div class=\"page\">")

	fmt.Fprintf(&buf, `<div class="header"><h1>%s — Executive Summary</h1><div class="meta">Generated %s</div></div>`,
		esc(orgName), payload.Generated.Format("Jan 2, 2006 15:04 MST"))

	fmt.Fprintf(&buf, `<div class="summary">%s</div>`, esc(payload.Summary))

	fmt.Fprintf(&buf, `<div class="score-row"><div class="score-badge">%.0f</div><div><div class="score-label">Risk score</div><div style="font-size:15px;font-weight:600;text-transform:capitalize">%s</div></div></div>`,
		payload.RiskScore, esc(payload.RiskTier))

	k := payload.KPIs
	buf.WriteString(`<div class="kpi-grid">`)
	kpis := []struct {
		n     int64
		label string
	}{
		{k.TotalAssets, "Total assets"},
		{k.InternetFacing, "Internet-facing"},
		{k.TotalDomains, "Domains"},
		{k.TotalServices, "Services"},
		{k.OpenFindings, "Open findings"},
		{k.CriticalAttackPathCount, "Critical attack paths"},
		{k.ExpiringCerts, "Expiring certs"},
		{k.OpenAlerts, "Open alerts"},
	}
	for _, kpi := range kpis {
		fmt.Fprintf(&buf, `<div class="kpi-card"><div class="n">%d</div><div class="l">%s</div></div>`, kpi.n, esc(kpi.label))
	}
	buf.WriteString(`</div>`)

	buf.WriteString(`<h2>Findings by severity</h2><table><tr><th>Severity</th><th>Open count</th></tr>`)
	sevRows := []struct {
		label string
		n     int64
	}{
		{"critical", k.CriticalFindings}, {"high", k.HighFindings},
		{"medium", k.MediumFindings}, {"low", k.LowFindings},
	}
	for _, r := range sevRows {
		fmt.Fprintf(&buf, `<tr><td><span class="sev-pill" style="background:%s">%s</span></td><td>%d</td></tr>`,
			sevColor(r.label), esc(r.label), r.n)
	}
	buf.WriteString(`</table>`)

	buf.WriteString(`<h2>Top open findings</h2>`)
	if len(payload.TopFindings) == 0 {
		buf.WriteString(`<div class="empty">No open findings.</div>`)
	} else {
		buf.WriteString(`<table><tr><th>Severity</th><th>Title</th><th>CVSS</th><th>Asset</th></tr>`)
		for _, f := range payload.TopFindings {
			cvss := "—"
			if f.CVSS > 0 {
				cvss = fmt.Sprintf("%.1f", f.CVSS)
			}
			asset := f.URL
			if asset == "" {
				asset = "—"
			}
			fmt.Fprintf(&buf, `<tr><td><span class="sev-pill" style="background:%s">%s</span></td><td>%s</td><td>%s</td><td>%s</td></tr>`,
				sevColor(f.Severity), esc(f.Severity), esc(f.Title), cvss, esc(asset))
		}
		buf.WriteString(`</table>`)
	}

	buf.WriteString(`</div></body></html>`)
	return buf.Bytes(), nil
}

func (d *Dispatcher) buildReport(ctx context.Context, report *models.Report) ([]byte, error) {
	orgID := report.OrgID

	switch report.Type {
	case "asset_inventory":
		var hosts []models.Host
		d.db.Where("org_id = ?", orgID).Find(&hosts)
		var domains []models.Domain
		d.db.Where("org_id = ?", orgID).Find(&domains)
		return json.Marshal(map[string]any{
			"report_type":   "asset_inventory",
			"generated":     time.Now(),
			"org_id":        orgID,
			"hosts":         hosts,
			"domains":       domains,
			"total_hosts":   len(hosts),
			"total_domains": len(domains),
		})

	case "service_inventory":
		var services []models.Service
		d.db.Where("org_id = ?", orgID).Find(&services)
		return json.Marshal(map[string]any{
			"report_type":    "service_inventory",
			"generated":      time.Now(),
			"services":       services,
			"total_services": len(services),
		})

	case "exposure":
		var openServices []models.Service
		d.db.Where("org_id = ? AND state = 'open'", orgID).Find(&openServices)
		var expCerts []models.Certificate
		d.db.Where("org_id = ? AND not_after < ?", orgID, time.Now().Add(30*24*time.Hour)).Find(&expCerts)
		var openAlerts []models.Alert
		d.db.Where("org_id = ? AND status = 'open'", orgID).Find(&openAlerts)
		return json.Marshal(map[string]any{
			"report_type":         "exposure",
			"generated":           time.Now(),
			"open_services":       openServices,
			"expiring_certs":      expCerts,
			"open_alerts":         openAlerts,
			"open_service_count":  len(openServices),
			"expiring_cert_count": len(expCerts),
			"open_alert_count":    len(openAlerts),
		})

	case "executive":
		// Previously this was 4 raw counts (domains/hosts/services/open
		// alerts) with no risk score, no severity breakdown, no findings,
		// and no narrative — every "report" was functionally the same
		// four numbers regardless of an org's actual posture. The
		// executive engine already computes all of this for the live
		// ExecutiveDashboardPage; reuse it here instead of maintaining a
		// second, much thinner, copy of the same metrics.
		live, err := executive.New(d.db, d.log).Summary(orgID)
		if err != nil {
			return nil, fmt.Errorf("computing executive summary: %w", err)
		}

		var topFindings []models.Finding
		if err := d.db.Where("org_id = ? AND status = 'open'", orgID).
			Order("cvss DESC, created_at DESC").
			Limit(10).
			Find(&topFindings).Error; err != nil {
			d.log.Warnw("executive report: failed to load top findings", "org_id", orgID, "error", err)
		}

		var org models.Organization
		orgName := ""
		if err := d.db.Select("name").First(&org, "id = ?", orgID).Error; err == nil {
			orgName = org.Name
		}

		return json.Marshal(map[string]any{
			"report_type":  "executive",
			"generated":    time.Now(),
			"org_id":       orgID,
			"org_name":     orgName,
			"summary":      executiveSummarySentence(orgName, live),
			"risk_score":   live.AvgRiskScore,
			"risk_tier":    riskTierLabel(live.AvgRiskScore),
			"kpis":         live,
			"top_findings": topFindings,
		})

	default:
		return nil, fmt.Errorf("unsupported report type: %s", report.Type)
	}
}

// executiveSummarySentence turns the raw KPI numbers into the one or two
// sentences a non-technical reader can act on without opening the rest of
// the report — commercial ASM tools lead every executive report with this,
// and it was previously missing entirely.
func executiveSummarySentence(orgName string, l executive.Live) string {
	who := orgName
	if who == "" {
		who = "Your organization"
	}
	postureWord := "stable"
	switch riskTierLabel(l.AvgRiskScore) {
	case "critical":
		postureWord = "critical"
	case "high":
		postureWord = "elevated"
	case "medium":
		postureWord = "moderate"
	}
	sentence := fmt.Sprintf(
		"%s is tracking %d internet-facing assets across %d domains, with an average risk score of %.0f/100 (%s posture). ",
		who, l.InternetFacing, l.TotalDomains, l.AvgRiskScore, postureWord,
	)
	if l.CriticalFindings > 0 || l.HighFindings > 0 {
		sentence += fmt.Sprintf(
			"%d critical and %d high-severity findings are currently open and require attention.",
			l.CriticalFindings, l.HighFindings,
		)
	} else {
		sentence += "No critical or high-severity findings are currently open."
	}
	return sentence
}

// riskTierLabel classifies a 0-100 score into the same four bands the risk
// score engine already uses (see internal/modules/riskscore.tierFromScore)
// — duplicated here rather than imported because tierFromScore is
// unexported and this report only needs the label, not the full scoring
// engine.
func riskTierLabel(score float64) string {
	switch {
	case score >= 75:
		return "critical"
	case score >= 50:
		return "high"
	case score >= 25:
		return "medium"
	default:
		return "low"
	}
}

// normalizeDomain strips protocol prefixes and trailing slashes so scanners
// always receive a bare domain (e.g. "example.com" not "https://example.com/").
func normalizeDomain(d string) string {
	d = strings.TrimSpace(d)
	d = strings.TrimPrefix(d, "https://")
	d = strings.TrimPrefix(d, "http://")
	d = strings.TrimSuffix(d, "/")
	return d
}

// persistSubdomainResult upserts one discovered subdomain, shared by every
// subdomain source (crt.sh/hackertarget/wordlist here, plus the chained
// subfinder/amass/assetfinder/findomain/VirusTotal sources below) so they
// all get identical dedup/update behaviour. Returns true if this call
// resulted in a new-or-updated row being persisted.
func (d *Dispatcher) persistSubdomainResult(scanJob *models.ScanJob, domainRec models.Domain, domain, fqdn string, ips []string, source string) bool {
	fqdn = strings.ToLower(strings.TrimSuffix(fqdn, "."))
	if fqdn == "" {
		return false
	}
	name := strings.TrimSuffix(fqdn, "."+domain)
	now := time.Now()
	sub := models.Subdomain{
		OrgID:         scanJob.OrgID,
		DomainID:      domainRec.ID,
		Name:          name,
		FQDN:          fqdn,
		IPs:           models.StringArray(ips),
		Source:        source,
		Status:        "active",
		FirstSeenAt:   now,
		LastSeenAt:    now,
		LastScannedAt: &now,
	}
	if err := d.db.Where("org_id = ? AND fqdn = ?", scanJob.OrgID, fqdn).
		Assign(models.Subdomain{
			IPs:           models.StringArray(ips),
			Status:        "active",
			LastSeenAt:    now,
			LastScannedAt: &now,
		}).
		FirstOrCreate(&sub).Error; err != nil {
		d.log.Warnw("subdomain scan: failed to persist subdomain", "job_id", scanJob.ID,
			"fqdn", fqdn, "source", source, "error", err)
		return false
	}

	d.saveResult(scanJob, fqdn, "subdomain", map[string]any{
		"fqdn":   fqdn,
		"ips":    ips,
		"source": source,
	})
	return true
}

// chainedSubdomainTool pairs a source name with the toolrunner function that
// produces it, so the loop in chainExtraSubdomainSources can stay a single
// small loop instead of four near-identical copy-pasted blocks.
type chainedSubdomainTool struct {
	source string
	run    func(target string, timeout time.Duration) ([]tools.SubdomainResult, error)
}

// chainExtraSubdomainSources runs every additional subdomain source beyond
// the built-in crt.sh/hackertarget/wordlist scan: the free external tools
// (subfinder, amass, assetfinder, findomain — installed via the Docker
// tool-install stages, invoked here the same way the toolrunner Workflow
// system does) plus the paid API providers (SecurityTrails via the shared
// intelligence.Engine, VirusTotal via a direct client call) when
// configured. Every source here is independently best-effort: a missing
// binary, an unconfigured API key, or a provider-side error only skips
// that one source (logged at Warn) and never fails the scan — the same
// "continue on step failure" philosophy already used for network/port/
// dns/web in runFull.
const chainedSubdomainTimeout = 90 * time.Second

func (d *Dispatcher) chainExtraSubdomainSources(ctx context.Context, scanJob *models.ScanJob, domainRec models.Domain, domain string) int {
	total := 0

	freeTools := []chainedSubdomainTool{
		{"subfinder", tools.RunSubfinder},
		{"amass", tools.RunAmass},
		{"assetfinder", tools.RunAssetfinder},
		{"findomain", tools.RunFindomain},
	}
	for _, t := range freeTools {
		if ctx.Err() != nil {
			return total
		}
		results, err := t.run(domain, chainedSubdomainTimeout)
		if err != nil {
			// Expected/routine when the binary isn't installed or the
			// scan environment doesn't have it — not worth more than a
			// debug-level breadcrumb, same as any other optional tool.
			d.log.Debugw("chained subdomain source unavailable", "source", t.source, "domain", domain, "error", err)
			continue
		}
		for _, r := range results {
			if d.persistSubdomainResult(scanJob, domainRec, domain, r.Subdomain, nil, t.source) {
				total++
			}
		}
	}

	if d.intel != nil {
		if _, err := d.intel.EnrichDomain(ctx, scanJob.OrgID, domain); err != nil {
			// intelligence.Engine already logs its own per-provider
			// warnings (e.g. "API key not configured"); this is just the
			// outer breadcrumb that the chain attempted it. It also
			// already persists any newly-found subdomains directly, so
			// there's no separate persistSubdomainResult call needed here.
			d.log.Debugw("securitytrails enrichment skipped or failed", "domain", domain, "error", err)
		}
	}

	d.snapWHOIS(scanJob, domain)

	if d.vtAPIKey != "" {
		vt := cloud.NewVirusTotalClient(d.vtAPIKey, d.log)
		vtCtx, cancel := context.WithTimeout(ctx, chainedSubdomainTimeout)
		found, err := vt.GetSubdomains(vtCtx, domain)
		cancel()
		if err != nil {
			d.log.Debugw("virustotal subdomain lookup failed", "domain", domain, "error", err)
		} else {
			for _, fqdn := range found {
				if d.persistSubdomainResult(scanJob, domainRec, domain, fqdn, nil, "virustotal") {
					total++
				}
			}
		}
	}

	// Wayback Machine (Internet Archive CDX API): free, no API key, so it
	// runs unconditionally for every scan like crt.sh rather than being
	// gated behind an operator-configured credential. It often surfaces
	// long-decommissioned subdomains (old staging/marketing hosts) that
	// still resolve but never show up in current certificate-transparency
	// logs or DNS wordlists.
	wb := cloud.NewWaybackClient(d.log)
	wbCtx, wbCancel := context.WithTimeout(ctx, chainedSubdomainTimeout)
	found, err := wb.GetSubdomains(wbCtx, domain)
	wbCancel()
	if err != nil {
		d.log.Debugw("wayback subdomain lookup failed", "domain", domain, "error", err)
	} else {
		for _, fqdn := range found {
			if d.persistSubdomainResult(scanJob, domainRec, domain, fqdn, nil, "wayback") {
				total++
			}
		}
	}

	return total
}

// snapWHOIS performs an RDAP lookup for domain and stores a WHOISHistory
// snapshot, using the exact same shared whois.FetchData the manual
// AdminOpsHandler.SnapWHOIS endpoint uses. Previously WHOIS only ever
// happened via that manual endpoint, or via the separate raw-`whois`-binary
// Toolbox lookup — never automatically during a scan. Best-effort: a
// failed RDAP lookup just gets recorded as an empty/error snapshot (whois.
// FetchData already encodes the failure reason into the "raw" field)
// rather than aborting the scan.
func (d *Dispatcher) snapWHOIS(scanJob *models.ScanJob, domain string) {
	data := whois.FetchData(domain)
	record := models.WHOISHistory{
		ID:         uuid.New(),
		OrgID:      scanJob.OrgID,
		Domain:     domain,
		Registrar:  data["registrar"],
		Registrant: data["registrant"],
		Raw:        data["raw"],
		SnappedAt:  time.Now(),
	}
	if exp, ok := data["expiry_date"]; ok && exp != "" {
		if t, err := time.Parse(time.RFC3339, exp); err == nil {
			record.ExpiryDate = &t
		}
	}
	if reg, ok := data["registration_date"]; ok && reg != "" {
		if t, err := time.Parse(time.RFC3339, reg); err == nil {
			record.RegistrationDate = &t
		}
	}
	if err := d.db.Create(&record).Error; err != nil {
		d.log.Warnw("whois snapshot: failed to persist", "domain", domain, "error", err)
	}
}

func (d *Dispatcher) runSubdomain(ctx context.Context, scanJob *models.ScanJob) error {
	targets := targetsFromPayload(scanJob)
	if len(targets) == 0 {
		return fmt.Errorf("no targets specified")
	}

	opts := subdomain.ScanOptions{
		Workers:         50,
		UseCRTSH:        true,
		UseHackerTarget: true,
		ResolveDNS:      true,
	}

	total := 0
	for _, domain := range targets {
		domain = normalizeDomain(domain)
		opts.Domain = domain
		resultCh, err := d.subdomain.Scan(ctx, opts)
		if err != nil {
			d.log.Warnw("subdomain scan error", "domain", domain, "error", err)
			continue
		}

		var domainRec models.Domain
		if err := d.db.Where("org_id = ? AND name = ?", scanJob.OrgID, domain).
			FirstOrCreate(&domainRec, models.Domain{
				OrgID: scanJob.OrgID,
				Name:  domain,
			}).Error; err != nil {
			d.log.Warnw("domain lookup failed", "domain", domain, "error", err)
			continue
		}

		for result := range resultCh {
			if d.persistSubdomainResult(scanJob, domainRec, domain, result.FQDN, result.IPs, result.Source) {
				total++
			}
		}

		total += d.chainExtraSubdomainSources(ctx, scanJob, domainRec, domain)
	}

	d.log.Infow("subdomain scan complete", "job_id", scanJob.ID, "found", total)
	return nil
}

// handleSubdomainScan handles dedicated subdomain_scan queue jobs (for scheduled runs).
func (d *Dispatcher) handleSubdomainScan(ctx context.Context, job queue.Job) error {
	domainName, _ := job.Payload["domain"].(string)
	orgIDStr, _ := job.Payload["org_id"].(string)
	if domainName == "" || orgIDStr == "" {
		return fmt.Errorf("subdomain_scan job missing domain or org_id")
	}

	orgID, err := uuid.Parse(orgIDStr)
	if err != nil {
		return fmt.Errorf("invalid org_id: %w", err)
	}

	domainName = normalizeDomain(domainName)

	opts := subdomain.ScanOptions{
		Domain:          domainName,
		Workers:         50,
		UseCRTSH:        true,
		UseHackerTarget: true,
		ResolveDNS:      true,
	}

	resultCh, err := d.subdomain.Scan(ctx, opts)
	if err != nil {
		return err
	}

	var domainRec models.Domain
	if err := d.db.Where("org_id = ? AND name = ?", orgID, domainName).
		FirstOrCreate(&domainRec, models.Domain{OrgID: orgID, Name: domainName}).Error; err != nil {
		return fmt.Errorf("domain lookup: %w", err)
	}

	count := 0
	for result := range resultCh {
		name := strings.TrimSuffix(result.FQDN, "."+domainName)
		now := time.Now()
		sub := models.Subdomain{
			OrgID:         orgID,
			DomainID:      domainRec.ID,
			Name:          name,
			FQDN:          result.FQDN,
			IPs:           models.StringArray(result.IPs),
			Source:        result.Source,
			Status:        "active",
			FirstSeenAt:   now,
			LastSeenAt:    now,
			LastScannedAt: &now,
		}
		if err := d.db.Where("org_id = ? AND fqdn = ?", orgID, result.FQDN).
			Assign(models.Subdomain{
				IPs:        models.StringArray(result.IPs),
				Status:     "active",
				LastSeenAt: now,
			}).
			FirstOrCreate(&sub).Error; err != nil {
			d.log.Warnw("scheduled subdomain scan: failed to persist subdomain", "domain", domainName,
				"fqdn", result.FQDN, "error", err)
			continue
		}
		count++
	}

	d.log.Infow("scheduled subdomain scan complete", "domain", domainName, "found", count)
	return nil
}
