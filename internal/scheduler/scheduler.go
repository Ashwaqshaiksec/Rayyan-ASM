package scheduler

import (
	"context"
	"encoding/json"
	"fmt"
	"net"
	"os"
	"strconv"
	"time"

	"github.com/ShadooowX/rayyan-asm/internal/api/handlers"
	cryptoutil "github.com/ShadooowX/rayyan-asm/internal/crypto"
	"github.com/ShadooowX/rayyan-asm/internal/models"
	"github.com/ShadooowX/rayyan-asm/internal/modules/cloud"
	"github.com/ShadooowX/rayyan-asm/internal/modules/executive"
	"github.com/ShadooowX/rayyan-asm/internal/modules/intelligence"
	"github.com/ShadooowX/rayyan-asm/internal/queue"
	"github.com/google/uuid"
	"github.com/robfig/cron/v3"
	"go.uber.org/zap"
	"gorm.io/gorm"
)

type Scheduler struct {
	db        *gorm.DB
	queue     *queue.Queue
	log       *zap.SugaredLogger
	cron      *cron.Cron
	executive *executive.Engine
	intel     *intelligence.Engine
	// credKey is the AES-256 key (32 bytes) for decrypting CloudProviderCredential
	// rows at sync time. nil disables scheduled cloud sync.
	credKey []byte
}

func New(db *gorm.DB, q *queue.Queue, log *zap.SugaredLogger) *Scheduler {
	return &Scheduler{
		db:        db,
		queue:     q,
		log:       log,
		cron:      cron.New(cron.WithSeconds()),
		executive: executive.New(db, log),
	}
}

// SetCredentialKey sets the AES-256 decryption key used by the scheduler to
// read stored cloud provider credentials at sync time. Must be called before
// Start() for scheduled cloud sync to be active.
func (s *Scheduler) SetCredentialKey(key []byte) {
	s.credKey = key
}

// SetIntelEngine wires the intelligence engine into the scheduler so that
// continuous-monitoring jobs are dispatched on their cadence automatically.
func (s *Scheduler) SetIntelEngine(e *intelligence.Engine) {
	s.intel = e
}

func (s *Scheduler) Start() {
	// Periodic: check for scheduled scan jobs every minute
	if _, err := s.cron.AddFunc("0 * * * * *", s.dispatchScheduledScans); err != nil {
		s.log.Errorw("failed to register cron job", "expr", "0 * * * * *", "job", "dispatchScheduledScans", "error", err)
	}

	// Periodic: check for certificate expiry every 6 hours
	if _, err := s.cron.AddFunc("0 0 */6 * * *", s.checkCertExpiry); err != nil {
		s.log.Errorw("failed to register cron job", "expr", "0 0 */6 * * *", "job", "checkCertExpiry", "error", err)
	}

	// Periodic: check for new assets (change detection) every hour
	if _, err := s.cron.AddFunc("0 0 * * * *", s.runChangeDetection); err != nil {
		s.log.Errorw("failed to register cron job", "expr", "0 0 * * * *", "job", "runChangeDetection", "error", err)
	}

	// Periodic: dead subdomain detection every 4 hours
	if _, err := s.cron.AddFunc("0 0 */4 * * *", s.detectDeadSubdomains); err != nil {
		s.log.Errorw("failed to register cron job", "expr", "0 0 */4 * * *", "job", "detectDeadSubdomains", "error", err)
	}

	// Periodic: per-domain cron scans every minute
	if _, err := s.cron.AddFunc("0 * * * * *", s.dispatchDomainCronScans); err != nil {
		s.log.Errorw("failed to register cron job", "expr", "0 * * * * *", "job", "dispatchDomainCronScans", "error", err)
	}

	// Periodic: SLA breach detection every hour
	if _, err := s.cron.AddFunc("0 5 * * * *", s.checkSLABreaches); err != nil {
		s.log.Errorw("failed to register cron job", "expr", "0 5 * * * *", "job", "checkSLABreaches", "error", err)
	}

	// Daily: compute executive dashboard KPI snapshots for every org, just
	// after midnight UTC, so trend charts have a fresh data point each day.
	if _, err := s.cron.AddFunc("0 30 0 * * *", s.computeExecutiveKPIs); err != nil {
		s.log.Errorw("failed to register cron job", "expr", "0 30 0 * * *", "job", "computeExecutiveKPIs", "error", err)
	}

	// Daily: purge expired report files and their DB rows (expires_at < now).
	// Runs at 01:00 UTC so it doesn't compete with the KPI job.
	if _, err := s.cron.AddFunc("0 0 1 * * *", s.purgeExpiredReports); err != nil {
		s.log.Errorw("failed to register cron job", "expr", "0 0 1 * * *", "job", "purgeExpiredReports", "error", err)
	}

	// Daily: sync cloud assets for every org that has stored cloud provider
	// credentials with sync_enabled=true. Runs at 02:00 UTC.
	// No-op if SetCredentialKey was not called (credKey == nil).
	if _, err := s.cron.AddFunc("0 0 2 * * *", s.dispatchCloudSync); err != nil {
		s.log.Errorw("failed to register cron job", "expr", "0 0 2 * * *", "job", "dispatchCloudSync", "error", err)
	}

	// Purge expired and used email verification tokens hourly to keep the table small.
	if _, err := s.cron.AddFunc("0 0 * * * *", s.purgeExpiredVerificationTokens); err != nil {
		s.log.Errorw("failed to register cron job", "expr", "0 0 * * * *", "job", "purgeExpiredVerificationTokens", "error", err)
	}

	// Every 15 minutes: run due intelligence continuous-monitoring jobs.
	if _, err := s.cron.AddFunc("0 */15 * * * *", func() {
		if s.intel != nil {
			s.intel.RunDueMonitorJobs(context.Background())
		}
	}); err != nil {
		s.log.Errorw("failed to register cron job", "expr", "0 */15 * * * *", "job", "intelMonitor", "error", err)
	}

	s.cron.Start()
	s.log.Info("Scheduler started")
}

func (s *Scheduler) Stop() {
	ctx := s.cron.Stop()
	select {
	case <-ctx.Done():
	case <-time.After(30 * time.Second):
	}
	s.log.Info("Scheduler stopped")
}

func (s *Scheduler) dispatchScheduledScans() {
	var jobs []models.ScanJob
	now := time.Now()

	// Find jobs that are scheduled and due
	s.db.Where(
		"status = 'pending' AND scheduled_at IS NOT NULL AND scheduled_at <= ? AND cron_expr = ''",
		now,
	).Find(&jobs)

	for _, job := range jobs {
		jobCopy := job
		s.queue.Enqueue(queue.Job{
			ID:   jobCopy.ID.String(),
			Type: "scan",
			Payload: map[string]interface{}{
				"job_id": jobCopy.ID.String(),
				"org_id": jobCopy.OrgID.String(),
				"type":   jobCopy.Type,
			},
		})
		if err := s.db.Model(&jobCopy).Update("status", "queued").Error; err != nil {
			// If this fails, the row stays at status="pending" and scheduled_at
			// is still in the past, so the query above matches it again on the
			// very next tick — a silent failure here causes duplicate dispatch
			// of the same scan, not just a stale status field.
			s.log.Warnw("scheduler: failed to mark scheduled scan as queued — may re-dispatch next tick", "job_id", jobCopy.ID, "error", err)
		}
	}

	// Find recurring cron jobs
	var cronJobs []models.ScanJob
	s.db.Where("cron_expr != '' AND status IN ('completed','failed')").Find(&cronJobs)

	for _, job := range cronJobs {
		sched, err := cron.ParseStandard(job.CronExpr)
		if err != nil {
			continue
		}
		nextRun := sched.Next(job.UpdatedAt)
		if nextRun.Before(now) {
			newJob := models.ScanJob{
				OrgID:     job.OrgID,
				CreatedBy: job.CreatedBy,
				Name:      job.Name,
				Type:      job.Type,
				Status:    "pending",
				Targets:   job.Targets,
				Options:   job.Options,
				CronExpr:  job.CronExpr,
			}
			if err := s.db.Create(&newJob).Error; err == nil {
				s.queue.Enqueue(queue.Job{
					ID:   newJob.ID.String(),
					Type: "scan",
					Payload: map[string]interface{}{
						"job_id": newJob.ID.String(),
					},
				})
				// Touch the triggering row's updated_at so sched.Next() computes
				// a fresh future occurrence on the next tick. Without this, the
				// same stale, already-passed nextRun keeps matching and this row
				// would re-fire a duplicate scan every minute indefinitely.
				if err := s.db.Model(&job).Update("updated_at", now).Error; err != nil {
					s.log.Warnw("scheduler: failed to touch cron job updated_at — will likely re-fire duplicate scans next tick", "job_id", job.ID, "error", err)
				}
			}
		}
	}
}

func (s *Scheduler) checkCertExpiry() {
	s.log.Info("Checking certificate expiry...")

	var certs []models.Certificate
	warnThreshold := time.Now().Add(30 * 24 * time.Hour)

	s.db.Where("not_after < ? AND is_expired = false", warnThreshold).Find(&certs)

	for _, cert := range certs {
		daysLeft := int(time.Until(cert.NotAfter).Hours() / 24)

		severity := "medium"
		if daysLeft <= 7 {
			severity = "critical"
		} else if daysLeft <= 14 {
			severity = "high"
		}

		// Check if alert already exists
		var existing int64
		if err := s.db.Model(&models.Alert{}).Where(
			"org_id = ? AND type = 'cert_expiry' AND asset_id = ? AND status = 'open'",
			cert.OrgID, cert.ID,
		).Count(&existing).Error; err != nil {
			// If this fails, `existing` stays 0 and the code below will try to
			// create an alert regardless of whether one already exists —
			// logged so a spike in duplicate cert-expiry alerts is traceable.
			s.log.Warnw("scheduler: failed to check for existing cert-expiry alert", "cert_id", cert.ID, "error", err)
		}

		if existing == 0 {
			alert := models.Alert{
				OrgID:     cert.OrgID,
				Type:      "cert_expiry",
				Severity:  severity,
				Title:     "Certificate Expiring Soon",
				Message:   formatCertExpiryMsg(cert.Subject, daysLeft),
				AssetType: "certificate",
				Status:    "open",
			}
			alert.ID = uuid.New()
			if err := s.db.Create(&alert).Error; err != nil {
				s.log.Warnw("scheduler: failed to create cert-expiry alert", "cert_id", cert.ID, "error", err)
			} else {
				handlers.DispatchAlertNotifications(s.db, s.log, &alert)
			}
		}

		// Mark expired
		if cert.NotAfter.Before(time.Now()) {
			if err := s.db.Model(&cert).Update("is_expired", true).Error; err != nil {
				s.log.Warnw("scheduler: failed to mark certificate as expired", "cert_id", cert.ID, "error", err)
			}
		}
	}
}

func (s *Scheduler) runChangeDetection() {
	s.log.Info("Running change detection...")
	cutoff := time.Now().Add(-1 * time.Hour)

	// New hosts discovered in the last hour
	var newHosts []models.Host
	s.db.Where("created_at > ?", cutoff).Find(&newHosts)
	for _, h := range newHosts {
		alert := models.Alert{
			OrgID:    h.OrgID,
			Type:     "new_asset",
			Severity: "info",
			Title:    "New host discovered: " + h.IP,
			Message:  "Host " + h.IP + " was discovered in your network",
			Status:   "open",
		}
		// Only create if not already alerted for this host
		var existing models.Alert
		if s.db.Where("org_id = ? AND type = ? AND title = ?", h.OrgID, "new_asset", alert.Title).
			First(&existing).Error != nil {
			alert.ID = uuid.New()
			s.db.Create(&alert)
			handlers.DispatchAlertNotifications(s.db, s.log, &alert)
		}
	}

	// New subdomains discovered in the last hour
	var newSubs []models.Subdomain
	s.db.Where("created_at > ?", cutoff).Find(&newSubs)
	for _, sub := range newSubs {
		alert := models.Alert{
			OrgID:    sub.OrgID,
			Type:     "new_asset",
			Severity: "info",
			Title:    "New subdomain discovered: " + sub.FQDN,
			Message:  "Subdomain " + sub.FQDN + " appeared in your attack surface",
			Status:   "open",
		}
		var existing models.Alert
		if s.db.Where("org_id = ? AND type = ? AND title = ?", sub.OrgID, "new_asset", alert.Title).
			First(&existing).Error != nil {
			alert.ID = uuid.New()
			s.db.Create(&alert)
			handlers.DispatchAlertNotifications(s.db, s.log, &alert)
		}
	}

	// New services on known hosts
	var newServices []models.Service
	s.db.Where("first_seen_at > ?", cutoff).Find(&newServices)
	for _, svc := range newServices {
		alert := models.Alert{
			OrgID:    svc.OrgID,
			Type:     "new_service",
			Severity: "medium",
			Title:    fmt.Sprintf("New service: %s:%d/%s", svc.HostRef, svc.Port, svc.Protocol),
			Message:  fmt.Sprintf("Service %s on port %d/%s detected on %s", svc.Service, svc.Port, svc.Protocol, svc.HostRef),
			Status:   "open",
		}
		var existing models.Alert
		if s.db.Where("org_id = ? AND type = ? AND title = ?", svc.OrgID, "new_service", alert.Title).
			First(&existing).Error != nil {
			alert.ID = uuid.New()
			s.db.Create(&alert)
			handlers.DispatchAlertNotifications(s.db, s.log, &alert)
		}
	}

	if total := len(newHosts) + len(newSubs) + len(newServices); total > 0 {
		s.log.Infow("change detection complete", "new_hosts", len(newHosts), "new_subdomains", len(newSubs), "new_services", len(newServices))
	}
}

// computeExecutiveKPIs runs the executive dashboard's daily snapshot job
// for every active organization.
func (s *Scheduler) computeExecutiveKPIs() {
	done, err := s.executive.ComputeAllOrgs()
	if err != nil {
		s.log.Errorw("executive KPI snapshot run failed", "error", err)
		return
	}
	s.log.Infow("executive KPI snapshots computed", "orgs", done)
}

func formatCertExpiryMsg(subject string, days int) string {
	if days <= 0 {
		return subject + " certificate has expired"
	}
	return subject + " certificate expires in " + strconv.Itoa(days) + " days"
}

// dispatchDomainCronScans checks all domains with a scan_cron set and enqueues scans on schedule.
func (s *Scheduler) dispatchDomainCronScans() {
	var domains []models.Domain
	s.db.Where("scan_cron != '' AND monitored = true").Find(&domains)

	now := time.Now()
	for _, domain := range domains {
		sched, err := cron.ParseStandard(domain.ScanCron)
		if err != nil {
			s.log.Warnw("invalid scan_cron on domain", "domain", domain.Name, "cron", domain.ScanCron)
			continue
		}
		// Next run relative to last scan
		lastScan := domain.UpdatedAt
		if domain.LastScannedAt != nil {
			lastScan = *domain.LastScannedAt
		}
		nextRun := sched.Next(lastScan)
		if nextRun.After(now) {
			continue
		}

		// Enqueue a passive subdomain scan for this domain
		job := models.ScanJob{
			OrgID:  domain.OrgID,
			Name:   "Domain cron: " + domain.Name,
			Type:   "subdomain",
			Status: "pending",
			Targets: models.JSONB{
				"targets": []string{domain.Name},
			},
		}
		job.ID = uuid.New()
		if err := s.db.Create(&job).Error; err == nil {
			s.queue.Enqueue(queue.Job{
				ID:   job.ID.String(),
				Type: "scan",
				Payload: map[string]interface{}{
					"job_id": job.ID.String(),
					"org_id": domain.OrgID.String(),
					"type":   "subdomain",
				},
			})
			if err := s.db.Model(&domain).Update("last_scanned_at", now).Error; err != nil {
				s.log.Warnw("scheduler: failed to update domain last_scanned_at", "domain_id", domain.ID, "error", err)
			}
			s.log.Infow("dispatched domain cron scan", "domain", domain.Name)
		}
	}
}

// checkSLABreaches marks findings as SLA-breached and fires alerts.
func (s *Scheduler) checkSLABreaches() {
	now := time.Now()
	var findings []models.Finding
	s.db.Where("sla_due_at < ? AND sla_breached = false AND status NOT IN ('fixed','false_positive','risk_accepted')", now).
		Find(&findings)

	for _, f := range findings {
		breach := now
		if err := s.db.Model(&f).Updates(map[string]interface{}{
			"sla_breached":  true,
			"sla_breach_at": breach,
		}).Error; err != nil {
			// findings query filters sla_breached=false — if this fails, the
			// row stays matched and re-fires a duplicate SLA-breach alert
			// every scheduler tick, same failure mode as the cron dispatch
			// above.
			s.log.Warnw("scheduler: failed to persist SLA breach flag — may re-fire duplicate alert next tick", "finding_id", f.ID, "error", err)
		}

		alert := models.Alert{
			OrgID:    f.OrgID,
			Type:     "sla_breach",
			Severity: f.Severity,
			Title:    fmt.Sprintf("SLA breached: %s", f.Title),
			Message:  fmt.Sprintf("Finding '%s' (severity: %s) passed its SLA due date without being resolved.", f.Title, f.Severity),
			Status:   "open",
		}
		alert.ID = uuid.New()
		if err := s.db.Create(&alert).Error; err == nil {
			handlers.DispatchAlertNotifications(s.db, s.log, &alert)
		}
	}
	if len(findings) > 0 {
		s.log.Infow("SLA breach check complete", "breached", len(findings))
	}
}

// detectDeadSubdomains pings every active subdomain via DNS lookup.
// If a subdomain fails 3 consecutive checks it is marked dead=true.
// If it recovers, consecutive_failures resets and dead=false.
func (s *Scheduler) detectDeadSubdomains() {
	s.log.Info("Running dead subdomain detection")

	var subs []models.Subdomain
	s.db.Where("dead = false").Find(&subs)

	now := time.Now()
	for _, sub := range subs {
		_, err := net.LookupHost(sub.FQDN)
		sub.LastCheckedAt = &now

		if err != nil {
			sub.ConsecutiveFailures++
			if sub.ConsecutiveFailures >= 3 {
				sub.Dead = true
				s.log.Infow("Subdomain marked dead",
					"subdomain", sub.FQDN,
					"failures", sub.ConsecutiveFailures,
				)
				// Fire alert
				if err := s.db.Create(&models.Alert{
					OrgID:     sub.OrgID,
					Type:      "subdomain_dead",
					Severity:  "medium",
					Title:     fmt.Sprintf("Subdomain unreachable: %s", sub.FQDN),
					Message:   fmt.Sprintf("Subdomain %s has failed DNS resolution %d consecutive times and has been marked inactive.", sub.FQDN, sub.ConsecutiveFailures),
					AssetType: "subdomain",
					Status:    "open",
				}).Error; err != nil {
					s.log.Warnw("scheduler: failed to create subdomain-dead alert", "subdomain_id", sub.ID, "error", err)
				}
			}
		} else {
			if sub.ConsecutiveFailures > 0 || sub.Dead {
				s.log.Infow("Subdomain recovered", "subdomain", sub.FQDN)
			}
			sub.ConsecutiveFailures = 0
			sub.Dead = false
		}

		if err := s.db.Save(&sub).Error; err != nil {
			// If this fails, ConsecutiveFailures/Dead never persist — a dead
			// subdomain silently reverts to looking untouched next tick (or a
			// recovered one stays marked dead), so the whole detection cycle
			// above effectively did nothing.
			s.log.Warnw("scheduler: failed to persist subdomain health state", "subdomain_id", sub.ID, "fqdn", sub.FQDN, "error", err)
		}
	}

	s.log.Infof("Dead subdomain detection complete — checked %d subdomains", len(subs))
}

// purgeExpiredReports deletes report files from disk and removes their DB rows
// when expires_at has passed. Runs daily at 01:00 UTC.
func (s *Scheduler) purgeExpiredReports() {
	var expired []models.Report
	if err := s.db.Where("expires_at IS NOT NULL AND expires_at < ?", time.Now()).
		Find(&expired).Error; err != nil {
		s.log.Warnw("purgeExpiredReports: failed to query expired reports", "error", err)
		return
	}
	if len(expired) == 0 {
		return
	}

	deleted, errs := 0, 0
	for _, r := range expired {
		// Remove file from disk if it exists.
		if r.FilePath != "" {
			if err := os.Remove(r.FilePath); err != nil && !os.IsNotExist(err) {
				s.log.Warnw("purgeExpiredReports: failed to delete file",
					"report_id", r.ID, "path", r.FilePath, "error", err)
				errs++
				continue
			}
		}
		if err := s.db.Delete(&r).Error; err != nil {
			s.log.Warnw("purgeExpiredReports: failed to delete DB row",
				"report_id", r.ID, "error", err)
			errs++
			continue
		}
		deleted++
	}
	s.log.Infow("purgeExpiredReports: complete",
		"deleted", deleted, "errors", errs, "total_expired", len(expired))
}

// purgeExpiredVerificationTokens deletes EmailVerificationToken rows that are
// either expired (expires_at in the past) or already consumed (used_at IS NOT
// NULL). Runs hourly so the table never accumulates stale rows. No-op when
// there is nothing to clean up.
func (s *Scheduler) purgeExpiredVerificationTokens() {
	result := s.db.
		Where("expires_at < ? OR used_at IS NOT NULL", time.Now()).
		Delete(&models.EmailVerificationToken{})
	if result.Error != nil {
		s.log.Warnw("purgeExpiredVerificationTokens: query failed", "error", result.Error)
		return
	}
	if result.RowsAffected > 0 {
		s.log.Infow("purgeExpiredVerificationTokens: purged tokens",
			"count", result.RowsAffected)
	}
}

// dispatchCloudSync fetches all cloud_provider_credentials rows where
// sync_enabled=true, decrypts each one with s.credKey, and runs the
// appropriate cloud.Sync* call. Results are upserted into cloud_assets.
// Runs daily at 02:00 UTC.  No-op when s.credKey == nil.
func (s *Scheduler) dispatchCloudSync() {
	if len(s.credKey) == 0 {
		s.log.Debug("dispatchCloudSync: no credential key configured, skipping")
		return
	}

	var creds []models.CloudProviderCredential
	if err := s.db.Where("sync_enabled = ? AND deleted_at IS NULL", true).
		Find(&creds).Error; err != nil {
		s.log.Warnw("dispatchCloudSync: failed to query credentials", "error", err)
		return
	}
	if len(creds) == 0 {
		return
	}

	s.log.Infow("dispatchCloudSync: starting", "credential_count", len(creds))
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Minute)
	defer cancel()

	synced, failed := 0, 0
	now := time.Now()

	for _, cred := range creds {
		plain, err := cryptoutil.Decrypt(s.credKey, cred.EncryptedCreds)
		if err != nil {
			s.log.Warnw("dispatchCloudSync: decrypt failed",
				"credential_id", cred.ID, "org_id", cred.OrgID, "error", err)
			failed++
			continue
		}

		var pc cloud.ProviderCreds
		if err := json.Unmarshal(plain, &pc); err != nil {
			s.log.Warnw("dispatchCloudSync: unmarshal failed",
				"credential_id", cred.ID, "error", err)
			failed++
			continue
		}

		var assets []cloud.Asset
		switch cred.Provider {
		case "aws":
			assets, err = cloud.SyncAWS(ctx, pc)
		case "azure":
			assets, err = cloud.SyncAzure(ctx, pc)
		case "gcp":
			assets, err = cloud.SyncGCP(ctx, pc)
		default:
			s.log.Warnw("dispatchCloudSync: unknown provider",
				"provider", cred.Provider, "credential_id", cred.ID)
			failed++
			continue
		}

		if err != nil {
			s.log.Warnw("dispatchCloudSync: sync error",
				"provider", cred.Provider, "org_id", cred.OrgID, "error", err)
			failed++
			continue
		}

		s.upsertCloudAssets(cred.OrgID, assets, now)
		if err := s.db.Model(&cred).Update("last_sync_at", now).Error; err != nil {
			s.log.Warnw("dispatchCloudSync: failed to update credential last_sync_at", "credential_id", cred.ID, "error", err)
		}
		synced++
		s.log.Infow("dispatchCloudSync: provider synced",
			"provider", cred.Provider, "org_id", cred.OrgID, "asset_count", len(assets))
	}

	s.log.Infow("dispatchCloudSync: complete",
		"synced", synced, "failed", failed, "total", len(creds))
}

// upsertCloudAssets persists cloud assets from a scheduler-triggered sync.
// Mirrors the upsert logic in handlers.CloudSync.
func (s *Scheduler) upsertCloudAssets(orgID uuid.UUID, assets []cloud.Asset, now time.Time) {
	for _, a := range assets {
		tagsJSON, _ := json.Marshal(a.Tags)
		metaJSON, _ := json.Marshal(a.Metadata)
		ipsJSON, _ := json.Marshal(a.IPs)

		record := models.CloudAsset{
			OrgID:        orgID,
			Provider:     a.Provider,
			AccountID:    a.AccountID,
			Region:       a.Region,
			ResourceID:   a.ResourceID,
			ResourceType: a.ResourceType,
			Name:         a.Name,
			Status:       a.Status,
			LastSyncedAt: &now,
		}

		if err := s.db.Where(models.CloudAsset{
			OrgID:      orgID,
			ResourceID: a.ResourceID,
		}).Assign(models.CloudAsset{
			Provider:     a.Provider,
			AccountID:    a.AccountID,
			Region:       a.Region,
			ResourceType: a.ResourceType,
			Name:         a.Name,
			Status:       a.Status,
			LastSyncedAt: &now,
		}).FirstOrCreate(&record).Error; err != nil {
			s.log.Warnw("dispatchCloudSync: upsert failed",
				"resource_id", a.ResourceID, "error", err)
			continue
		}

		if err := s.db.Model(&record).Updates(map[string]interface{}{
			"ips":      string(ipsJSON),
			"tags":     string(tagsJSON),
			"metadata": string(metaJSON),
		}).Error; err != nil {
			s.log.Warnw("dispatchCloudSync: field update failed", "resource_id", a.ResourceID, "error", err)
		}
	}
}
