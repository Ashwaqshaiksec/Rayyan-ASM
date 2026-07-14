package scheduler

import (
	"time"

	"github.com/ShadooowX/rayyan-asm/internal/models"
	"github.com/ShadooowX/rayyan-asm/internal/queue"
)

// cadenceInterval maps a DiscoveryJob.Cadence value to the minimum gap
// required since the last completed run before re-enqueueing — the
// "Continuous Discovery" requirement's daily / weekly / monthly options.
var cadenceInterval = map[string]time.Duration{
	"daily":   24 * time.Hour,
	"weekly":  7 * 24 * time.Hour,
	"monthly": 30 * 24 * time.Hour,
}

// DispatchContinuousDiscovery re-runs the External Attack Surface
// Discovery pipeline for every (org, seed-domain-set) combination that
// has an active recurring cadence and is due, based on its most recent
// completed job. "manual" cadence jobs are never auto-re-run.
//
// Distinct seed-domain sets per org are tracked independently — an org
// may run daily discovery against one brand's domains and weekly against
// another's without the two cadences interfering.
func (s *Scheduler) DispatchContinuousDiscovery() {
	var candidates []models.DiscoveryJob
	if err := s.db.
		Where("cadence IN ('daily','weekly','monthly') AND status = 'completed'").
		Order("org_id, seed_domains, completed_at DESC").
		Find(&candidates).Error; err != nil {
		s.log.Warnw("scheduler: failed to load discovery cadence candidates", "error", err)
		return
	}

	now := time.Now()
	seenKey := map[string]bool{}

	for _, job := range candidates {
		key := job.OrgID.String() + "|" + job.Cadence + "|" + seedKey(job.SeedDomains)
		if seenKey[key] {
			// Already evaluated the most recent run for this
			// (org, cadence, seed-set) combination — candidates are
			// ordered DESC by completed_at within each group, so the
			// first row seen per key is the latest.
			continue
		}
		seenKey[key] = true

		interval, ok := cadenceInterval[job.Cadence]
		if !ok || job.CompletedAt == nil {
			continue
		}
		if now.Sub(*job.CompletedAt) < interval {
			continue
		}

		newJob := models.DiscoveryJob{
			OrgID:       job.OrgID,
			CreatedBy:   job.CreatedBy,
			SeedDomains: job.SeedDomains,
			Status:      "pending",
			Cadence:     job.Cadence,
			Depth:       job.Depth,
			Options:     job.Options,
		}
		if err := s.db.Create(&newJob).Error; err != nil {
			s.log.Warnw("scheduler: failed to create recurring discovery job", "org_id", job.OrgID, "error", err)
			continue
		}

		s.queue.Enqueue(queue.Job{
			ID:   newJob.ID.String(),
			Type: "discovery_run",
			Payload: map[string]interface{}{
				"job_id": newJob.ID.String(),
				"org_id": newJob.OrgID.String(),
			},
		})
		s.log.Infow("scheduler: re-enqueued continuous discovery", "org_id", job.OrgID, "cadence", job.Cadence, "job_id", newJob.ID)
	}
}

// seedKey builds a stable map key from a job's seed domain list so two
// jobs targeting the same domains (regardless of slice ordering) are
// treated as the same recurring series.
func seedKey(domains models.StringArray) string {
	sorted := append([]string{}, domains...)
	for i := 1; i < len(sorted); i++ {
		for j := i; j > 0 && sorted[j-1] > sorted[j]; j-- {
			sorted[j-1], sorted[j] = sorted[j], sorted[j-1]
		}
	}
	key := ""
	for _, d := range sorted {
		key += d + ","
	}
	return key
}
