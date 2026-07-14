// Package executive builds the dashboard data execs actually look at —
// pulls from riskscore, correlation, attackpath and changedetect and rolls
// it up into KPIs (exposure summary, risk trend, asset growth, SLA
// compliance, etc). Snapshots a copy per org per day so we can chart trends.
package executive

import (
	"fmt"
	"time"

	"github.com/ShadooowX/rayyan-asm/internal/models"
	"github.com/google/uuid"
	"go.uber.org/zap"
	"gorm.io/gorm"
)

type Engine struct {
	db  *gorm.DB
	log *zap.SugaredLogger
}

func New(db *gorm.DB, log *zap.SugaredLogger) *Engine {
	return &Engine{db: db, log: log}
}

// Live is the real-time executive summary, computed directly from current
// tables (not from the snapshot history) so the dashboard never shows
// stale numbers between scheduled snapshot runs.
type Live struct {
	TotalAssets     int64 `json:"total_assets"`
	TotalDomains    int64 `json:"total_domains"`
	TotalSubdomains int64 `json:"total_subdomains"`
	TotalHosts      int64 `json:"total_hosts"`
	TotalServices   int64 `json:"total_services"`
	TotalCloud      int64 `json:"total_cloud_assets"`
	InternetFacing  int64 `json:"internet_facing_assets"`

	AvgRiskScore      float64 `json:"avg_risk_score"`
	ExposureScore     float64 `json:"exposure_score"`
	CriticalFindings  int64   `json:"critical_findings"`
	HighFindings      int64   `json:"high_findings"`
	MediumFindings    int64   `json:"medium_findings"`
	LowFindings       int64   `json:"low_findings"`
	OpenFindings      int64   `json:"open_findings"`
	RiskAcceptedCount int64   `json:"risk_accepted_count"`

	AttackPathCount         int64   `json:"attack_path_count"`
	CriticalAttackPathCount int64   `json:"critical_attack_path_count"`
	AvgChokepointScore      float64 `json:"avg_chokepoint_score"`

	SLATotal         int64   `json:"sla_total"`
	SLABreached      int64   `json:"sla_breached"`
	SLACompliancePct float64 `json:"sla_compliance_pct"`

	CriticalAssetsExposed int64 `json:"critical_assets_exposed"`

	OpenAlerts    int64 `json:"open_alerts"`
	ActiveScans   int64 `json:"active_scans"`
	ExpiringCerts int64 `json:"expiring_certs"`

	New7d     int64 `json:"new_assets_7d"`
	Removed7d int64 `json:"removed_assets_7d"`
	Changed7d int64 `json:"changed_assets_7d"`

	ComputedAt time.Time `json:"computed_at"`
}

// computeLive pulls the current state of the platform for one org. It is
// shared by both the live Summary endpoint and the snapshot writer so the
// two never drift apart in methodology.
func (e *Engine) computeLive(orgID uuid.UUID) (Live, error) {
	var l Live
	now := time.Now()
	l.ComputedAt = now

	e.db.Model(&models.Domain{}).Where("org_id = ?", orgID).Count(&l.TotalDomains)
	e.db.Model(&models.Subdomain{}).Where("org_id = ?", orgID).Count(&l.TotalSubdomains)
	e.db.Model(&models.Host{}).Where("org_id = ?", orgID).Count(&l.TotalHosts)
	e.db.Model(&models.Service{}).Where("org_id = ?", orgID).Count(&l.TotalServices)
	e.db.Model(&models.CloudAsset{}).Where("org_id = ?", orgID).Count(&l.TotalCloud)
	l.TotalAssets = l.TotalDomains + l.TotalSubdomains + l.TotalHosts + l.TotalCloud

	e.db.Model(&models.Host{}).
		Where("org_id = ? AND risk_factors->>'internet_exposed' = 'true'", orgID).
		Count(&l.InternetFacing)

	e.db.Model(&models.Host{}).Where("org_id = ?", orgID).
		Select("COALESCE(AVG(risk_score),0)").Scan(&l.AvgRiskScore)

	e.db.Model(&models.Finding{}).Where("org_id = ? AND severity = 'critical' AND status = 'open'", orgID).Count(&l.CriticalFindings)
	e.db.Model(&models.Finding{}).Where("org_id = ? AND severity = 'high' AND status = 'open'", orgID).Count(&l.HighFindings)
	e.db.Model(&models.Finding{}).Where("org_id = ? AND severity = 'medium' AND status = 'open'", orgID).Count(&l.MediumFindings)
	e.db.Model(&models.Finding{}).Where("org_id = ? AND severity = 'low' AND status = 'open'", orgID).Count(&l.LowFindings)
	e.db.Model(&models.Finding{}).Where("org_id = ? AND status = 'open'", orgID).Count(&l.OpenFindings)
	e.db.Model(&models.Finding{}).Where("org_id = ? AND risk_accepted = true", orgID).Count(&l.RiskAcceptedCount)

	e.db.Model(&models.AttackPath{}).Where("org_id = ?", orgID).Count(&l.AttackPathCount)
	e.db.Model(&models.AttackPath{}).Where("org_id = ? AND weakest_score >= 75", orgID).Count(&l.CriticalAttackPathCount)
	e.db.Model(&models.AttackPath{}).Where("org_id = ?", orgID).
		Select("COALESCE(AVG(weakest_score),0)").Scan(&l.AvgChokepointScore)

	e.db.Model(&models.Finding{}).Where("org_id = ? AND sla_due_at IS NOT NULL AND status NOT IN ('fixed','false_positive','risk_accepted')", orgID).Count(&l.SLATotal)
	e.db.Model(&models.Finding{}).Where("org_id = ? AND sla_breached = true", orgID).Count(&l.SLABreached)
	if l.SLATotal > 0 {
		l.SLACompliancePct = 100 * (1 - float64(l.SLABreached)/float64(l.SLATotal))
	} else {
		l.SLACompliancePct = 100
	}

	e.db.Model(&models.Host{}).
		Where("org_id = ? AND risk_factors->>'internet_exposed' = 'true' AND risk_factors->>'sensitive_asset' = 'true'", orgID).
		Count(&l.CriticalAssetsExposed)

	e.db.Model(&models.Alert{}).Where("org_id = ? AND status = 'open'", orgID).Count(&l.OpenAlerts)
	e.db.Model(&models.ScanJob{}).Where("org_id = ? AND status IN ('pending','running')", orgID).Count(&l.ActiveScans)
	e.db.Model(&models.Certificate{}).Where("org_id = ? AND not_after < ?", orgID, now.Add(30*24*time.Hour)).Count(&l.ExpiringCerts)

	weekAgo := now.AddDate(0, 0, -7)
	e.db.Model(&models.AssetChangeEvent{}).Where("org_id = ? AND change_type = 'new' AND detected_at >= ?", orgID, weekAgo).Count(&l.New7d)
	e.db.Model(&models.AssetChangeEvent{}).Where("org_id = ? AND change_type = 'removed' AND detected_at >= ?", orgID, weekAgo).Count(&l.Removed7d)
	e.db.Model(&models.AssetChangeEvent{}).Where("org_id = ? AND change_type = 'changed' AND detected_at >= ?", orgID, weekAgo).Count(&l.Changed7d)

	l.ExposureScore = exposureScore(l)
	return l, nil
}

// exposureScore blends asset risk, attack path presence and SLA health
// into a single 0-100 organization-wide exposure number — the headline
// figure of the Exposure Prioritization model surfaced on the executive
// dashboard.
func exposureScore(l Live) float64 {
	riskComponent := l.AvgRiskScore // already 0-100
	pathComponent := 0.0
	if l.TotalAssets > 0 {
		pathComponent = 100 * float64(l.CriticalAttackPathCount) / float64(l.TotalAssets)
		if pathComponent > 100 {
			pathComponent = 100
		}
	}
	slaComponent := 100 - l.SLACompliancePct
	exposureComponent := 0.0
	if l.TotalHosts > 0 {
		exposureComponent = 100 * float64(l.InternetFacing) / float64(l.TotalHosts)
	}

	score := riskComponent*0.40 + pathComponent*0.25 + slaComponent*0.20 + exposureComponent*0.15
	if score > 100 {
		score = 100
	}
	if score < 0 {
		score = 0
	}
	return score
}

// Summary returns the live executive view for one org.
func (e *Engine) Summary(orgID uuid.UUID) (Live, error) {
	return e.computeLive(orgID)
}

// Compute builds today's snapshot for an org and upserts it into
// executive_kpi_snapshots, diffing against the most recent prior snapshot
// to derive growth metrics.
func (e *Engine) Compute(orgID uuid.UUID) (*models.ExecutiveKPISnapshot, error) {
	live, err := e.computeLive(orgID)
	if err != nil {
		return nil, err
	}

	now := time.Now().UTC()
	today := time.Date(now.Year(), now.Month(), now.Day(), 0, 0, 0, 0, time.UTC)

	var prev models.ExecutiveKPISnapshot
	hasPrev := e.db.Where("org_id = ? AND date < ?", orgID, today).
		Order("date DESC").First(&prev).Error == nil

	snap := models.ExecutiveKPISnapshot{
		ID:                      uuid.New(),
		OrgID:                   orgID,
		Date:                    today,
		TotalAssets:             int(live.TotalAssets),
		TotalDomains:            int(live.TotalDomains),
		TotalHosts:              int(live.TotalHosts),
		TotalServices:           int(live.TotalServices),
		TotalCloud:              int(live.TotalCloud),
		InternetFacing:          int(live.InternetFacing),
		AvgRiskScore:            live.AvgRiskScore,
		ExposureScore:           live.ExposureScore,
		CriticalFindings:        int(live.CriticalFindings),
		HighFindings:            int(live.HighFindings),
		MediumFindings:          int(live.MediumFindings),
		LowFindings:             int(live.LowFindings),
		OpenFindings:            int(live.OpenFindings),
		RiskAcceptedCount:       int(live.RiskAcceptedCount),
		AttackPathCount:         int(live.AttackPathCount),
		CriticalAttackPathCount: int(live.CriticalAttackPathCount),
		AvgChokepointScore:      live.AvgChokepointScore,
		SLATotal:                int(live.SLATotal),
		SLABreached:             int(live.SLABreached),
		SLACompliance:           live.SLACompliancePct,
		CriticalAssetsExposed:   int(live.CriticalAssetsExposed),
		ComputedAt:              now,
	}

	if hasPrev {
		snap.NewAssets = snap.TotalAssets - prev.TotalAssets
		if snap.NewAssets < 0 {
			snap.NewAssets = 0
		}
		snap.RemovedAssets = prev.TotalAssets - snap.TotalAssets
		if snap.RemovedAssets < 0 {
			snap.RemovedAssets = 0
		}
	}
	// Modified-asset count for "today" comes straight from the change
	// detection engine's event log, which already distinguishes new vs
	// removed vs changed at the field level.
	dayEnd := today.Add(24 * time.Hour)
	var modified int64
	e.db.Model(&models.AssetChangeEvent{}).
		Where("org_id = ? AND change_type = 'changed' AND detected_at >= ? AND detected_at < ?", orgID, today, dayEnd).
		Count(&modified)
	snap.ModifiedAssets = int(modified)

	// Upsert via GORM: works on both PostgreSQL and SQLite.
	// Delete any existing snapshot for the same org+date, then create fresh.
	e.db.Where("org_id = ? AND date = ?", snap.OrgID, snap.Date).
		Delete(&models.ExecutiveKPISnapshot{})
	if err = e.db.Create(&snap).Error; err != nil {
		return nil, fmt.Errorf("executive: upsert snapshot: %w", err)
	}

	return &snap, nil
}

// ComputeAllOrgs runs Compute for every active organization. Used by the
// nightly scheduler job.
func (e *Engine) ComputeAllOrgs() (int, error) {
	var orgs []models.Organization
	if err := e.db.Where("active = true").Find(&orgs).Error; err != nil {
		return 0, err
	}
	done := 0
	for _, o := range orgs {
		if _, err := e.Compute(o.ID); err != nil {
			e.log.Warnw("executive: snapshot failed", "org_id", o.ID, "error", err)
			continue
		}
		done++
	}
	return done, nil
}

// Trends returns historical KPI snapshots bucketed by period
// (daily/weekly/monthly/quarterly), most recent last, for charting.
func (e *Engine) Trends(orgID uuid.UUID, period string, points int) ([]models.ExecutiveKPISnapshot, error) {
	if points <= 0 || points > 366 {
		points = 90
	}

	if period == "" || period == "daily" {
		var rows []models.ExecutiveKPISnapshot
		err := e.db.Where("org_id = ?", orgID).
			Order("date DESC").Limit(points).Find(&rows).Error
		if err != nil {
			return nil, err
		}
		reverse(rows)
		return rows, nil
	}

	trunc, lookback := bucketFor(period)
	cutoff := time.Now().AddDate(0, 0, -lookback)

	var rows []models.ExecutiveKPISnapshot
	err := e.db.Raw(`
		SELECT DISTINCT ON (date_trunc(?, date)) *
		FROM executive_kpi_snapshots
		WHERE org_id = ? AND date >= ?
		ORDER BY date_trunc(?, date), date DESC
	`, trunc, orgID, cutoff, trunc).Scan(&rows).Error
	if err != nil {
		return nil, err
	}

	// DISTINCT ON above returns the buckets in date_trunc order ascending
	// already (Postgres requires the DISTINCT ON expression to lead
	// ORDER BY), but cap to the requested number of points from the end.
	if len(rows) > points {
		rows = rows[len(rows)-points:]
	}
	return rows, nil
}

func bucketFor(period string) (string, int) {
	switch period {
	case "weekly":
		return "week", 365 * 2
	case "monthly":
		return "month", 365 * 3
	case "quarterly":
		return "quarter", 365 * 5
	default:
		return "day", 90
	}
}

func reverse(rows []models.ExecutiveKPISnapshot) {
	for i, j := 0, len(rows)-1; i < j; i, j = i+1, j-1 {
		rows[i], rows[j] = rows[j], rows[i]
	}
}
