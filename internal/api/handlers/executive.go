package handlers

import (
	"net/http"
	"strconv"

	"github.com/ShadooowX/rayyan-asm/internal/api/middleware"
	"github.com/ShadooowX/rayyan-asm/internal/models"
	"github.com/ShadooowX/rayyan-asm/internal/modules/executive"
	"github.com/gin-gonic/gin"
	"go.uber.org/zap"
	"gorm.io/gorm"
)

type ExecutiveHandler struct {
	db     *gorm.DB
	log    *zap.SugaredLogger
	engine *executive.Engine
}

func NewExecutiveHandler(db *gorm.DB, log *zap.SugaredLogger, engine *executive.Engine) *ExecutiveHandler {
	return &ExecutiveHandler{db: db, log: log, engine: engine}
}

// Summary GET /executive/summary
func (h *ExecutiveHandler) Summary(c *gin.Context) {
	user := middleware.GetUser(c)
	if user == nil {
		c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{"error": "unauthorized"})
		return
	}

	live, err := h.engine.Summary(user.OrgID)
	if err != nil {
		h.log.Errorw("executive summary failed", "error", err)
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to compute executive summary"})
		return
	}
	c.JSON(http.StatusOK, live)
}

// Trends GET /executive/trends?period=daily|weekly|monthly|quarterly&points=N
func (h *ExecutiveHandler) Trends(c *gin.Context) {
	user := middleware.GetUser(c)
	if user == nil {
		c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{"error": "unauthorized"})
		return
	}

	period := c.DefaultQuery("period", "daily")
	switch period {
	case "daily", "weekly", "monthly", "quarterly":
	default:
		c.JSON(http.StatusBadRequest, gin.H{"error": "period must be one of daily, weekly, monthly, quarterly"})
		return
	}
	points, _ := strconv.Atoi(c.DefaultQuery("points", "30"))

	rows, err := h.engine.Trends(user.OrgID, period, points)
	if err != nil {
		h.log.Errorw("executive trends failed", "error", err)
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to load exposure trends"})
		return
	}
	c.JSON(http.StatusOK, gin.H{"period": period, "data": rows})
}

// SLACompliance GET /executive/sla-compliance
func (h *ExecutiveHandler) SLACompliance(c *gin.Context) {
	user := middleware.GetUser(c)
	if user == nil {
		c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{"error": "unauthorized"})
		return
	}
	orgID := user.OrgID

	type row struct {
		Severity string `json:"severity"`
		Total    int64  `json:"total"`
		Breached int64  `json:"breached"`
	}
	severities := []string{"critical", "high", "medium", "low"}
	out := make([]row, 0, len(severities))

	for _, sev := range severities {
		var total, breached int64
		h.db.Model(&models.Finding{}).
			Where("org_id = ? AND severity = ? AND sla_due_at IS NOT NULL AND status NOT IN ('fixed','false_positive','risk_accepted')", orgID, sev).
			Count(&total)
		h.db.Model(&models.Finding{}).
			Where("org_id = ? AND severity = ? AND sla_breached = true", orgID, sev).
			Count(&breached)
		out = append(out, row{Severity: sev, Total: total, Breached: breached})
	}

	var totalAll, breachedAll int64
	h.db.Model(&models.Finding{}).
		Where("org_id = ? AND sla_due_at IS NOT NULL AND status NOT IN ('fixed','false_positive','risk_accepted')", orgID).
		Count(&totalAll)
	h.db.Model(&models.Finding{}).Where("org_id = ? AND sla_breached = true", orgID).Count(&breachedAll)

	compliance := 100.0
	if totalAll > 0 {
		compliance = 100 * (1 - float64(breachedAll)/float64(totalAll))
	}

	c.JSON(http.StatusOK, gin.H{
		"by_severity":    out,
		"total":          totalAll,
		"breached":       breachedAll,
		"compliance_pct": compliance,
	})
}

// AttackPathOverview GET /executive/attack-path-overview
func (h *ExecutiveHandler) AttackPathOverview(c *gin.Context) {
	user := middleware.GetUser(c)
	if user == nil {
		c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{"error": "unauthorized"})
		return
	}
	orgID := user.OrgID

	var total, critical, high, medium, low int64
	h.db.Model(&models.AttackPath{}).Where("org_id = ?", orgID).Count(&total)
	h.db.Model(&models.AttackPath{}).Where("org_id = ? AND weakest_score >= 75", orgID).Count(&critical)
	h.db.Model(&models.AttackPath{}).Where("org_id = ? AND weakest_score >= 50 AND weakest_score < 75", orgID).Count(&high)
	h.db.Model(&models.AttackPath{}).Where("org_id = ? AND weakest_score >= 25 AND weakest_score < 50", orgID).Count(&medium)
	h.db.Model(&models.AttackPath{}).Where("org_id = ? AND weakest_score < 25", orgID).Count(&low)

	var topPaths []models.AttackPath
	if err := h.db.Where("org_id = ?", orgID).Order("weakest_score DESC").Limit(10).Find(&topPaths).Error; err != nil {
		h.log.Warnw("attack path overview query failed", "error", err)
	}

	c.JSON(http.StatusOK, gin.H{
		"total":     total,
		"critical":  critical,
		"high":      high,
		"medium":    medium,
		"low":       low,
		"top_paths": topPaths,
	})
}

// BusinessImpact GET /executive/business-impact
func (h *ExecutiveHandler) BusinessImpact(c *gin.Context) {
	user := middleware.GetUser(c)
	if user == nil {
		c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{"error": "unauthorized"})
		return
	}
	orgID := user.OrgID

	var criticalHosts []models.Host
	if err := h.db.Where("org_id = ? AND risk_factors->>'internet_exposed' = 'true' AND risk_factors->>'sensitive_asset' = 'true'", orgID).
		Order("risk_score DESC").Limit(25).Find(&criticalHosts).Error; err != nil {
		h.log.Warnw("executive blast radius query failed", "org_id", orgID, "error", err)
		// Non-fatal: return empty slice so the rest of the response still renders.
		criticalHosts = []models.Host{}
	}

	type impactRow struct {
		HostID           string  `json:"host_id"`
		IP               string  `json:"ip"`
		Hostname         string  `json:"hostname"`
		BusinessUnit     string  `json:"business_unit"`
		Owner            string  `json:"owner"`
		RiskScore        float64 `json:"risk_score"`
		RiskTier         string  `json:"risk_tier"`
		OpenFindings     int64   `json:"open_findings"`
		CriticalFindings int64   `json:"critical_findings"`
	}

	out := make([]impactRow, 0, len(criticalHosts))
	for _, host := range criticalHosts {
		var open, crit int64
		h.db.Model(&models.Finding{}).Where("org_id = ? AND host_id = ? AND status = 'open'", orgID, host.ID).Count(&open)
		h.db.Model(&models.Finding{}).Where("org_id = ? AND host_id = ? AND status = 'open' AND severity = 'critical'", orgID, host.ID).Count(&crit)
		out = append(out, impactRow{
			HostID: host.ID.String(), IP: host.IP, Hostname: host.Hostname,
			BusinessUnit: host.BusinessUnit, Owner: host.Owner,
			RiskScore: host.RiskScore, RiskTier: host.RiskTier,
			OpenFindings: open, CriticalFindings: crit,
		})
	}

	var byBusinessUnit []struct {
		BusinessUnit string `json:"business_unit"`
		Count        int64  `json:"count"`
	}
	h.db.Model(&models.Host{}).
		Select("COALESCE(NULLIF(business_unit, ''), 'Unassigned') as business_unit, count(*) as count").
		Where("org_id = ?", orgID).
		Group("business_unit").Scan(&byBusinessUnit)

	c.JSON(http.StatusOK, gin.H{
		"critical_assets_exposed": len(out),
		"assets":                  out,
		"by_business_unit":        byBusinessUnit,
	})
}

// Recompute POST /executive/recompute
func (h *ExecutiveHandler) Recompute(c *gin.Context) {
	user := middleware.GetUser(c)
	if user == nil {
		c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{"error": "unauthorized"})
		return
	}

	snap, err := h.engine.Compute(user.OrgID)
	if err != nil {
		h.log.Errorw("executive recompute failed", "error", err)
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to recompute executive KPIs"})
		return
	}
	c.JSON(http.StatusOK, snap)
}
