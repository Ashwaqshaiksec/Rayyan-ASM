package handlers

import (
	"net/http"
	"sort"
	"strconv"
	"time"

	"github.com/ShadooowX/rayyan-asm/internal/api/middleware"
	"github.com/ShadooowX/rayyan-asm/internal/models"
	"github.com/ShadooowX/rayyan-asm/internal/modules/riskscore"
	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
	"go.uber.org/zap"
	"gorm.io/gorm"
)

type RiskScoreHandler struct {
	db     *gorm.DB
	log    *zap.SugaredLogger
	engine *riskscore.Engine
}

func NewRiskScoreHandler(db *gorm.DB, log *zap.SugaredLogger, engine *riskscore.Engine) *RiskScoreHandler {
	return &RiskScoreHandler{db: db, log: log, engine: engine}
}

type riskAssetRow struct {
	ID        uuid.UUID    `json:"id"`
	AssetType string       `json:"asset_type"`
	Label     string       `json:"label"`
	Score     float64      `json:"score"`
	Tier      string       `json:"tier"`
	Factors   models.JSONB `json:"factors"`
	ScoredAt  *time.Time   `json:"scored_at"`
}

// Assets GET /risk/assets?type=&tier=&page=&limit=
func (h *RiskScoreHandler) Assets(c *gin.Context) {
	user := middleware.GetUser(c)
	if user == nil {
		c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{"error": "unauthorized"})
		return
	}

	assetType := c.Query("type")
	tier := c.Query("tier")

	page, _ := strconv.Atoi(c.DefaultQuery("page", "1"))
	limit, _ := strconv.Atoi(c.DefaultQuery("limit", "50"))
	if page < 1 {
		page = 1
	}
	if limit < 1 || limit > MaxPageLimit {
		limit = 50
	}
	offset := (page - 1) * limit

	rows := []riskAssetRow{}
	var total int

	addHosts := assetType == "" || assetType == "host"
	addSubs := assetType == "" || assetType == "subdomain"
	addDomains := assetType == "" || assetType == "domain"

	if addHosts {
		q := h.db.Where("org_id = ?", user.OrgID)
		if tier != "" {
			q = q.Where("risk_tier = ?", tier)
		}
		var count int64
		q.Model(&models.Host{}).Count(&count)
		total += int(count)
		var hosts []models.Host
		if err := q.Order("risk_score desc").Offset(offset).Limit(limit).Find(&hosts).Error; err != nil {
			h.log.Warnw("risk score hosts query failed", "error", err)
		}
		for _, hh := range hosts {
			rows = append(rows, riskAssetRow{
				ID: hh.ID, AssetType: "host", Label: hh.IP, Score: hh.RiskScore,
				Tier: hh.RiskTier, Factors: hh.RiskFactors, ScoredAt: hh.RiskScoredAt,
			})
		}
	}
	if addSubs && len(rows) < limit {
		q := h.db.Where("org_id = ?", user.OrgID)
		if tier != "" {
			q = q.Where("risk_tier = ?", tier)
		}
		var count int64
		q.Model(&models.Subdomain{}).Count(&count)
		total += int(count)
		remaining := limit - len(rows)
		var subs []models.Subdomain
		if err := q.Order("risk_score desc").Limit(remaining).Find(&subs).Error; err != nil {
			h.log.Warnw("risk score subs query failed", "error", err)
		}
		for _, sd := range subs {
			rows = append(rows, riskAssetRow{
				ID: sd.ID, AssetType: "subdomain", Label: sd.FQDN, Score: sd.RiskScore,
				Tier: sd.RiskTier, Factors: sd.RiskFactors, ScoredAt: sd.RiskScoredAt,
			})
		}
	}
	if addDomains && len(rows) < limit {
		q := h.db.Where("org_id = ?", user.OrgID)
		if tier != "" {
			q = q.Where("risk_tier = ?", tier)
		}
		var count int64
		q.Model(&models.Domain{}).Count(&count)
		total += int(count)
		remaining := limit - len(rows)
		var domains []models.Domain
		if err := q.Order("risk_score desc").Limit(remaining).Find(&domains).Error; err != nil {
			h.log.Warnw("risk score domains query failed", "error", err)
		}
		for _, d := range domains {
			rows = append(rows, riskAssetRow{
				ID: d.ID, AssetType: "domain", Label: d.Name, Score: d.RiskScore,
				Tier: d.RiskTier, Factors: d.RiskFactors, ScoredAt: d.RiskScoredAt,
			})
		}
	}

	sort.Slice(rows, func(i, j int) bool { return rows[i].Score > rows[j].Score })
	c.JSON(http.StatusOK, gin.H{"data": rows, "total": total, "page": page, "limit": limit})
}

// Trends GET /risk/trends?asset_id=&days=
func (h *RiskScoreHandler) Trends(c *gin.Context) {
	user := middleware.GetUser(c)
	if user == nil {
		c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{"error": "unauthorized"})
		return
	}

	days, _ := strconv.Atoi(c.DefaultQuery("days", "30"))
	if days <= 0 {
		days = 30
	}
	if days > 180 {
		days = 180
	}

	since := time.Now().AddDate(0, 0, -days)
	q := h.db.Where("org_id = ? AND computed_at >= ?", user.OrgID, since)
	if assetID := c.Query("asset_id"); assetID != "" {
		if aid, err := uuid.Parse(assetID); err == nil {
			q = q.Where("asset_id = ?", aid)
		}
	}

	var history []models.AssetRiskHistory
	if err := q.Order("computed_at asc").Find(&history).Error; err != nil {
		h.log.Warnw("risk score history query failed", "error", err)
	}

	type daySum struct {
		total float64
		count int
	}
	buckets := make(map[string]*daySum)
	for _, r := range history {
		key := r.ComputedAt.Format("2006-01-02")
		b, ok := buckets[key]
		if !ok {
			b = &daySum{}
			buckets[key] = b
		}
		b.total += r.Score
		b.count++
	}

	type trendPoint struct {
		Date  string  `json:"date"`
		Score float64 `json:"score"`
	}
	points := make([]trendPoint, 0, days)
	now := time.Now()
	for i := days - 1; i >= 0; i-- {
		day := now.AddDate(0, 0, -i)
		key := day.Format("2006-01-02")
		score := 0.0
		if b, ok := buckets[key]; ok && b.count > 0 {
			score = b.total / float64(b.count)
		}
		points = append(points, trendPoint{Date: day.Format("Jan 02"), Score: score})
	}

	c.JSON(http.StatusOK, gin.H{"data": points})
}

// Heatmap GET /risk/heatmap
func (h *RiskScoreHandler) Heatmap(c *gin.Context) {
	user := middleware.GetUser(c)
	if user == nil {
		c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{"error": "unauthorized"})
		return
	}

	type cell struct {
		Group    string `json:"group"`
		Critical int64  `json:"critical"`
		High     int64  `json:"high"`
		Medium   int64  `json:"medium"`
		Low      int64  `json:"low"`
	}

	groups := map[string]*cell{}
	bump := func(group, tier string) {
		if group == "" {
			group = "Unassigned"
		}
		cl, ok := groups[group]
		if !ok {
			cl = &cell{Group: group}
			groups[group] = cl
		}
		switch tier {
		case "critical":
			cl.Critical++
		case "high":
			cl.High++
		case "medium":
			cl.Medium++
		default:
			cl.Low++
		}
	}

	// Aggregate hosts by business_unit and risk_tier via SQL — avoids full table load.
	type aggRow struct {
		BusinessUnit string
		RiskTier     string
		Count        int64
	}
	var hostAgg []aggRow
	h.db.Model(&models.Host{}).
		Select("COALESCE(business_unit, '') as business_unit, COALESCE(risk_tier, 'low') as risk_tier, COUNT(*) as count").
		Where("org_id = ?", user.OrgID).
		Group("business_unit, risk_tier").
		Scan(&hostAgg)
	for _, r := range hostAgg {
		for i := int64(0); i < r.Count; i++ {
			bump(r.BusinessUnit, r.RiskTier)
		}
	}

	// For subdomains, join to domain to get the business unit.
	type subAgg struct {
		BusinessUnit string
		RiskTier     string
		Count        int64
	}
	var subRows []subAgg
	h.db.Raw(`
		SELECT COALESCE(d.business_unit, '') as business_unit,
		       COALESCE(s.risk_tier, 'low')  as risk_tier,
		       COUNT(*)                       as count
		FROM subdomains s
		LEFT JOIN domains d ON d.id = s.domain_id
		WHERE s.org_id = ?
		GROUP BY d.business_unit, s.risk_tier
	`, user.OrgID).Scan(&subRows)
	for _, r := range subRows {
		for i := int64(0); i < r.Count; i++ {
			bump(r.BusinessUnit, r.RiskTier)
		}
	}

	out := make([]cell, 0, len(groups))
	for _, v := range groups {
		out = append(out, *v)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Group < out[j].Group })

	c.JSON(http.StatusOK, gin.H{"data": out})
}

// Recompute POST /risk/recompute
func (h *RiskScoreHandler) Recompute(c *gin.Context) {
	user := middleware.GetUser(c)
	if user == nil {
		c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{"error": "unauthorized"})
		return
	}

	summary, err := h.engine.RecomputeOrg(user.OrgID)
	if err != nil {
		h.log.Warnw("riskscore: recompute failed", "org_id", user.OrgID, "error", err)
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to recompute risk scores"})
		return
	}
	c.JSON(http.StatusOK, summary)
}
