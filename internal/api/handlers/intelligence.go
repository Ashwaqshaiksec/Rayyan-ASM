package handlers

import (
	"net/http"
	"strconv"
	"time"

	"github.com/ShadooowX/rayyan-asm/internal/api/middleware"
	"github.com/ShadooowX/rayyan-asm/internal/modules/intelligence"
	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
	"go.uber.org/zap"
	"gorm.io/gorm"
)

type IntelligenceHandler struct {
	log    *zap.SugaredLogger
	engine *intelligence.Engine
}

func NewIntelligenceHandler(db *gorm.DB, log *zap.SugaredLogger, engine *intelligence.Engine) *IntelligenceHandler {
	return &IntelligenceHandler{log: log, engine: engine}
}

// ─── results ──────────────────────────────────────────────────────────────

// GET /intelligence/results?target=&provider=&limit=&offset=
func (h *IntelligenceHandler) ListResults(c *gin.Context) {
	user := middleware.GetUser(c)
	target := c.Query("target")
	provider := c.Query("provider")
	limit, _ := strconv.Atoi(c.DefaultQuery("limit", "50"))
	offset, _ := strconv.Atoi(c.DefaultQuery("offset", "0"))
	if limit > MaxPageLimitSmall {
		limit = MaxPageLimitSmall
	}

	results, total, err := h.engine.ListResults(user.OrgID, target, provider, limit, offset)
	if err != nil {
		h.log.Warnw("intel.ListResults error", "error", err)
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to list intel results"})
		return
	}
	c.JSON(http.StatusOK, gin.H{
		"results": results,
		"total":   total,
		"limit":   limit,
		"offset":  offset,
	})
}

// POST /intelligence/enrich/host — body: {"ip":"1.2.3.4"}
func (h *IntelligenceHandler) EnrichHost(c *gin.Context) {
	user := middleware.GetUser(c)
	var req struct {
		IP string `json:"ip" binding:"required"`
	}
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	results, err := h.engine.EnrichHost(c.Request.Context(), user.OrgID, req.IP)
	if err != nil {
		h.log.Warnw("intel.EnrichHost error", "ip", req.IP, "error", err)
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}
	c.JSON(http.StatusOK, gin.H{"results": results, "count": len(results)})
}

// POST /intelligence/enrich/domain — body: {"domain":"example.com"}
func (h *IntelligenceHandler) EnrichDomain(c *gin.Context) {
	user := middleware.GetUser(c)
	var req struct {
		Domain string `json:"domain" binding:"required"`
	}
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	results, err := h.engine.EnrichDomain(c.Request.Context(), user.OrgID, req.Domain)
	if err != nil {
		h.log.Warnw("intel.EnrichDomain error", "domain", req.Domain, "error", err)
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}
	c.JSON(http.StatusOK, gin.H{"results": results, "count": len(results)})
}

// ─── monitor jobs ─────────────────────────────────────────────────────────

// GET /intelligence/monitors
func (h *IntelligenceHandler) ListMonitors(c *gin.Context) {
	user := middleware.GetUser(c)
	jobs, err := h.engine.ListMonitorJobs(user.OrgID)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to list monitor jobs"})
		return
	}
	c.JSON(http.StatusOK, gin.H{"jobs": jobs, "total": len(jobs)})
}

// POST /intelligence/monitors
func (h *IntelligenceHandler) CreateMonitor(c *gin.Context) {
	user := middleware.GetUser(c)
	var req struct {
		Target     string   `json:"target"      binding:"required"`
		TargetType string   `json:"target_type" binding:"required"`
		Providers  []string `json:"providers"`
		Cadence    string   `json:"cadence"`
		Notes      string   `json:"notes"`
	}
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	validTargetTypes := map[string]bool{"host": true, "domain": true}
	if !validTargetTypes[req.TargetType] {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid target_type; must be 'host' or 'domain'"})
		return
	}
	validCadences := map[string]bool{"hourly": true, "daily": true, "weekly": true, "manual": true}
	if req.Cadence != "" && !validCadences[req.Cadence] {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid cadence; must be one of: hourly, daily, weekly, manual"})
		return
	}
	if req.Cadence == "" {
		req.Cadence = "daily"
	}
	if len(req.Providers) == 0 {
		req.Providers = []string{"shodan", "censys", "securitytrails", "historical_dns"}
	}

	job := &intelligence.MonitorJob{
		OrgID:      user.OrgID,
		CreatedBy:  user.ID,
		Target:     req.Target,
		TargetType: req.TargetType,
		Providers:  req.Providers,
		Cadence:    req.Cadence,
		Enabled:    true,
		NextRunAt:  time.Now().Add(nextIntelRunOffset(req.Cadence)),
		Notes:      req.Notes,
	}
	if err := h.engine.CreateMonitorJob(job); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to create monitor job"})
		return
	}
	c.JSON(http.StatusCreated, job)
}

// PUT /intelligence/monitors/:id/toggle — body: {"enabled":true}
func (h *IntelligenceHandler) ToggleMonitor(c *gin.Context) {
	user := middleware.GetUser(c)
	jobID, err := uuid.Parse(c.Param("id"))
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid job id"})
		return
	}
	var req struct {
		Enabled bool `json:"enabled"`
	}
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	if err := h.engine.ToggleMonitorJob(user.OrgID, jobID, req.Enabled); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to toggle monitor job"})
		return
	}
	c.JSON(http.StatusOK, gin.H{"enabled": req.Enabled})
}

// DELETE /intelligence/monitors/:id
func (h *IntelligenceHandler) DeleteMonitor(c *gin.Context) {
	user := middleware.GetUser(c)
	jobID, err := uuid.Parse(c.Param("id"))
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid job id"})
		return
	}
	if err := h.engine.DeleteMonitorJob(user.OrgID, jobID); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to delete monitor job"})
		return
	}
	c.Status(http.StatusNoContent)
}

// ─── helpers ──────────────────────────────────────────────────────────────

func nextIntelRunOffset(cadence string) time.Duration {
	switch cadence {
	case "hourly":
		return time.Hour
	case "weekly":
		return 7 * 24 * time.Hour
	default:
		return 24 * time.Hour
	}
}
