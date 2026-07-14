package handlers

import (
	"fmt"
	"net"
	"net/http"
	"regexp"
	"strconv"
	"time"

	"github.com/ShadooowX/rayyan-asm/internal/api/middleware"
	"github.com/ShadooowX/rayyan-asm/internal/models"
	"github.com/ShadooowX/rayyan-asm/internal/queue"
	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
	"go.uber.org/zap"
	"gorm.io/gorm"
)

// DiscoveryHandler exposes the External Attack Surface Discovery Engine
// over HTTP. The actual pipeline runs asynchronously via the job queue
// (see modules.Dispatcher.handleDiscoveryRun) — this handler only
// creates/reads job rows and the supporting event/risk-flag/asset feeds.
type DiscoveryHandler struct {
	db    *gorm.DB
	queue *queue.Queue
	log   *zap.SugaredLogger
}

func NewDiscoveryHandler(db *gorm.DB, q *queue.Queue, log *zap.SugaredLogger) *DiscoveryHandler {
	return &DiscoveryHandler{db: db, queue: q, log: log}
}

// Start POST /discovery/start — create a discovery job for a set of seed
// domains and enqueue it for asynchronous execution.
func (h *DiscoveryHandler) Start(c *gin.Context) {
	user := middleware.GetUser(c)
	if user == nil {
		c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{"error": "unauthorized"})
		return
	}

	var req struct {
		SeedDomains []string `json:"seed_domains" binding:"required"`
		Depth       int      `json:"depth"`
		ScanPorts   bool     `json:"scan_ports"`
		Cadence     string   `json:"cadence"` // manual, daily, weekly, monthly
	}
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	if len(req.SeedDomains) == 0 {
		c.JSON(http.StatusBadRequest, gin.H{"error": "at least one seed domain is required"})
		return
	}
	const maxSeedDomains = 20
	if len(req.SeedDomains) > maxSeedDomains {
		c.JSON(http.StatusBadRequest, gin.H{"error": fmt.Sprintf("too many seed domains; maximum is %d", maxSeedDomains)})
		return
	}
	// Each seed must be a valid hostname or CIDR — reject raw URLs with
	// schemes, paths, or anything that would confuse the discovery engine.
	domainRE := regexp.MustCompile(`^(?:[a-zA-Z0-9](?:[a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}$`)
	for _, seed := range req.SeedDomains {
		if net.ParseIP(seed) == nil && !domainRE.MatchString(seed) {
			c.JSON(http.StatusBadRequest, gin.H{"error": fmt.Sprintf("invalid seed domain or IP: %q", seed)})
			return
		}
	}
	if req.Depth <= 0 {
		req.Depth = 2
	}
	if req.Depth > 5 {
		req.Depth = 5
	}
	cadence := req.Cadence
	if cadence == "" {
		cadence = "manual"
	}

	if !EnforceScanThrottle(c, h.db, user.OrgID) {
		return
	}

	job := models.DiscoveryJob{
		OrgID:       user.OrgID,
		CreatedBy:   &user.ID,
		SeedDomains: models.StringArray(req.SeedDomains),
		Status:      "pending",
		Cadence:     cadence,
		Depth:       req.Depth,
		Options:     models.JSONB{"scan_ports": req.ScanPorts},
	}
	job.ID = uuid.New()
	if err := h.db.Create(&job).Error; err != nil {
		h.log.Warnw("discovery: failed to create job", "error", err)
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to create discovery job"})
		return
	}

	h.queue.Enqueue(queue.Job{
		ID:   job.ID.String(),
		Type: "discovery_run",
		Payload: map[string]interface{}{
			"job_id": job.ID.String(),
			"org_id": user.OrgID.String(),
		},
	})

	c.JSON(http.StatusCreated, job)
}

// Jobs GET /discovery/jobs — list discovery jobs for the org, newest first.
func (h *DiscoveryHandler) Jobs(c *gin.Context) {
	user := middleware.GetUser(c)
	if user == nil {
		c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{"error": "unauthorized"})
		return
	}

	limit, _ := strconv.Atoi(c.DefaultQuery("limit", "50"))
	if limit <= 0 || limit > MaxPageLimit {
		limit = 50
	}

	q := h.db.Where("org_id = ?", user.OrgID)
	if status := c.Query("status"); status != "" {
		q = q.Where("status = ?", status)
	}

	var jobs []models.DiscoveryJob
	if err := q.Order("created_at DESC").Limit(limit).Find(&jobs).Error; err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to load discovery jobs"})
		return
	}
	c.JSON(http.StatusOK, gin.H{"data": jobs, "total": len(jobs)})
}

// Job GET /discovery/jobs/:id — single job detail.
func (h *DiscoveryHandler) Job(c *gin.Context) {
	user := middleware.GetUser(c)
	if user == nil {
		c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{"error": "unauthorized"})
		return
	}
	var job models.DiscoveryJob
	if err := h.db.Where("org_id = ? AND id = ?", user.OrgID, c.Param("id")).First(&job).Error; err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "discovery job not found"})
		return
	}
	c.JSON(http.StatusOK, job)
}

// Cancel DELETE /discovery/jobs/:id — best-effort cancel; the pipeline
// checks job status between hops and stops if it's no longer "running".
func (h *DiscoveryHandler) Cancel(c *gin.Context) {
	user := middleware.GetUser(c)
	if user == nil {
		c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{"error": "unauthorized"})
		return
	}
	var job models.DiscoveryJob
	if err := h.db.Where("org_id = ? AND id = ?", user.OrgID, c.Param("id")).First(&job).Error; err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "discovery job not found"})
		return
	}
	if job.Status != "pending" && job.Status != "running" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "job is not running"})
		return
	}
	if err := h.db.Model(&job).Update("status", "cancelled").Error; err != nil {
		h.log.Warnw("failed to cancel discovery job", "error", err)
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to cancel job"})
		return
	}
	c.JSON(http.StatusOK, gin.H{"status": "cancelled"})
}

// Dashboard GET /discovery/dashboard — summary counters for the External
// Discovery Dashboard page: total assets, new assets, coverage, and the
// most recent job's progress.
func (h *DiscoveryHandler) Dashboard(c *gin.Context) {
	user := middleware.GetUser(c)
	if user == nil {
		c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{"error": "unauthorized"})
		return
	}
	orgID := user.OrgID

	var domainCount, subdomainCount, hostCount, certCount, serviceCount int64
	h.db.Model(&models.Domain{}).Where("org_id = ?", orgID).Count(&domainCount)
	h.db.Model(&models.Subdomain{}).Where("org_id = ?", orgID).Count(&subdomainCount)
	h.db.Model(&models.Host{}).Where("org_id = ?", orgID).Count(&hostCount)
	h.db.Model(&models.Certificate{}).Where("org_id = ?", orgID).Count(&certCount)
	h.db.Model(&models.Service{}).Where("org_id = ?", orgID).Count(&serviceCount)

	var lastJob models.DiscoveryJob
	hasLastJob := h.db.Where("org_id = ?", orgID).Order("created_at DESC").First(&lastJob).Error == nil

	var openFlags int64
	h.db.Model(&models.DiscoveryRiskFlag{}).Where("org_id = ? AND status = 'open'", orgID).Count(&openFlags)

	var runningJobs int64
	h.db.Model(&models.DiscoveryJob{}).Where("org_id = ? AND status IN ('pending','running')", orgID).Count(&runningJobs)

	resp := gin.H{
		"total_assets":       domainCount + subdomainCount + hostCount + certCount + serviceCount,
		"total_domains":      domainCount,
		"total_subdomains":   subdomainCount,
		"total_hosts":        hostCount,
		"total_certificates": certCount,
		"total_services":     serviceCount,
		"open_risk_flags":    openFlags,
		"running_jobs":       runningJobs,
	}
	if hasLastJob {
		resp["last_job"] = lastJob
	}
	c.JSON(http.StatusOK, resp)
}

// Events GET /discovery/events — discovery pipeline narrative feed,
// optionally scoped to a job.
func (h *DiscoveryHandler) Events(c *gin.Context) {
	user := middleware.GetUser(c)
	if user == nil {
		c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{"error": "unauthorized"})
		return
	}

	limit, _ := strconv.Atoi(c.DefaultQuery("limit", "200"))
	if limit <= 0 || limit > 1000 {
		limit = 200
	}

	q := h.db.Where("org_id = ?", user.OrgID)
	if jobID := c.Query("job_id"); jobID != "" {
		q = q.Where("job_id = ?", jobID)
	}
	if eventType := c.Query("event_type"); eventType != "" {
		q = q.Where("event_type = ?", eventType)
	}

	var events []models.DiscoveryEvent
	if err := q.Order("detected_at DESC").Limit(limit).Find(&events).Error; err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to load discovery events"})
		return
	}
	c.JSON(http.StatusOK, gin.H{"data": events, "total": len(events)})
}

// Changes GET /discovery/changes — asset growth/loss summary derived
// from discovery_events, satisfying the brief's "Yesterday 245 / Today
// 257 / New +12" change-monitoring view without duplicating the existing
// changedetect engine's generic field-diff timeline.
func (h *DiscoveryHandler) Changes(c *gin.Context) {
	user := middleware.GetUser(c)
	if user == nil {
		c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{"error": "unauthorized"})
		return
	}

	var rows []struct {
		Day   string
		Count int64
	}
	h.db.Model(&models.DiscoveryEvent{}).
		Select("to_char(detected_at, 'YYYY-MM-DD') as day, count(*) as count").
		Where("org_id = ? AND event_type = 'asset_discovered'", user.OrgID).
		Group("day").
		Order("day DESC").
		Limit(30).
		Scan(&rows)

	c.JSON(http.StatusOK, gin.H{"data": rows})
}

// RiskFlags GET /discovery/risk-flags — risk indicators surfaced by the
// discovery pipeline (admin panels, VPN portals, login pages, expired
// certs, shadow IT / unknown assets).
func (h *DiscoveryHandler) RiskFlags(c *gin.Context) {
	user := middleware.GetUser(c)
	if user == nil {
		c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{"error": "unauthorized"})
		return
	}

	q := h.db.Where("org_id = ?", user.OrgID)
	if status := c.Query("status"); status != "" {
		q = q.Where("status = ?", status)
	} else {
		q = q.Where("status = 'open'")
	}
	if flagType := c.Query("flag_type"); flagType != "" {
		q = q.Where("flag_type = ?", flagType)
	}

	var flags []models.DiscoveryRiskFlag
	if err := q.Order("detected_at DESC").Limit(500).Find(&flags).Error; err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to load risk flags"})
		return
	}
	c.JSON(http.StatusOK, gin.H{"data": flags, "total": len(flags)})
}

// ResolveRiskFlag PUT /discovery/risk-flags/:id/resolve — mark a flag resolved.
func (h *DiscoveryHandler) ResolveRiskFlag(c *gin.Context) {
	user := middleware.GetUser(c)
	if user == nil {
		c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{"error": "unauthorized"})
		return
	}
	var flag models.DiscoveryRiskFlag
	if err := h.db.Where("org_id = ? AND id = ?", user.OrgID, c.Param("id")).First(&flag).Error; err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "risk flag not found"})
		return
	}
	now := time.Now()
	if err := h.db.Model(&flag).Updates(map[string]any{"status": "resolved", "resolved_at": &now}).Error; err != nil {
		h.log.Warnw("failed to resolve risk flag", "error", err)
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to resolve flag"})
		return
	}
	c.JSON(http.StatusOK, gin.H{"status": "resolved"})
}

// Assets GET /discovery/assets — unified, filterable inventory view
// across domains/subdomains/hosts/certificates/services, scoped to
// assets that originated from a discovery job (the brief's "Asset
// Inventory" page with domain/subdomain/IP/certificate/service filters).
// Pass discovered_only=false to include manually-added / scan-sourced
// assets alongside discovered ones.
func (h *DiscoveryHandler) Assets(c *gin.Context) {
	user := middleware.GetUser(c)
	if user == nil {
		c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{"error": "unauthorized"})
		return
	}
	orgID := user.OrgID
	assetType := c.DefaultQuery("type", "all") // domains, subdomains, ips, certificates, services, all
	discoveredOnly := c.DefaultQuery("discovered_only", "true") == "true"

	// Every key is always present in the response, even when its asset
	// type was excluded by `type=`, so callers never have to distinguish
	// "empty" from "missing" — the same defensive convention used by
	// /search (see internal/api/handlers/handlers.go).
	result := gin.H{
		"domains":      []models.Domain{},
		"subdomains":   []models.Subdomain{},
		"ips":          []models.Host{},
		"certificates": []models.Certificate{},
		"services":     []models.Service{},
	}

	include := func(t string) bool { return assetType == "all" || assetType == t }

	if include("domains") {
		q := h.db.Model(&models.Domain{}).Where("org_id = ?", orgID)
		if discoveredOnly {
			q = q.Where("discovery_job_id IS NOT NULL")
		}
		domains := []models.Domain{}
		if err := q.Order("created_at DESC").Limit(500).Find(&domains).Error; err != nil {
			h.log.Warnw("discovery export domains query failed", "error", err)
		}
		result["domains"] = domains
	}
	if include("subdomains") {
		q := h.db.Model(&models.Subdomain{}).Where("org_id = ?", orgID)
		if discoveredOnly {
			q = q.Where("discovery_job_id IS NOT NULL")
		}
		subs := []models.Subdomain{}
		if err := q.Order("created_at DESC").Limit(1000).Find(&subs).Error; err != nil {
			h.log.Warnw("discovery export subs query failed", "error", err)
		}
		result["subdomains"] = subs
	}
	if include("ips") {
		q := h.db.Model(&models.Host{}).Where("org_id = ?", orgID)
		if discoveredOnly {
			q = q.Where("discovery_job_id IS NOT NULL")
		}
		hosts := []models.Host{}
		if err := q.Order("created_at DESC").Limit(1000).Find(&hosts).Error; err != nil {
			h.log.Warnw("discovery export hosts query failed", "error", err)
		}
		result["ips"] = hosts
	}
	if include("certificates") {
		q := h.db.Model(&models.Certificate{}).Where("org_id = ?", orgID)
		if discoveredOnly {
			q = q.Where("discovery_job_id IS NOT NULL")
		}
		certs := []models.Certificate{}
		if err := q.Order("created_at DESC").Limit(500).Find(&certs).Error; err != nil {
			h.log.Warnw("discovery export certs query failed", "error", err)
		}
		result["certificates"] = certs
	}
	if include("services") {
		q := h.db.Model(&models.Service{}).Where("org_id = ?", orgID)
		if discoveredOnly {
			q = q.Where("discovery_job_id IS NOT NULL")
		}
		services := []models.Service{}
		if err := q.Order("created_at DESC").Limit(1000).Find(&services).Error; err != nil {
			h.log.Warnw("discovery export services query failed", "error", err)
		}
		result["services"] = services
	}

	c.JSON(http.StatusOK, result)
}
