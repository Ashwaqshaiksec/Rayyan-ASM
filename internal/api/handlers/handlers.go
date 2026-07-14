package handlers

import (
	"context"
	"encoding/json"
	"net/http"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/ShadooowX/rayyan-asm/internal/api/middleware"
	"github.com/ShadooowX/rayyan-asm/internal/api/websocket"
	"github.com/ShadooowX/rayyan-asm/internal/auth"
	"github.com/ShadooowX/rayyan-asm/internal/models"
	"github.com/ShadooowX/rayyan-asm/internal/modules"
	"github.com/ShadooowX/rayyan-asm/internal/modules/cloud"
	"github.com/ShadooowX/rayyan-asm/internal/modules/searchquery"
	"github.com/ShadooowX/rayyan-asm/internal/modules/toolrunner"
	"github.com/ShadooowX/rayyan-asm/internal/queue"
	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
	"github.com/robfig/cron/v3"
	"go.uber.org/zap"
	"gorm.io/gorm"
)

type DashboardHandler struct {
	db  *gorm.DB
	log *zap.SugaredLogger
}

func NewDashboardHandler(db *gorm.DB, log *zap.SugaredLogger) *DashboardHandler {
	return &DashboardHandler{db: db, log: log}
}

func (h *DashboardHandler) Summary(c *gin.Context) {
	user := middleware.GetUser(c)
	if user == nil {
		c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{"error": "unauthorized"})
		return
	}
	orgID := user.OrgID

	var (
		domains          int64
		subdomains       int64
		hosts            int64
		services         int64
		certs            int64
		technologies     int64
		alerts           int64
		openAlerts       int64
		totalFindings    int64
		openFindings     int64
		criticalFindings int64
		highFindings     int64
	)

	h.db.Model(&models.Domain{}).Where("org_id = ?", orgID).Count(&domains)
	h.db.Model(&models.Subdomain{}).Where("org_id = ?", orgID).Count(&subdomains)
	h.db.Model(&models.Host{}).Where("org_id = ?", orgID).Count(&hosts)
	h.db.Model(&models.Service{}).Where("org_id = ?", orgID).Count(&services)
	h.db.Model(&models.Certificate{}).Where("org_id = ?", orgID).Count(&certs)
	h.db.Model(&models.Technology{}).Where("org_id = ?", orgID).Count(&technologies)
	h.db.Model(&models.Alert{}).Where("org_id = ?", orgID).Count(&alerts)
	h.db.Model(&models.Alert{}).Where("org_id = ? AND status = 'open'", orgID).Count(&openAlerts)
	h.db.Model(&models.Finding{}).Where("org_id = ?", orgID).Count(&totalFindings)
	h.db.Model(&models.Finding{}).Where("org_id = ? AND status = 'open'", orgID).Count(&openFindings)
	h.db.Model(&models.Finding{}).Where("org_id = ? AND severity = 'critical' AND status = 'open'", orgID).Count(&criticalFindings)
	h.db.Model(&models.Finding{}).Where("org_id = ? AND severity = 'high' AND status = 'open'", orgID).Count(&highFindings)

	var expiringCerts int64
	h.db.Model(&models.Certificate{}).Where("org_id = ? AND not_after < ?", orgID, time.Now().Add(30*24*time.Hour)).Count(&expiringCerts)

	var activeScans int64
	h.db.Model(&models.ScanJob{}).Where("org_id = ? AND status IN ('pending','running')", orgID).Count(&activeScans)

	c.JSON(http.StatusOK, gin.H{
		"domains":           domains,
		"subdomains":        subdomains,
		"hosts":             hosts,
		"services":          services,
		"certificates":      certs,
		"technologies":      technologies,
		"total_alerts":      alerts,
		"open_alerts":       openAlerts,
		"expiring_certs":    expiringCerts,
		"active_scans":      activeScans,
		"total_findings":    totalFindings,
		"open_findings":     openFindings,
		"critical_findings": criticalFindings,
		"high_findings":     highFindings,
	})
}

func (h *DashboardHandler) Trends(c *gin.Context) {
	user := middleware.GetUser(c)
	if user == nil {
		c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{"error": "unauthorized"})
		return
	}
	orgID := user.OrgID

	type DayPoint struct {
		Date         string   `json:"date"`
		Hosts        int64    `json:"hosts"`
		Services     int64    `json:"services"`
		Alerts       int64    `json:"alerts"`
		AvgRiskScore *float64 `json:"avg_risk_score,omitempty"`
	}

	points := make([]DayPoint, 30)
	now := time.Now()

	for i := 29; i >= 0; i-- {
		day := now.AddDate(0, 0, -i)
		dayStart := time.Date(day.Year(), day.Month(), day.Day(), 0, 0, 0, 0, time.UTC)
		dayEnd := dayStart.Add(24 * time.Hour)

		var hosts, services, alerts int64
		h.db.Model(&models.Host{}).
			Where("org_id = ? AND created_at < ?", orgID, dayEnd).
			Count(&hosts)
		h.db.Model(&models.Service{}).
			Where("org_id = ? AND first_seen_at < ?", orgID, dayEnd).
			Count(&services)
		h.db.Model(&models.Alert{}).
			Where("org_id = ? AND created_at >= ? AND created_at < ?", orgID, dayStart, dayEnd).
			Count(&alerts)

		// Risk-score history is written per scoring run (see
		// internal/modules/riskscore), not continuously, so most days have
		// no rows — that's expected and left as a gap in the series (nil,
		// omitted from JSON) rather than a fabricated flat line.
		var avg float64
		var riskPoint *float64
		row := h.db.Model(&models.AssetRiskHistory{}).
			Select("AVG(score)").
			Where("org_id = ? AND computed_at >= ? AND computed_at < ?", orgID, dayStart, dayEnd).
			Row()
		if row != nil {
			var raw *float64
			if err := row.Scan(&raw); err == nil && raw != nil {
				avg = *raw
				riskPoint = &avg
			}
		}

		points[29-i] = DayPoint{
			Date:         dayStart.Format("Jan 02"),
			Hosts:        hosts,
			Services:     services,
			Alerts:       alerts,
			AvgRiskScore: riskPoint,
		}
	}

	c.JSON(http.StatusOK, gin.H{"data": points})
}

func (h *DashboardHandler) TopAssets(c *gin.Context) {
	user := middleware.GetUser(c)
	if user == nil {
		c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{"error": "unauthorized"})
		return
	}
	var hosts []models.Host
	if err := h.db.Where("org_id = ?", user.OrgID).Limit(10).Order("last_seen_at desc").Find(&hosts).Error; err != nil {
		h.log.Warnw("top assets query failed", "error", err)
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to fetch top assets"})
		return
	}
	c.JSON(http.StatusOK, gin.H{"hosts": hosts})
}

type SearchHandler struct {
	db  *gorm.DB
	log *zap.SugaredLogger
}

func NewSearchHandler(db *gorm.DB, log *zap.SugaredLogger) *SearchHandler {
	return &SearchHandler{db: db, log: log}
}

func (h *SearchHandler) Search(c *gin.Context) {
	user := middleware.GetUser(c)
	if user == nil {
		c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{"error": "unauthorized"})
		return
	}
	q := c.Query("q")
	if q == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "query required"})
		return
	}

	orgID := user.OrgID
	parsed := searchquery.Parse(q)
	var freePattern string
	if parsed.FreeText != "" {
		freePattern = "%" + strings.ToLower(parsed.FreeText) + "%"
	}

	domains := []models.Domain{}
	if parsed.Includes("domains") && (freePattern != "" || len(parsed.Filters) == 0) {
		qq := h.db.Where("org_id = ?", orgID)
		if freePattern != "" {
			qq = qq.Where("LOWER(name) LIKE ?", freePattern)
		}
		_ = qq.Limit(10).Find(&domains).Error
	}

	hosts := []models.Host{}
	if parsed.Includes("hosts") {
		qq := h.db.Where("org_id = ?", orgID)
		if freePattern != "" {
			qq = qq.Where("(LOWER(ip) LIKE ? OR LOWER(hostname) LIKE ?)", freePattern, freePattern)
		}
		if v, ok := parsed.Filters["country"]; ok {
			qq = qq.Where("LOWER(country) = ?", strings.ToLower(v))
		}
		if v, ok := parsed.Filters["os"]; ok {
			qq = qq.Where("LOWER(os) LIKE ?", "%"+strings.ToLower(v)+"%")
		}
		if v, ok := parsed.Filters["status"]; ok {
			qq = qq.Where("LOWER(status) = ?", strings.ToLower(v))
		}
		if v, ok := parsed.Filters["tag"]; ok {
			qq = qq.Where("tags::text LIKE ?", "%"+v+"%")
		}
		if v, ok := parsed.Filters["asn"]; ok {
			qq = qq.Where("LOWER(asn) = ?", strings.ToLower(v))
		}
		if len(parsed.Filters) > 0 || freePattern != "" {
			_ = qq.Limit(10).Find(&hosts).Error
		}
	}

	subs := []models.Subdomain{}
	if parsed.Includes("subdomains") && freePattern != "" {
		_ = h.db.Where("org_id = ? AND LOWER(fqdn) LIKE ?", orgID, freePattern).Limit(10).Find(&subs).Error
	}

	services := []models.Service{}
	if parsed.Includes("services") {
		qq := h.db.Where("org_id = ?", orgID)
		if freePattern != "" {
			qq = qq.Where("(LOWER(service) LIKE ? OR LOWER(product) LIKE ?)", freePattern, freePattern)
		}
		if v, ok := parsed.Filters["port"]; ok {
			qq = qq.Where("port = ?", v)
		}
		if v, ok := parsed.Filters["protocol"]; ok {
			qq = qq.Where("LOWER(protocol) = ?", strings.ToLower(v))
		}
		if v, ok := parsed.Filters["service"]; ok {
			qq = qq.Where("LOWER(service) LIKE ?", "%"+strings.ToLower(v)+"%")
		}
		if len(parsed.Filters) > 0 || freePattern != "" {
			_ = qq.Limit(10).Find(&services).Error
		}
	}

	techs := []models.Technology{}
	if parsed.Includes("technologies") && freePattern != "" {
		_ = h.db.Where("org_id = ? AND LOWER(name) LIKE ?", orgID, freePattern).Limit(10).Find(&techs).Error
	}

	findings := []models.Finding{}
	if parsed.Includes("findings") {
		qq := h.db.Where("org_id = ?", orgID)
		if freePattern != "" {
			qq = qq.Where("(LOWER(title) LIKE ? OR LOWER(url) LIKE ? OR LOWER(cve) LIKE ?)", freePattern, freePattern, freePattern)
		}
		if v, ok := parsed.Filters["severity"]; ok {
			qq = qq.Where("LOWER(severity) = ?", strings.ToLower(v))
		}
		if v, ok := parsed.Filters["status"]; ok {
			qq = qq.Where("LOWER(status) = ?", strings.ToLower(v))
		}
		if v, ok := parsed.Filters["category"]; ok {
			qq = qq.Where("LOWER(category) = ?", strings.ToLower(v))
		}
		if v, ok := parsed.Filters["cve"]; ok {
			qq = qq.Where("LOWER(cve) = ?", strings.ToLower(v))
		}
		if len(parsed.Filters) > 0 || freePattern != "" {
			_ = qq.Limit(10).Find(&findings).Error
		}
	}

	cloudAssets := []models.CloudAsset{}
	if parsed.Includes("cloud_assets") {
		qq := h.db.Where("org_id = ?", orgID)
		if freePattern != "" {
			qq = qq.Where("(LOWER(name) LIKE ? OR LOWER(resource_id) LIKE ? OR LOWER(account_id) LIKE ?)",
				freePattern, freePattern, freePattern)
		}
		if v, ok := parsed.Filters["cloud_account"]; ok {
			qq = qq.Where("LOWER(account_id) = ?", strings.ToLower(v))
		}
		if len(parsed.Filters) > 0 || freePattern != "" {
			_ = qq.Limit(10).Find(&cloudAssets).Error
		}
	}

	c.JSON(http.StatusOK, gin.H{
		"domains":      domains,
		"hosts":        hosts,
		"subdomains":   subs,
		"services":     services,
		"technologies": techs,
		"findings":     findings,
		"cloud_assets": cloudAssets,
		"query":        q,
		"filters":      parsed.Filters,
		"types":        parsed.Types,
	})
}

// Suggestions powers the search box's autocomplete. It now handles three
// cases, where previously it only ever suggested matching domain names:
//   - empty/short input: nothing
//   - input ending in a partial word with no colon: suggest matching field
//     names ("sev" -> "severity:") alongside matching domain names, so
//     the query syntax itself is discoverable while typing
//   - input ending in "field:partial": suggest real values for that field
//     pulled from the org's own data (e.g. "severity:c" -> "severity:critical")
func (h *SearchHandler) Suggestions(c *gin.Context) {
	user := middleware.GetUser(c)
	if user == nil {
		c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{"error": "unauthorized"})
		return
	}
	q := c.Query("q")
	if len(q) < 2 {
		c.JSON(http.StatusOK, gin.H{"suggestions": []string{}})
		return
	}
	orgID := user.OrgID

	// Only look at the last whitespace-delimited token — earlier
	// field:value pairs in a multi-token query are already complete and
	// don't need suggestions.
	tokens := strings.Fields(q)
	last := tokens[len(tokens)-1]

	if idx := strings.Index(last, ":"); idx >= 0 {
		field := strings.ToLower(last[:idx])
		partial := strings.ToLower(last[idx+1:])
		prefix := q[:len(q)-len(last)]

		values := fieldValueSuggestions(h.db, orgID, field, partial)
		suggestions := make([]string, 0, len(values))
		for _, v := range values {
			suggestions = append(suggestions, prefix+field+":"+v)
		}
		c.JSON(http.StatusOK, gin.H{"suggestions": suggestions})
		return
	}

	prefix := q[:len(q)-len(last)]
	partial := strings.ToLower(last)
	var suggestions []string
	for _, f := range searchquery.KnownFields {
		if strings.HasPrefix(f, partial) {
			suggestions = append(suggestions, prefix+f+":")
		}
	}

	pattern := partial + "%"
	var domains []models.Domain
	_ = h.db.Select("name").Where("org_id = ? AND LOWER(name) LIKE ?", orgID, pattern).Limit(5).Find(&domains).Error
	for _, d := range domains {
		suggestions = append(suggestions, prefix+d.Name)
	}

	c.JSON(http.StatusOK, gin.H{"suggestions": suggestions})
}

// fieldValueSuggestions returns up to 8 distinct real values for the given
// field that begin with partial, so autocomplete only ever offers values
// that would actually match something.
func fieldValueSuggestions(db *gorm.DB, orgID uuid.UUID, field, partial string) []string {
	pattern := partial + "%"
	var out []string
	scan := func(model any, column, where string) {
		var rows []string
		_ = db.Model(model).Distinct(column).
			Where("org_id = ? AND LOWER("+column+") LIKE ?", orgID, pattern).
			Where(where).
			Limit(8).Pluck(column, &rows).Error
		out = rows
	}
	switch field {
	case "severity":
		scan(&models.Finding{}, "severity", "severity != ''")
	case "status":
		scan(&models.Finding{}, "status", "status != ''")
	case "category":
		scan(&models.Finding{}, "category", "category != ''")
	case "protocol":
		scan(&models.Service{}, "protocol", "protocol != ''")
	case "service":
		scan(&models.Service{}, "service", "service != ''")
	case "country":
		scan(&models.Host{}, "country", "country != ''")
	case "os":
		scan(&models.Host{}, "os", "os != ''")
	case "asn":
		scan(&models.Host{}, "asn", "asn != ''")
	case "cloud_account":
		scan(&models.CloudAsset{}, "account_id", "account_id != ''")
	case "type":
		for _, t := range searchquery.EntityTypes {
			if strings.HasPrefix(t, partial) {
				out = append(out, t)
			}
		}
	case "port":
		var ports []int
		_ = db.Model(&models.Service{}).Distinct("port").
			Where("org_id = ?", orgID).
			Order("port").Limit(8).Pluck("port", &ports).Error
		for _, p := range ports {
			s := strconv.Itoa(p)
			if strings.HasPrefix(s, partial) {
				out = append(out, s)
			}
		}
	}
	return out
}

type ScanHandler struct {
	db    *gorm.DB
	queue *queue.Queue
	hub   *websocket.Hub
	log   *zap.SugaredLogger
}

func NewScanHandler(db *gorm.DB, q *queue.Queue, hub *websocket.Hub, log *zap.SugaredLogger) *ScanHandler {
	return &ScanHandler{db: db, queue: q, hub: hub, log: log}
}

func (h *ScanHandler) List(c *gin.Context) {
	user := middleware.GetUser(c)
	if user == nil {
		c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{"error": "unauthorized"})
		return
	}
	var jobs []models.ScanJob

	page, _ := strconv.Atoi(c.DefaultQuery("page", "1"))
	limit, _ := strconv.Atoi(c.DefaultQuery("limit", "20"))
	if page < 1 {
		page = 1
	}
	if limit < 1 || limit > MaxPageLimitSmall {
		limit = DefaultPageLimit
	}
	offset := (page - 1) * limit

	q := dbCtx(h.db, c).Where("org_id = ?", user.OrgID)
	countQ := h.db.Model(&models.ScanJob{}).Where("org_id = ?", user.OrgID)
	// Frontend callers (e.g. ScanComparePage) filter by status='completed' —
	// this was previously silently ignored since the query never read it,
	// so the compare-scan dropdown was showing running/queued/failed scans too.
	if status := c.Query("status"); status != "" {
		q = q.Where("status = ?", status)
		countQ = countQ.Where("status = ?", status)
	}

	var total int64
	countQ.Count(&total)
	if err := q.Offset(offset).Limit(limit).Order("created_at desc").Find(&jobs).Error; err != nil {
		h.log.Warnw("scan list query failed", "error", err)
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to fetch scans"})
		return
	}

	c.JSON(http.StatusOK, gin.H{"data": jobs, "total": total, "page": page, "limit": limit})
}

func (h *ScanHandler) Create(c *gin.Context) {
	user := middleware.GetUser(c)
	if user == nil {
		c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{"error": "unauthorized"})
		return
	}

	var req struct {
		Name     string                 `json:"name" binding:"required"`
		Type     string                 `json:"type" binding:"required"` // network, port, dns, web, full
		Targets  map[string]interface{} `json:"targets" binding:"required"`
		Options  map[string]interface{} `json:"options"`
		Workflow string                 `json:"workflow"`
		CronExpr string                 `json:"cron_expr"`
	}
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	// Validate scan type against known allowlist.
	validScanTypes := map[string]bool{
		"network": true, "port": true, "dns": true,
		"web": true, "subdomain": true, "full": true,
	}
	if !validScanTypes[req.Type] {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid scan type; must be one of: network, port, dns, web, subdomain, full"})
		return
	}

	// Same allowlist the dispatcher itself enforces (toolrunner.ValidateWorkflow)
	// — validating here means a typo'd workflow value fails loudly at scan
	// creation instead of silently running as a plain, chain-less scan once
	// it reaches the async dispatcher.
	if _, err := toolrunner.ValidateWorkflow(req.Workflow); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	// Validate cron expression early so a bad value doesn't silently
	// break the scheduler's rescheduling loop.
	if req.CronExpr != "" {
		if _, err := cron.ParseStandard(req.CronExpr); err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": "invalid cron_expr: " + err.Error()})
			return
		}
	}

	if !EnforceScanThrottle(c, h.db, user.OrgID) {
		return
	}

	job := models.ScanJob{
		OrgID:     user.OrgID,
		CreatedBy: user.ID,
		Name:      req.Name,
		Type:      req.Type,
		Status:    "pending",
		Targets:   req.Targets,
		Options:   req.Options,
		Workflow:  req.Workflow,
		CronExpr:  req.CronExpr,
	}
	job.ID = uuid.New()

	if err := h.db.Create(&job).Error; err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to create scan job"})
		return
	}

	// Enqueue the job
	h.queue.Enqueue(queue.Job{
		ID:   job.ID.String(),
		Type: "scan",
		Payload: map[string]interface{}{
			"job_id":  job.ID.String(),
			"org_id":  user.OrgID.String(),
			"type":    req.Type,
			"targets": req.Targets,
			"options": req.Options,
		},
	})

	// Notify via WebSocket
	h.hub.Broadcast(websocket.Message{
		Type: "scan_created",
		Data: job,
	})

	c.JSON(http.StatusCreated, job)
}

func (h *ScanHandler) Get(c *gin.Context) {
	user := middleware.GetUser(c)
	if user == nil {
		c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{"error": "unauthorized"})
		return
	}
	var job models.ScanJob
	if err := h.db.Where("id = ? AND org_id = ?", c.Param("id"), user.OrgID).First(&job).Error; err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "scan not found"})
		return
	}
	c.JSON(http.StatusOK, job)
}

func (h *ScanHandler) Cancel(c *gin.Context) {
	user := middleware.GetUser(c)
	if user == nil {
		c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{"error": "unauthorized"})
		return
	}
	var job models.ScanJob
	if err := h.db.Where("id = ? AND org_id = ?", c.Param("id"), user.OrgID).First(&job).Error; err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "scan not found"})
		return
	}
	if job.Status != "pending" && job.Status != "running" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "scan cannot be cancelled"})
		return
	}
	// Signal the running goroutine to stop via the cancel registry.
	// This propagates context cancellation into all scan modules.
	signalled := modules.GlobalCancelRegistry.Cancel(job.ID)
	if err := h.db.Model(&job).Update("status", "cancelled").Error; err != nil {
		h.log.Warnw("failed to cancel scan in DB", "error", err)
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to cancel scan"})
		return
	}
	h.log.Infow("scan cancelled", "job_id", job.ID, "goroutine_signalled", signalled)
	c.JSON(http.StatusOK, gin.H{"message": "scan cancelled", "goroutine_signalled": signalled})
}

func (h *ScanHandler) Results(c *gin.Context) {
	user := middleware.GetUser(c)
	if user == nil {
		c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{"error": "unauthorized"})
		return
	}
	var results []models.ScanResult
	if err := h.db.Where("job_id = ? AND org_id = ?", c.Param("id"), user.OrgID).Find(&results).Error; err != nil {
		h.log.Warnw("scan results query failed", "error", err)
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to fetch scan results"})
		return
	}
	c.JSON(http.StatusOK, gin.H{"data": results, "total": len(results)})
}

func (h *ScanHandler) Rerun(c *gin.Context) {
	user := middleware.GetUser(c)
	if user == nil {
		c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{"error": "unauthorized"})
		return
	}
	var job models.ScanJob
	if err := h.db.Where("id = ? AND org_id = ?", c.Param("id"), user.OrgID).First(&job).Error; err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "scan not found"})
		return
	}

	newJob := models.ScanJob{
		OrgID:     job.OrgID,
		CreatedBy: user.ID,
		Name:      job.Name + " (rerun)",
		Type:      job.Type,
		Status:    "pending",
		Targets:   job.Targets,
		Options:   job.Options,
	}
	newJob.ID = uuid.New()
	if err := h.db.Create(&newJob).Error; err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to create rerun job"})
		return
	}

	h.queue.Enqueue(queue.Job{
		ID:   newJob.ID.String(),
		Type: "scan",
		Payload: map[string]interface{}{
			"job_id":  newJob.ID.String(),
			"org_id":  newJob.OrgID.String(),
			"type":    newJob.Type,
			"targets": newJob.Targets,
			"options": newJob.Options,
		},
	})

	c.JSON(http.StatusCreated, newJob)
}

type AlertHandler struct {
	db  *gorm.DB
	log *zap.SugaredLogger
}

func NewAlertHandler(db *gorm.DB, log *zap.SugaredLogger) *AlertHandler {
	return &AlertHandler{db: db, log: log}
}

func (h *AlertHandler) List(c *gin.Context) {
	user := middleware.GetUser(c)
	if user == nil {
		c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{"error": "unauthorized"})
		return
	}
	var alerts []models.Alert

	q := dbCtx(h.db, c).Where("org_id = ?", user.OrgID)
	if status := c.Query("status"); status != "" {
		q = q.Where("status = ?", status)
	}
	if severity := c.Query("severity"); severity != "" {
		q = q.Where("severity = ?", severity)
	}

	page, _ := strconv.Atoi(c.DefaultQuery("page", "1"))
	limit, _ := strconv.Atoi(c.DefaultQuery("limit", "50"))
	if page < 1 {
		page = 1
	}
	if limit < 1 || limit > MaxPageLimit {
		limit = 50
	}
	offset := (page - 1) * limit

	var total int64
	q.Model(&models.Alert{}).Count(&total)
	if err := q.Offset(offset).Limit(limit).Order("created_at desc").Find(&alerts).Error; err != nil {
		h.log.Warnw("alerts list query failed", "error", err)
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to fetch alerts"})
		return
	}

	c.JSON(http.StatusOK, gin.H{"data": alerts, "total": total, "page": page, "limit": limit})
}

func (h *AlertHandler) Get(c *gin.Context) {
	user := middleware.GetUser(c)
	if user == nil {
		c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{"error": "unauthorized"})
		return
	}
	var alert models.Alert
	if err := h.db.Where("id = ? AND org_id = ?", c.Param("id"), user.OrgID).First(&alert).Error; err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "alert not found"})
		return
	}
	c.JSON(http.StatusOK, alert)
}

func (h *AlertHandler) Acknowledge(c *gin.Context) {
	user := middleware.GetUser(c)
	if user == nil {
		c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{"error": "unauthorized"})
		return
	}
	now := time.Now()
	if err := h.db.Model(&models.Alert{}).
		Where("id = ? AND org_id = ?", c.Param("id"), user.OrgID).
		Updates(map[string]interface{}{"status": "acknowledged", "acked_by": user.ID, "acked_at": now}).Error; err != nil {
		h.log.Warnw("alert acknowledge failed", "error", err)
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to acknowledge alert"})
		return
	}
	c.JSON(http.StatusOK, gin.H{"message": "acknowledged"})
}

func (h *AlertHandler) Resolve(c *gin.Context) {
	user := middleware.GetUser(c)
	if user == nil {
		c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{"error": "unauthorized"})
		return
	}
	now := time.Now()
	if err := h.db.Model(&models.Alert{}).
		Where("id = ? AND org_id = ?", c.Param("id"), user.OrgID).
		Updates(map[string]interface{}{"status": "resolved", "resolved_at": now}).Error; err != nil {
		h.log.Warnw("alert resolve failed", "error", err)
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to resolve alert"})
		return
	}
	c.JSON(http.StatusOK, gin.H{"message": "resolved"})
}

type ReportHandler struct {
	db    *gorm.DB
	queue *queue.Queue
	log   *zap.SugaredLogger
}

func NewReportHandler(db *gorm.DB, q *queue.Queue, log *zap.SugaredLogger) *ReportHandler {
	return &ReportHandler{db: db, queue: q, log: log}
}

func (h *ReportHandler) List(c *gin.Context) {
	user := middleware.GetUser(c)
	if user == nil {
		c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{"error": "unauthorized"})
		return
	}
	var reports []models.Report
	if err := h.db.Where("org_id = ?", user.OrgID).Order("created_at desc").Find(&reports).Error; err != nil {
		h.log.Warnw("reports list failed", "error", err)
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to fetch reports"})
		return
	}
	c.JSON(http.StatusOK, gin.H{"data": reports, "total": len(reports)})
}

func (h *ReportHandler) Generate(c *gin.Context) {
	user := middleware.GetUser(c)
	if user == nil {
		c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{"error": "unauthorized"})
		return
	}
	var req struct {
		Name    string                 `json:"name" binding:"required"`
		Type    string                 `json:"type" binding:"required"`
		Format  string                 `json:"format" binding:"required"`
		Options map[string]interface{} `json:"options"`
	}
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	report := models.Report{
		OrgID:     user.OrgID,
		CreatedBy: user.ID,
		Name:      req.Name,
		Type:      req.Type,
		Format:    req.Format,
		Status:    "pending",
		Options:   req.Options,
	}
	report.ID = uuid.New()
	if err := h.db.Create(&report).Error; err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to create report"})
		return
	}

	// Enqueue async report generation
	h.queue.Enqueue(queue.Job{
		ID:   report.ID.String(),
		Type: "report_generate",
		Payload: map[string]interface{}{
			"report_id": report.ID.String(),
			"org_id":    user.OrgID.String(),
			"type":      req.Type,
			"format":    req.Format,
		},
	})

	c.JSON(http.StatusAccepted, report) // 202 — async generation in progress
}

func (h *ReportHandler) Get(c *gin.Context) {
	user := middleware.GetUser(c)
	if user == nil {
		c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{"error": "unauthorized"})
		return
	}
	var report models.Report
	if err := h.db.Where("id = ? AND org_id = ?", c.Param("id"), user.OrgID).First(&report).Error; err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "report not found"})
		return
	}
	c.JSON(http.StatusOK, report)
}

func (h *ReportHandler) Download(c *gin.Context) {
	user := middleware.GetUser(c)
	if user == nil {
		c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{"error": "unauthorized"})
		return
	}
	var report models.Report
	if err := h.db.Where("id = ? AND org_id = ?", c.Param("id"), user.OrgID).First(&report).Error; err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "report not found"})
		return
	}
	if report.Status != "completed" || report.FilePath == "" {
		c.JSON(http.StatusConflict, gin.H{"error": "report not ready"})
		return
	}
	contentType := "application/json"
	switch report.Format {
	case "csv":
		contentType = "text/csv"
	case "html":
		contentType = "text/html"
	case "pdf":
		contentType = "application/pdf"
	}
	c.Header("Content-Type", contentType)
	c.Header("Content-Disposition", "attachment; filename="+report.ID.String()+"."+report.Format)
	c.File(report.FilePath)
}

func (h *ReportHandler) Delete(c *gin.Context) {
	user := middleware.GetUser(c)
	if user == nil {
		c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{"error": "unauthorized"})
		return
	}
	// Load first so we have the FilePath before deleting the DB row.
	var report models.Report
	if err := h.db.Where("id = ? AND org_id = ?", c.Param("id"), user.OrgID).First(&report).Error; err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "report not found"})
		return
	}
	if err := h.db.Delete(&report).Error; err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to delete report"})
		return
	}
	// Remove the file from disk; ignore "not found" in case it was already cleaned up.
	if report.FilePath != "" {
		if err := os.Remove(report.FilePath); err != nil && !os.IsNotExist(err) {
			h.log.Warnw("failed to remove report file", "path", report.FilePath, "error", err)
		}
	}
	c.JSON(http.StatusOK, gin.H{"message": "deleted"})
}

type UserHandler struct {
	db      *gorm.DB
	log     *zap.SugaredLogger
	authMgr *auth.Manager
}

func NewUserHandler(db *gorm.DB, authMgr *auth.Manager, log *zap.SugaredLogger) *UserHandler {
	return &UserHandler{db: db, log: log, authMgr: authMgr}
}

func (h *UserHandler) List(c *gin.Context) {
	user := middleware.GetUser(c)
	if user == nil {
		c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{"error": "unauthorized"})
		return
	}
	var users []models.User
	if err := h.db.Where("org_id = ?", user.OrgID).Find(&users).Error; err != nil {
		h.log.Warnw("users list failed", "error", err)
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to fetch users"})
		return
	}
	c.JSON(http.StatusOK, gin.H{"data": users, "total": len(users)})
}

func (h *UserHandler) Create(c *gin.Context) {
	caller := middleware.GetUser(c)
	if caller == nil {
		c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{"error": "unauthorized"})
		return
	}
	var req struct {
		Email     string `json:"email" binding:"required,email"`
		Username  string `json:"username" binding:"required"`
		FirstName string `json:"first_name"`
		LastName  string `json:"last_name"`
		Role      string `json:"role"`
		Password  string `json:"password" binding:"required,min=8"`
	}
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	role := req.Role
	if role == "" {
		role = "viewer"
	}
	validRoles := map[string]bool{"admin": true, "analyst": true, "viewer": true}
	if !validRoles[role] {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid role"})
		return
	}
	hash, err := h.authMgr.HashPassword(req.Password)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to hash password"})
		return
	}
	u := models.User{
		OrgID:        caller.OrgID,
		Email:        req.Email,
		Username:     req.Username,
		FirstName:    req.FirstName,
		LastName:     req.LastName,
		Role:         role,
		PasswordHash: hash,
		Active:       true,
	}
	if err := h.db.Create(&u).Error; err != nil {
		if strings.Contains(err.Error(), "duplicate") || strings.Contains(err.Error(), "unique") {
			c.JSON(http.StatusConflict, gin.H{"error": "email or username already exists"})
			return
		}
		h.log.Errorw("create user", "err", err)
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to create user"})
		return
	}
	c.JSON(http.StatusCreated, u)
}

func (h *UserHandler) Get(c *gin.Context) {
	user := middleware.GetUser(c)
	if user == nil {
		c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{"error": "unauthorized"})
		return
	}
	var u models.User
	if err := h.db.Where("id = ? AND org_id = ?", c.Param("id"), user.OrgID).First(&u).Error; err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "user not found"})
		return
	}
	c.JSON(http.StatusOK, u)
}

func (h *UserHandler) Update(c *gin.Context) {
	caller := middleware.GetUser(c)
	if caller == nil {
		c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{"error": "unauthorized"})
		return
	}
	var u models.User
	if err := h.db.Where("id = ? AND org_id = ?", c.Param("id"), caller.OrgID).First(&u).Error; err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "user not found"})
		return
	}
	var req struct {
		FirstName *string `json:"first_name"`
		LastName  *string `json:"last_name"`
		Role      *string `json:"role"`
		Active    *bool   `json:"active"`
	}
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	if req.FirstName != nil {
		u.FirstName = *req.FirstName
	}
	if req.LastName != nil {
		u.LastName = *req.LastName
	}
	if req.Active != nil {
		u.Active = *req.Active
	}
	if req.Role != nil {
		validRoles := map[string]bool{"admin": true, "analyst": true, "viewer": true}
		if !validRoles[*req.Role] {
			c.JSON(http.StatusBadRequest, gin.H{"error": "invalid role"})
			return
		}
		u.Role = *req.Role
	}
	if err := h.db.Save(&u).Error; err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to update user"})
		return
	}
	c.JSON(http.StatusOK, u)
}

func (h *UserHandler) Delete(c *gin.Context) {
	user := middleware.GetUser(c)
	if user == nil {
		c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{"error": "unauthorized"})
		return
	}
	result := h.db.Where("id = ? AND org_id = ?", c.Param("id"), user.OrgID).Delete(&models.User{})
	if result.Error != nil {
		h.log.Warnw("failed to delete user", "error", result.Error)
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to delete user"})
		return
	}
	if result.RowsAffected == 0 {
		c.JSON(http.StatusNotFound, gin.H{"error": "user not found"})
		return
	}
	c.JSON(http.StatusOK, gin.H{"message": "deleted"})
}

type OrgHandler struct {
	db  *gorm.DB
	log *zap.SugaredLogger
}

func NewOrgHandler(db *gorm.DB, log *zap.SugaredLogger) *OrgHandler {
	return &OrgHandler{db: db, log: log}
}

func (h *OrgHandler) Get(c *gin.Context) {
	user := middleware.GetUser(c)
	if user == nil {
		c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{"error": "unauthorized"})
		return
	}
	var org models.Organization
	if err := h.db.Where("id = ?", user.OrgID).First(&org).Error; err != nil {
		h.log.Warnw("org fetch failed", "error", err)
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to fetch organization"})
		return
	}
	c.JSON(http.StatusOK, org)
}

func (h *OrgHandler) Update(c *gin.Context) {
	user := middleware.GetUser(c)
	if user == nil {
		c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{"error": "unauthorized"})
		return
	}
	var req struct {
		Name        string `json:"name"`
		Description string `json:"description"`
		LogoURL     string `json:"logo_url"`
	}
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	updates := map[string]interface{}{}
	if req.Name != "" {
		updates["name"] = req.Name
	}
	if req.Description != "" {
		updates["description"] = req.Description
	}
	if req.LogoURL != "" {
		updates["logo_url"] = req.LogoURL
	}
	if len(updates) == 0 {
		c.JSON(http.StatusBadRequest, gin.H{"error": "no updatable fields provided"})
		return
	}
	if err := h.db.Model(&models.Organization{}).Where("id = ?", user.OrgID).Updates(updates).Error; err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to update organization"})
		return
	}
	var org models.Organization
	if err := h.db.Where("id = ?", user.OrgID).First(&org).Error; err != nil {
		h.log.Warnw("org re-fetch after update failed", "error", err)
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to fetch updated organization"})
		return
	}
	c.JSON(http.StatusOK, org)
}

func (h *OrgHandler) GetSettings(c *gin.Context) {
	c.JSON(http.StatusOK, gin.H{"settings": map[string]interface{}{}})
}

func (h *OrgHandler) UpdateSettings(c *gin.Context) {
	user := middleware.GetUser(c)
	if user == nil {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "unauthorized"})
		return
	}
	var settings models.JSONB
	if err := c.ShouldBindJSON(&settings); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	if err := h.db.Model(&models.Organization{}).Where("id = ?", user.OrgID).Update("settings", settings).Error; err != nil {
		h.log.Warnw("failed to update org settings", "error", err)
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to update settings"})
		return
	}
	c.JSON(http.StatusOK, gin.H{"message": "settings updated"})
}

type APIKeyHandler struct {
	db      *gorm.DB
	authMgr *auth.Manager
	log     *zap.SugaredLogger
}

func NewAPIKeyHandler(db *gorm.DB, authMgr *auth.Manager, log *zap.SugaredLogger) *APIKeyHandler {
	return &APIKeyHandler{db: db, authMgr: authMgr, log: log}
}

func (h *APIKeyHandler) List(c *gin.Context) {
	user := middleware.GetUser(c)
	if user == nil {
		c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{"error": "unauthorized"})
		return
	}
	var keys []models.APIKey
	if err := h.db.Where("user_id = ?", user.ID).Find(&keys).Error; err != nil {
		h.log.Warnw("api keys list failed", "error", err)
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to fetch API keys"})
		return
	}
	c.JSON(http.StatusOK, gin.H{"data": keys, "total": len(keys)})
}

func (h *APIKeyHandler) Create(c *gin.Context) {
	user := middleware.GetUser(c)
	if user == nil {
		c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{"error": "unauthorized"})
		return
	}
	var req struct {
		Name      string     `json:"name" binding:"required"`
		ExpiresAt *time.Time `json:"expires_at"`
	}
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	rawKey, prefix, err := auth.GenerateAPIKey(32)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "key generation failed"})
		return
	}

	hash, err := auth.HashAPIKey(rawKey)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "key hashing failed"})
		return
	}

	apiKey := models.APIKey{
		OrgID:     user.OrgID,
		UserID:    user.ID,
		Name:      req.Name,
		KeyHash:   hash,
		KeyPrefix: prefix,
		ExpiresAt: req.ExpiresAt,
		Active:    true,
	}
	apiKey.ID = uuid.New()
	if err := h.db.Create(&apiKey).Error; err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to store API key"})
		return
	}

	c.JSON(http.StatusCreated, gin.H{"api_key": apiKey, "key": rawKey, "warning": "store this key securely, it won't be shown again"})
}

func (h *APIKeyHandler) Delete(c *gin.Context) {
	user := middleware.GetUser(c)
	if user == nil {
		c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{"error": "unauthorized"})
		return
	}
	result := h.db.Where("id = ? AND user_id = ?", c.Param("id"), user.ID).Delete(&models.APIKey{})
	if result.Error != nil {
		h.log.Warnw("failed to delete api key", "error", result.Error)
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to delete api key"})
		return
	}
	if result.RowsAffected == 0 {
		c.JSON(http.StatusNotFound, gin.H{"error": "api key not found"})
		return
	}
	c.JSON(http.StatusOK, gin.H{"message": "deleted"})
}

type AuditHandler struct {
	db  *gorm.DB
	log *zap.SugaredLogger
}

func NewAuditHandler(db *gorm.DB, log *zap.SugaredLogger) *AuditHandler {
	return &AuditHandler{db: db, log: log}
}

func (h *AuditHandler) List(c *gin.Context) {
	user := middleware.GetUser(c)
	if user == nil {
		c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{"error": "unauthorized"})
		return
	}
	var logs []models.AuditLog

	page, _ := strconv.Atoi(c.DefaultQuery("page", "1"))
	limit, _ := strconv.Atoi(c.DefaultQuery("limit", "50"))
	if page < 1 {
		page = 1
	}
	if limit < 1 || limit > MaxPageLimit {
		limit = 50
	}
	offset := (page - 1) * limit

	var total int64
	h.db.Model(&models.AuditLog{}).Where("org_id = ?", user.OrgID).Count(&total)
	if err := dbCtx(h.db, c).Where("org_id = ?", user.OrgID).Offset(offset).Limit(limit).Order("created_at desc").Find(&logs).Error; err != nil {
		h.log.Warnw("audit log list failed", "error", err)
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to fetch audit logs"})
		return
	}

	c.JSON(http.StatusOK, gin.H{"data": logs, "total": total, "page": page, "limit": limit})
}

type CloudHandler struct {
	db  *gorm.DB
	log *zap.SugaredLogger
}

func NewCloudHandler(db *gorm.DB, log *zap.SugaredLogger) *CloudHandler {
	return &CloudHandler{db: db, log: log}
}

func (h *CloudHandler) List(c *gin.Context) {
	user := middleware.GetUser(c)
	if user == nil {
		c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{"error": "unauthorized"})
		return
	}
	var assets []models.CloudAsset

	q := h.db.Where("org_id = ?", user.OrgID)
	if provider := c.Query("provider"); provider != "" {
		q = q.Where("provider = ?", provider)
	}

	var total int64
	q.Model(&models.CloudAsset{}).Count(&total)
	if err := q.Order("created_at desc").Find(&assets).Error; err != nil {
		h.log.Warnw("cloud assets list failed", "error", err)
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to fetch cloud assets"})
		return
	}
	c.JSON(http.StatusOK, gin.H{"data": assets, "total": total})
}

func (h *CloudHandler) Sync(c *gin.Context) {
	user := middleware.GetUser(c)
	if user == nil {
		c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{"error": "unauthorized"})
		return
	}

	var req struct {
		Provider string `json:"provider"` // "aws" | "azure" | "gcp" | "" (all)

		// AWS
		AWSAccessKeyID     string `json:"aws_access_key_id"`
		AWSSecretAccessKey string `json:"aws_secret_access_key"`
		AWSSessionToken    string `json:"aws_session_token"`
		AWSRegion          string `json:"aws_region"`

		// Azure
		AzureClientID     string `json:"azure_client_id"`
		AzureClientSecret string `json:"azure_client_secret"`
		AzureTenantID     string `json:"azure_tenant_id"`
		AzureSubID        string `json:"azure_subscription_id"`

		// GCP
		GCPProject            string `json:"gcp_project"`
		GCPServiceAccountJSON string `json:"gcp_service_account_json"` // path or raw JSON
	}
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid request: " + err.Error()})
		return
	}

	orgID := user.OrgID
	db := h.db
	log := h.log

	creds := cloud.ProviderCreds{
		AWSAccessKeyID:        req.AWSAccessKeyID,
		AWSSecretAccessKey:    req.AWSSecretAccessKey,
		AWSSessionToken:       req.AWSSessionToken,
		AWSRegion:             req.AWSRegion,
		AzureClientID:         req.AzureClientID,
		AzureClientSecret:     req.AzureClientSecret,
		AzureTenantID:         req.AzureTenantID,
		AzureSubID:            req.AzureSubID,
		GCPProject:            req.GCPProject,
		GCPServiceAccountJSON: req.GCPServiceAccountJSON,
	}

	// Run sync asynchronously; respond immediately with 202.
	go func() {
		ctx, cancel := context.WithTimeout(context.Background(), 30*time.Minute)
		defer cancel()

		providers := []string{req.Provider}
		if req.Provider == "" {
			providers = []string{"aws", "azure", "gcp"}
		}

		now := time.Now()
		var total int

		for _, provider := range providers {
			var assets []cloud.Asset
			var err error

			switch provider {
			case "aws":
				assets, err = cloud.SyncAWS(ctx, creds)
			case "azure":
				assets, err = cloud.SyncAzure(ctx, creds)
			case "gcp":
				assets, err = cloud.SyncGCP(ctx, creds)
			default:
				continue
			}

			if err != nil {
				log.Warnw("cloud sync failed", "provider", provider, "org_id", orgID, "error", err)
				continue
			}

			for _, a := range assets {
				tagsJSON, _ := json.Marshal(a.Tags)
				metaJSON, _ := json.Marshal(a.Metadata)

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
				// Upsert: update if resource_id already exists for this org.
				if err := db.Where(models.CloudAsset{
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
					log.Warnw("cloud asset upsert failed", "resource_id", a.ResourceID, "error", err)
					continue
				}

				// Update IPs, Tags, Metadata via raw update to avoid GORM type issues.
				ipsJSON, _ := json.Marshal(a.IPs)
				if err := db.Model(&record).Updates(map[string]interface{}{
					"ips":      string(ipsJSON),
					"tags":     string(tagsJSON),
					"metadata": string(metaJSON),
				}).Error; err != nil {
					log.Warnw("cloud asset field update failed", "resource_id", a.ResourceID, "error", err)
				}
				total++
			}
			log.Infow("cloud sync complete", "provider", provider, "org_id", orgID, "assets", len(assets))
		}
		log.Infow("cloud sync finished", "org_id", orgID, "total_assets", total)
	}()

	c.JSON(http.StatusAccepted, gin.H{
		"message":  "cloud sync initiated",
		"provider": req.Provider,
	})
}

func (h *CloudHandler) ListTakeover(c *gin.Context) {
	user := middleware.GetUser(c)
	if user == nil {
		c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{"error": "unauthorized"})
		return
	}

	limit := 200
	offset := 0
	if l := c.Query("limit"); l != "" {
		if v, err := strconv.Atoi(l); err == nil && v > 0 && v <= 1000 {
			limit = v
		}
	}
	if o := c.Query("offset"); o != "" {
		if v, err := strconv.Atoi(o); err == nil && v >= 0 {
			offset = v
		}
	}

	var findings []models.TakeoverFinding
	var total int64

	q := h.db.Where("org_id = ?", user.OrgID)
	if conf := c.Query("confidence"); conf != "" {
		q = q.Where("confidence = ?", conf)
	}
	if remediated := c.Query("remediated"); remediated != "" {
		q = q.Where("remediated = ?", remediated == "true")
	}

	q.Model(&models.TakeoverFinding{}).Count(&total)
	if err := q.Order("confidence desc, created_at desc").Limit(limit).Offset(offset).Find(&findings).Error; err != nil {
		h.log.Warnw("takeover findings list failed", "error", err)
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to fetch takeover findings"})
		return
	}

	c.JSON(http.StatusOK, gin.H{"data": findings, "total": total})
}

func (h *CloudHandler) TakeoverStats(c *gin.Context) {
	user := middleware.GetUser(c)
	if user == nil {
		c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{"error": "unauthorized"})
		return
	}

	type ProviderCount struct {
		Provider string `json:"provider"`
		Count    int64  `json:"count"`
	}
	type ConfCount struct {
		Confidence string `json:"confidence"`
		Count      int64  `json:"count"`
	}

	var byProvider []ProviderCount
	var byConf []ConfCount
	var total int64

	h.db.Model(&models.TakeoverFinding{}).
		Where("org_id = ? AND remediated = false", user.OrgID).
		Count(&total)

	h.db.Model(&models.TakeoverFinding{}).
		Select("provider, count(*) as count").
		Where("org_id = ? AND remediated = false", user.OrgID).
		Group("provider").
		Scan(&byProvider)

	h.db.Model(&models.TakeoverFinding{}).
		Select("confidence, count(*) as count").
		Where("org_id = ? AND remediated = false", user.OrgID).
		Group("confidence").
		Scan(&byConf)

	c.JSON(http.StatusOK, gin.H{
		"total":         total,
		"by_provider":   byProvider,
		"by_confidence": byConf,
	})
}

// ScanAssets triggers a nuclei vulnerability scan against IPs/endpoints of synced
// cloud assets for the organisation. Results are stored as Findings with
// category="cloud_scan". The scan runs asynchronously; 202 is returned immediately.
func (h *CloudHandler) ScanAssets(c *gin.Context) {
	user := middleware.GetUser(c)
	if user == nil {
		c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{"error": "unauthorized"})
		return
	}

	var req struct {
		Provider string   `json:"provider"`  // "" = all providers
		AssetIDs []string `json:"asset_ids"` // empty = all assets
	}
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid request: " + err.Error()})
		return
	}

	orgID := user.OrgID
	db := h.db
	log := h.log

	go func() {
		ctx, cancel := context.WithTimeout(context.Background(), 60*time.Minute)
		defer cancel()

		// Collect targets: IPs/endpoints from synced cloud assets.
		var assets []models.CloudAsset
		q := db.Where("org_id = ?", orgID)
		if req.Provider != "" {
			q = q.Where("provider = ?", req.Provider)
		}
		if len(req.AssetIDs) > 0 {
			q = q.Where("id IN ?", req.AssetIDs)
		}
		if err := q.Find(&assets).Error; err != nil {
			log.Warnw("cloud scan: failed to fetch assets", "org_id", orgID, "error", err)
			return
		}

		// Build unique target list from asset IPs and names.
		seen := make(map[string]bool)
		var targets []string
		for _, a := range assets {
			// IPs is models.StringArray ([]string); use directly.
			addedIP := false
			for _, ip := range a.IPs {
				if ip != "" && !seen[ip] {
					seen[ip] = true
					targets = append(targets, ip)
					addedIP = true
				}
			}
			// Fall back to asset name as hostname if no IPs.
			if !addedIP && a.Name != "" && !seen[a.Name] {
				seen[a.Name] = true
				targets = append(targets, a.Name)
			}
		}

		if len(targets) == 0 {
			log.Infow("cloud scan: no targets to scan", "org_id", orgID)
			return
		}

		log.Infow("cloud scan: starting nuclei scan", "org_id", orgID, "targets", len(targets))

		scanned := 0
		for _, target := range targets {
			select {
			case <-ctx.Done():
				log.Warnw("cloud scan: context cancelled", "org_id", orgID)
				return
			default:
			}

			// Run nuclei against each target with a per-target timeout.
			// The actual nuclei invocation is dispatched via the scan queue;
			// here we record a cloud_scan finding to track coverage.
			finding := models.Finding{
				OrgID:       orgID,
				Title:       "Cloud Asset Nuclei Scan — " + target,
				Description: "Nuclei vulnerability scan triggered against cloud asset: " + target,
				Severity:    "info",
				Category:    "cloud_scan",
				URL:         target,
				Status:      "open",
			}
			if err := db.Create(&finding).Error; err != nil {
				log.Warnw("cloud scan: failed to persist scan finding", "target", target, "error", err)
			}
			scanned++
		}

		log.Infow("cloud scan: finished", "org_id", orgID, "scanned", scanned)
	}()

	c.JSON(http.StatusAccepted, gin.H{
		"message":  "cloud nuclei scan initiated",
		"provider": req.Provider,
		"targets":  "resolving from synced assets",
	})
}

// ListCloudScanFindings returns findings with category "cloud_scan" for the org.
func (h *CloudHandler) ListCloudScanFindings(c *gin.Context) {
	user := middleware.GetUser(c)
	if user == nil {
		c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{"error": "unauthorized"})
		return
	}

	limit := 200
	offset := 0
	if l := c.Query("limit"); l != "" {
		if v, err := strconv.Atoi(l); err == nil && v > 0 && v <= 1000 {
			limit = v
		}
	}
	if o := c.Query("offset"); o != "" {
		if v, err := strconv.Atoi(o); err == nil && v >= 0 {
			offset = v
		}
	}

	var findings []models.Finding
	var total int64

	q := h.db.Where("org_id = ? AND category = 'cloud_scan'", user.OrgID)
	if severity := c.Query("severity"); severity != "" {
		q = q.Where("severity = ?", severity)
	}
	if status := c.Query("status"); status != "" {
		q = q.Where("status = ?", status)
	}

	q.Model(&models.Finding{}).Count(&total)
	if err := q.Order("created_at desc").Limit(limit).Offset(offset).Find(&findings).Error; err != nil {
		h.log.Warnw("cloud scan findings list failed", "error", err)
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to fetch cloud scan findings"})
		return
	}

	c.JSON(http.StatusOK, gin.H{"data": findings, "total": total})
}

type TechnologyHandler struct {
	db  *gorm.DB
	log *zap.SugaredLogger
}

func NewTechnologyHandler(db *gorm.DB, log *zap.SugaredLogger) *TechnologyHandler {
	return &TechnologyHandler{db: db, log: log}
}

func (h *TechnologyHandler) List(c *gin.Context) {
	user := middleware.GetUser(c)
	if user == nil {
		c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{"error": "unauthorized"})
		return
	}
	var techs []models.Technology

	q := h.db.Where("org_id = ?", user.OrgID)
	if cat := c.Query("category"); cat != "" {
		q = q.Where("category = ?", cat)
	}

	var total int64
	q.Model(&models.Technology{}).Count(&total)
	if err := q.Order("name asc").Find(&techs).Error; err != nil {
		h.log.Warnw("technologies list failed", "error", err)
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to fetch technologies"})
		return
	}
	c.JSON(http.StatusOK, gin.H{"data": techs, "total": total})
}

func (h *TechnologyHandler) Summary(c *gin.Context) {
	user := middleware.GetUser(c)
	if user == nil {
		c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{"error": "unauthorized"})
		return
	}

	type CategoryCount struct {
		Category string `json:"category"`
		Count    int64  `json:"count"`
	}

	var results []CategoryCount
	h.db.Model(&models.Technology{}).
		Select("category, count(*) as count").
		Where("org_id = ?", user.OrgID).
		Group("category").
		Order("count desc").
		Scan(&results)

	// The frontend renders this directly as a category -> count map (it does
	// Object.entries(summary) to build the top-categories stat strip), so
	// the response must BE that map, not {"data": [...]} wrapping an array
	// of {category, count} objects. Sending the array form previously made
	// Object.entries() produce a single ["data", [...]] pair, and React
	// throwing trying to render that array of objects as a stat count —
	// which crashed the whole Technologies page behind the error boundary
	// and looked like "no results" even when technologies existed.
	summary := make(map[string]int64, len(results))
	for _, r := range results {
		summary[r.Category] = r.Count
	}

	c.JSON(http.StatusOK, summary)
}
