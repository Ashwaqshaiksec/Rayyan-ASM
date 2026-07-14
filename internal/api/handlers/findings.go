package handlers

import (
	"encoding/csv"
	"fmt"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/ShadooowX/rayyan-asm/internal/api/middleware"
	"github.com/ShadooowX/rayyan-asm/internal/models"
	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
	"go.uber.org/zap"
	"gorm.io/gorm"
)

type FindingHandler struct {
	db  *gorm.DB
	log *zap.SugaredLogger
}

func NewFindingHandler(db *gorm.DB, log *zap.SugaredLogger) *FindingHandler {
	return &FindingHandler{db: db, log: log}
}

// splitCSV parses a comma-separated query param (e.g. "critical,high") into
// its individual values, trimming whitespace and dropping empty segments so
// a trailing/leading comma or accidental double-comma doesn't produce a
// blank IN(...) entry that would silently match nothing.
func splitCSV(s string) []string {
	parts := strings.Split(s, ",")
	out := make([]string, 0, len(parts))
	for _, p := range parts {
		p = strings.TrimSpace(p)
		if p != "" {
			out = append(out, p)
		}
	}
	return out
}

func (h *FindingHandler) List(c *gin.Context) {
	user := middleware.GetUser(c)
	if user == nil {
		c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{"error": "unauthorized"})
		return
	}

	q := h.db.Model(&models.Finding{}).Where("org_id = ?", user.OrgID)

	if s := c.Query("severity"); s != "" {
		q = q.Where("severity IN ?", splitCSV(s))
	}
	if s := c.Query("status"); s != "" {
		q = q.Where("status IN ?", splitCSV(s))
	}
	if s := c.Query("category"); s != "" {
		q = q.Where("category IN ?", splitCSV(s))
	}

	page, _ := strconv.Atoi(c.DefaultQuery("page", "1"))
	limit, _ := strconv.Atoi(c.DefaultQuery("limit", "50"))
	if page < 1 {
		page = 1
	}
	if limit < 1 || limit > MaxPageLimitSmall {
		limit = 50
	}
	offset := (page - 1) * limit

	var total int64
	q.Count(&total)

	var findings []models.Finding
	if err := q.Order("created_at desc").Limit(limit).Offset(offset).Find(&findings).Error; err != nil {
		h.log.Warnw("findings list failed", "error", err)
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to fetch findings"})
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"data":  findings,
		"total": total,
		"page":  page,
		"limit": limit,
	})
}

func (h *FindingHandler) Get(c *gin.Context) {
	user := middleware.GetUser(c)
	if user == nil {
		c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{"error": "unauthorized"})
		return
	}
	id, err := uuid.Parse(c.Param("id"))
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid id"})
		return
	}
	var f models.Finding
	if err := h.db.Where("id = ? AND org_id = ?", id, user.OrgID).First(&f).Error; err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "finding not found"})
		return
	}
	c.JSON(http.StatusOK, f)
}

func (h *FindingHandler) Summary(c *gin.Context) {
	user := middleware.GetUser(c)
	if user == nil {
		c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{"error": "unauthorized"})
		return
	}
	type SevCount struct {
		Severity string `json:"severity"`
		Count    int64  `json:"count"`
	}
	var bySeverity []SevCount
	h.db.Model(&models.Finding{}).
		Select("severity, count(*) as count").
		Where("org_id = ?", user.OrgID).
		Group("severity").
		Scan(&bySeverity)

	type StatusCount struct {
		Status string `json:"status"`
		Count  int64  `json:"count"`
	}
	var byStatus []StatusCount
	h.db.Model(&models.Finding{}).
		Select("status, count(*) as count").
		Where("org_id = ?", user.OrgID).
		Group("status").
		Scan(&byStatus)

	type CategoryCount struct {
		Category string `json:"category"`
		Count    int64  `json:"count"`
	}
	var byCategory []CategoryCount
	h.db.Model(&models.Finding{}).
		Select("category, count(*) as count").
		Where("org_id = ? AND category != ''", user.OrgID).
		Group("category").
		Scan(&byCategory)

	var total int64
	h.db.Model(&models.Finding{}).Where("org_id = ?", user.OrgID).Count(&total)

	c.JSON(http.StatusOK, gin.H{
		"total":       total,
		"by_severity": bySeverity,
		"by_status":   byStatus,
		"by_category": byCategory,
	})
}

func (h *FindingHandler) Export(c *gin.Context) {
	user := middleware.GetUser(c)
	if user == nil {
		c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{"error": "unauthorized"})
		return
	}
	var findings []models.Finding
	if err := h.db.Where("org_id = ?", user.OrgID).Order("severity, created_at desc").Find(&findings).Error; err != nil {
		h.log.Warnw("findings export failed", "error", err)
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to export findings"})
		return
	}

	c.Header("Content-Disposition", "attachment; filename=findings.csv")
	c.Header("Content-Type", "text/csv")
	w := csv.NewWriter(c.Writer)
	_ = w.Write([]string{"ID", "Title", "Severity", "Category", "Status", "URL", "CVE", "CVSS", "Created"})
	for _, f := range findings {
		_ = w.Write([]string{
			f.ID.String(), f.Title, f.Severity, f.Category, f.Status,
			f.URL, f.CVE, strconv.FormatFloat(f.CVSS, 'f', 1, 64),
			f.CreatedAt.Format(time.RFC3339),
		})
	}
	w.Flush()
	if err := w.Error(); err != nil {
		// Headers already sent; log the error so it isn't silently dropped.
		// Returning an error body here would corrupt the CSV stream.
		h.log.Warnw("findings CSV export write error", "error", err)
	}
}

func (h *FindingHandler) Create(c *gin.Context) {
	user := middleware.GetUser(c)
	if user == nil {
		c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{"error": "unauthorized"})
		return
	}
	var body struct {
		Title       string  `json:"title" binding:"required"`
		Description string  `json:"description"`
		Severity    string  `json:"severity" binding:"required"`
		Category    string  `json:"category"`
		URL         string  `json:"url"`
		Evidence    string  `json:"evidence"`
		Remediation string  `json:"remediation"`
		CVSS        float64 `json:"cvss"`
		CVSSVector  string  `json:"cvss_vector"`
		CVSSVersion string  `json:"cvss_version"`
		CVE         string  `json:"cve"`
	}
	if err := c.ShouldBindJSON(&body); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	validSeverities := map[string]bool{"critical": true, "high": true, "medium": true, "low": true, "info": true}
	if !validSeverities[body.Severity] {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid severity; must be critical, high, medium, low, or info"})
		return
	}
	cvssVer := body.CVSSVersion
	if cvssVer == "" {
		cvssVer = "CVSS:3.1"
	}
	f := models.Finding{
		OrgID:       user.OrgID,
		Title:       body.Title,
		Description: body.Description,
		Severity:    body.Severity,
		Category:    body.Category,
		URL:         body.URL,
		Evidence:    body.Evidence,
		Remediation: body.Remediation,
		CVSS:        body.CVSS,
		CVSSVector:  body.CVSSVector,
		CVSSVersion: cvssVer,
		CVE:         body.CVE,
		Status:      "open",
	}
	if err := h.db.Create(&f).Error; err != nil {
		h.log.Errorw("create finding", "err", err)
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to create finding"})
		return
	}

	// Fire outbound webhook notification for high/critical findings
	if f.Severity == "critical" || f.Severity == "high" {
		alert := &models.Alert{
			OrgID:     f.OrgID,
			Type:      "new_finding",
			Severity:  f.Severity,
			Title:     fmt.Sprintf("New %s finding: %s", f.Severity, f.Title),
			Message:   fmt.Sprintf("A new %s severity finding was created: %s\nURL: %s\nCVSS: %.1f", f.Severity, f.Title, f.URL, f.CVSS),
			AssetType: "finding",
			Status:    "open",
		}
		if err := h.db.Create(alert).Error; err != nil {
			h.log.Warnw("failed to persist finding alert", "err", err)
		}
		go DispatchAlertNotifications(h.db, h.log, alert)
	}

	c.JSON(http.StatusCreated, f)
}

func (h *FindingHandler) Update(c *gin.Context) {
	user := middleware.GetUser(c)
	if user == nil {
		c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{"error": "unauthorized"})
		return
	}
	id, err := uuid.Parse(c.Param("id"))
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid id"})
		return
	}
	var f models.Finding
	if err := h.db.Where("id = ? AND org_id = ?", id, user.OrgID).First(&f).Error; err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "finding not found"})
		return
	}
	var body struct {
		Title       *string  `json:"title"`
		Description *string  `json:"description"`
		Severity    *string  `json:"severity"`
		Category    *string  `json:"category"`
		URL         *string  `json:"url"`
		Evidence    *string  `json:"evidence"`
		Remediation *string  `json:"remediation"`
		CVSS        *float64 `json:"cvss"`
		CVE         *string  `json:"cve"`
		Status      *string  `json:"status"`
	}
	if err := c.ShouldBindJSON(&body); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	if body.Title != nil {
		f.Title = *body.Title
	}
	if body.Description != nil {
		f.Description = *body.Description
	}
	if body.Severity != nil {
		f.Severity = *body.Severity
	}
	if body.Category != nil {
		f.Category = *body.Category
	}
	if body.URL != nil {
		f.URL = *body.URL
	}
	if body.Evidence != nil {
		f.Evidence = *body.Evidence
	}
	if body.Remediation != nil {
		f.Remediation = *body.Remediation
	}
	if body.CVSS != nil {
		f.CVSS = *body.CVSS
	}
	if body.CVE != nil {
		f.CVE = *body.CVE
	}
	if body.Status != nil {
		validStatuses := map[string]bool{"open": true, "acknowledged": true, "false_positive": true, "fixed": true}
		if !validStatuses[*body.Status] {
			c.JSON(http.StatusBadRequest, gin.H{"error": "invalid status"})
			return
		}
		f.Status = *body.Status
		now := time.Now()
		switch *body.Status {
		case "acknowledged":
			f.AcknowledgedAt = &now
		case "fixed":
			f.FixedAt = &now
		}
	}
	if err := h.db.Save(&f).Error; err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to update finding"})
		return
	}

	// Fire webhook if severity was escalated to critical/high
	if body.Severity != nil && (f.Severity == "critical" || f.Severity == "high") {
		alert := &models.Alert{
			OrgID:     f.OrgID,
			Type:      "finding_escalated",
			Severity:  f.Severity,
			Title:     fmt.Sprintf("Finding escalated to %s: %s", f.Severity, f.Title),
			Message:   fmt.Sprintf("Finding severity updated to %s: %s\nURL: %s\nCVSS: %.1f", f.Severity, f.Title, f.URL, f.CVSS),
			AssetType: "finding",
			Status:    "open",
		}
		if err := h.db.Create(alert).Error; err != nil {
			h.log.Warnw("failed to persist escalation alert", "err", err)
		}
		go DispatchAlertNotifications(h.db, h.log, alert)
	}

	c.JSON(http.StatusOK, f)
}

func (h *FindingHandler) Acknowledge(c *gin.Context) {
	h.setStatus(c, "acknowledged", func(f *models.Finding) {
		now := time.Now()
		f.AcknowledgedAt = &now
	})
}

func (h *FindingHandler) FalsePositive(c *gin.Context) {
	h.setStatus(c, "false_positive", nil)
}

func (h *FindingHandler) MarkFixed(c *gin.Context) {
	h.setStatus(c, "fixed", func(f *models.Finding) {
		now := time.Now()
		f.FixedAt = &now
	})
}

func (h *FindingHandler) BulkUpdate(c *gin.Context) {
	user := middleware.GetUser(c)
	if user == nil {
		c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{"error": "unauthorized"})
		return
	}
	var body struct {
		IDs    []string `json:"ids"`
		Status string   `json:"status"`
	}
	if err := c.ShouldBindJSON(&body); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	validStatuses := map[string]bool{"open": true, "acknowledged": true, "false_positive": true, "fixed": true}
	if !validStatuses[body.Status] {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid status; must be open, acknowledged, false_positive, or fixed"})
		return
	}
	ids := make([]uuid.UUID, 0, len(body.IDs))
	for _, s := range body.IDs {
		if id, err := uuid.Parse(s); err == nil {
			ids = append(ids, id)
		}
	}
	if len(ids) == 0 {
		c.JSON(http.StatusBadRequest, gin.H{"error": "no valid ids provided"})
		return
	}
	h.db.Model(&models.Finding{}).
		Where("id IN ? AND org_id = ?", ids, user.OrgID).
		Update("status", body.Status)
	c.JSON(http.StatusOK, gin.H{"updated": len(ids)})
}

func (h *FindingHandler) Delete(c *gin.Context) {
	user := middleware.GetUser(c)
	if user == nil {
		c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{"error": "unauthorized"})
		return
	}
	id, err := uuid.Parse(c.Param("id"))
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid id"})
		return
	}
	result := h.db.Where("id = ? AND org_id = ?", id, user.OrgID).Delete(&models.Finding{})
	if result.Error != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to delete finding"})
		return
	}
	if result.RowsAffected == 0 {
		c.JSON(http.StatusNotFound, gin.H{"error": "finding not found"})
		return
	}
	c.JSON(http.StatusOK, gin.H{"message": "deleted"})
}

func (h *FindingHandler) setStatus(c *gin.Context, status string, mutate func(*models.Finding)) {
	user := middleware.GetUser(c)
	if user == nil {
		c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{"error": "unauthorized"})
		return
	}
	id, err := uuid.Parse(c.Param("id"))
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid id"})
		return
	}
	var f models.Finding
	if err := h.db.Where("id = ? AND org_id = ?", id, user.OrgID).First(&f).Error; err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "finding not found"})
		return
	}
	f.Status = status
	if mutate != nil {
		mutate(&f)
	}
	if err := h.db.Save(&f).Error; err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to update finding"})
		return
	}
	c.JSON(http.StatusOK, f)
}
