package handlers

import (
	"bufio"
	"encoding/json"
	"net/http"
	"os/exec"
	"sort"
	"time"

	"github.com/ShadooowX/rayyan-asm/internal/api/middleware"
	"github.com/ShadooowX/rayyan-asm/internal/api/websocket"
	"github.com/ShadooowX/rayyan-asm/internal/modules/toolrunner"
	"github.com/gin-gonic/gin"
	"go.uber.org/zap"
	"gorm.io/gorm"
)

// ToolHandler handles the external tool management API endpoints.
type ToolHandler struct {
	registry *toolrunner.Registry
	hub      *websocket.Hub
	db       *gorm.DB
	log      *zap.SugaredLogger
}

// NewToolHandler creates a new ToolHandler.
func NewToolHandler(registry *toolrunner.Registry, hub *websocket.Hub, db *gorm.DB, log *zap.SugaredLogger) *ToolHandler {
	return &ToolHandler{registry: registry, hub: hub, db: db, log: log}
}

type toolResponse struct {
	Name               string                `json:"name"`
	Category           toolrunner.Category   `json:"category"`
	Description        string                `json:"description"`
	BinaryPath         string                `json:"binary_path"`
	Version            string                `json:"version"`
	Status             toolrunner.ToolStatus `json:"status"`
	Enabled            bool                  `json:"enabled"`
	MaxConcurrent      int                   `json:"max_concurrent"`
	MinIntervalSeconds int                   `json:"min_interval_seconds"`
	LastRun            interface{}           `json:"last_run"`
	LastRunOK          bool                  `json:"last_run_ok"`
}

func toResponse(t toolrunner.ToolInfo) toolResponse {
	var lastRun interface{}
	if t.LastRun != nil {
		lastRun = t.LastRun
	}
	return toolResponse{
		Name:               t.Name,
		Category:           t.Category,
		Description:        t.Description,
		BinaryPath:         t.BinaryPath,
		Version:            t.Version,
		Status:             t.Status,
		Enabled:            t.Enabled,
		MaxConcurrent:      t.MaxConcurrent,
		MinIntervalSeconds: t.MinIntervalSeconds,
		LastRun:            lastRun,
		LastRunOK:          t.LastRunOK,
	}
}

// List returns all registered tools grouped by category. Admin only.
func (h *ToolHandler) List(c *gin.Context) {
	tools := h.registry.List()
	grouped := make(map[string][]toolResponse)
	for _, t := range tools {
		cat := string(t.Category)
		grouped[cat] = append(grouped[cat], toResponse(t))
	}
	for cat := range grouped {
		sort.Slice(grouped[cat], func(i, j int) bool {
			return grouped[cat][i].Name < grouped[cat][j].Name
		})
	}
	categories := make([]string, 0, len(grouped))
	for cat := range grouped {
		categories = append(categories, cat)
	}
	sort.Strings(categories)

	type categoryGroup struct {
		Category string         `json:"category"`
		Tools    []toolResponse `json:"tools"`
	}
	result := make([]categoryGroup, 0, len(categories))
	for _, cat := range categories {
		result = append(result, categoryGroup{Category: cat, Tools: grouped[cat]})
	}
	c.JSON(http.StatusOK, gin.H{"data": result, "total": len(tools)})
}

// Get returns details for a single tool.
func (h *ToolHandler) Get(c *gin.Context) {
	name := c.Param("name")
	tool, ok := h.registry.Get(name)
	if !ok {
		c.JSON(http.StatusNotFound, gin.H{"error": "tool not found: " + name})
		return
	}
	c.JSON(http.StatusOK, toResponse(tool))
}

// Verify re-checks installation status and version for the named tool.
func (h *ToolHandler) Verify(c *gin.Context) {
	name := c.Param("name")
	tool, ok := h.registry.Verify(name)
	if !ok {
		c.JSON(http.StatusNotFound, gin.H{"error": "tool not found: " + name})
		return
	}
	h.log.Infow("tool verified", "tool", name, "status", tool.Status, "version", tool.Version)
	c.JSON(http.StatusOK, gin.H{"message": "verification complete", "tool": toResponse(tool)})
}

// Enable enables the named tool for use in scans.
func (h *ToolHandler) Enable(c *gin.Context) {
	name := c.Param("name")
	if !h.registry.SetEnabled(name, true) {
		c.JSON(http.StatusNotFound, gin.H{"error": "tool not found: " + name})
		return
	}
	tool, _ := h.registry.Get(name)
	h.log.Infow("tool enabled", "tool", name)
	c.JSON(http.StatusOK, gin.H{"message": "tool enabled", "tool": toResponse(tool)})
}

// Disable disables the named tool so it is skipped during scans.
func (h *ToolHandler) Disable(c *gin.Context) {
	name := c.Param("name")
	if !h.registry.SetEnabled(name, false) {
		c.JSON(http.StatusNotFound, gin.H{"error": "tool not found: " + name})
		return
	}
	tool, _ := h.registry.Get(name)
	h.log.Infow("tool disabled", "tool", name)
	c.JSON(http.StatusOK, gin.H{"message": "tool disabled", "tool": toResponse(tool)})
}

// VerifyAll re-checks all registered tools.
func (h *ToolHandler) VerifyAll(c *gin.Context) {
	h.registry.VerifyAll()
	tools := h.registry.List()
	installed, missing := 0, 0
	for _, t := range tools {
		if t.Status == toolrunner.StatusInstalled {
			installed++
		} else {
			missing++
		}
	}
	h.log.Infow("all tools verified", "installed", installed, "missing", missing)
	c.JSON(http.StatusOK, gin.H{
		"message":   "verification complete",
		"installed": installed,
		"missing":   missing,
		"total":     len(tools),
	})
}

// SetRateLimits updates per-tool concurrency and interval limits.
// PATCH /api/v1/tools/:name/rate-limits
func (h *ToolHandler) SetRateLimits(c *gin.Context) {
	name := c.Param("name")
	var body struct {
		MaxConcurrent      int `json:"max_concurrent"`
		MinIntervalSeconds int `json:"min_interval_seconds"`
	}
	if err := c.ShouldBindJSON(&body); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid request body: " + err.Error()})
		return
	}
	if !h.registry.SetRateLimits(name, body.MaxConcurrent, body.MinIntervalSeconds) {
		c.JSON(http.StatusNotFound, gin.H{"error": "tool not found: " + name})
		return
	}
	tool, _ := h.registry.Get(name)
	h.log.Infow("tool rate limits updated", "tool", name,
		"max_concurrent", body.MaxConcurrent,
		"min_interval_seconds", body.MinIntervalSeconds)
	c.JSON(http.StatusOK, gin.H{"message": "rate limits updated", "tool": toResponse(tool)})
}

type toolRunHistoryRow struct {
	ID          string    `gorm:"primaryKey" json:"id"`
	ScanID      string    `json:"scan_id"`
	ToolName    string    `json:"tool_name"`
	ResultCount int       `json:"result_count"`
	DurationMS  int64     `json:"duration_ms"`
	Status      string    `json:"status"`
	Truncated   bool      `json:"truncated"`
	CreatedAt   time.Time `json:"created_at"`
}

func (toolRunHistoryRow) TableName() string { return "tool_run_results" }

// Runs returns the run history for a single tool, scoped to the caller's org.
// GET /api/v1/tools/:name/runs
func (h *ToolHandler) Runs(c *gin.Context) {
	name := c.Param("name")
	if _, ok := h.registry.Get(name); !ok {
		c.JSON(http.StatusNotFound, gin.H{"error": "tool not found: " + name})
		return
	}
	user := middleware.GetUser(c)
	if user == nil {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "unauthorized"})
		return
	}
	var rows []toolRunHistoryRow
	// tool_run_results has no org_id column of its own — it's scoped to an org
	// only via its parent scan_jobs row, so that join is required here.
	// Without it, any org's admin could read every other org's tool run
	// history (durations, result counts, statuses) for a given tool name.
	if err := h.db.Table("tool_run_results").
		Joins("JOIN scan_jobs ON scan_jobs.id = tool_run_results.scan_id").
		Where("tool_run_results.tool_name = ? AND scan_jobs.org_id = ?", name, user.OrgID).
		Order("tool_run_results.created_at DESC").
		Limit(50).
		Select("tool_run_results.*").
		Find(&rows).Error; err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to fetch run history"})
		return
	}
	c.JSON(http.StatusOK, gin.H{"data": rows, "tool": name})
}

type installLineEvent struct {
	Type string `json:"type"`
	Line string `json:"line"`
}

// Install streams install-tools.sh output via WebSocket.
// POST /api/v1/tools/install  (admin only)
func (h *ToolHandler) Install(c *gin.Context) {
	if h.hub == nil {
		c.JSON(http.StatusServiceUnavailable, gin.H{"error": "WebSocket hub not available"})
		return
	}

	go func() {
		h.log.Info("starting install-tools.sh")
		// Must be /bin/bash, not /bin/sh: on Ubuntu (this image's base),
		// /bin/sh is dash, and install-tools.sh's first line uses bash-only
		// array syntax (${BASH_SOURCE[0]}) that dash rejects outright with
		// "Bad substitution" — the script was exiting on line 2 before ever
		// reaching release-tools.sh/git-tools.sh/cloud-tools.sh, so nothing
		// ever actually installed regardless of what those scripts do.
		cmd := exec.Command("/bin/bash", "scripts/install-tools.sh") // #nosec G204 — fixed path
		stdout, err := cmd.StdoutPipe()
		if err != nil {
			h.log.Warnw("install: stdout pipe failed", "error", err)
			return
		}
		cmd.Stderr = cmd.Stdout
		if err := cmd.Start(); err != nil {
			h.log.Warnw("install: start failed", "error", err)
			return
		}

		scanner := bufio.NewScanner(stdout)
		for scanner.Scan() {
			line := scanner.Text()
			msg, _ := json.Marshal(installLineEvent{Type: "install_log", Line: line})
			h.hub.BroadcastRaw(msg)
		}
		if err := cmd.Wait(); err != nil {
			h.log.Warnw("install script exited with error", "error", err)
		}
		h.registry.VerifyAll()
		done, _ := json.Marshal(map[string]string{"type": "install_done"})
		h.hub.BroadcastRaw(done)
		h.log.Info("install-tools.sh complete; registry re-verified")
	}()

	c.JSON(http.StatusAccepted, gin.H{"message": "install started; follow progress via WebSocket"})
}
