package handlers

import (
	"fmt"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
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

const screenshotDir = "/var/rayyan-asm/screenshots"

type ScreenshotHandler struct {
	db  *gorm.DB
	log *zap.SugaredLogger
}

func NewScreenshotHandler(db *gorm.DB, log *zap.SugaredLogger) *ScreenshotHandler {
	return &ScreenshotHandler{db: db, log: log}
}

// List returns web assets that have been screenshotted, with optional filters
func (h *ScreenshotHandler) List(c *gin.Context) {
	user := middleware.GetUser(c)
	if user == nil {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "unauthorized"})
		return
	}
	page, _ := strconv.Atoi(c.DefaultQuery("page", "1"))
	limit, _ := strconv.Atoi(c.DefaultQuery("limit", "20"))
	if limit > MaxPageLimitSmall {
		limit = MaxPageLimitSmall
	}
	q := h.db.Where("org_id = ? AND screenshotted = true", user.OrgID)
	if statusCode := c.Query("status_code"); statusCode != "" {
		q = q.Where("status_code = ?", statusCode)
	}
	if title := c.Query("title"); title != "" {
		q = q.Where("title ILIKE ?", "%"+title+"%")
	}
	var total int64
	q.Model(&models.WebAsset{}).Count(&total)
	var assets []models.WebAsset
	q.Order("scanned_at desc").
		Offset((page - 1) * limit).
		Limit(limit).
		Find(&assets)
	c.JSON(http.StatusOK, gin.H{
		"total":  total,
		"page":   page,
		"limit":  limit,
		"assets": assets,
	})
}

// Capture triggers gowitness to screenshot one or more URLs and updates WebAsset records
func (h *ScreenshotHandler) Capture(c *gin.Context) {
	user := middleware.GetUser(c)
	if user == nil {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "unauthorized"})
		return
	}
	var req struct {
		URLs []string `json:"urls" binding:"required"`
	}
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	if len(req.URLs) == 0 {
		c.JSON(http.StatusBadRequest, gin.H{"error": "urls required"})
		return
	}
	const maxScreenshotURLs = 50
	if len(req.URLs) > maxScreenshotURLs {
		c.JSON(http.StatusBadRequest, gin.H{"error": fmt.Sprintf("too many URLs; maximum is %d per request", maxScreenshotURLs)})
		return
	}
	// Validate each URL has an http/https scheme so we don't pass file://
	// or other dangerous schemes to gowitness.
	for _, u := range req.URLs {
		parsed, err := url.Parse(u)
		if err != nil || (parsed.Scheme != "http" && parsed.Scheme != "https") {
			c.JSON(http.StatusBadRequest, gin.H{"error": "all URLs must begin with http:// or https://"})
			return
		}
	}

	// Check gowitness available
	gowitness, err := exec.LookPath("gowitness")
	if err != nil {
		c.JSON(http.StatusServiceUnavailable, gin.H{
			"error": "gowitness not installed — run 'go install github.com/sensepost/gowitness@latest'",
		})
		return
	}

	// Write URL list to temp file
	tmpFile, err := os.CreateTemp("", "rayyan-urls-*.txt")
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to create temp file"})
		return
	}
	defer os.Remove(tmpFile.Name())
	for _, u := range req.URLs {
		fmt.Fprintln(tmpFile, u)
	}
	_ = tmpFile.Close()

	outDir := filepath.Join(screenshotDir, user.OrgID.String(), time.Now().Format("20060102-150405"))
	if err := os.MkdirAll(outDir, 0755); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to create screenshot dir"})
		return
	}

	ctx := c.Request.Context()
	cmd := exec.CommandContext(ctx,
		gowitness, "file",
		"--file", tmpFile.Name(),
		"--screenshot-path", outDir,
		"--timeout", "15",
		"--threads", "4",
	)
	out, _ := cmd.CombinedOutput()
	h.log.Infow("gowitness capture", "urls", len(req.URLs), "outDir", outDir, "output", string(out))

	// Update WebAsset records
	updated := 0
	for _, url := range req.URLs {
		// gowitness names files based on URL slug
		safeURL := strings.NewReplacer("://", "-", "/", "-", ":", "-", "?", "-", "&", "-", "=", "-").Replace(url)
		candidates := []string{
			filepath.Join(outDir, safeURL+".png"),
			filepath.Join(outDir, url2filename(url)),
		}
		for _, path := range candidates {
			if _, err := os.Stat(path); err == nil {
				h.db.Model(&models.WebAsset{}).
					Where("org_id = ? AND url = ?", user.OrgID, url).
					Updates(map[string]interface{}{
						"screenshotted":   true,
						"screenshot_path": path,
					})
				updated++
				break
			}
		}
	}

	c.JSON(http.StatusOK, gin.H{
		"queued":  len(req.URLs),
		"updated": updated,
		"out_dir": outDir,
		"output":  string(out),
	})
}

// Get serves the screenshot image file for a web asset
func (h *ScreenshotHandler) Get(c *gin.Context) {
	user := middleware.GetUser(c)
	if user == nil {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "unauthorized"})
		return
	}
	id, err := uuid.Parse(c.Param("id"))
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid id"})
		return
	}
	var asset models.WebAsset
	if err := h.db.Where("id = ? AND org_id = ?", id, user.OrgID).First(&asset).Error; err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "not found"})
		return
	}
	if !asset.Screenshotted || asset.ScreenshotPath == "" {
		c.JSON(http.StatusNotFound, gin.H{"error": "no screenshot available"})
		return
	}
	// Validate the stored path is inside the expected screenshot directory
	// to prevent path traversal if screenshot_path was ever corrupted.
	clean := filepath.Clean(asset.ScreenshotPath)
	expectedPrefix := filepath.Join(screenshotDir, user.OrgID.String())
	if !strings.HasPrefix(clean, expectedPrefix) {
		c.JSON(http.StatusForbidden, gin.H{"error": "invalid screenshot path"})
		return
	}
	c.File(clean)
}

func url2filename(u string) string {
	r := strings.NewReplacer(
		"https://", "", "http://", "",
		"/", "_", ":", "_", ".", "_", "?", "_", "&", "_", "=", "_",
	)
	return r.Replace(u) + ".png"
}
