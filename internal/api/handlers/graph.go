package handlers

import (
	"net/http"

	"github.com/ShadooowX/rayyan-asm/internal/api/middleware"
	"github.com/ShadooowX/rayyan-asm/internal/modules/correlation"
	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
	"go.uber.org/zap"
	"gorm.io/gorm"
)

// GraphHandler exposes the asset relationship graph under /api/v1/graph/*.
// It is a thin, additional API surface over the existing correlation
// engine — no new graph-build logic lives here, so the underlying
// relationship data and rebuild behavior used by /correlation/* is unchanged.
type GraphHandler struct {
	db     *gorm.DB
	log    *zap.SugaredLogger
	engine *correlation.Engine
}

func NewGraphHandler(db *gorm.DB, log *zap.SugaredLogger, engine *correlation.Engine) *GraphHandler {
	return &GraphHandler{db: db, log: log, engine: engine}
}

// Asset GET /api/v1/graph/assets/:id?type= — one asset plus its
// relationships and connected assets.
func (h *GraphHandler) Asset(c *gin.Context) {
	user := middleware.GetUser(c)
	if user == nil {
		c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{"error": "unauthorized"})
		return
	}
	assetID, err := uuid.Parse(c.Param("id"))
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid id"})
		return
	}
	assetType := c.Query("type")
	if assetType == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "type query param is required"})
		return
	}

	related, err := h.engine.Related(user.OrgID, assetType, assetID)
	if err != nil {
		h.log.Warnw("graph: asset lookup failed", "org_id", user.OrgID, "error", err)
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to load asset graph"})
		return
	}

	connected := make([]correlation.Node, 0, len(related))
	for _, r := range related {
		connected = append(connected, r.Asset)
	}

	c.JSON(http.StatusOK, gin.H{
		"asset":            correlation.Node{Type: assetType, ID: assetID},
		"relationships":    related,
		"connected_assets": connected,
	})
}

// Neighbors GET /api/v1/graph/neighbors/:id?type= — all directly connected assets.
func (h *GraphHandler) Neighbors(c *gin.Context) {
	user := middleware.GetUser(c)
	if user == nil {
		c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{"error": "unauthorized"})
		return
	}
	assetID, err := uuid.Parse(c.Param("id"))
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid id"})
		return
	}
	assetType := c.Query("type")
	if assetType == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "type query param is required"})
		return
	}

	related, err := h.engine.Related(user.OrgID, assetType, assetID)
	if err != nil {
		h.log.Warnw("graph: neighbors lookup failed", "org_id", user.OrgID, "error", err)
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to load neighbors"})
		return
	}
	c.JSON(http.StatusOK, gin.H{"data": related})
}

// Path GET /api/v1/graph/path?source=&source_type=&destination=&destination_type=
// — shortest relationship path between two assets.
func (h *GraphHandler) Path(c *gin.Context) {
	user := middleware.GetUser(c)
	if user == nil {
		c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{"error": "unauthorized"})
		return
	}
	sourceType := c.Query("source_type")
	destType := c.Query("destination_type")
	sourceID, err := uuid.Parse(c.Query("source"))
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid source"})
		return
	}
	destID, err := uuid.Parse(c.Query("destination"))
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid destination"})
		return
	}
	if sourceType == "" || destType == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "source_type and destination_type are required"})
		return
	}

	path, err := h.engine.ExposurePath(user.OrgID, sourceType, sourceID, destType, destID)
	if err != nil {
		h.log.Warnw("graph: path query failed", "org_id", user.OrgID, "error", err)
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to compute path"})
		return
	}
	if path == nil {
		c.JSON(http.StatusOK, gin.H{"data": []interface{}{}, "found": false})
		return
	}
	c.JSON(http.StatusOK, gin.H{"data": path, "found": true})
}

// Stats GET /api/v1/graph/stats — org-wide degree/critical/orphan summary.
func (h *GraphHandler) Stats(c *gin.Context) {
	user := middleware.GetUser(c)
	if user == nil {
		c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{"error": "unauthorized"})
		return
	}
	stats, err := h.engine.Stats(user.OrgID)
	if err != nil {
		h.log.Warnw("graph: stats failed", "org_id", user.OrgID, "error", err)
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to compute graph stats"})
		return
	}
	c.JSON(http.StatusOK, stats)
}

// AssetStats GET /api/v1/graph/asset-stats — per-asset degree/risk table,
// used by the Asset Relationships UI page.
func (h *GraphHandler) AssetStats(c *gin.Context) {
	user := middleware.GetUser(c)
	if user == nil {
		c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{"error": "unauthorized"})
		return
	}
	stats, err := h.engine.AssetStats(user.OrgID)
	if err != nil {
		h.log.Warnw("graph: asset-stats failed", "org_id", user.OrgID, "error", err)
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to compute asset stats"})
		return
	}
	c.JSON(http.StatusOK, gin.H{"data": stats})
}
