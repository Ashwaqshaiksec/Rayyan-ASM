package handlers

import (
	"net/http"
	"strconv"

	"github.com/ShadooowX/rayyan-asm/internal/api/middleware"
	"github.com/ShadooowX/rayyan-asm/internal/modules/correlation"
	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
	"go.uber.org/zap"
	"gorm.io/gorm"
)

type CorrelationHandler struct {
	db     *gorm.DB
	log    *zap.SugaredLogger
	engine *correlation.Engine
}

func NewCorrelationHandler(db *gorm.DB, log *zap.SugaredLogger, engine *correlation.Engine) *CorrelationHandler {
	return &CorrelationHandler{db: db, log: log, engine: engine}
}

// Rebuild POST /correlation/rebuild
func (h *CorrelationHandler) Rebuild(c *gin.Context) {
	user := middleware.GetUser(c)
	if user == nil {
		c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{"error": "unauthorized"})
		return
	}

	summary, err := h.engine.RecomputeOrg(user.OrgID)
	if err != nil {
		h.log.Warnw("correlation: rebuild failed", "org_id", user.OrgID, "error", err)
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to rebuild correlation graph"})
		return
	}
	c.JSON(http.StatusOK, summary)
}

// Graph GET /correlation/graph?type=&id=&depth=
func (h *CorrelationHandler) Graph(c *gin.Context) {
	user := middleware.GetUser(c)
	if user == nil {
		c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{"error": "unauthorized"})
		return
	}

	assetType := c.Query("type")
	var assetID uuid.UUID
	if idStr := c.Query("id"); idStr != "" {
		parsed, err := uuid.Parse(idStr)
		if err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": "invalid id"})
			return
		}
		assetID = parsed
	}
	depth := 0
	if d, ok := c.GetQuery("depth"); ok {
		if parsed, err := strconv.Atoi(d); err == nil && parsed > 0 {
			depth = parsed
		}
	}

	graph, err := h.engine.Graph(user.OrgID, assetType, assetID, depth)
	if err != nil {
		h.log.Warnw("correlation: graph query failed", "org_id", user.OrgID, "error", err)
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to load correlation graph"})
		return
	}
	c.JSON(http.StatusOK, gin.H{"nodes": graph.Nodes, "edges": graph.Edges})
}

// Related GET /correlation/related/:type/:id
func (h *CorrelationHandler) Related(c *gin.Context) {
	user := middleware.GetUser(c)
	if user == nil {
		c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{"error": "unauthorized"})
		return
	}

	assetType := c.Param("type")
	assetID, err := uuid.Parse(c.Param("id"))
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid id"})
		return
	}

	related, err := h.engine.Related(user.OrgID, assetType, assetID)
	if err != nil {
		h.log.Warnw("correlation: related query failed", "org_id", user.OrgID, "error", err)
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to load related assets"})
		return
	}
	c.JSON(http.StatusOK, gin.H{"data": related})
}

// ExposurePath GET /correlation/exposure-path?from_type=&from_id=&to_type=&to_id=
func (h *CorrelationHandler) ExposurePath(c *gin.Context) {
	user := middleware.GetUser(c)
	if user == nil {
		c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{"error": "unauthorized"})
		return
	}

	fromType := c.Query("from_type")
	toType := c.Query("to_type")
	fromID, err := uuid.Parse(c.Query("from_id"))
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid from_id"})
		return
	}
	toID, err := uuid.Parse(c.Query("to_id"))
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid to_id"})
		return
	}
	if fromType == "" || toType == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "from_type and to_type are required"})
		return
	}

	path, err := h.engine.ExposurePath(user.OrgID, fromType, fromID, toType, toID)
	if err != nil {
		h.log.Warnw("correlation: exposure path query failed", "org_id", user.OrgID, "error", err)
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to compute exposure path"})
		return
	}
	if path == nil {
		c.JSON(http.StatusOK, gin.H{"data": []interface{}{}, "found": false})
		return
	}
	c.JSON(http.StatusOK, gin.H{"data": path, "found": true})
}
