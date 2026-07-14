package handlers

import (
	"net/http"
	"strconv"

	"github.com/ShadooowX/rayyan-asm/internal/api/middleware"
	"github.com/ShadooowX/rayyan-asm/internal/modules/attackpath"
	"github.com/gin-gonic/gin"
	"go.uber.org/zap"
	"gorm.io/gorm"
)

type AttackPathHandler struct {
	db     *gorm.DB
	log    *zap.SugaredLogger
	engine *attackpath.Engine
}

func NewAttackPathHandler(db *gorm.DB, log *zap.SugaredLogger, engine *attackpath.Engine) *AttackPathHandler {
	return &AttackPathHandler{db: db, log: log, engine: engine}
}

// List GET /attack-paths — ranked list of stored attack paths for the org
func (h *AttackPathHandler) List(c *gin.Context) {
	user := middleware.GetUser(c)
	if user == nil {
		c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{"error": "unauthorized"})
		return
	}

	limit := 100
	if l := c.Query("limit"); l != "" {
		if parsed, err := strconv.Atoi(l); err == nil && parsed > 0 && parsed <= 500 {
			limit = parsed
		}
	}

	paths, err := h.engine.List(user.OrgID, limit)
	if err != nil {
		h.log.Warnw("attack-paths: list failed", "org_id", user.OrgID, "error", err)
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to load attack paths"})
		return
	}
	c.JSON(http.StatusOK, gin.H{"data": paths, "count": len(paths)})
}

// Recompute POST /attack-paths/recompute — rebuild paths for the org
func (h *AttackPathHandler) Recompute(c *gin.Context) {
	user := middleware.GetUser(c)
	if user == nil {
		c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{"error": "unauthorized"})
		return
	}

	summary, err := h.engine.RecomputeOrg(user.OrgID)
	if err != nil {
		h.log.Warnw("attack-paths: recompute failed", "org_id", user.OrgID, "error", err)
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to recompute attack paths"})
		return
	}
	c.JSON(http.StatusOK, summary)
}
