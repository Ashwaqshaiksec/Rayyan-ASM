package exposure

import (
	"net/http"
	"strconv"

	"github.com/ShadooowX/rayyan-asm/internal/api/middleware"
	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
	"go.uber.org/zap"
	"gorm.io/gorm"
)

// Handler wires the Engine into Gin routes, registered in router.go like
// any other handler.
type Handler struct {
	db     *gorm.DB
	log    *zap.SugaredLogger
	engine *Engine
}

func NewHandler(db *gorm.DB, log *zap.SugaredLogger, engine *Engine) *Handler {
	return &Handler{db: db, log: log, engine: engine}
}

// Assets GET /exposure/assets?level=&limit= — top exposed assets, most
// exposed first, optionally filtered to one exposure level.
func (h *Handler) Assets(c *gin.Context) {
	user := middleware.GetUser(c)
	if user == nil {
		c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{"error": "unauthorized"})
		return
	}

	limit, _ := strconv.Atoi(c.DefaultQuery("limit", "50"))
	if limit < 1 || limit > 500 {
		limit = 50
	}
	rows, err := h.engine.Assets(user.OrgID, c.Query("level"), limit)
	if err != nil {
		h.log.Warnw("exposure: assets query failed", "org_id", user.OrgID, "error", err)
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to load exposure assets"})
		return
	}
	c.JSON(http.StatusOK, gin.H{"data": rows, "total": len(rows)})
}

// Detail GET /exposure/:id — full factor breakdown for one scored asset.
func (h *Handler) Detail(c *gin.Context) {
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

	detail, err := h.engine.Detail(user.OrgID, id)
	if err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "exposure score not found"})
		return
	}
	c.JSON(http.StatusOK, detail)
}

// Dashboard GET /exposure/dashboard — Exposure Center widget data.
func (h *Handler) Dashboard(c *gin.Context) {
	user := middleware.GetUser(c)
	if user == nil {
		c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{"error": "unauthorized"})
		return
	}

	dash, err := h.engine.Dashboard(user.OrgID)
	if err != nil {
		h.log.Warnw("exposure: dashboard query failed", "org_id", user.OrgID, "error", err)
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to load exposure dashboard"})
		return
	}
	c.JSON(http.StatusOK, dash)
}

// Recompute POST /exposure/recompute — manually trigger a recompute for
// the caller's org, on top of the periodic background worker.
func (h *Handler) Recompute(c *gin.Context) {
	user := middleware.GetUser(c)
	if user == nil {
		c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{"error": "unauthorized"})
		return
	}

	summary, err := h.engine.RecomputeOrg(user.OrgID)
	if err != nil {
		h.log.Warnw("exposure: recompute failed", "org_id", user.OrgID, "error", err)
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to recompute exposure scores"})
		return
	}
	c.JSON(http.StatusOK, summary)
}
