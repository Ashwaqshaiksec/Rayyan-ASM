package handlers

import (
	"net/http"
	"strconv"

	"github.com/ShadooowX/rayyan-asm/internal/api/middleware"
	"github.com/ShadooowX/rayyan-asm/internal/modules/changedetect"
	"github.com/gin-gonic/gin"
	"go.uber.org/zap"
	"gorm.io/gorm"
)

type ChangeDetectHandler struct {
	db     *gorm.DB
	log    *zap.SugaredLogger
	engine *changedetect.Engine
}

func NewChangeDetectHandler(db *gorm.DB, log *zap.SugaredLogger, engine *changedetect.Engine) *ChangeDetectHandler {
	return &ChangeDetectHandler{db: db, log: log, engine: engine}
}

// Run POST /changes/run — snapshot current state and detect changes since the last run
func (h *ChangeDetectHandler) Run(c *gin.Context) {
	user := middleware.GetUser(c)
	if user == nil {
		c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{"error": "unauthorized"})
		return
	}

	summary, err := h.engine.RunDetection(user.OrgID)
	if err != nil {
		h.log.Warnw("changedetect: run failed", "org_id", user.OrgID, "error", err)
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to run change detection"})
		return
	}
	c.JSON(http.StatusOK, summary)
}

// Timeline GET /changes/timeline?asset_type=&change_type=&limit= — recent change events
func (h *ChangeDetectHandler) Timeline(c *gin.Context) {
	user := middleware.GetUser(c)
	if user == nil {
		c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{"error": "unauthorized"})
		return
	}

	limit, _ := strconv.Atoi(c.DefaultQuery("limit", "200"))
	if limit < 1 || limit > MaxPageLimitLarge {
		limit = MaxPageLimitSmall
	}
	events, err := h.engine.Timeline(user.OrgID, c.Query("asset_type"), c.Query("change_type"), limit)
	if err != nil {
		h.log.Warnw("changedetect: timeline query failed", "org_id", user.OrgID, "error", err)
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to load change timeline"})
		return
	}
	c.JSON(http.StatusOK, gin.H{"data": events, "total": len(events)})
}
