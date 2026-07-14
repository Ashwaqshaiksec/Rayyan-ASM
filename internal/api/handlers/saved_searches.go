package handlers

import (
	"net/http"
	"time"

	"github.com/ShadooowX/rayyan-asm/internal/api/middleware"
	"github.com/ShadooowX/rayyan-asm/internal/models"
	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
	"go.uber.org/zap"
	"gorm.io/gorm"
)

// SavedSearchHandler backs the search page's "save this search" / saved
// searches list. Previously a query only ever lived in the input box —
// closing the tab lost it, and there was no way to name and reuse a query
// like "critical findings on internet-facing hosts" without retyping it.
type SavedSearchHandler struct {
	db  *gorm.DB
	log *zap.SugaredLogger
}

func NewSavedSearchHandler(db *gorm.DB, log *zap.SugaredLogger) *SavedSearchHandler {
	return &SavedSearchHandler{db: db, log: log}
}

func (h *SavedSearchHandler) List(c *gin.Context) {
	user := middleware.GetUser(c)
	if user == nil {
		c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{"error": "unauthorized"})
		return
	}
	var searches []models.SavedSearch
	if err := h.db.Where("org_id = ? AND user_id = ?", user.OrgID, user.ID).
		Order("last_used DESC, created_at DESC").
		Find(&searches).Error; err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to load saved searches"})
		return
	}
	c.JSON(http.StatusOK, gin.H{"data": searches})
}

type createSavedSearchRequest struct {
	Name  string `json:"name" binding:"required"`
	Query string `json:"query" binding:"required"`
}

func (h *SavedSearchHandler) Create(c *gin.Context) {
	user := middleware.GetUser(c)
	if user == nil {
		c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{"error": "unauthorized"})
		return
	}
	var req createSavedSearchRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	s := models.SavedSearch{
		OrgID:    user.OrgID,
		UserID:   user.ID,
		Name:     req.Name,
		Query:    req.Query,
		LastUsed: time.Now(),
	}
	if err := h.db.Create(&s).Error; err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to save search"})
		return
	}
	c.JSON(http.StatusCreated, s)
}

func (h *SavedSearchHandler) Delete(c *gin.Context) {
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
	res := h.db.Where("id = ? AND org_id = ? AND user_id = ?", id, user.OrgID, user.ID).
		Delete(&models.SavedSearch{})
	if res.Error != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to delete"})
		return
	}
	if res.RowsAffected == 0 {
		c.JSON(http.StatusNotFound, gin.H{"error": "not found"})
		return
	}
	c.JSON(http.StatusOK, gin.H{"message": "deleted"})
}

// Use bumps a saved search's use_count/last_used_at — called when the
// user actually runs it, not just when it's listed, so "most used" /
// "recently used" ordering reflects real usage.
func (h *SavedSearchHandler) Use(c *gin.Context) {
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
	if err := h.db.Model(&models.SavedSearch{}).
		Where("id = ? AND org_id = ? AND user_id = ?", id, user.OrgID, user.ID).
		Updates(map[string]any{
			"use_count": gorm.Expr("use_count + 1"),
			"last_used": time.Now(),
		}).Error; err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to update"})
		return
	}
	c.JSON(http.StatusOK, gin.H{"message": "ok"})
}
