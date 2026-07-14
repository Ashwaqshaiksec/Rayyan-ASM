package handlers

import (
	"net/http"
	"regexp"
	"strings"
	"time"

	"github.com/ShadooowX/rayyan-asm/internal/api/middleware"
	"github.com/ShadooowX/rayyan-asm/internal/models"
	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
	"go.uber.org/zap"
	"gorm.io/gorm"
)

type ProjectHandler struct {
	db  *gorm.DB
	log *zap.SugaredLogger
}

func NewProjectHandler(db *gorm.DB, log *zap.SugaredLogger) *ProjectHandler {
	return &ProjectHandler{db: db, log: log}
}

func slugify(s string) string {
	re := regexp.MustCompile(`[^a-z0-9]+`)
	return strings.Trim(re.ReplaceAllString(strings.ToLower(s), "-"), "-")
}

func (h *ProjectHandler) List(c *gin.Context) {
	user := middleware.GetUser(c)
	if user == nil {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "unauthorized"})
		return
	}
	var projects []models.Project
	if err := h.db.Where("org_id = ?", user.OrgID).Order("created_at desc").Find(&projects).Error; err != nil {
		h.log.Warnw("projects list failed", "error", err)
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to fetch projects"})
		return
	}
	c.JSON(http.StatusOK, gin.H{"data": projects, "total": len(projects)})
}

func (h *ProjectHandler) Create(c *gin.Context) {
	user := middleware.GetUser(c)
	if user == nil {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "unauthorized"})
		return
	}
	var req struct {
		Name        string   `json:"name" binding:"required"`
		Description string   `json:"description"`
		Type        string   `json:"type"`
		Scope       []string `json:"scope"`
		OutOfScope  []string `json:"out_of_scope"`
		Color       string   `json:"color"`
	}
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	if req.Type == "" {
		req.Type = "general"
	}
	proj := models.Project{
		OrgID:       user.OrgID,
		CreatedBy:   user.ID,
		Name:        req.Name,
		Slug:        slugify(req.Name),
		Description: req.Description,
		Type:        req.Type,
		Scope:       req.Scope,
		OutOfScope:  req.OutOfScope,
		Color:       req.Color,
		Active:      true,
	}
	proj.ID = uuid.New()
	if err := h.db.Create(&proj).Error; err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}
	c.JSON(http.StatusCreated, proj)
}

func (h *ProjectHandler) Get(c *gin.Context) {
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
	var proj models.Project
	if err := h.db.Where("id = ? AND org_id = ?", id, user.OrgID).First(&proj).Error; err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "not found"})
		return
	}
	c.JSON(http.StatusOK, proj)
}

func (h *ProjectHandler) Update(c *gin.Context) {
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
	var proj models.Project
	if err := h.db.Where("id = ? AND org_id = ?", id, user.OrgID).First(&proj).Error; err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "not found"})
		return
	}
	var req struct {
		Name        string   `json:"name"`
		Description string   `json:"description"`
		Type        string   `json:"type"`
		Scope       []string `json:"scope"`
		OutOfScope  []string `json:"out_of_scope"`
		Color       string   `json:"color"`
		Active      *bool    `json:"active"`
	}
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	updates := map[string]interface{}{}
	if req.Name != "" {
		updates["name"] = req.Name
		updates["slug"] = slugify(req.Name)
	}
	if req.Description != "" {
		updates["description"] = req.Description
	}
	if req.Type != "" {
		updates["type"] = req.Type
	}
	if req.Scope != nil {
		updates["scope"] = models.StringArray(req.Scope)
	}
	if req.OutOfScope != nil {
		updates["out_of_scope"] = models.StringArray(req.OutOfScope)
	}
	if req.Color != "" {
		updates["color"] = req.Color
	}
	if req.Active != nil {
		updates["active"] = *req.Active
	}
	if err := h.db.Model(&proj).Updates(updates).Error; err != nil {
		h.log.Warnw("failed to update project", "error", err)
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to update project"})
		return
	}
	c.JSON(http.StatusOK, proj)
}

func (h *ProjectHandler) Delete(c *gin.Context) {
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
	result := h.db.Where("id = ? AND org_id = ?", id, user.OrgID).Delete(&models.Project{})
	if result.Error != nil {
		h.log.Warnw("failed to delete project", "error", result.Error)
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to delete project"})
		return
	}
	if result.RowsAffected == 0 {
		c.JSON(http.StatusNotFound, gin.H{"error": "project not found"})
		return
	}
	c.JSON(http.StatusNoContent, nil)
}

type NoteHandler struct {
	db  *gorm.DB
	log *zap.SugaredLogger
}

func NewNoteHandler(db *gorm.DB, log *zap.SugaredLogger) *NoteHandler {
	return &NoteHandler{db: db, log: log}
}

func (h *NoteHandler) List(c *gin.Context) {
	user := middleware.GetUser(c)
	if user == nil {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "unauthorized"})
		return
	}
	q := h.db.Where("org_id = ?", user.OrgID)
	if pid := c.Query("project_id"); pid != "" {
		q = q.Where("project_id = ?", pid)
	}
	if target := c.Query("target"); target != "" {
		q = q.Where("target ILIKE ?", "%"+target+"%")
	}
	if pinned := c.Query("pinned"); pinned == "true" {
		q = q.Where("pinned = true")
	}
	var notes []models.Note
	if err := q.Order("pinned desc, created_at desc").Find(&notes).Error; err != nil {
		h.log.Warnw("notes list failed", "error", err)
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to fetch notes"})
		return
	}
	c.JSON(http.StatusOK, gin.H{"data": notes, "total": len(notes)})
}

func (h *NoteHandler) Create(c *gin.Context) {
	user := middleware.GetUser(c)
	if user == nil {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "unauthorized"})
		return
	}
	var req struct {
		Title     string   `json:"title" binding:"required"`
		Content   string   `json:"content" binding:"required"`
		Target    string   `json:"target"`
		Tags      []string `json:"tags"`
		Pinned    bool     `json:"pinned"`
		ProjectID string   `json:"project_id"`
	}
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	note := models.Note{
		OrgID:     user.OrgID,
		CreatedBy: user.ID,
		Title:     req.Title,
		Content:   req.Content,
		Target:    req.Target,
		Tags:      req.Tags,
		Pinned:    req.Pinned,
	}
	if req.ProjectID != "" {
		if pid, err := uuid.Parse(req.ProjectID); err == nil {
			note.ProjectID = &pid
		}
	}
	note.ID = uuid.New()
	if err := h.db.Create(&note).Error; err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}
	c.JSON(http.StatusCreated, note)
}

func (h *NoteHandler) Get(c *gin.Context) {
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
	var note models.Note
	if err := h.db.Where("id = ? AND org_id = ?", id, user.OrgID).First(&note).Error; err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "not found"})
		return
	}
	c.JSON(http.StatusOK, note)
}

func (h *NoteHandler) Update(c *gin.Context) {
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
	var note models.Note
	if err := h.db.Where("id = ? AND org_id = ?", id, user.OrgID).First(&note).Error; err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "not found"})
		return
	}
	var req struct {
		Title   string   `json:"title"`
		Content string   `json:"content"`
		Target  string   `json:"target"`
		Tags    []string `json:"tags"`
		Pinned  *bool    `json:"pinned"`
	}
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	updates := map[string]interface{}{}
	if req.Title != "" {
		updates["title"] = req.Title
	}
	if req.Content != "" {
		updates["content"] = req.Content
	}
	if req.Target != "" {
		updates["target"] = req.Target
	}
	if req.Tags != nil {
		updates["tags"] = models.StringArray(req.Tags)
	}
	if req.Pinned != nil {
		updates["pinned"] = *req.Pinned
	}
	if err := h.db.Model(&note).Updates(updates).Error; err != nil {
		h.log.Warnw("failed to update note", "error", err)
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to update note"})
		return
	}
	c.JSON(http.StatusOK, note)
}

func (h *NoteHandler) Delete(c *gin.Context) {
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
	result := h.db.Where("id = ? AND org_id = ?", id, user.OrgID).Delete(&models.Note{})
	if result.Error != nil {
		h.log.Warnw("failed to delete note", "error", result.Error)
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to delete note"})
		return
	}
	if result.RowsAffected == 0 {
		c.JSON(http.StatusNotFound, gin.H{"error": "note not found"})
		return
	}
	c.JSON(http.StatusNoContent, nil)
}

type TodoHandler struct {
	db  *gorm.DB
	log *zap.SugaredLogger
}

func NewTodoHandler(db *gorm.DB, log *zap.SugaredLogger) *TodoHandler {
	return &TodoHandler{db: db, log: log}
}

func (h *TodoHandler) List(c *gin.Context) {
	user := middleware.GetUser(c)
	if user == nil {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "unauthorized"})
		return
	}
	q := h.db.Where("org_id = ?", user.OrgID)
	if pid := c.Query("project_id"); pid != "" {
		q = q.Where("project_id = ?", pid)
	}
	if status := c.Query("status"); status != "" {
		q = q.Where("status = ?", status)
	}
	if priority := c.Query("priority"); priority != "" {
		q = q.Where("priority = ?", priority)
	}
	if assignee := c.Query("assigned_to"); assignee != "" {
		q = q.Where("assigned_to = ?", assignee)
	}
	var todos []models.Todo
	if err := q.Order("priority desc, created_at desc").Find(&todos).Error; err != nil {
		h.log.Warnw("todos list failed", "error", err)
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to fetch todos"})
		return
	}
	c.JSON(http.StatusOK, gin.H{"data": todos, "total": len(todos)})
}

func (h *TodoHandler) Create(c *gin.Context) {
	user := middleware.GetUser(c)
	if user == nil {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "unauthorized"})
		return
	}
	var req struct {
		Title      string  `json:"title" binding:"required"`
		Notes      string  `json:"notes"`
		Priority   string  `json:"priority"`
		Target     string  `json:"target"`
		ProjectID  string  `json:"project_id"`
		AssignedTo string  `json:"assigned_to"`
		DueAt      *string `json:"due_at"`
	}
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	if req.Priority == "" {
		req.Priority = "medium"
	}
	todo := models.Todo{
		OrgID:     user.OrgID,
		CreatedBy: user.ID,
		Title:     req.Title,
		Notes:     req.Notes,
		Priority:  req.Priority,
		Target:    req.Target,
		Status:    "open",
	}
	if req.ProjectID != "" {
		if pid, err := uuid.Parse(req.ProjectID); err == nil {
			todo.ProjectID = &pid
		}
	}
	if req.AssignedTo != "" {
		if aid, err := uuid.Parse(req.AssignedTo); err == nil {
			todo.AssignedTo = &aid
		}
	}
	if req.DueAt != nil {
		if t, err := time.Parse(time.RFC3339, *req.DueAt); err == nil {
			todo.DueAt = &t
		}
	}
	todo.ID = uuid.New()
	if err := h.db.Create(&todo).Error; err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}
	c.JSON(http.StatusCreated, todo)
}

func (h *TodoHandler) Get(c *gin.Context) {
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
	var todo models.Todo
	if err := h.db.Where("id = ? AND org_id = ?", id, user.OrgID).First(&todo).Error; err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "not found"})
		return
	}
	c.JSON(http.StatusOK, todo)
}

func (h *TodoHandler) Update(c *gin.Context) {
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
	var todo models.Todo
	if err := h.db.Where("id = ? AND org_id = ?", id, user.OrgID).First(&todo).Error; err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "not found"})
		return
	}
	var req struct {
		Title    string  `json:"title"`
		Notes    string  `json:"notes"`
		Status   string  `json:"status"`
		Priority string  `json:"priority"`
		Target   string  `json:"target"`
		DueAt    *string `json:"due_at"`
	}
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	updates := map[string]interface{}{}
	if req.Title != "" {
		updates["title"] = req.Title
	}
	if req.Notes != "" {
		updates["notes"] = req.Notes
	}
	if req.Status != "" {
		updates["status"] = req.Status
		if req.Status == "done" {
			now := time.Now()
			updates["done_at"] = &now
		}
	}
	if req.Priority != "" {
		updates["priority"] = req.Priority
	}
	if req.Target != "" {
		updates["target"] = req.Target
	}
	if req.DueAt != nil {
		if t, err := time.Parse(time.RFC3339, *req.DueAt); err == nil {
			updates["due_at"] = &t
		}
	}
	if err := h.db.Model(&todo).Updates(updates).Error; err != nil {
		h.log.Warnw("failed to update todo", "error", err)
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to update todo"})
		return
	}
	c.JSON(http.StatusOK, todo)
}

func (h *TodoHandler) Delete(c *gin.Context) {
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
	result := h.db.Where("id = ? AND org_id = ?", id, user.OrgID).Delete(&models.Todo{})
	if result.Error != nil {
		h.log.Warnw("failed to delete todo", "error", result.Error)
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to delete todo"})
		return
	}
	if result.RowsAffected == 0 {
		c.JSON(http.StatusNotFound, gin.H{"error": "todo not found"})
		return
	}
	c.JSON(http.StatusNoContent, nil)
}

type NotificationHandler struct {
	db  *gorm.DB
	log *zap.SugaredLogger
}

func NewNotificationHandler(db *gorm.DB, log *zap.SugaredLogger) *NotificationHandler {
	return &NotificationHandler{db: db, log: log}
}

func (h *NotificationHandler) List(c *gin.Context) {
	user := middleware.GetUser(c)
	if user == nil {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "unauthorized"})
		return
	}
	var cfgs []models.NotificationConfig
	if err := h.db.Where("org_id = ?", user.OrgID).Order("created_at desc").Find(&cfgs).Error; err != nil {
		h.log.Warnw("notification configs list failed", "error", err)
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to fetch notification configs"})
		return
	}
	c.JSON(http.StatusOK, cfgs)
}

// validNotificationChannels lists channels DispatchAlertNotifications knows
// how to deliver. Keep in sync with the switch in notifications.go.
var validNotificationChannels = map[string]bool{
	"slack": true, "discord": true, "telegram": true, "teams": true, "email": true, "siem": true,
}

func (h *NotificationHandler) Create(c *gin.Context) {
	user := middleware.GetUser(c)
	if user == nil {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "unauthorized"})
		return
	}
	var req struct {
		Channel     string   `json:"channel" binding:"required"` // slack, discord, telegram, teams, email, siem
		Name        string   `json:"name" binding:"required"`
		WebhookURL  string   `json:"webhook_url"`
		BotToken    string   `json:"bot_token"`
		ChatID      string   `json:"chat_id"`
		AuthHeader  string   `json:"auth_header"`
		AuthToken   string   `json:"auth_token"`
		SMTPHost    string   `json:"smtp_host"`
		SMTPPort    int      `json:"smtp_port"`
		SMTPUser    string   `json:"smtp_username"`
		SMTPPass    string   `json:"smtp_password"`
		SMTPFrom    string   `json:"smtp_from"`
		SMTPTo      []string `json:"smtp_to"`
		SMTPUseTLS  *bool    `json:"smtp_use_tls"`
		AlertTypes  []string `json:"alert_types"`
		MinSeverity string   `json:"min_severity"`
	}
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	if !validNotificationChannels[req.Channel] {
		c.JSON(http.StatusBadRequest, gin.H{
			"error": "channel must be one of: slack, discord, telegram, teams, email, siem",
		})
		return
	}
	if req.MinSeverity == "" {
		req.MinSeverity = "info"
	}

	cfg := models.NotificationConfig{
		OrgID:       user.OrgID,
		CreatedBy:   user.ID,
		Channel:     req.Channel,
		Name:        req.Name,
		WebhookURL:  req.WebhookURL,
		BotToken:    req.BotToken,
		ChatID:      req.ChatID,
		AlertTypes:  req.AlertTypes,
		MinSeverity: req.MinSeverity,
		Active:      true,
	}

	switch req.Channel {
	case "slack", "discord", "teams":
		if req.WebhookURL == "" {
			c.JSON(http.StatusBadRequest, gin.H{"error": req.Channel + " requires webhook_url"})
			return
		}
	case "siem":
		if req.WebhookURL == "" {
			c.JSON(http.StatusBadRequest, gin.H{"error": "siem requires webhook_url"})
			return
		}
		if req.AuthToken != "" && !NotificationCredentialKeyConfigured() {
			c.JSON(http.StatusServiceUnavailable, gin.H{
				"error": "siem notification storage is not configured (RAYYAN_AUTH_CREDENTIALKEY is unset)",
			})
			return
		}
		cfg.AuthHeader = req.AuthHeader
		if req.AuthToken != "" {
			encrypted, err := EncryptAuthToken(req.AuthToken)
			if err != nil {
				c.JSON(http.StatusServiceUnavailable, gin.H{"error": err.Error()})
				return
			}
			cfg.AuthTokenEncrypted = encrypted
		}
	case "telegram":
		if req.BotToken == "" || req.ChatID == "" {
			c.JSON(http.StatusBadRequest, gin.H{"error": "telegram requires bot_token and chat_id"})
			return
		}
	case "email":
		if req.SMTPHost == "" || req.SMTPFrom == "" || len(req.SMTPTo) == 0 {
			c.JSON(http.StatusBadRequest, gin.H{"error": "email requires smtp_host, smtp_from, and smtp_to"})
			return
		}
		if req.SMTPPass != "" && !NotificationCredentialKeyConfigured() {
			c.JSON(http.StatusServiceUnavailable, gin.H{
				"error": "email notification storage is not configured (RAYYAN_AUTH_CREDENTIALKEY is unset)",
			})
			return
		}
		cfg.SMTPHost = req.SMTPHost
		cfg.SMTPPort = req.SMTPPort
		if cfg.SMTPPort == 0 {
			cfg.SMTPPort = 587
		}
		cfg.SMTPUsername = req.SMTPUser
		cfg.SMTPFrom = req.SMTPFrom
		cfg.SMTPTo = req.SMTPTo
		cfg.SMTPUseTLS = true
		if req.SMTPUseTLS != nil {
			cfg.SMTPUseTLS = *req.SMTPUseTLS
		}
		if req.SMTPPass != "" {
			encrypted, err := EncryptSMTPPassword(req.SMTPPass)
			if err != nil {
				c.JSON(http.StatusServiceUnavailable, gin.H{"error": err.Error()})
				return
			}
			cfg.SMTPPasswordEncrypted = encrypted
		}
	}

	cfg.ID = uuid.New()
	if err := h.db.Create(&cfg).Error; err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}
	// Don't return secrets in response
	cfg.BotToken = ""
	cfg.SMTPPasswordEncrypted = ""
	cfg.AuthTokenEncrypted = ""
	c.JSON(http.StatusCreated, cfg)
}

func (h *NotificationHandler) Update(c *gin.Context) {
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
	var cfg models.NotificationConfig
	if err := h.db.Where("id = ? AND org_id = ?", id, user.OrgID).First(&cfg).Error; err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "not found"})
		return
	}
	var req struct {
		Name        string   `json:"name"`
		WebhookURL  string   `json:"webhook_url"`
		BotToken    string   `json:"bot_token"`
		ChatID      string   `json:"chat_id"`
		AuthHeader  string   `json:"auth_header"`
		AuthToken   string   `json:"auth_token"`
		SMTPHost    string   `json:"smtp_host"`
		SMTPPort    int      `json:"smtp_port"`
		SMTPUser    string   `json:"smtp_username"`
		SMTPPass    string   `json:"smtp_password"`
		SMTPFrom    string   `json:"smtp_from"`
		SMTPTo      []string `json:"smtp_to"`
		SMTPUseTLS  *bool    `json:"smtp_use_tls"`
		AlertTypes  []string `json:"alert_types"`
		MinSeverity string   `json:"min_severity"`
		Active      *bool    `json:"active"`
	}
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	updates := map[string]interface{}{}
	if req.Name != "" {
		updates["name"] = req.Name
	}
	if req.WebhookURL != "" {
		updates["webhook_url"] = req.WebhookURL
	}
	if req.BotToken != "" {
		updates["bot_token"] = req.BotToken
	}
	if req.ChatID != "" {
		updates["chat_id"] = req.ChatID
	}
	if req.AuthHeader != "" {
		updates["auth_header"] = req.AuthHeader
	}
	if req.AuthToken != "" {
		if !NotificationCredentialKeyConfigured() {
			c.JSON(http.StatusServiceUnavailable, gin.H{
				"error": "siem notification storage is not configured (RAYYAN_AUTH_CREDENTIALKEY is unset)",
			})
			return
		}
		encrypted, err := EncryptAuthToken(req.AuthToken)
		if err != nil {
			c.JSON(http.StatusServiceUnavailable, gin.H{"error": err.Error()})
			return
		}
		updates["auth_token_encrypted"] = encrypted
	}
	if req.SMTPHost != "" {
		updates["smtp_host"] = req.SMTPHost
	}
	if req.SMTPPort != 0 {
		updates["smtp_port"] = req.SMTPPort
	}
	if req.SMTPUser != "" {
		updates["smtp_username"] = req.SMTPUser
	}
	if req.SMTPFrom != "" {
		updates["smtp_from"] = req.SMTPFrom
	}
	if req.SMTPTo != nil {
		updates["smtp_to"] = models.StringArray(req.SMTPTo)
	}
	if req.SMTPUseTLS != nil {
		updates["smtp_use_tls"] = *req.SMTPUseTLS
	}
	if req.SMTPPass != "" {
		if !NotificationCredentialKeyConfigured() {
			c.JSON(http.StatusServiceUnavailable, gin.H{
				"error": "email notification storage is not configured (RAYYAN_AUTH_CREDENTIALKEY is unset)",
			})
			return
		}
		encrypted, err := EncryptSMTPPassword(req.SMTPPass)
		if err != nil {
			c.JSON(http.StatusServiceUnavailable, gin.H{"error": err.Error()})
			return
		}
		updates["smtp_password_encrypted"] = encrypted
	}
	if req.AlertTypes != nil {
		updates["alert_types"] = models.StringArray(req.AlertTypes)
	}
	if req.MinSeverity != "" {
		updates["min_severity"] = req.MinSeverity
	}
	if req.Active != nil {
		updates["active"] = *req.Active
	}
	if err := h.db.Model(&cfg).Updates(updates).Error; err != nil {
		h.log.Warnw("failed to update notification config", "error", err)
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to update config"})
		return
	}
	cfg.BotToken = ""
	cfg.SMTPPasswordEncrypted = ""
	cfg.AuthTokenEncrypted = ""
	c.JSON(http.StatusOK, cfg)
}

func (h *NotificationHandler) Delete(c *gin.Context) {
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
	result := h.db.Where("id = ? AND org_id = ?", id, user.OrgID).Delete(&models.NotificationConfig{})
	if result.Error != nil {
		h.log.Warnw("failed to delete notification config", "error", result.Error)
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to delete config"})
		return
	}
	if result.RowsAffected == 0 {
		c.JSON(http.StatusNotFound, gin.H{"error": "notification config not found"})
		return
	}
	c.JSON(http.StatusNoContent, nil)
}

// Test fires a test notification to confirm the webhook is working
func (h *NotificationHandler) Test(c *gin.Context) {
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
	var cfg models.NotificationConfig
	if err := h.db.Where("id = ? AND org_id = ?", id, user.OrgID).First(&cfg).Error; err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "not found"})
		return
	}
	testAlert := &models.Alert{
		Type:     "test",
		Severity: "info",
		Title:    "Rayyan ASM — Test Notification",
		Message:  "This is a test notification from Rayyan ASM. Your webhook is configured correctly.",
	}
	testAlert.OrgID = user.OrgID
	DispatchTestNotification(h.db, h.log, cfg, testAlert)
	c.JSON(http.StatusOK, gin.H{"message": "test notification dispatched"})
}

type ImportExportHandler struct {
	db  *gorm.DB
	log *zap.SugaredLogger
}

func NewImportExportHandler(db *gorm.DB, log *zap.SugaredLogger) *ImportExportHandler {
	return &ImportExportHandler{db: db, log: log}
}

// ImportSubdomains accepts a JSON array of FQDNs or a newline-delimited text body
func (h *ImportExportHandler) ImportSubdomains(c *gin.Context) {
	user := middleware.GetUser(c)
	if user == nil {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "unauthorized"})
		return
	}
	domainID, err := uuid.Parse(c.Param("id"))
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid domain id"})
		return
	}
	// Ensure domain belongs to org
	var domain models.Domain
	if err := h.db.Where("id = ? AND org_id = ?", domainID, user.OrgID).First(&domain).Error; err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "domain not found"})
		return
	}
	var req struct {
		Subdomains []string `json:"subdomains" binding:"required"`
		Source     string   `json:"source"`
	}
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	if req.Source == "" {
		req.Source = "import"
	}
	now := time.Now()
	created := 0
	for _, fqdn := range req.Subdomains {
		fqdn = strings.TrimSpace(strings.ToLower(fqdn))
		if fqdn == "" {
			continue
		}
		name := strings.TrimSuffix(fqdn, "."+domain.Name)
		sub := models.Subdomain{
			OrgID:       user.OrgID,
			DomainID:    domainID,
			Name:        name,
			FQDN:        fqdn,
			Status:      "active",
			Source:      req.Source,
			FirstSeenAt: now,
			LastSeenAt:  now,
		}
		sub.ID = uuid.New()
		// Skip duplicates
		var existing models.Subdomain
		if h.db.Where("org_id = ? AND fqdn = ?", user.OrgID, fqdn).First(&existing).Error != nil {
			if err := h.db.Create(&sub).Error; err != nil {
				h.log.Warnw("failed to import subdomain", "fqdn", fqdn, "error", err)
				continue
			}
			created++
		}
	}
	c.JSON(http.StatusOK, gin.H{"imported": created, "total": len(req.Subdomains)})
}

// ExportSubdomains returns all subdomains for a domain as JSON
func (h *ImportExportHandler) ExportSubdomains(c *gin.Context) {
	user := middleware.GetUser(c)
	if user == nil {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "unauthorized"})
		return
	}
	domainID, err := uuid.Parse(c.Param("id"))
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid domain id"})
		return
	}
	var subs []models.Subdomain
	if err := h.db.Where("org_id = ? AND domain_id = ?", user.OrgID, domainID).Find(&subs).Error; err != nil {
		h.log.Warnw("subdomain suggestions query failed", "error", err)
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to fetch subdomains"})
		return
	}
	c.JSON(http.StatusOK, subs)
}

// ImportTargets accepts a list of IPs / CIDRs and creates Host records
func (h *ImportExportHandler) ImportTargets(c *gin.Context) {
	user := middleware.GetUser(c)
	if user == nil {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "unauthorized"})
		return
	}
	var req struct {
		Targets []string `json:"targets" binding:"required"` // IPs or CIDRs
		Source  string   `json:"source"`
	}
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	if req.Source == "" {
		req.Source = "import"
	}
	now := time.Now()
	created := 0
	for _, target := range req.Targets {
		target = strings.TrimSpace(target)
		if target == "" {
			continue
		}
		host := models.Host{
			OrgID:       user.OrgID,
			IP:          target,
			Status:      "active",
			FirstSeenAt: now,
			LastSeenAt:  now,
		}
		host.ID = uuid.New()
		var existing models.Host
		if h.db.Where("org_id = ? AND ip = ?", user.OrgID, target).First(&existing).Error != nil {
			if err := h.db.Create(&host).Error; err != nil {
				h.log.Warnw("failed to import host", "ip", target, "error", err)
				continue
			}
			created++
		}
	}
	c.JSON(http.StatusOK, gin.H{"imported": created, "total": len(req.Targets)})
}
