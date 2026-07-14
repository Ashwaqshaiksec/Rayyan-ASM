package handlers

import (
	"encoding/json"
	"net/http"
	"strings"
	"time"

	"github.com/ShadooowX/rayyan-asm/internal/api/middleware"
	cryptoutil "github.com/ShadooowX/rayyan-asm/internal/crypto"
	"github.com/ShadooowX/rayyan-asm/internal/models"
	"github.com/ShadooowX/rayyan-asm/internal/modules/cloud"
	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
	"go.uber.org/zap"
	"gorm.io/gorm"
)

// CloudCredentialHandler manages per-org encrypted cloud provider credentials
// used by the scheduler for automatic daily asset syncs.
//
// Credentials are AES-256-GCM encrypted at rest with the same
// RAYYAN_AUTH_CREDENTIALKEY used for ToolCredential.
// EncryptedCreds is NEVER returned in any API response.
type CloudCredentialHandler struct {
	db  *gorm.DB
	log *zap.SugaredLogger
	key []byte // 32-byte AES-256 key, nil → storage disabled
}

// NewCloudCredentialHandler constructs a handler. If key is nil, all write
// endpoints return 503 Service Unavailable.
func NewCloudCredentialHandler(db *gorm.DB, log *zap.SugaredLogger, key []byte) *CloudCredentialHandler {
	return &CloudCredentialHandler{db: db, log: log, key: key}
}

// cloudCredentialSummary is the safe API representation — never includes
// the raw or encrypted credential material.
type cloudCredentialSummary struct {
	ID          uuid.UUID  `json:"id"`
	Provider    string     `json:"provider"`
	Label       string     `json:"label"`
	SyncEnabled bool       `json:"sync_enabled"`
	LastSyncAt  *time.Time `json:"last_sync_at,omitempty"`
	CreatedBy   uuid.UUID  `json:"created_by"`
	CreatedAt   time.Time  `json:"created_at"`
}

func toSummary(r models.CloudProviderCredential) cloudCredentialSummary {
	return cloudCredentialSummary{
		ID:          r.ID,
		Provider:    r.Provider,
		Label:       r.Label,
		SyncEnabled: r.SyncEnabled,
		LastSyncAt:  r.LastSyncAt,
		CreatedBy:   r.CreatedBy,
		CreatedAt:   r.CreatedAt,
	}
}

// List GET /cloud/credentials
func (h *CloudCredentialHandler) List(c *gin.Context) {
	user := middleware.GetUser(c)
	var rows []models.CloudProviderCredential
	if err := h.db.Where("org_id = ? AND deleted_at IS NULL", user.OrgID).
		Order("created_at DESC").Find(&rows).Error; err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to list credentials"})
		return
	}
	out := make([]cloudCredentialSummary, len(rows))
	for i, r := range rows {
		out[i] = toSummary(r)
	}
	c.JSON(http.StatusOK, gin.H{"data": out, "total": len(out)})
}

// Create POST /cloud/credentials
//
// Body:
//
//	{
//	  "provider":    "aws" | "azure" | "gcp",
//	  "label":       "prod-us-east",        // optional, default ""
//	  "sync_enabled": true,
//	  "credentials": { ...cloud.ProviderCreds fields... }
//	}
func (h *CloudCredentialHandler) Create(c *gin.Context) {
	if len(h.key) == 0 {
		c.JSON(http.StatusServiceUnavailable, gin.H{
			"error": "cloud credential storage is disabled: RAYYAN_AUTH_CREDENTIALKEY not configured",
		})
		return
	}
	user := middleware.GetUser(c)

	var body struct {
		Provider    string              `json:"provider"     binding:"required"`
		Label       string              `json:"label"`
		SyncEnabled *bool               `json:"sync_enabled"`
		Credentials cloud.ProviderCreds `json:"credentials"  binding:"required"`
	}
	if err := c.ShouldBindJSON(&body); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	body.Provider = strings.ToLower(body.Provider)
	switch body.Provider {
	case "aws", "azure", "gcp":
	default:
		c.JSON(http.StatusBadRequest, gin.H{"error": "provider must be aws, azure, or gcp"})
		return
	}

	// Serialize and encrypt the credentials.
	plain, err := json.Marshal(body.Credentials)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to serialize credentials"})
		return
	}
	encrypted, err := cryptoutil.Encrypt(h.key, plain)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to encrypt credentials"})
		return
	}

	syncEnabled := true
	if body.SyncEnabled != nil {
		syncEnabled = *body.SyncEnabled
	}

	row := models.CloudProviderCredential{
		OrgID:          user.OrgID,
		Provider:       body.Provider,
		Label:          body.Label,
		EncryptedCreds: encrypted,
		SyncEnabled:    syncEnabled,
		CreatedBy:      user.ID,
	}
	row.ID = uuid.New()
	if err := h.db.Create(&row).Error; err != nil {
		h.log.Warnw("cloud credential create failed", "org_id", user.OrgID, "error", err)
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to save credential"})
		return
	}

	c.JSON(http.StatusCreated, gin.H{"data": toSummary(row)})
}

// Update PATCH /cloud/credentials/:id
//
// Allows toggling sync_enabled and rotating the credential material.
// Omit "credentials" to leave it unchanged.
func (h *CloudCredentialHandler) Update(c *gin.Context) {
	if len(h.key) == 0 {
		c.JSON(http.StatusServiceUnavailable, gin.H{"error": "cloud credential storage is disabled"})
		return
	}
	user := middleware.GetUser(c)
	credID, err := uuid.Parse(c.Param("id"))
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid credential id"})
		return
	}

	var row models.CloudProviderCredential
	if err := h.db.Where("id = ? AND org_id = ? AND deleted_at IS NULL", credID, user.OrgID).
		First(&row).Error; err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "credential not found"})
		return
	}

	var body struct {
		Label       *string              `json:"label"`
		SyncEnabled *bool                `json:"sync_enabled"`
		Credentials *cloud.ProviderCreds `json:"credentials"`
	}
	if err := c.ShouldBindJSON(&body); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	updates := map[string]interface{}{}
	if body.Label != nil {
		updates["label"] = *body.Label
	}
	if body.SyncEnabled != nil {
		updates["sync_enabled"] = *body.SyncEnabled
	}
	if body.Credentials != nil {
		plain, _ := json.Marshal(body.Credentials)
		encrypted, err := cryptoutil.Encrypt(h.key, plain)
		if err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to encrypt credentials"})
			return
		}
		updates["encrypted_creds"] = encrypted
	}
	if len(updates) == 0 {
		c.JSON(http.StatusBadRequest, gin.H{"error": "no updatable fields supplied"})
		return
	}

	if err := h.db.Model(&row).Updates(updates).Error; err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to update credential"})
		return
	}
	c.JSON(http.StatusOK, gin.H{"data": toSummary(row)})
}

// Delete DELETE /cloud/credentials/:id
func (h *CloudCredentialHandler) Delete(c *gin.Context) {
	user := middleware.GetUser(c)
	credID, err := uuid.Parse(c.Param("id"))
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid credential id"})
		return
	}

	result := h.db.Where("id = ? AND org_id = ?", credID, user.OrgID).
		Delete(&models.CloudProviderCredential{})
	if result.Error != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to delete credential"})
		return
	}
	if result.RowsAffected == 0 {
		c.JSON(http.StatusNotFound, gin.H{"error": "credential not found"})
		return
	}
	c.JSON(http.StatusOK, gin.H{"message": "deleted"})
}

// TriggerSync POST /cloud/credentials/:id/sync
// Manually triggers a sync for one stored credential without waiting for the
// daily scheduler. Useful for testing or on-demand refresh.
func (h *CloudCredentialHandler) TriggerSync(c *gin.Context) {
	if len(h.key) == 0 {
		c.JSON(http.StatusServiceUnavailable, gin.H{"error": "cloud credential storage is disabled"})
		return
	}
	user := middleware.GetUser(c)
	credID, err := uuid.Parse(c.Param("id"))
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid credential id"})
		return
	}

	var row models.CloudProviderCredential
	if err := h.db.Where("id = ? AND org_id = ? AND deleted_at IS NULL", credID, user.OrgID).
		First(&row).Error; err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "credential not found"})
		return
	}

	plain, err := cryptoutil.Decrypt(h.key, row.EncryptedCreds)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to decrypt credential"})
		return
	}
	var pc cloud.ProviderCreds
	if err := json.Unmarshal(plain, &pc); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to parse credential"})
		return
	}

	ctx := c.Request.Context()
	var assets []cloud.Asset
	switch row.Provider {
	case "aws":
		assets, err = cloud.SyncAWS(ctx, pc)
	case "azure":
		assets, err = cloud.SyncAzure(ctx, pc)
	case "gcp":
		assets, err = cloud.SyncGCP(ctx, pc)
	default:
		c.JSON(http.StatusBadRequest, gin.H{"error": "unknown provider"})
		return
	}
	if err != nil {
		h.log.Warnw("manual cloud sync failed", "provider", row.Provider, "org_id", user.OrgID, "error", err)
		c.JSON(http.StatusBadGateway, gin.H{"error": "cloud sync failed: " + err.Error()})
		return
	}

	// Upsert all returned assets.
	now := time.Now()
	upserted := 0
	for _, a := range assets {
		tagsJSON, _ := json.Marshal(a.Tags)
		metaJSON, _ := json.Marshal(a.Metadata)
		ipsJSON, _ := json.Marshal(a.IPs)

		record := models.CloudAsset{
			OrgID:        user.OrgID,
			Provider:     a.Provider,
			AccountID:    a.AccountID,
			Region:       a.Region,
			ResourceID:   a.ResourceID,
			ResourceType: a.ResourceType,
			Name:         a.Name,
			Status:       a.Status,
			LastSyncedAt: &now,
		}
		record.ID = uuid.New()

		if err := h.db.Where(models.CloudAsset{
			OrgID: user.OrgID, ResourceID: a.ResourceID,
		}).Assign(models.CloudAsset{
			Provider:     a.Provider,
			AccountID:    a.AccountID,
			Region:       a.Region,
			ResourceType: a.ResourceType,
			Name:         a.Name,
			Status:       a.Status,
			LastSyncedAt: &now,
		}).FirstOrCreate(&record).Error; err != nil {
			h.log.Warnw("cloud asset upsert failed", "resource_id", a.ResourceID, "error", err)
			continue
		}
		if err := h.db.Model(&record).Updates(map[string]interface{}{
			"ips": string(ipsJSON), "tags": string(tagsJSON), "metadata": string(metaJSON),
		}).Error; err != nil {
			h.log.Warnw("cloud asset field update failed", "resource_id", a.ResourceID, "error", err)
		}
		upserted++
	}

	if err := h.db.Model(&row).Update("last_sync_at", now).Error; err != nil {
		h.log.Warnw("cloud credential: failed to update last_sync_at", "credential_id", row.ID, "error", err)
	}
	c.JSON(http.StatusOK, gin.H{
		"provider":      row.Provider,
		"assets_synced": upserted,
		"synced_at":     now,
	})
}
