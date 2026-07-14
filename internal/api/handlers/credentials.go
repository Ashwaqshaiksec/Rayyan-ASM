package handlers

import (
	"encoding/json"
	"net/http"
	"strings"
	"time"

	"github.com/ShadooowX/rayyan-asm/internal/api/middleware"
	cryptoutil "github.com/ShadooowX/rayyan-asm/internal/crypto"
	"github.com/ShadooowX/rayyan-asm/internal/models"
	trtypes "github.com/ShadooowX/rayyan-asm/internal/modules/toolrunner/types"
	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
	"go.uber.org/zap"
	"gorm.io/gorm"
)

// credentialCapableTools lists the tools that currently accept stored
// credentials via *WithCreds wrappers (internal/modules/toolrunner/tools/smb_creds.go)
// or credential-based dispatch in workflow_dispatcher.go.
//
// jwt_tool convention: the raw JWT string is stored in the `username` field.
// The token must begin with "eyJ" (the base64url-encoded '{"' that opens every
// well-formed JWT header). Do NOT store the token in the password or nt_hash
// fields — the dispatcher reads `credentials.Username` directly and passes it
// to tools.RunJWTTool as the token argument.
var credentialCapableTools = map[string]bool{
	"smbclient":     true,
	"enum4linux-ng": true,
	"crackmapexec":  true,
	"jwt_tool":      true,
	"gopherus":      true, // Domain field carries the SSRF protocol hint (e.g. "mysql")
}

// CredentialHandler manages encrypted external-tool credentials.
type CredentialHandler struct {
	db  *gorm.DB
	log *zap.SugaredLogger
	// key is the decoded 32-byte AES-256 key, or nil if credential storage
	// is disabled (RAYYAN_AUTH_CREDENTIALKEY not configured).
	key []byte
}

// NewCredentialHandler creates a CredentialHandler. credentialKey is the raw
// config value (base64/hex/raw 32-byte string); if empty or invalid, the
// handler is created in "disabled" mode and all endpoints return 503.
func NewCredentialHandler(db *gorm.DB, log *zap.SugaredLogger, credentialKey string) *CredentialHandler {
	var key []byte
	if credentialKey != "" {
		if k, err := cryptoutil.DecodeKey(credentialKey); err == nil {
			key = k
		} else {
			log.Warn("tool credential storage disabled: invalid RAYYAN_AUTH_CREDENTIALKEY", "error", err)
		}
	}
	return &CredentialHandler{db: db, log: log, key: key}
}

// enabled reports whether credential encryption is configured.
func (h *CredentialHandler) enabled() bool {
	return len(h.key) == 32
}

func (h *CredentialHandler) requireEnabled(c *gin.Context) bool {
	if !h.enabled() {
		c.AbortWithStatusJSON(http.StatusServiceUnavailable, gin.H{
			"error": "tool credential storage is not configured (RAYYAN_AUTH_CREDENTIALKEY is unset)",
		})
		return false
	}
	return true
}

type credentialCreateRequest struct {
	ToolName string `json:"tool_name" binding:"required"`
	Label    string `json:"label"`
	Username string `json:"username"`
	Password string `json:"password"`
	Domain   string `json:"domain"`
	NTHash   string `json:"nt_hash"`
}

type credentialResponse struct {
	ID        uuid.UUID `json:"id"`
	ToolName  string    `json:"tool_name"`
	Label     string    `json:"label"`
	Username  string    `json:"username"`
	Domain    string    `json:"domain"`
	HasSecret bool      `json:"has_secret"`
	CreatedAt time.Time `json:"created_at"`
	UpdatedAt time.Time `json:"updated_at"`
}

func toCredentialResponse(cred *models.ToolCredential, key []byte) credentialResponse {
	resp := credentialResponse{
		ID:        cred.ID,
		ToolName:  cred.ToolName,
		Label:     cred.Label,
		HasSecret: cred.EncryptedSecret != "",
		CreatedAt: cred.CreatedAt,
		UpdatedAt: cred.UpdatedAt,
	}
	// Decrypt just enough to surface non-secret fields (username/domain) in
	// list views, without ever returning the password or NT hash.
	if plaintext, err := cryptoutil.Decrypt(key, cred.EncryptedSecret); err == nil {
		var tc trtypes.ToolCredentials
		if json.Unmarshal(plaintext, &tc) == nil {
			resp.Username = tc.Username
			resp.Domain = tc.Domain
		}
	}
	return resp
}

// List returns all stored credentials for the org (secrets never included).
// GET /api/v1/tool-credentials
func (h *CredentialHandler) List(c *gin.Context) {
	if !h.requireEnabled(c) {
		return
	}
	user := middleware.GetUser(c)
	if user == nil {
		c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{"error": "unauthorized"})
		return
	}

	var creds []models.ToolCredential
	if err := h.db.Where("org_id = ?", user.OrgID).Order("created_at desc").Find(&creds).Error; err != nil {
		c.AbortWithStatusJSON(http.StatusInternalServerError, gin.H{"error": "failed to list credentials"})
		return
	}

	out := make([]credentialResponse, 0, len(creds))
	for i := range creds {
		out = append(out, toCredentialResponse(&creds[i], h.key))
	}
	c.JSON(http.StatusOK, gin.H{"credentials": out})
}

// Create stores a new encrypted credential.
// POST /api/v1/tool-credentials
func (h *CredentialHandler) Create(c *gin.Context) {
	if !h.requireEnabled(c) {
		return
	}
	user := middleware.GetUser(c)
	if user == nil {
		c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{"error": "unauthorized"})
		return
	}

	var req credentialCreateRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.AbortWithStatusJSON(http.StatusBadRequest, gin.H{"error": "invalid request: " + err.Error()})
		return
	}

	if !credentialCapableTools[req.ToolName] {
		c.AbortWithStatusJSON(http.StatusBadRequest, gin.H{
			"error": "tool_name must be one of: smbclient, enum4linux-ng, crackmapexec, jwt_tool, gopherus",
		})
		return
	}

	// jwt_tool stores the raw JWT in the username field.
	// Validate that the value looks like a real JWT (base64url header prefix).
	if req.ToolName == "jwt_tool" {
		if req.Username == "" || !strings.HasPrefix(req.Username, "eyJ") {
			c.AbortWithStatusJSON(http.StatusBadRequest, gin.H{
				"error": "jwt_tool credentials must store the raw JWT in the username field (must start with eyJ)",
			})
			return
		}
	}

	if req.Username == "" {
		c.AbortWithStatusJSON(http.StatusBadRequest, gin.H{"error": "username is required"})
		return
	}

	plaintext, err := json.Marshal(trtypes.ToolCredentials{
		Username: req.Username,
		Password: req.Password,
		Domain:   req.Domain,
		NTHash:   req.NTHash,
	})
	if err != nil {
		c.AbortWithStatusJSON(http.StatusInternalServerError, gin.H{"error": "failed to encode credential"})
		return
	}

	encrypted, err := cryptoutil.Encrypt(h.key, plaintext)
	if err != nil {
		// Never log plaintext; log only the failure.
		h.log.Errorw("failed to encrypt tool credential", "error", err)
		c.AbortWithStatusJSON(http.StatusInternalServerError, gin.H{"error": "failed to encrypt credential"})
		return
	}

	cred := models.ToolCredential{
		OrgID:           user.OrgID,
		ToolName:        req.ToolName,
		Label:           req.Label,
		EncryptedSecret: encrypted,
		CreatedBy:       user.ID,
	}
	if err := h.db.Create(&cred).Error; err != nil {
		c.AbortWithStatusJSON(http.StatusInternalServerError, gin.H{"error": "failed to save credential"})
		return
	}

	c.JSON(http.StatusCreated, toCredentialResponse(&cred, h.key))
}

// Delete removes a stored credential.
// DELETE /api/v1/tool-credentials/:id
func (h *CredentialHandler) Delete(c *gin.Context) {
	if !h.requireEnabled(c) {
		return
	}
	user := middleware.GetUser(c)
	if user == nil {
		c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{"error": "unauthorized"})
		return
	}

	id, err := uuid.Parse(c.Param("id"))
	if err != nil {
		c.AbortWithStatusJSON(http.StatusBadRequest, gin.H{"error": "invalid id"})
		return
	}

	result := h.db.Where("id = ? AND org_id = ?", id, user.OrgID).Delete(&models.ToolCredential{})
	if result.Error != nil {
		c.AbortWithStatusJSON(http.StatusInternalServerError, gin.H{"error": "failed to delete credential"})
		return
	}
	if result.RowsAffected == 0 {
		c.AbortWithStatusJSON(http.StatusNotFound, gin.H{"error": "credential not found"})
		return
	}

	c.JSON(http.StatusOK, gin.H{"deleted": true})
}

// LoadCredentials is implemented in internal/modules/toolrunner (credentials.go)
// to avoid an import cycle (handlers -> toolrunner -> handlers). See
// toolrunner.LoadCredentials, which has the same signature and behavior.
