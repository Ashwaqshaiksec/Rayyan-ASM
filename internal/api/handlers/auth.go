package handlers

import (
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"net"
	"net/http"
	"net/smtp"
	"time"

	"github.com/ShadooowX/rayyan-asm/internal/api/middleware"
	"github.com/ShadooowX/rayyan-asm/internal/auth"
	cryptoutil "github.com/ShadooowX/rayyan-asm/internal/crypto"
	"github.com/ShadooowX/rayyan-asm/internal/models"
	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
	"go.uber.org/zap"
	"gorm.io/gorm"
)

type AuthHandler struct {
	db      *gorm.DB
	authMgr *auth.Manager
	log     *zap.SugaredLogger
	revoke  middleware.TokenRevoker
	appURL  string
	credKey []byte // 32-byte AES-256 key for encrypting TOTP secrets at rest; nil = plaintext fallback
}

func NewAuthHandler(db *gorm.DB, authMgr *auth.Manager, log *zap.SugaredLogger) *AuthHandler {
	return &AuthHandler{db: db, authMgr: authMgr, log: log}
}

// SetCredKey sets the AES-256 key used to encrypt TOTP secrets at rest.
func (h *AuthHandler) SetCredKey(key []byte) {
	h.credKey = key
}

// getMFASecret returns the plaintext TOTP secret, decrypting if a credKey is set.
func (h *AuthHandler) getMFASecret(raw string) string {
	if len(h.credKey) != 32 || raw == "" {
		return raw
	}
	dec, err := cryptoutil.Decrypt(h.credKey, raw)
	if err != nil {
		// May be a plaintext secret from before encryption was enabled — return as-is.
		return raw
	}
	return string(dec)
}

func (h *AuthHandler) SetRevoke(r middleware.TokenRevoker) {
	h.revoke = r
}

func (h *AuthHandler) SetAppURL(u string) {
	h.appURL = u
}

func (h *AuthHandler) sendResetEmail(toAddr, token string) {
	var cfg models.NotificationConfig
	err := h.db.Where("channel = ? AND active = true", "email").
		Order("created_at asc").
		First(&cfg).Error
	if err != nil {
		h.log.Infow("password reset email skipped: no active email notification config", "to", toAddr)
		return
	}
	if cfg.SMTPHost == "" || cfg.SMTPFrom == "" {
		h.log.Warnw("password reset email skipped: incomplete smtp config", "to", toAddr)
		return
	}

	baseURL := h.appURL
	if baseURL == "" {
		baseURL = "http://localhost:8080"
	}
	resetLink := fmt.Sprintf("%s/reset-password?token=%s", baseURL, token)

	port := cfg.SMTPPort
	if port == 0 {
		port = 587
	}
	addr := net.JoinHostPort(cfg.SMTPHost, fmt.Sprintf("%d", port))

	body := fmt.Sprintf(
		"From: %s\r\nTo: %s\r\nSubject: Rayyan ASM — Password Reset\r\n\r\n"+
			"You requested a password reset. Click the link below within 1 hour:\r\n\r\n%s\r\n\r\n"+
			"If you did not request this, you can ignore this email.\r\n",
		cfg.SMTPFrom, toAddr, resetLink,
	)

	var smtpAuth smtp.Auth
	if cfg.SMTPUsername != "" {
		pass, err := decryptSMTPPassword(cfg.SMTPPasswordEncrypted)
		if err != nil {
			h.log.Warnw("password reset email failed: decrypt", "to", toAddr, "error", err)
			return
		}
		smtpAuth = smtp.PlainAuth("", cfg.SMTPUsername, pass, cfg.SMTPHost)
	}

	if err := smtp.SendMail(addr, smtpAuth, cfg.SMTPFrom, []string{toAddr}, []byte(body)); err != nil {
		h.log.Warnw("password reset email failed", "to", toAddr, "error", err)
		return
	}
	h.log.Infow("password reset email sent", "to", toAddr)
}

type loginRequest struct {
	Email    string `json:"email" binding:"required,email"`
	Password string `json:"password" binding:"required,min=8"`
}

type loginResponse struct {
	AccessToken  string      `json:"access_token"`
	RefreshToken string      `json:"refresh_token"`
	ExpiresIn    int         `json:"expires_in"`
	User         models.User `json:"user"`
	MFARequired  bool        `json:"mfa_required,omitempty"`
}

func (h *AuthHandler) Login(c *gin.Context) {
	var req loginRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	var user models.User
	if err := h.db.Where("email = ?", req.Email).First(&user).Error; err != nil {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "invalid credentials"})
		return
	}

	if !user.Active {
		c.JSON(http.StatusForbidden, gin.H{"error": "account disabled"})
		return
	}

	if !user.EmailVerified {
		c.JSON(http.StatusForbidden, gin.H{"error": "email address not verified — check your inbox"})
		return
	}

	if user.LockedUntil != nil && user.LockedUntil.After(time.Now()) {
		c.JSON(http.StatusTooManyRequests, gin.H{"error": "account temporarily locked"})
		return
	}

	if err := h.authMgr.CheckPassword(user.PasswordHash, req.Password); err != nil {
		// Atomically increment and retrieve the new attempt count in one query
		// to avoid a TOCTOU race where concurrent requests all read < 5 and skip lockout.
		var newAttempts int
		if err := h.db.Raw(
			`UPDATE users SET login_attempts = login_attempts + 1 WHERE id = ? RETURNING login_attempts`,
			user.ID,
		).Scan(&newAttempts).Error; err != nil {
			// If this fails, newAttempts stays at its zero value and the lockout
			// check below never fires — a security-relevant silent failure, not
			// just a stale-metadata one, so this is logged even though the
			// request still proceeds to the generic "invalid credentials" response.
			h.log.Warnw("auth: failed to increment login_attempts", "user_id", user.ID, "error", err)
		}
		if newAttempts >= 5 {
			lockUntil := time.Now().Add(15 * time.Minute)
			if err := h.db.Model(&user).Updates(map[string]interface{}{
				"locked_until":   lockUntil,
				"login_attempts": 0,
			}).Error; err != nil {
				h.log.Warnw("auth: failed to lock account after repeated failed logins", "user_id", user.ID, "error", err)
			}
		}
		c.JSON(http.StatusUnauthorized, gin.H{"error": "invalid credentials"})
		return
	}

	now := time.Now()
	if err := h.db.Model(&user).Updates(map[string]interface{}{
		"login_attempts": 0,
		"last_login_at":  now,
		"locked_until":   nil,
	}).Error; err != nil {
		h.log.Warnw("auth: failed to reset login_attempts on successful login", "user_id", user.ID, "error", err)
	}

	// If MFA is enabled, return a partial response requiring TOTP verification.
	if user.MFAEnabled && user.MFASecret != "" {
		// Issue a short-lived MFA-pending token so the client can call /auth/mfa/verify.
		mfaToken, err := h.authMgr.GenerateAccessToken(user.ID, user.OrgID, user.Email, "mfa_pending")
		if err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": "token generation failed"})
			return
		}
		c.JSON(http.StatusOK, gin.H{
			"mfa_required": true,
			"mfa_token":    mfaToken,
		})
		return
	}

	accessToken, err := h.authMgr.GenerateAccessToken(user.ID, user.OrgID, user.Email, user.Role)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "token generation failed"})
		return
	}

	refreshToken, err := h.authMgr.GenerateRefreshToken(user.ID, user.OrgID, user.Email, user.Role)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "token generation failed"})
		return
	}

	c.JSON(http.StatusOK, loginResponse{
		AccessToken:  accessToken,
		RefreshToken: refreshToken,
		ExpiresIn:    h.authMgr.AccessExpirySeconds(),
		User:         user,
	})
}

type registerRequest struct {
	OrgName   string `json:"org_name" binding:"required,min=2"`
	Email     string `json:"email" binding:"required,email"`
	Username  string `json:"username" binding:"required,min=3,alphanum"`
	Password  string `json:"password" binding:"required,min=10"`
	FirstName string `json:"first_name" binding:"required"`
	LastName  string `json:"last_name" binding:"required"`
}

func (h *AuthHandler) Register(c *gin.Context) {
	var req registerRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	if err := h.authMgr.ValidatePasswordComplexity(req.Password); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	var count int64
	h.db.Model(&models.User{}).Where("email = ?", req.Email).Count(&count)
	if count > 0 {
		c.JSON(http.StatusConflict, gin.H{"error": "email already registered"})
		return
	}

	hash, err := h.authMgr.HashPassword(req.Password)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to process password"})
		return
	}

	org := models.Organization{Name: req.OrgName, Slug: slug(req.OrgName), Active: true}
	org.ID = uuid.New()
	user := models.User{
		OrgID:        org.ID,
		Email:        req.Email,
		Username:     req.Username,
		PasswordHash: hash,
		FirstName:    req.FirstName,
		LastName:     req.LastName,
		Role:         "admin",
		Active:       true,
	}
	user.ID = uuid.New()

	if err := h.db.Transaction(func(tx *gorm.DB) error {
		if err := tx.Create(&org).Error; err != nil {
			return err
		}
		return tx.Create(&user).Error
	}); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to create account"})
		return
	}

	// If SMTP is not configured, there is no way to deliver the verification
	// link, so auto-verify the new user immediately and skip token generation.
	// This avoids permanently locking out users in dev/self-hosted deployments
	// that run without email.
	var emailCfg models.NotificationConfig
	smtpReady := h.db.Where("channel = ? AND active = true AND smtp_host != '' AND smtp_from != ''", "email").
		First(&emailCfg).Error == nil

	if !smtpReady {
		if err := h.db.Model(&models.User{}).Where("id = ?", user.ID).Update("email_verified", true).Error; err != nil {
			// No SMTP means no fallback verification link either — a failure
			// here leaves the user permanently locked out with no way to
			// verify at all, so this is worth surfacing loudly.
			h.log.Warnw("failed to auto-verify email (no SMTP config) — user may be locked out", "user_id", user.ID, "error", err)
		}
		h.log.Infow("email auto-verified (no SMTP config)", "user_id", user.ID)
		c.JSON(http.StatusCreated, gin.H{
			"message": "registration successful",
			"org_id":  org.ID,
			"user_id": user.ID,
		})
		return
	}

	// Generate and persist email verification token.
	raw := make([]byte, 32)
	if _, err := rand.Read(raw); err == nil {
		token := hex.EncodeToString(raw)
		if tokenHash, hashErr := h.authMgr.HashPassword(token); hashErr == nil {
			evt := models.EmailVerificationToken{
				UserID:    user.ID,
				TokenHash: tokenHash,
				ExpiresAt: time.Now().Add(24 * time.Hour),
			}
			evt.ID = uuid.New()
			if h.db.Create(&evt).Error == nil {
				go h.sendVerificationEmail(user.Email, token)
			}
		}
	}

	c.JSON(http.StatusCreated, gin.H{
		"message": "registration successful — check your email to verify your account",
		"org_id":  org.ID,
		"user_id": user.ID,
	})
}

func (h *AuthHandler) VerifyEmail(c *gin.Context) {
	token := c.Query("token")
	if token == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "token required"})
		return
	}

	var tokens []models.EmailVerificationToken
	h.db.Where("used_at IS NULL AND expires_at > ?", time.Now()).Find(&tokens)

	var matched *models.EmailVerificationToken
	for i := range tokens {
		if err := h.authMgr.CheckPassword(tokens[i].TokenHash, token); err == nil {
			matched = &tokens[i]
			break
		}
	}
	if matched == nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid or expired verification token"})
		return
	}

	now := time.Now()
	if err := h.db.Model(matched).Update("used_at", now).Error; err != nil {
		h.log.Warnw("failed to mark verification token used", "error", err)
		c.JSON(http.StatusInternalServerError, gin.H{"error": "verification failed, please try again"})
		return
	}
	if err := h.db.Model(&models.User{}).Where("id = ?", matched.UserID).Update("email_verified", true).Error; err != nil {
		h.log.Warnw("failed to set email_verified", "user_id", matched.UserID, "error", err)
		c.JSON(http.StatusInternalServerError, gin.H{"error": "verification failed, please try again"})
		return
	}
	h.log.Infow("email verified", "user_id", matched.UserID)
	c.JSON(http.StatusOK, gin.H{"message": "email verified successfully"})
}

func (h *AuthHandler) ResendVerification(c *gin.Context) {
	var req struct {
		Email string `json:"email" binding:"required,email"`
	}
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	var user models.User
	if err := h.db.Where("email = ? AND active = true", req.Email).First(&user).Error; err != nil {
		c.JSON(http.StatusOK, gin.H{"message": "if the account exists, a new link will be sent"})
		return
	}
	if user.EmailVerified {
		c.JSON(http.StatusOK, gin.H{"message": "email already verified"})
		return
	}

	h.db.Where("user_id = ? AND used_at IS NULL", user.ID).Delete(&models.EmailVerificationToken{})

	raw := make([]byte, 32)
	if _, err := rand.Read(raw); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to generate token"})
		return
	}
	token := hex.EncodeToString(raw)
	tokenHash, err := h.authMgr.HashPassword(token)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to process token"})
		return
	}

	evt := models.EmailVerificationToken{
		UserID:    user.ID,
		TokenHash: tokenHash,
		ExpiresAt: time.Now().Add(24 * time.Hour),
	}
	evt.ID = uuid.New()
	if err := h.db.Create(&evt).Error; err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to store token"})
		return
	}

	go h.sendVerificationEmail(user.Email, token)
	c.JSON(http.StatusOK, gin.H{"message": "if the account exists, a new link will be sent"})
}

func (h *AuthHandler) sendVerificationEmail(toAddr, rawToken string) {
	var cfg models.NotificationConfig
	err := h.db.Where("channel = ? AND active = true", "email").
		Order("created_at asc").
		First(&cfg).Error
	if err != nil {
		h.log.Infow("verification email skipped: no active email notification config", "to", toAddr)
		return
	}
	if cfg.SMTPHost == "" || cfg.SMTPFrom == "" {
		h.log.Warnw("verification email skipped: incomplete smtp config", "to", toAddr)
		return
	}

	baseURL := h.appURL
	if baseURL == "" {
		baseURL = "http://localhost:8080"
	}
	verifyLink := fmt.Sprintf("%s/verify-email?token=%s", baseURL, rawToken)

	port := cfg.SMTPPort
	if port == 0 {
		port = 587
	}
	addr := net.JoinHostPort(cfg.SMTPHost, fmt.Sprintf("%d", port))

	body := fmt.Sprintf(
		"From: %s\r\nTo: %s\r\nSubject: Rayyan ASM — Verify Email\r\n\r\n"+
			"Click the link below to verify your email address (valid 24 hours):\r\n\r\n%s\r\n\r\n"+
			"If you did not create this account you can ignore this email.\r\n",
		cfg.SMTPFrom, toAddr, verifyLink,
	)

	var smtpAuth smtp.Auth
	if cfg.SMTPUsername != "" {
		pass, err := decryptSMTPPassword(cfg.SMTPPasswordEncrypted)
		if err != nil {
			h.log.Warnw("verification email failed: decrypt", "to", toAddr, "error", err)
			return
		}
		smtpAuth = smtp.PlainAuth("", cfg.SMTPUsername, pass, cfg.SMTPHost)
	}

	if err := smtp.SendMail(addr, smtpAuth, cfg.SMTPFrom, []string{toAddr}, []byte(body)); err != nil {
		h.log.Warnw("verification email failed", "to", toAddr, "error", err)
		return
	}
	h.log.Infow("verification email sent", "to", toAddr)
}
func (h *AuthHandler) RefreshToken(c *gin.Context) {
	var req struct {
		RefreshToken string `json:"refresh_token" binding:"required"`
	}
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	claims, err := h.authMgr.ValidateToken(req.RefreshToken)
	if err != nil {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "invalid refresh token"})
		return
	}

	if claims.TokenType != "refresh" {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "invalid token type"})
		return
	}

	// Revoke the used refresh token (rotation).
	middleware.RevokeToken(h.revoke, claims)

	accessToken, err := h.authMgr.GenerateAccessToken(claims.UserID, claims.OrgID, claims.Email, claims.Role)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "token generation failed"})
		return
	}

	refreshToken, err := h.authMgr.GenerateRefreshToken(claims.UserID, claims.OrgID, claims.Email, claims.Role)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "token generation failed"})
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"access_token":  accessToken,
		"refresh_token": refreshToken,
		"expires_in":    h.authMgr.AccessExpirySeconds(),
	})
}

func (h *AuthHandler) Logout(c *gin.Context) {
	// Revoke the access token currently in use.
	claims := middleware.GetClaims(c)
	if claims != nil {
		middleware.RevokeToken(h.revoke, claims)
	}

	// Also revoke the refresh token if the client sent it in the request body.
	// This prevents the user from obtaining a new access token after logout.
	var req struct {
		RefreshToken string `json:"refresh_token"`
	}
	if err := c.ShouldBindJSON(&req); err == nil && req.RefreshToken != "" {
		if refreshClaims, err := h.authMgr.ValidateToken(req.RefreshToken); err == nil {
			middleware.RevokeToken(h.revoke, refreshClaims)
		}
	}

	c.JSON(http.StatusOK, gin.H{"message": "logged out successfully"})
}

func (h *AuthHandler) Me(c *gin.Context) {
	user := middleware.GetUser(c)
	if user == nil {
		c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{"error": "unauthorized"})
		return
	}
	c.JSON(http.StatusOK, user)
}

func (h *AuthHandler) UpdateMe(c *gin.Context) {
	user := middleware.GetUser(c)
	if user == nil {
		c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{"error": "unauthorized"})
		return
	}
	var req struct {
		FirstName string `json:"first_name"`
		LastName  string `json:"last_name"`
		AvatarURL string `json:"avatar_url"`
	}
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	if err := h.db.Model(user).Updates(req).Error; err != nil {
		h.log.Warnw("failed to update profile", "error", err)
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to update profile"})
		return
	}
	c.JSON(http.StatusOK, user)
}

func (h *AuthHandler) ChangePassword(c *gin.Context) {
	user := middleware.GetUser(c)
	if user == nil {
		c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{"error": "unauthorized"})
		return
	}
	var req struct {
		Current string `json:"current_password" binding:"required"`
		New     string `json:"new_password" binding:"required,min=10"`
	}
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	if err := h.authMgr.ValidatePasswordComplexity(req.New); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	if err := h.authMgr.CheckPassword(user.PasswordHash, req.Current); err != nil {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "current password is incorrect"})
		return
	}

	hash, err := h.authMgr.HashPassword(req.New)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to hash password"})
		return
	}
	if err := h.db.Model(user).Update("password_hash", hash).Error; err != nil {
		h.log.Warnw("failed to update password", "error", err)
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to change password"})
		return
	}

	// Revoke current session so the user must re-login with the new password.
	middleware.RevokeToken(h.revoke, middleware.GetClaims(c))

	c.JSON(http.StatusOK, gin.H{"message": "password changed"})
}

// ForgotPassword generates a time-limited reset token and stores its hash.
// In production this sends an email; here we log the token and return it
// in the response body only in non-production so developers can test the flow.
func (h *AuthHandler) ForgotPassword(c *gin.Context) {
	var req struct {
		Email string `json:"email" binding:"required,email"`
	}
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	var user models.User
	if err := h.db.Where("email = ? AND active = true", req.Email).First(&user).Error; err != nil {
		// Always return 200 to avoid user enumeration.
		c.JSON(http.StatusOK, gin.H{"message": "if the email exists, a reset link will be sent"})
		return
	}

	raw := make([]byte, 32)
	if _, err := rand.Read(raw); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to generate reset token"})
		return
	}
	token := hex.EncodeToString(raw)

	// Store hashed token.
	tokenHash, err := h.authMgr.HashPassword(token)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to process reset token"})
		return
	}

	expiry := time.Now().Add(1 * time.Hour)
	prt := models.PasswordResetToken{
		UserID:    user.ID,
		TokenHash: tokenHash,
		ExpiresAt: expiry,
	}
	prt.ID = uuid.New()

	// Invalidate any existing reset tokens for this user.
	h.db.Where("user_id = ? AND used_at IS NULL", user.ID).Delete(&models.PasswordResetToken{})

	if err := h.db.Create(&prt).Error; err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to store reset token"})
		return
	}

	h.log.Infow("password reset requested", "user_id", user.ID, "email", user.Email)

	go h.sendResetEmail(user.Email, token)

	resp := gin.H{"message": "if the email exists, a reset link will be sent"}
	c.JSON(http.StatusOK, resp)
}

func (h *AuthHandler) ResetPassword(c *gin.Context) {
	var req struct {
		Token    string `json:"token" binding:"required"`
		Password string `json:"password" binding:"required,min=10"`
	}
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	if err := h.authMgr.ValidatePasswordComplexity(req.Password); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	// Find all non-expired, unused tokens and check each one.
	var tokens []models.PasswordResetToken
	h.db.Where("expires_at > ? AND used_at IS NULL", time.Now()).Find(&tokens)

	var matched *models.PasswordResetToken
	for i := range tokens {
		if h.authMgr.CheckPassword(tokens[i].TokenHash, req.Token) == nil {
			matched = &tokens[i]
			break
		}
	}

	if matched == nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid or expired reset token"})
		return
	}

	hash, err := h.authMgr.HashPassword(req.Password)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to hash password"})
		return
	}

	now := time.Now()
	if err := h.db.Model(matched).Update("used_at", now).Error; err != nil {
		h.log.Warnw("failed to mark reset token used", "error", err)
		c.JSON(http.StatusInternalServerError, gin.H{"error": "reset failed, please try again"})
		return
	}
	if err := h.db.Model(&models.User{}).Where("id = ?", matched.UserID).Updates(map[string]interface{}{
		"password_hash":  hash,
		"login_attempts": 0,
		"locked_until":   nil,
	}).Error; err != nil {
		h.log.Warnw("failed to update password hash", "user_id", matched.UserID, "error", err)
		c.JSON(http.StatusInternalServerError, gin.H{"error": "reset failed, please try again"})
		return
	}
	h.log.Infow("password reset completed", "user_id", matched.UserID)
	c.JSON(http.StatusOK, gin.H{"message": "password has been reset"})
}

// EnableMFA generates a TOTP secret and returns a QR URI.
// The secret is NOT saved until VerifyMFA confirms the user can generate valid codes.
func (h *AuthHandler) EnableMFA(c *gin.Context) {
	user := middleware.GetUser(c)
	if user == nil {
		c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{"error": "unauthorized"})
		return
	}

	secret, err := auth.GenerateTOTPSecret()
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to generate MFA secret"})
		return
	}

	// Store the pending secret temporarily so VerifyMFA can confirm it.
	// We store it on the user row as mfa_secret but leave mfa_enabled=false
	// until verification succeeds.
	if err := h.db.Model(user).Update("mfa_secret", secret).Error; err != nil {
		h.log.Warnw("failed to store MFA secret", "error", err)
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to set up MFA"})
		return
	}

	issuer := "Rayyan ASM"
	otpUri := auth.TOTPUri(secret, user.Email, issuer)

	c.JSON(http.StatusOK, gin.H{
		"secret":  secret,
		"otp_uri": otpUri,
		"message": "scan the QR code with your authenticator app, then call /auth/mfa/verify to complete setup",
	})
}

// VerifyMFA validates a TOTP code and activates MFA for the user if not yet enabled,
// or issues a full session token when completing an MFA login.
func (h *AuthHandler) VerifyMFA(c *gin.Context) {
	user := middleware.GetUser(c)
	if user == nil {
		c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{"error": "unauthorized"})
		return
	}

	var req struct {
		Code string `json:"code" binding:"required,len=6"`
	}
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	if user.MFASecret == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "MFA setup not initiated — call /auth/mfa/enable first"})
		return
	}

	if !auth.ValidateTOTP(h.getMFASecret(user.MFASecret), req.Code) {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "invalid MFA code"})
		return
	}

	claims := middleware.GetClaims(c)

	// If this is an MFA-pending login (role == "mfa_pending"), issue real tokens.
	if claims != nil && claims.Role == "mfa_pending" {
		accessToken, err := h.authMgr.GenerateAccessToken(user.ID, user.OrgID, user.Email, user.Role)
		if err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": "token generation failed"})
			return
		}
		refreshToken, err := h.authMgr.GenerateRefreshToken(user.ID, user.OrgID, user.Email, user.Role)
		if err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": "token generation failed"})
			return
		}
		// Revoke the mfa_pending token.
		middleware.RevokeToken(h.revoke, claims)
		c.JSON(http.StatusOK, gin.H{
			"access_token":  accessToken,
			"refresh_token": refreshToken,
			"expires_in":    h.authMgr.AccessExpirySeconds(),
			"user":          user,
		})
		return
	}

	// This is MFA setup completion — activate MFA.
	if err := h.db.Model(user).Update("mfa_enabled", true).Error; err != nil {
		h.log.Warnw("failed to enable MFA", "error", err)
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to enable MFA"})
		return
	}
	c.JSON(http.StatusOK, gin.H{"message": "MFA enabled successfully"})
}

// DisableMFA deactivates MFA for the user after verifying a valid code.
func (h *AuthHandler) DisableMFA(c *gin.Context) {
	user := middleware.GetUser(c)
	if user == nil {
		c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{"error": "unauthorized"})
		return
	}

	var req struct {
		Code string `json:"code" binding:"required,len=6"`
	}
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	if !auth.ValidateTOTP(h.getMFASecret(user.MFASecret), req.Code) {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "invalid MFA code"})
		return
	}

	if err := h.db.Model(user).Updates(map[string]interface{}{"mfa_enabled": false, "mfa_secret": ""}).Error; err != nil {
		h.log.Warnw("failed to disable MFA", "error", err)
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to disable MFA"})
		return
	}
	c.JSON(http.StatusOK, gin.H{"message": "MFA disabled"})
}

func slug(s string) string {
	result := make([]byte, 0, len(s))
	for i := 0; i < len(s); i++ {
		ch := s[i]
		if ch >= 'A' && ch <= 'Z' {
			ch += 32
		}
		if (ch >= 'a' && ch <= 'z') || (ch >= '0' && ch <= '9') {
			result = append(result, ch)
		} else if ch == ' ' || ch == '-' {
			result = append(result, '-')
		}
	}
	return string(result)
}
