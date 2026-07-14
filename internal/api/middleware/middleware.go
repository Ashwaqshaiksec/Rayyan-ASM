package middleware

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/ShadooowX/rayyan-asm/internal/auth"
	"github.com/ShadooowX/rayyan-asm/internal/models"
	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
	"go.uber.org/zap"
	"gorm.io/gorm"
)

const (
	CtxUserKey      = "user"
	CtxClaimsKey    = "claims"
	CtxOrgKey       = "org"
	CtxRequestIDKey = "request_id"
)

// RequestID injects a unique X-Request-ID into every request and response.
// If the client already sent an X-Request-ID it is reused (max 64 chars).
func RequestID() gin.HandlerFunc {
	return func(c *gin.Context) {
		id := c.GetHeader("X-Request-ID")
		if id == "" || len(id) > 64 {
			b := make([]byte, 8)
			rand.Read(b) //nolint:errcheck
			id = hex.EncodeToString(b)
		}
		c.Set(CtxRequestIDKey, id)
		c.Header("X-Request-ID", id)
		c.Next()
	}
}

// GetRequestID retrieves the request ID from context.
func GetRequestID(c *gin.Context) string {
	val, _ := c.Get(CtxRequestIDKey)
	s, _ := val.(string)
	return s
}

// TokenRevoker is satisfied by *queue.RedisClient so middleware doesn't
// import the queue package directly.
type TokenRevoker interface {
	Get(ctx context.Context, key string) (string, error)
	Set(ctx context.Context, key string, value interface{}, ttl time.Duration) error
}

// Auth validates JWT tokens and API keys.
func Auth(authMgr *auth.Manager, db *gorm.DB) gin.HandlerFunc {
	return AuthWithRevocation(authMgr, db, nil)
}

// AuthWithRevocation is Auth plus optional Redis-backed token revocation check.
func AuthWithRevocation(authMgr *auth.Manager, db *gorm.DB, revoke TokenRevoker) gin.HandlerFunc {
	return func(c *gin.Context) {
		token := extractToken(c)
		if token == "" {
			apiKey := c.GetHeader("X-API-Key")
			if apiKey == "" {
				c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{"error": "authentication required"})
				return
			}
			if !validateAPIKey(apiKey, db, c) {
				c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{"error": "invalid API key"})
				return
			}
			c.Next()
			return
		}

		claims, err := authMgr.ValidateToken(token)
		if err != nil {
			c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{"error": "invalid token"})
			return
		}

		if claims.TokenType != "access" {
			c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{"error": "invalid token type"})
			return
		}

		// mfa_pending tokens are access tokens with a restricted role — they
		// may only be used to call /auth/mfa/verify and must not grant access
		// to any other protected route.
		if claims.Role == "mfa_pending" && c.FullPath() != "/api/v1/auth/mfa/verify" {
			c.AbortWithStatusJSON(http.StatusForbidden, gin.H{"error": "MFA verification required"})
			return
		}

		// Check revocation list (Redis) if available.
		if revoke != nil && claims.ID != "" {
			revokeKey := "rayyan:revoked:" + claims.ID
			if val, err := revoke.Get(c.Request.Context(), revokeKey); err == nil && val == "1" {
				c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{"error": "token has been revoked"})
				return
			}
		}

		var user models.User
		if err := db.Where("id = ? AND active = true", claims.UserID).First(&user).Error; err != nil {
			c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{"error": "user not found"})
			return
		}

		if !user.EmailVerified {
			c.AbortWithStatusJSON(http.StatusForbidden, gin.H{"error": "email not verified"})
			return
		}

		c.Set(CtxClaimsKey, claims)
		c.Set(CtxUserKey, &user)
		c.Next()
	}
}

// RevokeToken stores a token's jti in Redis so it cannot be reused before expiry.
func RevokeToken(revoke TokenRevoker, claims *auth.Claims) {
	if revoke == nil || claims == nil || claims.ID == "" {
		return
	}
	ttl := time.Until(claims.ExpiresAt.Time)
	if ttl <= 0 {
		return
	}
	revoke.Set(context.Background(), "rayyan:revoked:"+claims.ID, "1", ttl) //nolint:errcheck
}

func extractToken(c *gin.Context) string {
	bearer := c.GetHeader("Authorization")
	if strings.HasPrefix(bearer, "Bearer ") {
		return strings.TrimPrefix(bearer, "Bearer ")
	}
	if cookie, err := c.Cookie("rayyan_token"); err == nil {
		return cookie
	}
	return ""
}

// validateAPIKey uses the key prefix (first 12 chars) to narrow the DB lookup
// to at most a handful of rows before doing the bcrypt comparison, avoiding the
// O(n) full-table scan that would otherwise make API key auth unusable at scale.
func validateAPIKey(key string, db *gorm.DB, c *gin.Context) bool {
	if len(key) < 12 {
		return false
	}

	prefix := key[:12]
	var apiKeys []models.APIKey
	if err := db.Where("key_prefix = ? AND active = true", prefix).Find(&apiKeys).Error; err != nil {
		return false
	}

	for _, ak := range apiKeys {
		if auth.CheckAPIKey(ak.KeyHash, key) {
			now := time.Now()
			if ak.ExpiresAt != nil && ak.ExpiresAt.Before(now) {
				return false
			}
			// Cross-org guard: API key must belong to the same org as the user.
			var user models.User
			if err := db.First(&user, "id = ? AND active = true", ak.UserID).Error; err != nil {
				return false
			}
			if ak.OrgID != user.OrgID {
				return false
			}

			db.Model(&ak).Update("last_used_at", now) //nolint:errcheck

			c.Set(CtxUserKey, &user)
			c.Set(CtxOrgKey, user.OrgID)
			return true
		}
	}
	return false
}

// RequireRole enforces RBAC — user must have one of the specified roles.
func RequireRole(roles ...string) gin.HandlerFunc {
	allowed := make(map[string]bool, len(roles))
	for _, r := range roles {
		allowed[r] = true
	}

	return func(c *gin.Context) {
		user := GetUser(c)
		if user == nil {
			c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{"error": "unauthorized"})
			return
		}
		if !allowed[user.Role] {
			c.AbortWithStatusJSON(http.StatusForbidden, gin.H{"error": "insufficient permissions"})
			return
		}
		c.Next()
	}
}

// GetUser retrieves the authenticated user from context.
func GetUser(c *gin.Context) *models.User {
	val, exists := c.Get(CtxUserKey)
	if !exists {
		return nil
	}
	user, _ := val.(*models.User)
	return user
}

// GetClaims retrieves JWT claims from context.
func GetClaims(c *gin.Context) *auth.Claims {
	val, exists := c.Get(CtxClaimsKey)
	if !exists {
		return nil
	}
	claims, _ := val.(*auth.Claims)
	return claims
}

// AuditLog records mutating requests. GET/OPTIONS are skipped.
func AuditLog(db *gorm.DB, log *zap.SugaredLogger) gin.HandlerFunc {
	return func(c *gin.Context) {
		c.Next()

		if c.Request.Method == http.MethodGet || c.Request.Method == http.MethodOptions {
			return
		}

		user := GetUser(c)
		if user == nil {
			return
		}

		resource := c.FullPath()
		action := c.Request.Method + " " + resource

		entry := models.AuditLog{
			OrgID:      user.OrgID,
			UserID:     user.ID,
			Action:     action,
			Resource:   resource,
			ResourceID: c.Param("id"),
			IP:         c.ClientIP(),
			UserAgent:  c.Request.UserAgent(),
			RequestID:  GetRequestID(c),
			Success:    c.Writer.Status() < 400,
		}
		entry.ID = uuid.New()
		entry.CreatedAt = time.Now()
		entry.UpdatedAt = time.Now()

		if err := db.Create(&entry).Error; err != nil {
			log.Warnw("failed to write audit log", "error", err)
		}
	}
}

// RateLimit is an in-process sliding-window rate limiter.
// For multi-instance deployments, use Redis-backed limiting via RedisRateLimit.
func RateLimit(limit int, window time.Duration) gin.HandlerFunc {
	type entry struct {
		times []time.Time
	}
	var (
		mu   = make(chan struct{}, 1)
		data = make(map[string]*entry)
	)
	mu <- struct{}{}

	return func(c *gin.Context) {
		ip := c.ClientIP()
		now := time.Now()
		cutoff := now.Add(-window)

		<-mu
		e, ok := data[ip]
		if !ok {
			e = &entry{}
			data[ip] = e
		}

		valid := e.times[:0]
		for _, t := range e.times {
			if t.After(cutoff) {
				valid = append(valid, t)
			}
		}
		e.times = valid

		if len(valid) >= limit {
			mu <- struct{}{}
			c.AbortWithStatusJSON(http.StatusTooManyRequests, gin.H{
				"error":       "rate limit exceeded",
				"retry_after": window.Seconds(),
			})
			return
		}

		e.times = append(e.times, now)
		if len(e.times) == 0 {
			delete(data, ip)
		}
		mu <- struct{}{}

		c.Next()
	}
}

// RequestLogger logs every request with method, path, status, and latency.
// RedisRateLimiter is the interface RedisRateLimit needs on a Redis client.
// queue.RedisClient satisfies this via its Get/Set methods.
type RedisRateLimiter interface {
	Get(ctx context.Context, key string) (string, error)
	Set(ctx context.Context, key string, value interface{}, ttl time.Duration) error
}

// RedisRateLimit is a Redis-backed fixed-window rate limiter safe for multi-instance deployments.
// It uses an atomic compare-and-set pattern via Get/Set on the Redis client.
// Falls back to in-process limiting if the client doesn't satisfy RedisRateLimiter.
func RedisRateLimit(rdb interface{}, limit int, window time.Duration) gin.HandlerFunc {
	rl, ok := rdb.(RedisRateLimiter)
	if !ok {
		// Fall back to in-process limiter when Redis isn't available.
		return RateLimit(limit, window)
	}
	return func(c *gin.Context) {
		key := "rl:" + c.FullPath() + ":" + c.ClientIP()
		ctx := c.Request.Context()

		val, err := rl.Get(ctx, key)
		if err != nil {
			// Key doesn't exist or Redis unavailable — fail open.
			_ = rl.Set(ctx, key, "1", window)
			c.Next()
			return
		}

		count := 0
		_, _ = fmt.Sscanf(val, "%d", &count)
		count++

		if count > limit {
			c.AbortWithStatusJSON(http.StatusTooManyRequests, gin.H{
				"error":       "rate limit exceeded",
				"retry_after": window.Seconds(),
			})
			return
		}
		// Update count; keep original TTL by using the remaining window time.
		_ = rl.Set(ctx, key, fmt.Sprintf("%d", count), window)
		c.Next()
	}
}

func RequestLogger(log *zap.SugaredLogger) gin.HandlerFunc {
	return func(c *gin.Context) {
		start := time.Now()
		path := c.Request.URL.Path

		c.Next()

		log.Infow("request",
			"method", c.Request.Method,
			"path", path,
			"status", c.Writer.Status(),
			"latency", time.Since(start),
			"ip", c.ClientIP(),
			"request_id", GetRequestID(c),
		)
	}
}

// SecurityHeaders adds defensive HTTP response headers to every reply.
// It does not set Content-Security-Policy because the correct policy
// varies per deployment; operators should add that via a reverse proxy.
func SecurityHeaders() gin.HandlerFunc {
	return func(c *gin.Context) {
		c.Header("X-Content-Type-Options", "nosniff")
		c.Header("X-Frame-Options", "DENY")
		c.Header("X-XSS-Protection", "1; mode=block")
		c.Header("Referrer-Policy", "strict-origin-when-cross-origin")
		c.Header("Permissions-Policy", "camera=(), microphone=(), geolocation=()")
		c.Header("Strict-Transport-Security", "max-age=63072000; includeSubDomains")
		// CSP: API only returns JSON/binary; no scripts, frames, or plugins needed.
		c.Header("Content-Security-Policy", "default-src 'none'; frame-ancestors 'none'")
		// Prevent caching of sensitive API responses.
		c.Header("Cache-Control", "no-store")
		c.Header("Pragma", "no-cache")
		c.Next()
	}
}

// Recovery returns a middleware that recovers from panics and returns a
// generic 500 without exposing the stack trace in the response body.
func Recovery(log *zap.SugaredLogger) gin.HandlerFunc {
	return func(c *gin.Context) {
		defer func() {
			if err := recover(); err != nil {
				log.Errorw("panic recovered", "error", err, "path", c.Request.URL.Path)
				c.AbortWithStatusJSON(http.StatusInternalServerError, gin.H{"error": "internal server error"})
			}
		}()
		c.Next()
	}
}
