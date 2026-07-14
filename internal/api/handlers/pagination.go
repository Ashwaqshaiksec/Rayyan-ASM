package handlers

import (
	"github.com/gin-gonic/gin"
	"gorm.io/gorm"
)

// Page size caps used across all list endpoints.
// Centralising them here prevents drift between handlers and makes
// tuning a single-line change.
const (
	// MaxPageLimit is the hard ceiling for paginated list endpoints that
	// return rich objects (domains, hosts, findings, scans, …).
	MaxPageLimit = 500

	// MaxPageLimitLarge is used for lightweight endpoints where the caller
	// legitimately needs larger batches (e.g. discovery asset inventory,
	// change-detection history).
	MaxPageLimitLarge = 1000

	// MaxPageLimitSmall is used for endpoints whose payloads are expensive
	// to render (screenshots, audit logs, admin delivery history).
	MaxPageLimitSmall = 200

	// DefaultPageLimit is the default when the caller omits the limit param.
	DefaultPageLimit = 20
)

// dbCtx returns db scoped to the HTTP request's context so that client
// disconnects cancel in-flight queries and release DB connections promptly.
// Call this instead of h.db directly on any blocking query.
func dbCtx(db *gorm.DB, c *gin.Context) *gorm.DB {
	return db.WithContext(c.Request.Context())
}
