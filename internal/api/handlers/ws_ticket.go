package handlers

import (
	"crypto/rand"
	"encoding/hex"
	"net/http"
	"sync"
	"time"

	"github.com/ShadooowX/rayyan-asm/internal/api/middleware"
	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
	"go.uber.org/zap"
	"gorm.io/gorm"
)

// wsTicket is a single-use short-lived token exchanged for a WebSocket upgrade.
type wsTicket struct {
	OrgID     uuid.UUID
	ExpiresAt time.Time
}

type WSTicketStore struct {
	mu      sync.Mutex
	tickets map[string]wsTicket
}

var GlobalWSTicketStore = &WSTicketStore{
	tickets: make(map[string]wsTicket),
}

// Issue creates a one-time ticket valid for 30 seconds.
func (s *WSTicketStore) Issue(orgID uuid.UUID) (string, error) {
	raw := make([]byte, 16)
	if _, err := rand.Read(raw); err != nil {
		return "", err
	}
	ticket := hex.EncodeToString(raw)

	s.mu.Lock()
	// Evict expired tickets opportunistically.
	now := time.Now()
	for k, v := range s.tickets {
		if v.ExpiresAt.Before(now) {
			delete(s.tickets, k)
		}
	}
	s.tickets[ticket] = wsTicket{OrgID: orgID, ExpiresAt: now.Add(30 * time.Second)}
	s.mu.Unlock()

	return ticket, nil
}

// Consume validates and single-use-consumes a ticket, returning the OrgID.
func (s *WSTicketStore) Consume(ticket string) (uuid.UUID, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	t, ok := s.tickets[ticket]
	if !ok {
		return uuid.Nil, false
	}
	delete(s.tickets, ticket)
	if t.ExpiresAt.Before(time.Now()) {
		return uuid.Nil, false
	}
	return t.OrgID, true
}

// WSTicketHandler issues short-lived one-time tickets for WebSocket auth.
type WSTicketHandler struct {
	db  *gorm.DB
	log *zap.SugaredLogger
}

func NewWSTicketHandler(db *gorm.DB, log *zap.SugaredLogger) *WSTicketHandler {
	return &WSTicketHandler{db: db, log: log}
}

// Issue POST /ws/ticket  — requires normal JWT auth, returns a 30s one-time ticket.
func (h *WSTicketHandler) Issue(c *gin.Context) {
	user := middleware.GetUser(c)
	if user == nil {
		c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{"error": "unauthorized"})
		return
	}
	ticket, err := GlobalWSTicketStore.Issue(user.OrgID)
	if err != nil {
		h.log.Warnw("ws ticket issue failed", "error", err)
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to issue ticket"})
		return
	}
	c.JSON(http.StatusOK, gin.H{"ticket": ticket, "expires_in": 30})
}

// NewWSTicketStoreForTest creates an isolated WSTicketStore for unit tests.
func NewWSTicketStoreForTest() *WSTicketStore {
	return &WSTicketStore{
		tickets: make(map[string]wsTicket),
	}
}

// IssueWithTTL issues a ticket with a custom TTL; used in tests to verify expiry.
func (s *WSTicketStore) IssueWithTTL(orgID uuid.UUID, ttl time.Duration) (string, error) {
	raw := make([]byte, 16)
	if _, err := rand.Read(raw); err != nil {
		return "", err
	}
	ticket := hex.EncodeToString(raw)
	s.mu.Lock()
	s.tickets[ticket] = wsTicket{OrgID: orgID, ExpiresAt: time.Now().Add(ttl)}
	s.mu.Unlock()
	return ticket, nil
}
