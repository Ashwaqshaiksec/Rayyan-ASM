package unit_test

import (
	"testing"
	"time"

	"github.com/ShadooowX/rayyan-asm/internal/api/handlers"
	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestWSTicketStore(t *testing.T) {
	store := handlers.NewWSTicketStoreForTest()
	orgID := uuid.New()

	ticket, err := store.Issue(orgID)
	require.NoError(t, err)
	assert.NotEmpty(t, ticket)
	assert.Len(t, ticket, 32) // 16 bytes hex = 32 chars

	// First consume should succeed
	gotOrg, ok := store.Consume(ticket)
	assert.True(t, ok)
	assert.Equal(t, orgID, gotOrg)

	// Second consume of same ticket should fail (single-use)
	_, ok2 := store.Consume(ticket)
	assert.False(t, ok2)
}

func TestWSTicketExpiry(t *testing.T) {
	store := handlers.NewWSTicketStoreForTest()
	orgID := uuid.New()

	ticket, err := store.IssueWithTTL(orgID, -1*time.Second) // already expired
	require.NoError(t, err)

	_, ok := store.Consume(ticket)
	assert.False(t, ok, "expired ticket should be rejected")
}
