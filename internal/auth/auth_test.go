package auth_test

import (
	"testing"
	"time"

	"github.com/ShadooowX/rayyan-asm/internal/auth"
	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func newManager() *auth.Manager {
	return auth.NewManager(
		"test-secret-key-that-is-at-least-32-chars",
		24*time.Hour,
		168*time.Hour,
		10,
	)
}

func TestGenerateAndValidateAccessToken(t *testing.T) {
	mgr := newManager()

	userID := uuid.New()
	orgID := uuid.New()

	token, err := mgr.GenerateAccessToken(userID, orgID, "test@example.com", "admin")
	require.NoError(t, err)
	assert.NotEmpty(t, token)

	claims, err := mgr.ValidateToken(token)
	require.NoError(t, err)
	assert.Equal(t, userID, claims.UserID)
	assert.Equal(t, orgID, claims.OrgID)
	assert.Equal(t, "test@example.com", claims.Email)
	assert.Equal(t, "admin", claims.Role)
	assert.Equal(t, "access", claims.TokenType)
}

func TestGenerateAndValidateRefreshToken(t *testing.T) {
	mgr := newManager()
	userID := uuid.New()
	orgID := uuid.New()

	token, err := mgr.GenerateRefreshToken(userID, orgID, "test@example.com", "viewer")
	require.NoError(t, err)

	claims, err := mgr.ValidateToken(token)
	require.NoError(t, err)
	assert.Equal(t, "refresh", claims.TokenType)
	assert.Equal(t, "viewer", claims.Role)
}

func TestValidateInvalidToken(t *testing.T) {
	mgr := newManager()
	_, err := mgr.ValidateToken("this.is.not.a.valid.token")
	assert.ErrorIs(t, err, auth.ErrInvalidToken)
}

func TestValidateExpiredToken(t *testing.T) {
	mgr := auth.NewManager("test-secret-key-that-is-at-least-32-chars", -1*time.Hour, -1*time.Hour, 10)
	token, err := mgr.GenerateAccessToken(uuid.New(), uuid.New(), "x@x.com", "admin")
	require.NoError(t, err)

	_, err = mgr.ValidateToken(token)
	assert.ErrorIs(t, err, auth.ErrExpiredToken)
}

func TestPasswordHashAndCheck(t *testing.T) {
	mgr := newManager()

	hash, err := mgr.HashPassword("supersecretpassword")
	require.NoError(t, err)
	assert.NotEmpty(t, hash)
	assert.NotEqual(t, "supersecretpassword", hash)

	err = mgr.CheckPassword(hash, "supersecretpassword")
	assert.NoError(t, err)

	err = mgr.CheckPassword(hash, "wrongpassword")
	assert.Error(t, err)
}

func TestGenerateAPIKey(t *testing.T) {
	key, prefix, err := auth.GenerateAPIKey(32)
	require.NoError(t, err)
	assert.NotEmpty(t, key)
	assert.NotEmpty(t, prefix)
	assert.Contains(t, key, "rayyan_")
	assert.True(t, len(key) > 32)

	// Two keys should be different
	key2, _, _ := auth.GenerateAPIKey(32)
	assert.NotEqual(t, key, key2)
}

func TestAPIKeyHashAndCheck(t *testing.T) {
	key, _, _ := auth.GenerateAPIKey(32)

	hash, err := auth.HashAPIKey(key)
	require.NoError(t, err)

	assert.True(t, auth.CheckAPIKey(hash, key))
	assert.False(t, auth.CheckAPIKey(hash, "wrong-key"))
}

func TestTokenWrongSecret(t *testing.T) {
	mgr1 := auth.NewManager("secret-one-32-chars-padded-here!!", 24*time.Hour, 24*time.Hour, 10)
	mgr2 := auth.NewManager("secret-two-32-chars-padded-here!!", 24*time.Hour, 24*time.Hour, 10)

	token, _ := mgr1.GenerateAccessToken(uuid.New(), uuid.New(), "a@b.com", "admin")
	_, err := mgr2.ValidateToken(token)
	assert.Error(t, err)
}
