package integration_test

import (
	"net/http"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// ---------------------------------------------------------------------------
// Password management
// ---------------------------------------------------------------------------

func TestChangePassword(t *testing.T) {
	token := setupOrgUser(t, "ChangePwOrg", "changepw@org.com", "changepwuser")

	resp, data := do("POST", "/api/v1/auth/change-password", map[string]string{
		"current_password": "Password123!",
		"new_password":     "NewPassword456!",
	}, token)
	require.Equal(t, http.StatusOK, resp.StatusCode, data)

	// old password no longer works
	resp, _ = do("POST", "/api/v1/auth/login", map[string]string{
		"email": "changepw@org.com", "password": "Password123!",
	}, "")
	assert.Equal(t, http.StatusUnauthorized, resp.StatusCode)

	// new password works
	resp, data = do("POST", "/api/v1/auth/login", map[string]string{
		"email": "changepw@org.com", "password": "NewPassword456!",
	}, "")
	require.Equal(t, http.StatusOK, resp.StatusCode, data)
	assert.NotEmpty(t, data["access_token"])
}

func TestChangePasswordWrongCurrent(t *testing.T) {
	token := setupOrgUser(t, "BadPwOrg", "badpw@org.com", "badpwuser")

	resp, data := do("POST", "/api/v1/auth/change-password", map[string]string{
		"current_password": "wrongpassword",
		"new_password":     "NewPassword456!",
	}, token)
	assert.Equal(t, http.StatusUnauthorized, resp.StatusCode, data)
}

func TestChangePasswordRequiresAuth(t *testing.T) {
	resp, _ := do("POST", "/api/v1/auth/change-password", map[string]string{
		"current_password": "Password123!",
		"new_password":     "NewPassword456!",
	}, "")
	assert.Equal(t, http.StatusUnauthorized, resp.StatusCode)
}

// ---------------------------------------------------------------------------
// Profile update
// ---------------------------------------------------------------------------

func TestProfileUpdate(t *testing.T) {
	token := setupOrgUser(t, "ProfileOrg", "profile@org.com", "profileuser")

	resp, data := do("PUT", "/api/v1/auth/me", map[string]interface{}{
		"first_name": "Updated",
		"last_name":  "Name",
	}, token)
	require.Equal(t, http.StatusOK, resp.StatusCode, data)

	// verify via /me
	resp, data = do("GET", "/api/v1/auth/me", nil, token)
	require.Equal(t, http.StatusOK, resp.StatusCode)
	assert.Equal(t, "Updated", data["first_name"])
	assert.Equal(t, "Name", data["last_name"])
}

func TestProfileUpdateRequiresAuth(t *testing.T) {
	resp, _ := do("PUT", "/api/v1/auth/me", map[string]interface{}{
		"first_name": "Hacker",
	}, "")
	assert.Equal(t, http.StatusUnauthorized, resp.StatusCode)
}

// ---------------------------------------------------------------------------
// API key management
// ---------------------------------------------------------------------------

func TestAPIKeyCreateListDelete(t *testing.T) {
	token := setupOrgUser(t, "APIKeyOrg", "apikey@org.com", "apikeyuser")

	// Create
	resp, data := do("POST", "/api/v1/apikeys", map[string]interface{}{
		"name":   "ci-key",
		"scopes": []string{"read"},
	}, token)
	require.Equal(t, http.StatusCreated, resp.StatusCode, data)
	apiKeyObj, ok := data["api_key"].(map[string]interface{})
	require.True(t, ok, data)
	keyID, ok := apiKeyObj["id"].(string)
	require.True(t, ok)
	assert.NotEmpty(t, data["key"]) // raw key returned only on creation

	// List
	resp, data = do("GET", "/api/v1/apikeys", nil, token)
	require.Equal(t, http.StatusOK, resp.StatusCode)
	keys, ok := data["data"].([]interface{})
	require.True(t, ok)
	assert.Len(t, keys, 1)

	// Delete
	resp, _ = do("DELETE", "/api/v1/apikeys/"+keyID, nil, token)
	assert.Equal(t, http.StatusOK, resp.StatusCode)

	// Confirm deleted
	resp, data = do("GET", "/api/v1/apikeys", nil, token)
	require.Equal(t, http.StatusOK, resp.StatusCode)
	keys = data["data"].([]interface{})
	assert.Len(t, keys, 0)
}

func TestAPIKeyRequiresAuth(t *testing.T) {
	resp, _ := do("GET", "/api/v1/apikeys", nil, "")
	assert.Equal(t, http.StatusUnauthorized, resp.StatusCode)
}

// ---------------------------------------------------------------------------
// Token logout / revocation
// ---------------------------------------------------------------------------

func TestLogout(t *testing.T) {
	token := setupOrgUser(t, "LogoutOrg", "logout@org.com", "logoutuser")

	// Verify token works
	resp, _ := do("GET", "/api/v1/auth/me", nil, token)
	require.Equal(t, http.StatusOK, resp.StatusCode)

	// Logout
	resp, _ = do("POST", "/api/v1/auth/logout", nil, token)
	assert.Equal(t, http.StatusOK, resp.StatusCode)
}

// ---------------------------------------------------------------------------
// Org isolation: org A cannot see org B's data
// ---------------------------------------------------------------------------

func TestOrgIsolation(t *testing.T) {
	tokenA := setupOrgUser(t, "OrgIsoA", "isoa@org.com", "isouserA")
	tokenB := setupOrgUser(t, "OrgIsoB", "isob@org.com", "isouserB")

	// Org A creates a domain
	resp, data := do("POST", "/api/v1/domains", map[string]interface{}{
		"name": "orga-secret.com",
	}, tokenA)
	require.Equal(t, http.StatusCreated, resp.StatusCode, data)
	domainID := data["id"].(string)

	// Org B cannot access it
	resp, _ = do("GET", "/api/v1/domains/"+domainID, nil, tokenB)
	assert.Equal(t, http.StatusNotFound, resp.StatusCode)

	// Org B cannot delete it
	resp, _ = do("DELETE", "/api/v1/domains/"+domainID, nil, tokenB)
	assert.Equal(t, http.StatusNotFound, resp.StatusCode)

	// Domain still exists for Org A
	resp, _ = do("GET", "/api/v1/domains/"+domainID, nil, tokenA)
	assert.Equal(t, http.StatusOK, resp.StatusCode)
}
