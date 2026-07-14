package integration_test

import (
	"net/http"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// ---------------------------------------------------------------------------
// Tool credentials (encrypted at rest)
// ---------------------------------------------------------------------------

func TestToolCredentialCRUD(t *testing.T) {
	token := setupOrgUser(t, "CredOrg", "cred@org.com", "creduser")

	// Create
	resp, data := do("POST", "/api/v1/tool-credentials", map[string]interface{}{
		"tool_name": "smbclient",
		"label":     "Lab SMB Creds",
		"username":  "labuser",
		"password":  "SMB_TEST_PASSWORD_ABC123",
	}, token)
	require.Equal(t, http.StatusCreated, resp.StatusCode, data)
	credID, ok := data["id"].(string)
	require.True(t, ok)
	assert.Equal(t, "smbclient", data["tool_name"])
	// Secret must NOT be returned in response (encrypted at rest) — only a
	// has_secret boolean is exposed.
	assert.Equal(t, true, data["has_secret"])
	_, hasPassword := data["password"]
	assert.False(t, hasPassword)

	// List
	resp, data = do("GET", "/api/v1/tool-credentials", nil, token)
	require.Equal(t, http.StatusOK, resp.StatusCode, data)
	creds, ok := data["credentials"].([]interface{})
	require.True(t, ok)
	assert.Len(t, creds, 1)
	// Secret must not leak in list either
	first := creds[0].(map[string]interface{})
	_, hasPassword = first["password"]
	assert.False(t, hasPassword)

	// Delete
	resp, _ = do("DELETE", "/api/v1/tool-credentials/"+credID, nil, token)
	assert.Equal(t, http.StatusOK, resp.StatusCode)

	// Confirm deleted
	resp, data = do("GET", "/api/v1/tool-credentials", nil, token)
	require.Equal(t, http.StatusOK, resp.StatusCode)
	creds = data["credentials"].([]interface{})
	assert.Len(t, creds, 0)
}

func TestToolCredentialRequiresAuth(t *testing.T) {
	resp, _ := do("GET", "/api/v1/tool-credentials", nil, "")
	assert.Equal(t, http.StatusUnauthorized, resp.StatusCode)

	resp, _ = do("POST", "/api/v1/tool-credentials", map[string]interface{}{
		"tool_name": "smbclient",
		"label":     "Key",
		"password":  "secret",
	}, "")
	assert.Equal(t, http.StatusUnauthorized, resp.StatusCode)
}

func TestToolCredentialOrgIsolation(t *testing.T) {
	tokenA := setupOrgUser(t, "CredIsoA", "credisoA@org.com", "credisoAuser")
	tokenB := setupOrgUser(t, "CredIsoB", "credisoB@org.com", "credisoBuser")

	// Org A creates a credential
	resp, data := do("POST", "/api/v1/tool-credentials", map[string]interface{}{
		"tool_name": "crackmapexec",
		"label":     "Org A Key",
		"username":  "orgauser",
		"password":  "CME_TEST_PASSWORD_ORG_A",
	}, tokenA)
	require.Equal(t, http.StatusCreated, resp.StatusCode, data)

	// Org B sees no credentials
	resp, data = do("GET", "/api/v1/tool-credentials", nil, tokenB)
	require.Equal(t, http.StatusOK, resp.StatusCode)
	creds := data["credentials"].([]interface{})
	assert.Len(t, creds, 0)
}

// ---------------------------------------------------------------------------
// Cloud credentials
// ---------------------------------------------------------------------------

func TestCloudCredentialRequiresAuth(t *testing.T) {
	resp, _ := do("GET", "/api/v1/cloud-credentials", nil, "")
	assert.Equal(t, http.StatusUnauthorized, resp.StatusCode)
}

func TestCloudCredentialListEmpty(t *testing.T) {
	token := setupOrgUser(t, "CloudCredOrg", "cloudcred@org.com", "cloudcreduser")
	resp, data := do("GET", "/api/v1/cloud-credentials", nil, token)
	require.Equal(t, http.StatusOK, resp.StatusCode, data)
	creds, ok := data["data"].([]interface{})
	require.True(t, ok)
	assert.Len(t, creds, 0)
}

// ---------------------------------------------------------------------------
// User management (admin)
// ---------------------------------------------------------------------------

func TestUserListRequiresAdmin(t *testing.T) {
	// viewer/analyst roles shouldn't be able to list all users in practice
	// but for now test it requires auth at minimum
	resp, _ := do("GET", "/api/v1/users", nil, "")
	assert.Equal(t, http.StatusUnauthorized, resp.StatusCode)
}

func TestUserListAndCreate(t *testing.T) {
	token := setupOrgUser(t, "UserMgmtOrg", "usermgmt@org.com", "usermgmtadmin")

	// List users — should have 1 (the admin)
	resp, data := do("GET", "/api/v1/users", nil, token)
	require.Equal(t, http.StatusOK, resp.StatusCode, data)
	users, ok := data["data"].([]interface{})
	require.True(t, ok)
	assert.Len(t, users, 1)

	// Create another user in same org
	resp, data = do("POST", "/api/v1/users", map[string]interface{}{
		"email":      "analyst@usermgmt.com",
		"username":   "analyst1",
		"password":   "Password123!",
		"first_name": "Ana",
		"last_name":  "Lyst",
		"role":       "analyst",
	}, token)
	require.Equal(t, http.StatusCreated, resp.StatusCode, data)
	userID := data["id"].(string)

	// List should now have 2
	resp, data = do("GET", "/api/v1/users", nil, token)
	require.Equal(t, http.StatusOK, resp.StatusCode)
	users = data["data"].([]interface{})
	assert.Len(t, users, 2)

	// Delete the new user
	resp, _ = do("DELETE", "/api/v1/users/"+userID, nil, token)
	assert.Equal(t, http.StatusOK, resp.StatusCode)

	// Back to 1
	_, data = do("GET", "/api/v1/users", nil, token)
	users = data["data"].([]interface{})
	assert.Len(t, users, 1)
}
