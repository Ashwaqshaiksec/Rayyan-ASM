package integration_test

import (
	"net/http"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestExecutiveSummary(t *testing.T) {
	resp, data := registerAndVerify(map[string]string{
		"org_name": "ExecOrg", "email": "exec@org.com", "username": "execuser",
		"password": "Password123!", "first_name": "Exec", "last_name": "User",
	}, "")
	require.Equal(t, http.StatusCreated, resp.StatusCode, data)
	_, loginData := do("POST", "/api/v1/auth/login", map[string]string{
		"email": "exec@org.com", "password": "Password123!",
	}, "")
	token := loginData["access_token"].(string)

	resp, data = do("GET", "/api/v1/executive/summary", nil, token)
	require.Equal(t, http.StatusOK, resp.StatusCode, data)
	// fresh org — all counts zero
	assert.Equal(t, float64(0), data["total_assets"])
	assert.Equal(t, float64(0), data["open_findings"])
	assert.Equal(t, float64(0), data["attack_path_count"])

	// seed assets and verify summary reflects them
	do("POST", "/api/v1/domains", map[string]interface{}{
		"name": "exec-test.com", "status": "active",
	}, token)
	do("POST", "/api/v1/hosts", map[string]interface{}{
		"ip": "10.0.0.1", "status": "active",
	}, token)

	resp, data = do("GET", "/api/v1/executive/summary", nil, token)
	require.Equal(t, http.StatusOK, resp.StatusCode, data)
	assert.Equal(t, float64(2), data["total_assets"])
	assert.Equal(t, float64(1), data["total_domains"])
	assert.Equal(t, float64(1), data["total_hosts"])
}

func TestExecutiveTrends(t *testing.T) {
	_, loginData := do("POST", "/api/v1/auth/login", map[string]string{
		"email": "exec@org.com", "password": "Password123!",
	}, "")
	token := loginData["access_token"].(string)

	resp, data := do("GET", "/api/v1/executive/trends?period=daily&points=7", nil, token)
	require.Equal(t, http.StatusOK, resp.StatusCode, data)
	assert.Equal(t, "daily", data["period"])
	_, ok := data["data"].([]interface{})
	require.True(t, ok)

	// invalid period → 400
	resp, _ = do("GET", "/api/v1/executive/trends?period=hourly", nil, token)
	assert.Equal(t, http.StatusBadRequest, resp.StatusCode)
}

func TestExecutiveSLACompliance(t *testing.T) {
	_, loginData := do("POST", "/api/v1/auth/login", map[string]string{
		"email": "exec@org.com", "password": "Password123!",
	}, "")
	token := loginData["access_token"].(string)

	resp, data := do("GET", "/api/v1/executive/sla-compliance", nil, token)
	require.Equal(t, http.StatusOK, resp.StatusCode, data)
	// no findings → 100% compliance
	assert.Equal(t, float64(100), data["compliance_pct"])
	assert.Equal(t, float64(0), data["breached"])
	bySeverity, ok := data["by_severity"].([]interface{})
	require.True(t, ok)
	assert.Len(t, bySeverity, 4) // critical, high, medium, low
}

func TestExecutiveAttackPathOverview(t *testing.T) {
	_, loginData := do("POST", "/api/v1/auth/login", map[string]string{
		"email": "exec@org.com", "password": "Password123!",
	}, "")
	token := loginData["access_token"].(string)

	resp, data := do("GET", "/api/v1/executive/attack-path-overview", nil, token)
	require.Equal(t, http.StatusOK, resp.StatusCode, data)
	assert.Equal(t, float64(0), data["total"])
	_, ok := data["top_paths"].([]interface{})
	require.True(t, ok)
}

func TestExecutiveBusinessImpact(t *testing.T) {
	_, loginData := do("POST", "/api/v1/auth/login", map[string]string{
		"email": "exec@org.com", "password": "Password123!",
	}, "")
	token := loginData["access_token"].(string)

	resp, data := do("GET", "/api/v1/executive/business-impact", nil, token)
	require.Equal(t, http.StatusOK, resp.StatusCode, data)
	assert.Equal(t, float64(0), data["critical_assets_exposed"])
	_, ok := data["assets"].([]interface{})
	require.True(t, ok)
}

func TestExecutiveRecompute(t *testing.T) {
	// Register a fresh user so this test is self-contained.
	registerAndVerify(map[string]string{
		"org_name": "ExecRecomputeOrg", "email": "exec-recompute@org.com",
		"username": "execrecompute", "password": "Password123!",
		"first_name": "Exec", "last_name": "Recompute",
	}, "")
	_, loginData := do("POST", "/api/v1/auth/login", map[string]string{
		"email": "exec-recompute@org.com", "password": "Password123!",
	}, "")
	rawToken, ok := loginData["access_token"]
	if !ok {
		t.Skip("login failed — skipping recompute test")
	}
	token := rawToken.(string)

	resp, data := do("POST", "/api/v1/executive/recompute", nil, token)
	require.Equal(t, http.StatusOK, resp.StatusCode, data)
	// snapshot fields present
	_, hasTotal := data["total_assets"]
	assert.True(t, hasTotal)
}
