package integration_test

import (
	"fmt"
	"net/http"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestRiskScoreAssets(t *testing.T) {
	suffix := fmt.Sprintf("%d", time.Now().UnixNano())
	email := "risk+" + suffix + "@org.com"
	username := "riskuser" + suffix
	resp, data := registerAndVerify(map[string]string{
		"org_name": "RiskOrg" + suffix, "email": email, "username": username,
		"password": "Password123!", "first_name": "Risk", "last_name": "User",
	}, "")
	require.Equal(t, http.StatusCreated, resp.StatusCode, data)
	_, loginData := do("POST", "/api/v1/auth/login", map[string]string{
		"email": email, "password": "Password123!",
	}, "")
	token := loginData["access_token"].(string)

	// no assets yet → empty list, not error
	resp, data = do("GET", "/api/v1/risk/assets", nil, token)
	require.Equal(t, http.StatusOK, resp.StatusCode, data)
	// API may return null or [] for empty sets; both are valid.
	var items []interface{}
	var ok bool
	if raw, exists := data["data"]; exists && raw != nil {
		items, ok = raw.([]interface{})
		_ = ok
	}
	assert.Len(t, items, 0)
	assert.Equal(t, float64(0), data["total"])

	// seed a domain
	resp, data = do("POST", "/api/v1/domains", map[string]interface{}{
		"name": "riskscore-test.com", "status": "active",
	}, token)
	require.Equal(t, http.StatusCreated, resp.StatusCode, data)

	// recompute — runs against seeded domain
	resp, data = do("POST", "/api/v1/risk/recompute", nil, token)
	require.Equal(t, http.StatusOK, resp.StatusCode, data)
	assert.Equal(t, float64(1), data["domains_scored"])

	// assets list now includes the domain
	resp, data = do("GET", "/api/v1/risk/assets?type=domain", nil, token)
	require.Equal(t, http.StatusOK, resp.StatusCode, data)
	items, ok = data["data"].([]interface{})
	require.True(t, ok)
	require.Len(t, items, 1)
	row := items[0].(map[string]interface{})
	assert.Equal(t, "domain", row["asset_type"])
	assert.Equal(t, "riskscore-test.com", row["label"])

	// tier filter — all assets have a tier after recompute
	resp, data = do("GET", "/api/v1/risk/assets?tier=low", nil, token)
	require.Equal(t, http.StatusOK, resp.StatusCode, data)
	_, ok = data["data"].([]interface{})
	require.True(t, ok)
}

func TestRiskScoreTrends(t *testing.T) {
	_, loginData := do("POST", "/api/v1/auth/login", map[string]string{
		"email": "risk@org.com", "password": "Password123!",
	}, "")
	token := loginData["access_token"].(string)

	resp, data := do("GET", "/api/v1/risk/trends?days=7", nil, token)
	require.Equal(t, http.StatusOK, resp.StatusCode, data)
	points, ok := data["data"].([]interface{})
	require.True(t, ok)
	assert.Len(t, points, 7)
}

func TestRiskScoreHeatmap(t *testing.T) {
	_, loginData := do("POST", "/api/v1/auth/login", map[string]string{
		"email": "risk@org.com", "password": "Password123!",
	}, "")
	token := loginData["access_token"].(string)

	resp, data := do("GET", "/api/v1/risk/heatmap", nil, token)
	require.Equal(t, http.StatusOK, resp.StatusCode, data)
	_, ok := data["data"].([]interface{})
	require.True(t, ok)
}

func TestRiskScorePagination(t *testing.T) {
	_, loginData := do("POST", "/api/v1/auth/login", map[string]string{
		"email": "risk@org.com", "password": "Password123!",
	}, "")
	token := loginData["access_token"].(string)

	resp, data := do("GET", "/api/v1/risk/assets?page=1&limit=1", nil, token)
	require.Equal(t, http.StatusOK, resp.StatusCode, data)
	assert.Equal(t, float64(1), data["page"])
	assert.Equal(t, float64(1), data["limit"])
}
