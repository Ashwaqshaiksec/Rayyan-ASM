package integration_test

import (
	"net/http"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// ---------------------------------------------------------------------------
// Intelligence monitors
// ---------------------------------------------------------------------------

func TestIntelligenceMonitorCRUD(t *testing.T) {
	token := setupOrgUser(t, "IntelOrg", "intel@org.com", "inteluser")

	// List — empty
	resp, data := do("GET", "/api/v1/intelligence/monitors", nil, token)
	require.Equal(t, http.StatusOK, resp.StatusCode, data)
	assert.Equal(t, float64(0), data["total"])

	// Create monitor
	resp, data = do("POST", "/api/v1/intelligence/monitors", map[string]interface{}{
		"target_type": "domain",
		"target":      "example.com",
		"cadence":     "daily",
	}, token)
	require.Equal(t, http.StatusCreated, resp.StatusCode, data)
	monitorID, ok := data["id"].(string)
	require.True(t, ok)
	assert.Equal(t, "daily", data["cadence"])

	// List — now has one
	resp, data = do("GET", "/api/v1/intelligence/monitors", nil, token)
	require.Equal(t, http.StatusOK, resp.StatusCode)
	assert.Equal(t, float64(1), data["total"])

	// Delete
	resp, _ = do("DELETE", "/api/v1/intelligence/monitors/"+monitorID, nil, token)
	assert.Equal(t, http.StatusNoContent, resp.StatusCode)

	_, data = do("GET", "/api/v1/intelligence/monitors", nil, token)
	assert.Equal(t, float64(0), data["total"])
}

func TestIntelligenceMonitorInvalidCadence(t *testing.T) {
	token := setupOrgUser(t, "IntelBadOrg", "intelbad@org.com", "intelbaduser")

	resp, data := do("POST", "/api/v1/intelligence/monitors", map[string]interface{}{
		"target_type": "domain",
		"target":      "example.com",
		"cadence":     "yearly", // invalid
	}, token)
	assert.Equal(t, http.StatusBadRequest, resp.StatusCode, data)
}

func TestIntelligenceMonitorDefaultCadence(t *testing.T) {
	token := setupOrgUser(t, "IntelDefaultOrg", "inteldefault@org.com", "inteldefaultuser")

	// Omit cadence — should default to "daily"
	resp, data := do("POST", "/api/v1/intelligence/monitors", map[string]interface{}{
		"target_type": "domain",
		"target":      "defaultcadence.com",
	}, token)
	require.Equal(t, http.StatusCreated, resp.StatusCode, data)
	assert.Equal(t, "daily", data["cadence"])
}

func TestIntelligenceRequiresAuth(t *testing.T) {
	resp, _ := do("GET", "/api/v1/intelligence/monitors", nil, "")
	assert.Equal(t, http.StatusUnauthorized, resp.StatusCode)
}

func TestIntelligenceResultsEmpty(t *testing.T) {
	token := setupOrgUser(t, "IntelResultsOrg", "intelresults@org.com", "intelresultsuser")
	resp, data := do("GET", "/api/v1/intelligence/results", nil, token)
	require.Equal(t, http.StatusOK, resp.StatusCode, data)
	assert.Equal(t, float64(0), data["total"])
}

// ---------------------------------------------------------------------------
// Exposure center
// ---------------------------------------------------------------------------

func TestExposureCenterRequiresAuth(t *testing.T) {
	resp, _ := do("GET", "/api/v1/exposure/dashboard", nil, "")
	assert.Equal(t, http.StatusUnauthorized, resp.StatusCode)
}

func TestExposureDashboardEmpty(t *testing.T) {
	token := setupOrgUser(t, "ExposureOrg", "exposure@org.com", "exposureuser")
	resp, data := do("GET", "/api/v1/exposure/dashboard", nil, token)
	require.Equal(t, http.StatusOK, resp.StatusCode, data)
	assert.Contains(t, data, "total_scored")
	assert.Equal(t, float64(0), data["total_scored"])
}

func TestExposureRecomputeEmpty(t *testing.T) {
	token := setupOrgUser(t, "ExpRecompOrg", "exprecomp@org.com", "exprecompuser")
	resp, data := do("POST", "/api/v1/exposure/recompute", nil, token)
	require.Equal(t, http.StatusOK, resp.StatusCode, data)
}

// ---------------------------------------------------------------------------
// Discovery
// ---------------------------------------------------------------------------

func TestDiscoveryRequiresAuth(t *testing.T) {
	resp, _ := do("GET", "/api/v1/discovery/jobs", nil, "")
	assert.Equal(t, http.StatusUnauthorized, resp.StatusCode)
}

func TestDiscoveryJobsListEmpty(t *testing.T) {
	token := setupOrgUser(t, "DiscoveryOrg", "discovery@org.com", "discoveryuser")
	resp, data := do("GET", "/api/v1/discovery/jobs", nil, token)
	require.Equal(t, http.StatusOK, resp.StatusCode, data)
	assert.Equal(t, float64(0), data["total"])
}

// ---------------------------------------------------------------------------
// Audit log
// ---------------------------------------------------------------------------

func TestAuditLogRequiresAuth(t *testing.T) {
	resp, _ := do("GET", "/api/v1/audit", nil, "")
	assert.Equal(t, http.StatusUnauthorized, resp.StatusCode)
}

func TestAuditLogRecordsActivity(t *testing.T) {
	token := setupOrgUser(t, "AuditOrg", "audit@org.com", "audituser")

	// Do something auditable
	do("POST", "/api/v1/domains", map[string]interface{}{
		"name": "auditme.com",
	}, token)

	resp, data := do("GET", "/api/v1/audit", nil, token)
	require.Equal(t, http.StatusOK, resp.StatusCode, data)
	entries, ok := data["data"].([]interface{})
	require.True(t, ok)
	assert.Greater(t, len(entries), 0)
}

// ---------------------------------------------------------------------------
// Toolbox
// ---------------------------------------------------------------------------

func TestToolboxRequiresAuth(t *testing.T) {
	resp, _ := do("GET", "/api/v1/toolbox/status", nil, "")
	assert.Equal(t, http.StatusUnauthorized, resp.StatusCode)
}

func TestToolboxStatus(t *testing.T) {
	token := setupOrgUser(t, "ToolboxOrg", "toolbox@org.com", "toolboxuser")
	resp, data := do("GET", "/api/v1/toolbox/status", nil, token)
	require.Equal(t, http.StatusOK, resp.StatusCode, data)
	assert.Contains(t, data, "tools")
}
