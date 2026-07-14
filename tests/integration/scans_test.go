package integration_test

import (
	"net/http"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// ---------------------------------------------------------------------------
// Scan lifecycle
// ---------------------------------------------------------------------------

func TestScanCreateListGet(t *testing.T) {
	token := setupOrgUser(t, "ScanOrg", "scan@org.com", "scanuser")

	// List empty
	resp, data := do("GET", "/api/v1/scans", nil, token)
	require.Equal(t, http.StatusOK, resp.StatusCode, data)
	assert.Equal(t, float64(0), data["total"])

	// Create scan
	resp, data = do("POST", "/api/v1/scans", map[string]interface{}{
		"name":    "Scan 203.0.113.50",
		"type":    "port",
		"targets": map[string]interface{}{"ips": []string{"203.0.113.50"}},
	}, token)
	require.Equal(t, http.StatusCreated, resp.StatusCode, data)
	scanID, ok := data["id"].(string)
	require.True(t, ok)
	assert.Equal(t, "pending", data["status"])

	// Get scan
	resp, data = do("GET", "/api/v1/scans/"+scanID, nil, token)
	require.Equal(t, http.StatusOK, resp.StatusCode, data)
	assert.Equal(t, scanID, data["id"])

	// List now has one
	resp, data = do("GET", "/api/v1/scans", nil, token)
	require.Equal(t, http.StatusOK, resp.StatusCode)
	assert.Equal(t, float64(1), data["total"])
}

func TestScanCancel(t *testing.T) {
	token := setupOrgUser(t, "ScanCancelOrg", "scancancel@org.com", "scanceluser")

	resp, data := do("POST", "/api/v1/scans", map[string]interface{}{
		"name":    "Scan 203.0.113.51",
		"type":    "port",
		"targets": map[string]interface{}{"ips": []string{"203.0.113.51"}},
	}, token)
	require.Equal(t, http.StatusCreated, resp.StatusCode, data)
	scanID := data["id"].(string)

	// Cancel while pending
	resp, data = do("DELETE", "/api/v1/scans/"+scanID, nil, token)
	require.Equal(t, http.StatusOK, resp.StatusCode, data)

	// Verify cancelled
	resp, data = do("GET", "/api/v1/scans/"+scanID, nil, token)
	require.Equal(t, http.StatusOK, resp.StatusCode)
	assert.Equal(t, "cancelled", data["status"])
}

func TestScanCancelAlreadyCancelled(t *testing.T) {
	token := setupOrgUser(t, "ScanDblCancelOrg", "scandblcancel@org.com", "scandblcanceluser")

	resp, data := do("POST", "/api/v1/scans", map[string]interface{}{
		"name":    "Scan 203.0.113.52",
		"type":    "port",
		"targets": map[string]interface{}{"ips": []string{"203.0.113.52"}},
	}, token)
	require.Equal(t, http.StatusCreated, resp.StatusCode, data)
	scanID := data["id"].(string)

	// First cancel
	resp, _ = do("DELETE", "/api/v1/scans/"+scanID, nil, token)
	require.Equal(t, http.StatusOK, resp.StatusCode)

	// Second cancel — already done, should 400
	resp, _ = do("DELETE", "/api/v1/scans/"+scanID, nil, token)
	assert.Equal(t, http.StatusBadRequest, resp.StatusCode)
}

func TestScanResults(t *testing.T) {
	token := setupOrgUser(t, "ScanResultsOrg", "scanresults@org.com", "scanresultsuser")

	resp, data := do("POST", "/api/v1/scans", map[string]interface{}{
		"name":    "Scan 203.0.113.53",
		"type":    "port",
		"targets": map[string]interface{}{"ips": []string{"203.0.113.53"}},
	}, token)
	require.Equal(t, http.StatusCreated, resp.StatusCode, data)
	scanID := data["id"].(string)

	resp, data = do("GET", "/api/v1/scans/"+scanID+"/results", nil, token)
	require.Equal(t, http.StatusOK, resp.StatusCode, data)
	// No results yet (queue not running), but endpoint must respond
	assert.Equal(t, float64(0), data["total"])
}

func TestScanRequiresAuth(t *testing.T) {
	resp, _ := do("GET", "/api/v1/scans", nil, "")
	assert.Equal(t, http.StatusUnauthorized, resp.StatusCode)

	resp, _ = do("POST", "/api/v1/scans", map[string]interface{}{
		"name": "Unauthorized Scan", "type": "port",
		"targets": map[string]interface{}{"ips": []string{"10.0.0.1"}},
	}, "")
	assert.Equal(t, http.StatusUnauthorized, resp.StatusCode)
}

func TestScanGetNonExistent(t *testing.T) {
	token := setupOrgUser(t, "ScanNEOrg", "scanne@org.com", "scanneuser")
	resp, _ := do("GET", "/api/v1/scans/00000000-0000-0000-0000-000000000000", nil, token)
	assert.Equal(t, http.StatusNotFound, resp.StatusCode)
}

// ---------------------------------------------------------------------------
// Findings
// ---------------------------------------------------------------------------

func TestFindingsRequiresAuth(t *testing.T) {
	resp, _ := do("GET", "/api/v1/findings", nil, "")
	assert.Equal(t, http.StatusUnauthorized, resp.StatusCode)
}

func TestFindingsListEmpty(t *testing.T) {
	token := setupOrgUser(t, "FindingOrg", "finding@org.com", "findinguser")
	resp, data := do("GET", "/api/v1/findings", nil, token)
	require.Equal(t, http.StatusOK, resp.StatusCode, data)
	assert.Equal(t, float64(0), data["total"])
}

func TestFindingCRUD(t *testing.T) {
	token := setupOrgUser(t, "FindingCRUDOrg", "findingcrud@org.com", "findingcruduser")

	resp, data := do("POST", "/api/v1/findings", map[string]interface{}{
		"title":       "Open RDP",
		"severity":    "high",
		"description": "RDP port 3389 exposed to internet",
		"asset_type":  "host",
	}, token)
	require.Equal(t, http.StatusCreated, resp.StatusCode, data)
	findingID := data["id"].(string)
	assert.Equal(t, "open", data["status"])

	// Get
	resp, data = do("GET", "/api/v1/findings/"+findingID, nil, token)
	require.Equal(t, http.StatusOK, resp.StatusCode)
	assert.Equal(t, "Open RDP", data["title"])

	// Update status
	resp, data = do("PUT", "/api/v1/findings/"+findingID, map[string]interface{}{
		"status": "acknowledged",
	}, token)
	require.Equal(t, http.StatusOK, resp.StatusCode, data)

	// Verify
	_, data = do("GET", "/api/v1/findings/"+findingID, nil, token)
	assert.Equal(t, "acknowledged", data["status"])
}

// ---------------------------------------------------------------------------
// Alerts
// ---------------------------------------------------------------------------

func TestAlertsRequiresAuth(t *testing.T) {
	resp, _ := do("GET", "/api/v1/alerts", nil, "")
	assert.Equal(t, http.StatusUnauthorized, resp.StatusCode)
}

func TestAlertsListEmpty(t *testing.T) {
	token := setupOrgUser(t, "AlertOrg", "alert@org.com", "alertuser")
	resp, data := do("GET", "/api/v1/alerts", nil, token)
	require.Equal(t, http.StatusOK, resp.StatusCode, data)
	assert.Equal(t, float64(0), data["total"])
}
