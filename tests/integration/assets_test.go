package integration_test

import (
	"net/http"
	"testing"

	"github.com/ShadooowX/rayyan-asm/internal/models"
	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// ---------------------------------------------------------------------------
// Host CRUD
// ---------------------------------------------------------------------------

func TestHostCRUD(t *testing.T) {
	token := setupOrgUser(t, "HostCRUDOrg", "hostcrud@org.com", "hostcruduser")

	// Create
	resp, data := do("POST", "/api/v1/hosts", map[string]interface{}{
		"ip":          "203.0.113.10",
		"environment": "production",
		"status":      "active",
	}, token)
	require.Equal(t, http.StatusCreated, resp.StatusCode, data)
	hostID := data["id"].(string)
	assert.Equal(t, "203.0.113.10", data["ip"])

	// Get
	resp, data = do("GET", "/api/v1/hosts/"+hostID, nil, token)
	require.Equal(t, http.StatusOK, resp.StatusCode)
	assert.Equal(t, hostID, data["id"])

	// List
	resp, data = do("GET", "/api/v1/hosts", nil, token)
	require.Equal(t, http.StatusOK, resp.StatusCode)
	assert.Equal(t, float64(1), data["total"])

	// Update
	resp, data = do("PUT", "/api/v1/hosts/"+hostID, map[string]interface{}{
		"status": "inactive",
	}, token)
	require.Equal(t, http.StatusOK, resp.StatusCode, data)

	// Verify update
	resp, data = do("GET", "/api/v1/hosts/"+hostID, nil, token)
	require.Equal(t, http.StatusOK, resp.StatusCode)
	assert.Equal(t, "inactive", data["status"])

	// Delete
	resp, _ = do("DELETE", "/api/v1/hosts/"+hostID, nil, token)
	assert.Equal(t, http.StatusOK, resp.StatusCode)

	// Confirm gone
	resp, _ = do("GET", "/api/v1/hosts/"+hostID, nil, token)
	assert.Equal(t, http.StatusNotFound, resp.StatusCode)
}

func TestHostRequiresAuth(t *testing.T) {
	resp, _ := do("GET", "/api/v1/hosts", nil, "")
	assert.Equal(t, http.StatusUnauthorized, resp.StatusCode)

	resp, _ = do("POST", "/api/v1/hosts", map[string]interface{}{
		"ip": "10.0.0.1",
	}, "")
	assert.Equal(t, http.StatusUnauthorized, resp.StatusCode)
}

func TestHostDeleteNonExistent(t *testing.T) {
	token := setupOrgUser(t, "HostDelOrg", "hostdel@org.com", "hostdeluser")
	resp, _ := do("DELETE", "/api/v1/hosts/00000000-0000-0000-0000-000000000000", nil, token)
	assert.Equal(t, http.StatusNotFound, resp.StatusCode)
}

func TestHostTagging(t *testing.T) {
	token := setupOrgUser(t, "HostTagOrg", "hosttag@org.com", "hosttaguser")

	resp, data := do("POST", "/api/v1/hosts", map[string]interface{}{
		"ip": "203.0.113.20",
	}, token)
	require.Equal(t, http.StatusCreated, resp.StatusCode, data)
	hostID := data["id"].(string)

	// Bulk tag
	resp, data = do("PUT", "/api/v1/hosts/bulk-tag", map[string]interface{}{
		"ids":    []string{hostID},
		"tags":   []string{"critical", "dmz"},
		"action": "add",
	}, token)
	require.Equal(t, http.StatusOK, resp.StatusCode, data)

	// Verify tags
	resp, data = do("GET", "/api/v1/hosts/"+hostID, nil, token)
	require.Equal(t, http.StatusOK, resp.StatusCode)
	tags, ok := data["tags"].([]interface{})
	require.True(t, ok)
	assert.Contains(t, tags, "critical")
	assert.Contains(t, tags, "dmz")
}

// ---------------------------------------------------------------------------
// Domain + subdomain import
// ---------------------------------------------------------------------------

func TestDomainSubdomainImport(t *testing.T) {
	token := setupOrgUser(t, "SubImportOrg", "subimport@org.com", "subimportuser")

	resp, data := do("POST", "/api/v1/domains", map[string]interface{}{
		"name": "importtest.com",
	}, token)
	require.Equal(t, http.StatusCreated, resp.StatusCode, data)
	domainID := data["id"].(string)

	// Import subdomains
	resp, data = do("POST", "/api/v1/domains/"+domainID+"/import-subdomains", map[string]interface{}{
		"subdomains": []string{"api.importtest.com", "www.importtest.com", "admin.importtest.com"},
	}, token)
	require.Equal(t, http.StatusOK, resp.StatusCode, data)
	assert.Equal(t, float64(3), data["imported"])

	// List subdomains
	resp, data = do("GET", "/api/v1/subdomains?domain_id="+domainID, nil, token)
	require.Equal(t, http.StatusOK, resp.StatusCode, data)
	subs, ok := data["data"].([]interface{})
	require.True(t, ok)
	assert.Len(t, subs, 3)

	// Duplicate import — should not create duplicates
	resp, data = do("POST", "/api/v1/domains/"+domainID+"/import-subdomains", map[string]interface{}{
		"subdomains": []string{"api.importtest.com"},
	}, token)
	require.Equal(t, http.StatusOK, resp.StatusCode, data)

	resp, data = do("GET", "/api/v1/subdomains?domain_id="+domainID, nil, token)
	require.Equal(t, http.StatusOK, resp.StatusCode)
	subs = data["data"].([]interface{})
	assert.Len(t, subs, 3)
}

// ---------------------------------------------------------------------------
// Certificates
// ---------------------------------------------------------------------------

func TestCertificateListRequiresAuth(t *testing.T) {
	resp, _ := do("GET", "/api/v1/certificates", nil, "")
	assert.Equal(t, http.StatusUnauthorized, resp.StatusCode)
}

func TestCertificateListEmpty(t *testing.T) {
	token := setupOrgUser(t, "CertOrg", "cert@org.com", "certuser")
	resp, data := do("GET", "/api/v1/certificates", nil, token)
	require.Equal(t, http.StatusOK, resp.StatusCode, data)
	assert.Equal(t, float64(0), data["total"])
}

// ---------------------------------------------------------------------------
// Services
// ---------------------------------------------------------------------------

func TestServiceListRequiresAuth(t *testing.T) {
	resp, _ := do("GET", "/api/v1/services", nil, "")
	assert.Equal(t, http.StatusUnauthorized, resp.StatusCode)
}

func TestServiceListEmpty(t *testing.T) {
	token := setupOrgUser(t, "SvcOrg", "svc@org.com", "svcuser")
	resp, data := do("GET", "/api/v1/services", nil, token)
	require.Equal(t, http.StatusOK, resp.StatusCode, data)
	assert.Equal(t, float64(0), data["total"])
}

// TestServiceListReturnsSeededRows seeds a Service directly (mirroring what
// a real port scan writes) and confirms GET /services actually returns it —
// the two tests above only ever exercised the empty-list path, so a bug in
// the populated case could have shipped without either one catching it.
func TestServiceListReturnsSeededRows(t *testing.T) {
	token, orgID := setupOrgUserWithID(t, "SvcDataOrg", "svcdata@org.com", "svcdatauser")

	host := models.Host{Base: models.Base{ID: uuid.New()}, OrgID: orgID, IP: "203.0.113.50"}
	require.NoError(t, testDB.Create(&host).Error)

	svc := models.Service{
		Base: models.Base{ID: uuid.New()}, OrgID: orgID, HostID: host.ID,
		Port: 443, Protocol: "tcp", Service: "https", State: "open",
	}
	require.NoError(t, testDB.Create(&svc).Error)

	resp, data := do("GET", "/api/v1/services", nil, token)
	require.Equal(t, http.StatusOK, resp.StatusCode, data)
	assert.Equal(t, float64(1), data["total"], "seeded service should be counted")
	items, ok := data["data"].([]interface{})
	require.True(t, ok)
	require.Len(t, items, 1, "seeded service should be listed")
	row := items[0].(map[string]interface{})
	assert.Equal(t, float64(443), row["port"])
	assert.Equal(t, "https", row["service"])
}

// ---------------------------------------------------------------------------
// Technologies
// ---------------------------------------------------------------------------

func TestTechnologyListEmpty(t *testing.T) {
	token := setupOrgUser(t, "TechOrg", "tech@org.com", "techuser")
	resp, data := do("GET", "/api/v1/technologies", nil, token)
	require.Equal(t, http.StatusOK, resp.StatusCode, data)
	assert.Equal(t, float64(0), data["total"])
}

// TestTechnologyListAndSummaryReturnSeededRows is the technologies analog of
// the services test above, and also covers /technologies/summary — the
// endpoint that previously crashed the whole page for any org with real
// technology rows (it returned {"data": [...]} but the frontend expected a
// plain {category: count} map). This locks that fix in.
func TestTechnologyListAndSummaryReturnSeededRows(t *testing.T) {
	token, orgID := setupOrgUserWithID(t, "TechDataOrg", "techdata@org.com", "techdatauser")

	techs := []models.Technology{
		{Base: models.Base{ID: uuid.New()}, OrgID: orgID, Name: "nginx", Category: "web-server", Confidence: 90},
		{Base: models.Base{ID: uuid.New()}, OrgID: orgID, Name: "React", Category: "javascript-framework", Confidence: 80},
	}
	for _, tc := range techs {
		require.NoError(t, testDB.Create(&tc).Error)
	}

	resp, data := do("GET", "/api/v1/technologies", nil, token)
	require.Equal(t, http.StatusOK, resp.StatusCode, data)
	assert.Equal(t, float64(2), data["total"], "seeded technologies should be counted")
	items, ok := data["data"].([]interface{})
	require.True(t, ok)
	require.Len(t, items, 2, "seeded technologies should be listed")

	sumResp, sumData := do("GET", "/api/v1/technologies/summary", nil, token)
	require.Equal(t, http.StatusOK, sumResp.StatusCode, sumData)
	// sumData must be the flat {category: count} map itself, not
	// {"data": [...]} — Object.entries() on the latter shape is what
	// crashed the frontend page.
	assert.Equal(t, float64(1), sumData["web-server"])
	assert.Equal(t, float64(1), sumData["javascript-framework"])
	_, wrapped := sumData["data"]
	assert.False(t, wrapped, "summary must not be wrapped in a data key")
}

// ---------------------------------------------------------------------------
// Bulk delete hosts
// ---------------------------------------------------------------------------

func TestBulkDeleteHosts(t *testing.T) {
	token := setupOrgUser(t, "BulkDelOrg", "bulkdel@org.com", "bulkdeluser")

	var ids []string
	for _, ip := range []string{"203.0.113.30", "203.0.113.31", "203.0.113.32"} {
		resp, data := do("POST", "/api/v1/hosts", map[string]interface{}{"ip": ip}, token)
		require.Equal(t, http.StatusCreated, resp.StatusCode, data)
		ids = append(ids, data["id"].(string))
	}

	resp, data := do("DELETE", "/api/v1/hosts/bulk", map[string]interface{}{
		"ids": ids,
	}, token)
	require.Equal(t, http.StatusOK, resp.StatusCode, data)
	assert.Equal(t, float64(3), data["deleted"])

	resp, data = do("GET", "/api/v1/hosts", nil, token)
	require.Equal(t, http.StatusOK, resp.StatusCode)
	assert.Equal(t, float64(0), data["total"])
}
