package integration_test

import (
	"archive/zip"
	"bytes"
	"encoding/csv"
	"encoding/json"
	"io"
	"net/http"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/ShadooowX/rayyan-asm/internal/models"
	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// setupOrgUser registers + verifies + logs in a fresh org/user pair and
// returns the access token. Reduces boilerplate across the tests below.
func setupOrgUser(t *testing.T, orgName, email, username string) string {
	t.Helper()
	regResp, regData := registerAndVerify(map[string]string{
		"org_name": orgName, "email": email, "username": username,
		"password": "Password123!", "first_name": "Admin", "last_name": "User",
	})
	require.Equal(t, 201, regResp.StatusCode, regData)
	_, loginData := do("POST", "/api/v1/auth/login", map[string]string{
		"email": email, "password": "Password123!",
	}, "")
	token, ok := loginData["access_token"].(string)
	require.True(t, ok, loginData)
	return token
}

// setupOrgUserWithID is setupOrgUser plus the resulting org's UUID, for
// tests that need to seed rows directly via testDB scoped to that org.
func setupOrgUserWithID(t *testing.T, orgName, email, username string) (string, uuid.UUID) {
	t.Helper()
	token := setupOrgUser(t, orgName, email, username)
	var user models.User
	require.NoError(t, testDB.Where("email = ?", email).First(&user).Error)
	return token, user.OrgID
}

// loginAsAdmin registers a fresh org/admin pair with a unique name/email per
// call (so parallel/repeated invocations across test functions don't collide
// on uniqueness constraints) and returns the resulting access token.
func loginAsAdmin(t *testing.T) string {
	t.Helper()
	suffix := strings.ReplaceAll(uuid.New().String(), "-", "")
	return setupOrgUser(t, "Admin Org "+suffix, "admin-"+suffix+"@example.com", "admin"+suffix)
}

// mustRequest builds an *http.Request against the running test server.
func mustRequest(t *testing.T, method, path string, body interface{}, token string) *http.Request {
	t.Helper()
	var buf bytes.Buffer
	if body != nil {
		require.NoError(t, json.NewEncoder(&buf).Encode(body))
	}
	req, err := http.NewRequest(method, testServer.URL+path, &buf)
	require.NoError(t, err)
	req.Header.Set("Content-Type", "application/json")
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	return req
}

// mustDo executes a raw request and returns the *http.Response unparsed,
// for endpoints that return non-JSON bodies (zip, csv).
func mustDo(t *testing.T, req *http.Request) *http.Response {
	t.Helper()
	resp, err := http.DefaultClient.Do(req)
	require.NoError(t, err)
	return resp
}

// readBackupZipJSON reads a BackupOrg response body (a zip containing one
// JSON file) and returns the raw JSON bytes.
func readBackupZipJSON(t *testing.T, resp *http.Response) []byte {
	t.Helper()
	bodyBytes, err := io.ReadAll(resp.Body)
	require.NoError(t, err)
	zr, err := zip.NewReader(bytes.NewReader(bodyBytes), int64(len(bodyBytes)))
	require.NoError(t, err)
	require.Len(t, zr.File, 1)
	f, err := zr.File[0].Open()
	require.NoError(t, err)
	defer f.Close()
	data, err := io.ReadAll(f)
	require.NoError(t, err)
	return data
}

// json2map decodes raw JSON bytes into a generic map for use as a request
// body in `do`, which JSON-encodes whatever interface{} it's given.
func json2map(raw []byte) map[string]interface{} {
	var m map[string]interface{}
	_ = json.Unmarshal(raw, &m)
	return m
}

func jsonUnmarshal(raw []byte, v interface{}) error {
	return json.Unmarshal(raw, v)
}

// ---------------------------------------------------------------------------
// BackupOrg / RestoreOrg
// ---------------------------------------------------------------------------

func TestBackupAndRestoreOrg(t *testing.T) {
	token := setupOrgUser(t, "BackupOrg", "backup@org.com", "backupuser")

	// Seed some data via the public API.
	resp, data := do("POST", "/api/v1/domains", map[string]interface{}{
		"name": "backupme.com", "status": "active",
	}, token)
	require.Equal(t, 201, resp.StatusCode, data)

	resp, data = do("POST", "/api/v1/hosts", map[string]interface{}{
		"ip": "203.0.113.10", "environment": "production",
	}, token)
	require.Equal(t, 201, resp.StatusCode, data)

	resp, data = do("POST", "/api/v1/findings", map[string]interface{}{
		"title": "Backup test finding", "severity": "high",
	}, token)
	require.Equal(t, 201, resp.StatusCode, data)

	// Backup returns a zip; fetch it via raw HTTP since `do` assumes JSON.
	req := mustRequest(t, "GET", "/api/v1/org/backup", nil, token)
	rawResp := mustDo(t, req)
	defer rawResp.Body.Close()
	require.Equal(t, 200, rawResp.StatusCode)
	assert.Equal(t, "application/zip", rawResp.Header.Get("Content-Type"))

	backupJSON := readBackupZipJSON(t, rawResp)

	var backup struct {
		Domains  []map[string]interface{} `json:"domains"`
		Hosts    []map[string]interface{} `json:"hosts"`
		Findings []map[string]interface{} `json:"findings"`
	}
	require.NoError(t, jsonUnmarshal(backupJSON, &backup))
	require.Len(t, backup.Domains, 1)
	require.Len(t, backup.Hosts, 1)
	require.Len(t, backup.Findings, 1)
	assert.Equal(t, "backupme.com", backup.Domains[0]["name"])

	// Restore into a second, empty org and confirm the counts come back.
	token2 := setupOrgUser(t, "RestoreOrg", "restore@org.com", "restoreuser")
	resp, restoreData := do("POST", "/api/v1/org/restore", json2map(backupJSON), token2)
	require.Equal(t, 200, resp.StatusCode, restoreData)

	restored, ok := restoreData["restored"].(map[string]interface{})
	require.True(t, ok, restoreData)
	assert.Equal(t, float64(1), restored["domains"])
	assert.Equal(t, float64(1), restored["hosts"])
	assert.Equal(t, float64(1), restored["findings"])

	// Domain should now exist under the second org.
	resp, data = do("GET", "/api/v1/domains", nil, token2)
	require.Equal(t, 200, resp.StatusCode)
	assert.Equal(t, float64(1), data["total"])

	// Re-running restore with the same payload must be idempotent (upsert,
	// not duplicate) — counts should reflect "matched existing", not grow.
	resp, restoreData = do("POST", "/api/v1/org/restore", json2map(backupJSON), token2)
	require.Equal(t, 200, resp.StatusCode, restoreData)
	resp, data = do("GET", "/api/v1/domains", nil, token2)
	require.Equal(t, 200, resp.StatusCode)
	assert.Equal(t, float64(1), data["total"], "restore must not duplicate domains on re-run")

	resp, data = do("GET", "/api/v1/hosts", nil, token2)
	require.Equal(t, 200, resp.StatusCode)
	assert.Equal(t, float64(1), data["total"], "restore must not duplicate hosts on re-run")
}

func TestRestoreOrgRejectsInvalidJSON(t *testing.T) {
	token := setupOrgUser(t, "BadRestoreOrg", "badrestore@org.com", "badrestoreuser")
	resp, data := do("PUT", "/api/v1/nope", nil, token) // sanity: unrelated route 404s, not a panic
	assert.Equal(t, 404, resp.StatusCode, data)

	resp, data = do("POST", "/api/v1/org/restore", "not-a-json-object", token)
	assert.Equal(t, 400, resp.StatusCode, data)
}

// ---------------------------------------------------------------------------
// CheckSLABreaches (SLAReport)
// ---------------------------------------------------------------------------

func TestSLAReportDetectsAndDispatchesBreaches(t *testing.T) {
	token := setupOrgUser(t, "SLAOrg", "sla@org.com", "slauser")

	// Finding with an SLA due date in the past -> should be flagged breached.
	resp, data := do("POST", "/api/v1/findings", map[string]interface{}{
		"title": "Overdue finding", "severity": "critical",
	}, token)
	require.Equal(t, 201, resp.StatusCode, data)
	overdueID := data["id"].(string)

	pastDue := time.Now().Add(-48 * time.Hour).UTC().Format(time.RFC3339)
	resp, data = do("PUT", "/api/v1/findings/"+overdueID+"/sla", map[string]string{
		"due_at": pastDue,
	}, token)
	require.Equal(t, 200, resp.StatusCode, data)

	// Finding with a future SLA due date -> should remain on track.
	resp, data = do("POST", "/api/v1/findings", map[string]interface{}{
		"title": "On-track finding", "severity": "medium",
	}, token)
	require.Equal(t, 201, resp.StatusCode, data)
	onTrackID := data["id"].(string)

	futureDue := time.Now().Add(72 * time.Hour).UTC().Format(time.RFC3339)
	resp, data = do("PUT", "/api/v1/findings/"+onTrackID+"/sla", map[string]string{
		"due_at": futureDue,
	}, token)
	require.Equal(t, 200, resp.StatusCode, data)

	// Run the SLA report/check.
	resp, data = do("GET", "/api/v1/findings/sla-report", nil, token)
	require.Equal(t, 200, resp.StatusCode, data)
	assert.Equal(t, float64(1), data["overdue"])
	assert.Equal(t, float64(1), data["ontrack"])

	rows, ok := data["data"].([]interface{})
	require.True(t, ok)
	require.Len(t, rows, 2)

	var sawBreached, sawOnTrack bool
	for _, r := range rows {
		row := r.(map[string]interface{})
		if row["id"] == overdueID {
			sawBreached = true
			assert.Equal(t, true, row["sla_breached"])
		}
		if row["id"] == onTrackID {
			sawOnTrack = true
			assert.Equal(t, false, row["sla_breached"])
		}
	}
	assert.True(t, sawBreached)
	assert.True(t, sawOnTrack)

	// The breach must have persisted sla_breached=true on the Finding row
	// and created an open Alert (the dispatch goroutine is fire-and-forget,
	// but Alert creation itself happens synchronously before it's kicked off).
	var finding models.Finding
	require.NoError(t, testDB.Where("id = ?", overdueID).First(&finding).Error)
	assert.True(t, finding.SLABreached)
	require.NotNil(t, finding.SLABreachAt)

	var alertCount int64
	require.NoError(t, testDB.Model(&models.Alert{}).
		Where("type = ? AND status = ?", "sla_breach", "open").
		Count(&alertCount).Error)
	assert.GreaterOrEqual(t, alertCount, int64(1))

	// Calling the report again must not double-fire: sla_breach_at should
	// not change and no second alert should be created for the same finding.
	var firstBreachAt time.Time
	require.NoError(t, testDB.Model(&models.Finding{}).
		Select("sla_breach_at").Where("id = ?", overdueID).Scan(&firstBreachAt).Error)

	resp, data = do("GET", "/api/v1/findings/sla-report", nil, token)
	require.Equal(t, 200, resp.StatusCode, data)
	assert.Equal(t, float64(1), data["overdue"])

	var secondBreachAt time.Time
	require.NoError(t, testDB.Model(&models.Finding{}).
		Select("sla_breach_at").Where("id = ?", overdueID).Scan(&secondBreachAt).Error)
	assert.Equal(t, firstBreachAt.Unix(), secondBreachAt.Unix())
}

// ---------------------------------------------------------------------------
// ListASNRanges pagination
// ---------------------------------------------------------------------------

func TestListASNRangesPagination(t *testing.T) {
	token, orgID := setupOrgUserWithID(t, "ASNOrg", "asn@org.com", "asnuser")

	// Seed 7 ranges directly (no public create-one route besides ExpandASN,
	// which depends on external network access).
	for i := 0; i < 7; i++ {
		r := models.ASNRange{
			ID:     uuid.New(),
			OrgID:  orgID,
			ASN:    "AS1234",
			ASNOrg: "Test Org",
			CIDR:   "10.0." + strconv.Itoa(i) + ".0/24",
		}
		require.NoError(t, testDB.Create(&r).Error)
	}

	resp, data := do("GET", "/api/v1/asn-ranges?per_page=3&page=1", nil, token)
	require.Equal(t, 200, resp.StatusCode, data)
	assert.Equal(t, float64(7), data["total"])
	assert.Equal(t, float64(1), data["page"])
	assert.Equal(t, float64(3), data["per_page"])
	assert.Equal(t, float64(3), data["pages"]) // ceil(7/3)
	page1, ok := data["data"].([]interface{})
	require.True(t, ok)
	assert.Len(t, page1, 3)

	resp, data = do("GET", "/api/v1/asn-ranges?per_page=3&page=3", nil, token)
	require.Equal(t, 200, resp.StatusCode, data)
	page3, ok := data["data"].([]interface{})
	require.True(t, ok)
	assert.Len(t, page3, 1) // remainder

	// Filter by asn query param.
	resp, data = do("GET", "/api/v1/asn-ranges?asn=AS9999", nil, token)
	require.Equal(t, 200, resp.StatusCode, data)
	assert.Equal(t, float64(0), data["total"])

	// per_page above the 500 ceiling falls back to the default of 50.
	resp, data = do("GET", "/api/v1/asn-ranges?per_page=9999", nil, token)
	require.Equal(t, 200, resp.StatusCode, data)
	assert.Equal(t, float64(50), data["per_page"])
}

// ---------------------------------------------------------------------------
// ListWebhookDeliveries pagination + filters
// ---------------------------------------------------------------------------

func TestListWebhookDeliveriesPaginationAndFilters(t *testing.T) {
	token, orgID := setupOrgUserWithID(t, "WebhookOrg", "webhook@org.com", "webhookuser")

	seedDeliveries := []models.WebhookDelivery{
		{ID: uuid.New(), OrgID: orgID, Channel: "slack", Success: true, SentAt: time.Now().Add(-1 * time.Hour)},
		{ID: uuid.New(), OrgID: orgID, Channel: "slack", Success: false, SentAt: time.Now().Add(-2 * time.Hour)},
		{ID: uuid.New(), OrgID: orgID, Channel: "teams", Success: true, SentAt: time.Now().Add(-3 * time.Hour)},
		{ID: uuid.New(), OrgID: orgID, Channel: "teams", Success: false, SentAt: time.Now().Add(-4 * time.Hour)},
		{ID: uuid.New(), OrgID: orgID, Channel: "email", Success: true, SentAt: time.Now().Add(-5 * time.Hour)},
	}
	for i := range seedDeliveries {
		require.NoError(t, testDB.Create(&seedDeliveries[i]).Error)
	}

	// No filters: all 5, paginated.
	resp, data := do("GET", "/api/v1/webhook-deliveries?per_page=2&page=1", nil, token)
	require.Equal(t, 200, resp.StatusCode, data)
	assert.Equal(t, float64(5), data["total"])
	assert.Equal(t, float64(3), data["pages"]) // ceil(5/2)
	items, ok := data["data"].([]interface{})
	require.True(t, ok)
	assert.Len(t, items, 2)

	// Channel filter.
	resp, data = do("GET", "/api/v1/webhook-deliveries?channel=slack", nil, token)
	require.Equal(t, 200, resp.StatusCode, data)
	assert.Equal(t, float64(2), data["total"])

	// Success filter.
	resp, data = do("GET", "/api/v1/webhook-deliveries?success=true", nil, token)
	require.Equal(t, 200, resp.StatusCode, data)
	assert.Equal(t, float64(3), data["total"])

	resp, data = do("GET", "/api/v1/webhook-deliveries?success=false", nil, token)
	require.Equal(t, 200, resp.StatusCode, data)
	assert.Equal(t, float64(2), data["total"])

	// Combined channel + success filter.
	resp, data = do("GET", "/api/v1/webhook-deliveries?channel=teams&success=false", nil, token)
	require.Equal(t, 200, resp.StatusCode, data)
	assert.Equal(t, float64(1), data["total"])
	rows, ok := data["data"].([]interface{})
	require.True(t, ok)
	require.Len(t, rows, 1)
	assert.Equal(t, "teams", rows[0].(map[string]interface{})["channel"])
}

// ---------------------------------------------------------------------------
// ExportHosts pagination + filters, CSV and JSON
// ---------------------------------------------------------------------------

func TestExportHostsJSONPaginationAndFilters(t *testing.T) {
	token := setupOrgUser(t, "ExportOrg", "export@org.com", "exportuser")

	hosts := []map[string]interface{}{
		{"ip": "198.51.100.1", "status": "active", "country": "US"},
		{"ip": "198.51.100.2", "status": "active", "country": "US"},
		{"ip": "198.51.100.3", "status": "inactive", "country": "DE"},
	}
	for _, h := range hosts {
		resp, data := do("POST", "/api/v1/hosts", h, token)
		require.Equal(t, 201, resp.StatusCode, data)
	}

	// JSON export, no filters, paginated.
	resp, data := do("GET", "/api/v1/hosts/export?format=json&per_page=2&page=1", nil, token)
	require.Equal(t, 200, resp.StatusCode, data)
	assert.Equal(t, "attachment; filename=hosts.json", resp.Header.Get("Content-Disposition"))
	assert.Equal(t, float64(3), data["total"])
	items, ok := data["data"].([]interface{})
	require.True(t, ok)
	assert.Len(t, items, 2)

	// status filter.
	resp, data = do("GET", "/api/v1/hosts/export?format=json&status=inactive", nil, token)
	require.Equal(t, 200, resp.StatusCode, data)
	assert.Equal(t, float64(1), data["total"])

	// country filter.
	resp, data = do("GET", "/api/v1/hosts/export?format=json&country=US", nil, token)
	require.Equal(t, 200, resp.StatusCode, data)
	assert.Equal(t, float64(2), data["total"])
}

func TestExportHostsCSV(t *testing.T) {
	token := setupOrgUser(t, "ExportCSVOrg", "exportcsv@org.com", "exportcsvuser")

	resp, data := do("POST", "/api/v1/hosts", map[string]interface{}{
		"ip": "203.0.113.50", "status": "active", "country": "US",
	}, token)
	require.Equal(t, 201, resp.StatusCode, data)

	req := mustRequest(t, "GET", "/api/v1/hosts/export?format=csv", nil, token)
	rawResp := mustDo(t, req)
	defer rawResp.Body.Close()
	require.Equal(t, 200, rawResp.StatusCode)
	assert.Equal(t, "text/csv", rawResp.Header.Get("Content-Type"))
	assert.Equal(t, "attachment; filename=hosts.csv", rawResp.Header.Get("Content-Disposition"))

	reader := csv.NewReader(rawResp.Body)
	records, err := reader.ReadAll()
	require.NoError(t, err)
	require.GreaterOrEqual(t, len(records), 2) // header + 1 row
	assert.Equal(t, []string{"ip", "hostname", "asn", "asn_org", "country", "os", "status", "first_seen", "last_seen", "tags"}, records[0])
	assert.Equal(t, "203.0.113.50", records[1][0])
}

// ---------------------------------------------------------------------------
// ServiceDiff: host_id UUID validation, host_ref blank rejection,
// host_ref -> host_id resolution
// ---------------------------------------------------------------------------

func TestServiceDiffValidation(t *testing.T) {
	token := setupOrgUser(t, "DiffValidationOrg", "diffvalidation@org.com", "diffvalidationuser")

	// Neither param supplied.
	resp, data := do("GET", "/api/v1/services/diff", nil, token)
	assert.Equal(t, 400, resp.StatusCode, data)
	assert.Contains(t, data["error"], "host_id or host_ref required")

	// host_id not a valid UUID.
	resp, data = do("GET", "/api/v1/services/diff?host_id=not-a-uuid", nil, token)
	assert.Equal(t, 400, resp.StatusCode, data)
	assert.Contains(t, data["error"], "valid UUID")

	// host_ref blank (whitespace only) is rejected.
	resp, data = do("GET", "/api/v1/services/diff?host_ref=%20%20", nil, token)
	assert.Equal(t, 400, resp.StatusCode, data)
	assert.Contains(t, data["error"], "must not be blank")

	// Valid UUID host_id with no data -> empty diff, not an error.
	resp, data = do("GET", "/api/v1/services/diff?host_id="+uuid.New().String(), nil, token)
	require.Equal(t, 200, resp.StatusCode, data)
	assert.Equal(t, float64(0), data["total"])
}

func TestServiceDiffHostRefResolution(t *testing.T) {
	token, orgID := setupOrgUserWithID(t, "DiffResolveOrg", "diffresolve@org.com", "diffresolveuser")

	// Create a host through the API (so it has a known hostname to use as host_ref).
	resp, data := do("POST", "/api/v1/hosts", map[string]interface{}{
		"ip": "192.0.2.55", "hostname": "svc.diffresolve.com", "status": "active",
	}, token)
	require.Equal(t, 201, resp.StatusCode, data)
	hostID := uuid.MustParse(data["id"].(string))

	// Seed a current service keyed by host_id (the normal path) and a
	// service_history row keyed only by host_ref — this is exactly the
	// split-path scenario the host_ref resolution fix exists for.
	current := models.Service{
		Base:     models.Base{ID: uuid.New()},
		OrgID:    orgID,
		HostID:   hostID,
		Port:     443,
		Protocol: "tcp",
		Service:  "https",
		State:    "open",
	}
	require.NoError(t, testDB.Create(&current).Error)

	hist := models.ServiceHistory{
		ID:       uuid.New(),
		OrgID:    orgID,
		HostRef:  "svc.diffresolve.com",
		Port:     22,
		Protocol: "tcp",
		Service:  "ssh",
		State:    "open",
	}
	require.NoError(t, testDB.Create(&hist).Error)

	// Query by host_ref (hostname) only. The handler should resolve
	// host_ref -> host_id, find the current 443 service (appeared, since
	// there's no host_id-keyed history for it) and the disappeared 22
	// service from history — NOT silently miss one side due to the
	// host_id/host_ref split.
	resp, data = do("GET", "/api/v1/services/diff?host_ref=svc.diffresolve.com", nil, token)
	require.Equal(t, 200, resp.StatusCode, data)

	rows, ok := data["data"].([]interface{})
	require.True(t, ok)

	var sawAppeared443, sawDisappeared22 bool
	for _, r := range rows {
		row := r.(map[string]interface{})
		if int(row["port"].(float64)) == 443 && row["change_type"] == "appeared" {
			sawAppeared443 = true
		}
		if int(row["port"].(float64)) == 22 && row["change_type"] == "disappeared" {
			sawDisappeared22 = true
		}
	}
	assert.True(t, sawAppeared443, "expected port 443 to show as appeared via resolved host_id: %+v", rows)
	assert.True(t, sawDisappeared22, "expected port 22 to show as disappeared from host_ref history: %+v", rows)
}

func TestServiceDiffChangedState(t *testing.T) {
	token, orgID := setupOrgUserWithID(t, "DiffChangedOrg", "diffchanged@org.com", "diffchangeduser")

	hostID := uuid.New()
	current := models.Service{
		Base:     models.Base{ID: uuid.New()},
		OrgID:    orgID,
		HostID:   hostID,
		Port:     8080,
		Protocol: "tcp",
		Service:  "http",
		Version:  "2.0",
		State:    "open",
	}
	require.NoError(t, testDB.Create(&current).Error)

	hist := models.ServiceHistory{
		ID:       uuid.New(),
		OrgID:    orgID,
		HostID:   &hostID,
		HostRef:  "irrelevant",
		Port:     8080,
		Protocol: "tcp",
		Service:  "http",
		Version:  "1.0",
		State:    "open",
	}
	require.NoError(t, testDB.Create(&hist).Error)

	resp, data := do("GET", "/api/v1/services/diff?host_id="+hostID.String(), nil, token)
	require.Equal(t, 200, resp.StatusCode, data)
	rows, ok := data["data"].([]interface{})
	require.True(t, ok)
	require.Len(t, rows, 1)
	row := rows[0].(map[string]interface{})
	assert.Equal(t, "changed", row["change_type"])
	assert.Equal(t, float64(8080), row["port"])
}
