package integration_test

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"testing"

	"github.com/ShadooowX/rayyan-asm/internal/api"
	"github.com/ShadooowX/rayyan-asm/internal/api/websocket"
	"github.com/ShadooowX/rayyan-asm/internal/config"
	"github.com/ShadooowX/rayyan-asm/internal/database"
	"github.com/ShadooowX/rayyan-asm/internal/models"
	"github.com/ShadooowX/rayyan-asm/internal/queue"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/zap"
	"gorm.io/gorm"
)

var testServer *httptest.Server
var testDB *gorm.DB

func TestMain(m *testing.M) {
	cfg := &config.Config{
		App: config.AppConfig{
			Name:        "Rayyan ASM Test",
			Version:     "test",
			Environment: "test",
		},
		Server: config.ServerConfig{
			Host:           "localhost",
			Port:           8081,
			AllowedOrigins: []string{"http://localhost:5173"},
		},
		Database: config.DatabaseConfig{
			Driver:   "sqlite",
			FilePath: ":memory:",
		},
		Redis: config.RedisConfig{Enabled: false},
		Queue: config.QueueConfig{Workers: 2, BufferSize: 10},
		Auth: config.AuthConfig{
			JWTSecret:     "test-secret-key-at-least-32-chars!!",
			JWTExpiry:     86400 * 1e9,
			RefreshExpiry: 604800 * 1e9,
			BcryptCost:    4,                                  // fast for tests
			CredentialKey: "test-credential-key-32-bytes-ok!", // exactly 32 bytes
		},
		Log: config.LogConfig{Level: "error", Format: "console"},
	}

	db, err := database.New(cfg.Database)
	if err != nil {
		panic(err)
	}
	testDB = db
	if err := database.Migrate(db); err != nil {
		panic(err)
	}

	log := zap.NewNop().Sugar()
	jobQueue := queue.New(nil, cfg.Queue)
	hub := websocket.NewHub()
	go hub.Run()
	router := api.NewRouter(cfg, db, nil, jobQueue, hub, log)

	testServer = httptest.NewServer(router)
	defer testServer.Close()

	os.Exit(m.Run())
}

func do(method, path string, body interface{}, token string) (*http.Response, map[string]interface{}) {
	var buf bytes.Buffer
	if body != nil {
		_ = json.NewEncoder(&buf).Encode(body)
	}

	req, _ := http.NewRequest(method, testServer.URL+path, &buf)
	req.Header.Set("Content-Type", "application/json")
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}

	resp, _ := http.DefaultClient.Do(req)
	var data map[string]interface{}
	_ = json.NewDecoder(resp.Body).Decode(&data)
	_ = resp.Body.Close()
	return resp, data
}

// doList is like do, but for list endpoints that return a bare JSON array
// (e.g. []models.Project) rather than a {"data": [...]} wrapper.
func doList(method, path string, body interface{}, token string) (*http.Response, []interface{}) {
	var buf bytes.Buffer
	if body != nil {
		_ = json.NewEncoder(&buf).Encode(body)
	}

	req, _ := http.NewRequest(method, testServer.URL+path, &buf)
	req.Header.Set("Content-Type", "application/json")
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}

	resp, _ := http.DefaultClient.Do(req)
	var data []interface{}
	_ = json.NewDecoder(resp.Body).Decode(&data)
	_ = resp.Body.Close()
	return resp, data
}

// registerAndVerify registers a user and immediately sets email_verified = true
// so integration tests are not blocked by the email verification gate.
func registerAndVerify(payload map[string]string, _ ...string) (*http.Response, map[string]interface{}) {
	resp, data := do("POST", "/api/v1/auth/register", payload, "")
	if resp.StatusCode == http.StatusCreated {
		var user models.User
		testDB.Where("email = ?", payload["email"]).First(&user)
		testDB.Model(&user).Update("email_verified", true)
	}
	return resp, data
}

func TestHealthEndpoint(t *testing.T) {
	resp, data := do("GET", "/health", nil, "")
	assert.Equal(t, http.StatusOK, resp.StatusCode)
	assert.Equal(t, "ok", data["status"])
}

func TestRegisterAndLogin(t *testing.T) {
	// Register
	resp, data := registerAndVerify(map[string]string{
		"org_name":   "Test Org",
		"email":      "admin@testorg.com",
		"username":   "testadmin",
		"password":   "SecurePassword123!",
		"first_name": "Test",
		"last_name":  "Admin",
	}, "")
	require.Equal(t, http.StatusCreated, resp.StatusCode, data)
	assert.NotEmpty(t, data["org_id"])
	assert.NotEmpty(t, data["user_id"])

	// Login
	resp, data = do("POST", "/api/v1/auth/login", map[string]string{
		"email":    "admin@testorg.com",
		"password": "SecurePassword123!",
	}, "")
	require.Equal(t, http.StatusOK, resp.StatusCode, data)
	assert.NotEmpty(t, data["access_token"])
	assert.NotEmpty(t, data["refresh_token"])

	token := data["access_token"].(string)

	// Me
	resp, data = do("GET", "/api/v1/auth/me", nil, token)
	require.Equal(t, http.StatusOK, resp.StatusCode)
	assert.Equal(t, "admin@testorg.com", data["email"])
}

func TestLoginWrongPassword(t *testing.T) {
	// Register fresh user
	registerAndVerify(map[string]string{
		"org_name": "Org2", "email": "user2@org2.com", "username": "user2org2",
		"password": "Password123!", "first_name": "User", "last_name": "Two",
	}, "")

	resp, _ := do("POST", "/api/v1/auth/login", map[string]string{
		"email": "user2@org2.com", "password": "wrongpassword",
	}, "")
	assert.Equal(t, http.StatusUnauthorized, resp.StatusCode)
}

func TestProtectedRouteRequiresAuth(t *testing.T) {
	resp, _ := do("GET", "/api/v1/dashboard", nil, "")
	assert.Equal(t, http.StatusUnauthorized, resp.StatusCode)
}

func TestDomainCRUD(t *testing.T) {
	// Setup: register and login
	regResp, regData := registerAndVerify(map[string]string{
		"org_name": "DomainTestOrg", "email": "domaintest@org.com", "username": "domaintest",
		"password": "Password123!", "first_name": "Domain", "last_name": "Test",
	}, "")
	require.Equal(t, http.StatusCreated, regResp.StatusCode, regData)
	_, loginData := do("POST", "/api/v1/auth/login", map[string]string{
		"email": "domaintest@org.com", "password": "Password123!",
	}, "")
	token := loginData["access_token"].(string)

	// Create domain
	resp, data := do("POST", "/api/v1/domains", map[string]interface{}{
		"name":        "example.com",
		"environment": "production",
		"status":      "active",
	}, token)
	require.Equal(t, http.StatusCreated, resp.StatusCode, data)
	assert.Equal(t, "example.com", data["name"])
	domainID := data["id"].(string)

	// Get domain
	resp, data = do("GET", "/api/v1/domains/"+domainID, nil, token)
	require.Equal(t, http.StatusOK, resp.StatusCode)
	assert.Equal(t, domainID, data["id"])

	// List domains
	resp, data = do("GET", "/api/v1/domains", nil, token)
	require.Equal(t, http.StatusOK, resp.StatusCode)
	assert.NotNil(t, data["data"])
	assert.Equal(t, float64(1), data["total"])

	// Delete domain
	resp, _ = do("DELETE", "/api/v1/domains/"+domainID, nil, token)
	assert.Equal(t, http.StatusOK, resp.StatusCode)
}

func TestDashboardSummary(t *testing.T) {
	regResp, regData := registerAndVerify(map[string]string{
		"org_name": "DashOrg", "email": "dash@org.com", "username": "dashuser",
		"password": "Password123!", "first_name": "Dash", "last_name": "User",
	}, "")
	require.Equal(t, http.StatusCreated, regResp.StatusCode, regData)
	_, loginData := do("POST", "/api/v1/auth/login", map[string]string{
		"email": "dash@org.com", "password": "Password123!",
	}, "")
	token := loginData["access_token"].(string)

	resp, data := do("GET", "/api/v1/dashboard", nil, token)
	require.Equal(t, http.StatusOK, resp.StatusCode)
	assert.Contains(t, data, "domains")
	assert.Contains(t, data, "hosts")
	assert.Contains(t, data, "services")
	assert.Contains(t, data, "open_alerts")
}

func TestSearch(t *testing.T) {
	regResp, regData := registerAndVerify(map[string]string{
		"org_name": "SearchOrg", "email": "search@org.com", "username": "searchuser",
		"password": "Password123!", "first_name": "Search", "last_name": "User",
	}, "")
	require.Equal(t, http.StatusCreated, regResp.StatusCode, regData)
	_, loginData := do("POST", "/api/v1/auth/login", map[string]string{
		"email": "search@org.com", "password": "Password123!",
	}, "")
	token := loginData["access_token"].(string)

	resp, data := do("GET", "/api/v1/search?q=example", nil, token)
	require.Equal(t, http.StatusOK, resp.StatusCode)
	assert.Contains(t, data, "domains")
	assert.Contains(t, data, "hosts")
}

func TestRiskScoring(t *testing.T) {
	regResp, regData := registerAndVerify(map[string]string{
		"org_name": "RiskOrg", "email": "risk@org.com", "username": "riskuser",
		"password": "Password123!", "first_name": "Risk", "last_name": "User",
	}, "")
	require.Equal(t, http.StatusCreated, regResp.StatusCode, regData)
	_, loginData := do("POST", "/api/v1/auth/login", map[string]string{
		"email": "risk@org.com", "password": "Password123!",
	}, "")
	token := loginData["access_token"].(string)

	// Empty list
	resp, data := do("GET", "/api/v1/risk/assets", nil, token)
	require.Equal(t, http.StatusOK, resp.StatusCode, data)
	assert.Equal(t, float64(0), data["total"])

	// Create host
	resp, data = do("POST", "/api/v1/hosts", map[string]interface{}{
		"ip": "198.51.100.7", "environment": "production",
	}, token)
	require.Equal(t, http.StatusCreated, resp.StatusCode, data)

	// Recompute
	resp, data = do("POST", "/api/v1/risk/recompute", nil, token)
	require.Equal(t, http.StatusOK, resp.StatusCode, data)
	assert.Equal(t, float64(1), data["hosts_scored"])

	// List assets
	resp, data = do("GET", "/api/v1/risk/assets?type=host", nil, token)
	require.Equal(t, http.StatusOK, resp.StatusCode, data)
	assert.Equal(t, float64(1), data["total"])

	// Trends
	resp, data = do("GET", "/api/v1/risk/trends?days=7", nil, token)
	require.Equal(t, http.StatusOK, resp.StatusCode, data)
	trendPoints, ok := data["data"].([]interface{})
	require.True(t, ok)
	assert.Len(t, trendPoints, 7)

	// Heatmap
	resp, data = do("GET", "/api/v1/risk/heatmap", nil, token)
	require.Equal(t, http.StatusOK, resp.StatusCode, data)
	assert.Contains(t, data, "data")
}

func TestRefreshToken(t *testing.T) {
	regResp, regData := registerAndVerify(map[string]string{
		"org_name": "RefreshOrg", "email": "refresh@org.com", "username": "refreshuser",
		"password": "Password123!", "first_name": "Refresh", "last_name": "User",
	}, "")
	require.Equal(t, http.StatusCreated, regResp.StatusCode, regData)

	loginResp, loginData := do("POST", "/api/v1/auth/login", map[string]string{
		"email": "refresh@org.com", "password": "Password123!",
	}, "")
	require.Equal(t, http.StatusOK, loginResp.StatusCode, loginData)
	refreshToken := loginData["refresh_token"].(string)

	resp, data := do("POST", "/api/v1/auth/refresh", map[string]string{
		"refresh_token": refreshToken,
	}, "")
	require.Equal(t, http.StatusOK, resp.StatusCode)
	assert.NotEmpty(t, data["access_token"])
}

func TestAssetCorrelation(t *testing.T) {
	regResp, regData := registerAndVerify(map[string]string{
		"org_name": "CorrelationOrg", "email": "correlation@org.com", "username": "correlationuser",
		"password": "Password123!", "first_name": "Correlation", "last_name": "User",
	}, "")
	require.Equal(t, http.StatusCreated, regResp.StatusCode, regData)
	_, loginData := do("POST", "/api/v1/auth/login", map[string]string{
		"email": "correlation@org.com", "password": "Password123!",
	}, "")
	token := loginData["access_token"].(string)

	resp, data := do("POST", "/api/v1/domains", map[string]interface{}{
		"name": "correlate.com",
	}, token)
	require.Equal(t, http.StatusCreated, resp.StatusCode, data)
	domainID := data["id"].(string)

	resp, data = do("POST", "/api/v1/domains/"+domainID+"/import-subdomains", map[string]interface{}{
		"subdomains": []string{"app.correlate.com"},
	}, token)
	require.Equal(t, http.StatusOK, resp.StatusCode, data)

	resp, data = do("GET", "/api/v1/subdomains", nil, token)
	require.Equal(t, http.StatusOK, resp.StatusCode, data)
	subs, ok := data["data"].([]interface{})
	require.True(t, ok)
	require.Len(t, subs, 1)
	subID := subs[0].(map[string]interface{})["id"].(string)

	resp, data = do("POST", "/api/v1/correlation/rebuild", nil, token)
	require.Equal(t, http.StatusOK, resp.StatusCode, data)
	assert.Equal(t, float64(1), data["edges_built"])

	resp, data = do("GET", "/api/v1/correlation/graph?type=domain&id="+domainID, nil, token)
	require.Equal(t, http.StatusOK, resp.StatusCode, data)
	nodes, ok := data["nodes"].([]interface{})
	require.True(t, ok)
	assert.Len(t, nodes, 2)

	resp, data = do("GET", "/api/v1/correlation/related/domain/"+domainID, nil, token)
	require.Equal(t, http.StatusOK, resp.StatusCode, data)
	related, ok := data["data"].([]interface{})
	require.True(t, ok)
	require.Len(t, related, 1)
	first := related[0].(map[string]interface{})
	assert.Equal(t, "child", first["direction"])

	resp, data = do("GET", "/api/v1/correlation/exposure-path?from_type=domain&from_id="+domainID+"&to_type=subdomain&to_id="+subID, nil, token)
	require.Equal(t, http.StatusOK, resp.StatusCode, data)
	assert.Equal(t, true, data["found"])
	path, ok := data["data"].([]interface{})
	require.True(t, ok)
	assert.Len(t, path, 2)
}

func TestChangeDetection(t *testing.T) {
	regResp, regData := registerAndVerify(map[string]string{
		"org_name": "ChangeOrg", "email": "changedetect@org.com", "username": "changedetectuser",
		"password": "Password123!", "first_name": "Change", "last_name": "User",
	}, "")
	require.Equal(t, http.StatusCreated, regResp.StatusCode, regData)
	_, loginData := do("POST", "/api/v1/auth/login", map[string]string{
		"email": "changedetect@org.com", "password": "Password123!",
	}, "")
	token := loginData["access_token"].(string)

	resp, data := do("POST", "/api/v1/domains", map[string]interface{}{
		"name": "watched.com", "status": "active",
	}, token)
	require.Equal(t, http.StatusCreated, resp.StatusCode, data)
	domainID := data["id"].(string)

	resp, data = do("POST", "/api/v1/changes/run", nil, token)
	require.Equal(t, http.StatusOK, resp.StatusCode, data)
	assert.Equal(t, float64(1), data["events_found"])

	resp, data = do("GET", "/api/v1/changes/timeline?asset_type=domain", nil, token)
	require.Equal(t, http.StatusOK, resp.StatusCode, data)
	events, ok := data["data"].([]interface{})
	require.True(t, ok)
	require.Len(t, events, 1)
	first := events[0].(map[string]interface{})
	assert.Equal(t, "new", first["change_type"])

	resp, data = do("PUT", "/api/v1/domains/"+domainID, map[string]interface{}{
		"status": "inactive",
	}, token)
	require.Equal(t, http.StatusOK, resp.StatusCode, data)

	resp, data = do("POST", "/api/v1/changes/run", nil, token)
	require.Equal(t, http.StatusOK, resp.StatusCode, data)
	assert.Equal(t, float64(1), data["events_found"])

	resp, data = do("GET", "/api/v1/changes/timeline?change_type=changed", nil, token)
	require.Equal(t, http.StatusOK, resp.StatusCode, data)
	events, ok = data["data"].([]interface{})
	require.True(t, ok)
	require.Len(t, events, 1)
	changed := events[0].(map[string]interface{})
	assert.Equal(t, "status", changed["field"])
	assert.Equal(t, "active", changed["old_value"])
	assert.Equal(t, "inactive", changed["new_value"])
}

func TestAttackPaths(t *testing.T) {
	regResp, regData := registerAndVerify(map[string]string{
		"org_name": "AttackPathOrg", "email": "attackpath@org.com", "username": "attackpathuser",
		"password": "Password123!", "first_name": "Attack", "last_name": "Path",
	}, "")
	require.Equal(t, http.StatusCreated, regResp.StatusCode, regData)
	_, loginData := do("POST", "/api/v1/auth/login", map[string]string{
		"email": "attackpath@org.com", "password": "Password123!",
	}, "")
	token := loginData["access_token"].(string)

	// list with no paths stored → empty list, not error
	resp, data := do("GET", "/api/v1/attack-paths", nil, token)
	require.Equal(t, http.StatusOK, resp.StatusCode, data)
	items, ok := data["data"].([]interface{})
	require.True(t, ok)
	assert.Len(t, items, 0)

	// recompute with no assets → 0 paths, no error
	resp, data = do("POST", "/api/v1/attack-paths/recompute", nil, token)
	require.Equal(t, http.StatusOK, resp.StatusCode, data)
	assert.Equal(t, float64(0), data["paths_found"])
}

func TestReportGenerateAndList(t *testing.T) {
	regResp, regData := registerAndVerify(map[string]string{
		"org_name": "ReportOrg", "email": "report@org.com", "username": "reportuser",
		"password": "Password123!", "first_name": "Report", "last_name": "User",
	})
	require.Equal(t, http.StatusCreated, regResp.StatusCode, regData)
	_, loginData := do("POST", "/api/v1/auth/login", map[string]string{
		"email": "report@org.com", "password": "Password123!",
	}, "")
	token := loginData["access_token"].(string)

	// List reports — should be empty initially
	resp, data := do("GET", "/api/v1/reports", nil, token)
	require.Equal(t, http.StatusOK, resp.StatusCode, data)
	items, ok := data["data"].([]interface{})
	require.True(t, ok)
	assert.Len(t, items, 0)

	// Generate a report
	resp, data = do("POST", "/api/v1/reports", map[string]interface{}{
		"name":   "Test Executive Report",
		"type":   "executive",
		"format": "json",
	}, token)
	require.Equal(t, http.StatusAccepted, resp.StatusCode, data)
	reportID, ok := data["id"].(string)
	require.True(t, ok, "response should include report id")
	assert.Equal(t, "pending", data["status"])

	// List reports — should now have one entry
	resp, data = do("GET", "/api/v1/reports", nil, token)
	require.Equal(t, http.StatusOK, resp.StatusCode, data)
	items, ok = data["data"].([]interface{})
	require.True(t, ok)
	assert.Len(t, items, 1)

	// Get the specific report
	resp, data = do("GET", "/api/v1/reports/"+reportID, nil, token)
	require.Equal(t, http.StatusOK, resp.StatusCode, data)
	assert.Equal(t, reportID, data["id"])

	// Delete the report
	resp, data = do("DELETE", "/api/v1/reports/"+reportID, nil, token)
	require.Equal(t, http.StatusOK, resp.StatusCode, data)

	// Confirm deleted
	resp, data = do("GET", "/api/v1/reports", nil, token)
	require.Equal(t, http.StatusOK, resp.StatusCode, data)
	items = data["data"].([]interface{})
	assert.Len(t, items, 0)
}

func TestReportDownloadNotReady(t *testing.T) {
	regResp, regData := registerAndVerify(map[string]string{
		"org_name": "ReportDLOrg", "email": "reportdl@org.com", "username": "reportdluser",
		"password": "Password123!", "first_name": "Report", "last_name": "DL",
	})
	require.Equal(t, http.StatusCreated, regResp.StatusCode, regData)
	_, loginData := do("POST", "/api/v1/auth/login", map[string]string{
		"email": "reportdl@org.com", "password": "Password123!",
	}, "")
	token := loginData["access_token"].(string)

	// Generate a report (will be in pending state — queue not running)
	resp, data := do("POST", "/api/v1/reports", map[string]interface{}{
		"name":   "Pending Report",
		"type":   "asset_inventory",
		"format": "csv",
	}, token)
	require.Equal(t, http.StatusAccepted, resp.StatusCode, data)
	reportID := data["id"].(string)

	// Attempt download while still pending — expect 409 Conflict
	resp, _ = do("GET", "/api/v1/reports/"+reportID+"/download", nil, token)
	assert.Equal(t, http.StatusConflict, resp.StatusCode)
}

func TestReportRequiresAuth(t *testing.T) {
	resp, _ := do("GET", "/api/v1/reports", nil, "")
	assert.Equal(t, http.StatusUnauthorized, resp.StatusCode)

	resp, _ = do("POST", "/api/v1/reports", map[string]interface{}{
		"name": "Unauthorized", "type": "executive", "format": "json",
	}, "")
	assert.Equal(t, http.StatusUnauthorized, resp.StatusCode)
}

func TestMFAEnableVerifyDisable(t *testing.T) {
	regResp, regData := registerAndVerify(map[string]string{
		"org_name": "MFAOrg", "email": "mfa@org.com", "username": "mfauser",
		"password": "Password123!", "first_name": "MFA", "last_name": "User",
	})
	require.Equal(t, http.StatusCreated, regResp.StatusCode, regData)
	_, loginData := do("POST", "/api/v1/auth/login", map[string]string{
		"email": "mfa@org.com", "password": "Password123!",
	}, "")
	token := loginData["access_token"].(string)

	// Enable MFA — should return a TOTP URI
	resp, data := do("POST", "/api/v1/auth/mfa/enable", nil, token)
	require.Equal(t, http.StatusOK, resp.StatusCode, data)
	totpURI, hasURI := data["otp_uri"].(string)
	require.True(t, hasURI, "enable should return otp_uri")
	assert.Contains(t, totpURI, "otpauth://totp/")

	// Attempt verify with obviously wrong code — should 401
	resp, data = do("POST", "/api/v1/auth/mfa/verify", map[string]string{
		"code": "000000",
	}, token)
	assert.Equal(t, http.StatusUnauthorized, resp.StatusCode, data)

	// Disable MFA with wrong code — should 401
	resp, data = do("POST", "/api/v1/auth/mfa/disable", map[string]string{
		"code": "000000",
	}, token)
	assert.Equal(t, http.StatusUnauthorized, resp.StatusCode, data)
}

func TestWHOISHistoryRequiresAuth(t *testing.T) {
	resp, _ := do("GET", "/api/v1/whois-history?domain=example.com", nil, "")
	assert.Equal(t, http.StatusUnauthorized, resp.StatusCode)
}

func TestWHOISHistoryListAndSnap(t *testing.T) {
	regResp, regData := registerAndVerify(map[string]string{
		"org_name": "WHOISOrg", "email": "whois@org.com", "username": "whoisuser",
		"password": "Password123!", "first_name": "WHOIS", "last_name": "User",
	})
	require.Equal(t, http.StatusCreated, regResp.StatusCode, regData)
	_, loginData := do("POST", "/api/v1/auth/login", map[string]string{
		"email": "whois@org.com", "password": "Password123!",
	}, "")
	token := loginData["access_token"].(string)

	// List with no history → empty list
	resp, data := do("GET", "/api/v1/whois-history?domain=example.com", nil, token)
	require.Equal(t, http.StatusOK, resp.StatusCode, data)
	items, ok := data["data"].([]interface{})
	require.True(t, ok)
	assert.Len(t, items, 0)

	// Snap now — this is the part the widget's "Snap now" button actually
	// calls, and the original version of this test never exercised it.
	// The real RDAP lookup inside will fail in a network-isolated test env
	// (dial error / DNS failure), but SnapWHOIS is written to still create
	// a record either way — whois.FetchData embeds the failure in "raw"
	// rather than returning an error — so the record must still exist and
	// be listable afterward regardless of whether the live lookup itself
	// succeeded.
	snapResp, snapData := do("POST", "/api/v1/whois-history/snap", map[string]string{"domain": "example.com"}, token)
	require.Equal(t, http.StatusCreated, snapResp.StatusCode, snapData)
	assert.Equal(t, "example.com", snapData["domain"])

	resp2, data2 := do("GET", "/api/v1/whois-history?domain=example.com", nil, token)
	require.Equal(t, http.StatusOK, resp2.StatusCode, data2)
	items2, ok := data2["data"].([]interface{})
	require.True(t, ok)
	assert.Len(t, items2, 1, "the snap should have created exactly one listable record")
}
