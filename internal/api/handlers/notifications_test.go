package handlers_test

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/ShadooowX/rayyan-asm/internal/api/handlers"
	"github.com/ShadooowX/rayyan-asm/internal/models"
	"github.com/google/uuid"
	"github.com/stretchr/testify/require"
	"go.uber.org/zap"
	"gorm.io/gorm"
)

func testCredentialKey() []byte {
	return bytes.Repeat([]byte("k"), 32)
}

// waitForDelivery polls until dispatchOne's background goroutine has
// written a WebhookDelivery row for cfgID, since DispatchTestNotification
// (like DispatchAlertNotifications) fires the actual send in a goroutine
// rather than synchronously.
func waitForDelivery(t *testing.T, db *gorm.DB, cfgID uuid.UUID) {
	t.Helper()
	require.Eventually(t, func() bool {
		var count int64
		db.Model(&models.WebhookDelivery{}).Where("notif_config_id = ?", cfgID).Count(&count)
		return count > 0
	}, 2*time.Second, 10*time.Millisecond, "expected a WebhookDelivery row to be recorded")
}

// ── sendSIEMWithStatus (via DispatchTestNotification, the same path the UI's "Test" button uses) ──

func TestSIEMNotification_SendsWithConfiguredAuthHeader(t *testing.T) {
	handlers.SetNotificationCredentialKey(testCredentialKey())
	defer handlers.SetNotificationCredentialKey(nil)

	var gotHeader, gotAuth string
	var gotBody map[string]any
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotHeader = r.Header.Get("X-Splunk-Token")
		gotAuth = r.Header.Get("Authorization")
		_ = json.NewDecoder(r.Body).Decode(&gotBody)
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	db := newTestDB(t)
	log := zap.NewNop().Sugar()
	org := seedOrg(t, db)

	encToken, err := handlers.EncryptAuthToken("super-secret-token")
	require.NoError(t, err)

	cfg := models.NotificationConfig{
		OrgID:              org.ID,
		Channel:            "siem",
		Name:               "splunk-hec",
		WebhookURL:         srv.URL,
		AuthHeader:         "X-Splunk-Token",
		AuthTokenEncrypted: encToken,
		Active:             true,
	}
	cfg.ID = uuid.New()
	require.NoError(t, db.Create(&cfg).Error)

	alert := &models.Alert{OrgID: org.ID, Type: "test", Severity: "high", Title: "Test Alert", Message: "hello"}
	alert.ID = uuid.New()
	require.NoError(t, db.Create(alert).Error)

	handlers.DispatchTestNotification(db, log, cfg, alert)
	waitForDelivery(t, db, cfg.ID)

	require.Equal(t, "super-secret-token", gotHeader, "expected the decrypted token on the operator-configured header")
	require.Empty(t, gotAuth, "should not also set Authorization when a different header was configured")
	require.Equal(t, "rayyan-asm", gotBody["source"])
	require.Equal(t, "high", gotBody["severity"])

	var delivery models.WebhookDelivery
	require.NoError(t, db.Where("notif_config_id = ?", cfg.ID).First(&delivery).Error)
	require.True(t, delivery.Success)
	require.Equal(t, http.StatusOK, delivery.StatusCode)
}

func TestSIEMNotification_DefaultsToAuthorizationHeader(t *testing.T) {
	handlers.SetNotificationCredentialKey(testCredentialKey())
	defer handlers.SetNotificationCredentialKey(nil)

	var gotAuth string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotAuth = r.Header.Get("Authorization")
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	db := newTestDB(t)
	log := zap.NewNop().Sugar()
	org := seedOrg(t, db)

	encToken, err := handlers.EncryptAuthToken("token-123")
	require.NoError(t, err)

	cfg := models.NotificationConfig{
		OrgID:              org.ID,
		Channel:            "siem",
		Name:               "generic-collector",
		WebhookURL:         srv.URL,
		AuthTokenEncrypted: encToken,
		// AuthHeader intentionally left blank to exercise the default.
		Active: true,
	}
	cfg.ID = uuid.New()
	require.NoError(t, db.Create(&cfg).Error)

	alert := &models.Alert{OrgID: org.ID, Type: "test", Severity: "low", Title: "T", Message: "m"}
	alert.ID = uuid.New()
	require.NoError(t, db.Create(alert).Error)

	handlers.DispatchTestNotification(db, log, cfg, alert)
	waitForDelivery(t, db, cfg.ID)

	require.Equal(t, "token-123", gotAuth)
}

func TestSIEMNotification_MissingWebhookURLFails(t *testing.T) {
	handlers.SetNotificationCredentialKey(testCredentialKey())
	defer handlers.SetNotificationCredentialKey(nil)

	db := newTestDB(t)
	log := zap.NewNop().Sugar()
	org := seedOrg(t, db)

	cfg := models.NotificationConfig{OrgID: org.ID, Channel: "siem", Name: "broken", Active: true}
	cfg.ID = uuid.New()
	require.NoError(t, db.Create(&cfg).Error)

	alert := &models.Alert{OrgID: org.ID, Type: "test", Severity: "low", Title: "T", Message: "m"}
	alert.ID = uuid.New()
	require.NoError(t, db.Create(alert).Error)

	handlers.DispatchTestNotification(db, log, cfg, alert)
	var delivery models.WebhookDelivery
	waitForDelivery(t, db, cfg.ID)
	require.NoError(t, db.Where("notif_config_id = ?", cfg.ID).First(&delivery).Error)
	require.False(t, delivery.Success)
}

// ── Create/Update handler wiring ─────────────────────────────────────────

func TestNotificationHandler_Create_SIEM_RequiresWebhookURL(t *testing.T) {
	db := newTestDB(t)
	log := zap.NewNop().Sugar()
	org := seedOrg(t, db)
	user := seedUser(t, db, org.ID)

	h := handlers.NewNotificationHandler(db, log)
	r := newRouter(http.MethodPost, "/notifications", h.Create, &user)

	body, _ := json.Marshal(map[string]any{"channel": "siem", "name": "no-url"})
	req := httptest.NewRequest(http.MethodPost, "/notifications", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)

	require.Equal(t, http.StatusBadRequest, w.Code)
}

func TestNotificationHandler_Create_SIEM_EncryptsTokenAndRedactsResponse(t *testing.T) {
	handlers.SetNotificationCredentialKey(testCredentialKey())
	defer handlers.SetNotificationCredentialKey(nil)

	db := newTestDB(t)
	log := zap.NewNop().Sugar()
	org := seedOrg(t, db)
	user := seedUser(t, db, org.ID)

	h := handlers.NewNotificationHandler(db, log)
	r := newRouter(http.MethodPost, "/notifications", h.Create, &user)

	body, _ := json.Marshal(map[string]any{
		"channel":     "siem",
		"name":        "splunk",
		"webhook_url": "https://splunk.example.com/services/collector",
		"auth_header": "X-Splunk-Token",
		"auth_token":  "plaintext-secret",
	})
	req := httptest.NewRequest(http.MethodPost, "/notifications", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)

	require.Equal(t, http.StatusCreated, w.Code)

	var resp map[string]any
	require.NoError(t, json.Unmarshal(w.Body.Bytes(), &resp))
	// The encrypted token field is tagged json:"-", so it must never appear
	// in the response at all.
	_, present := resp["AuthTokenEncrypted"]
	require.False(t, present, "auth_token_encrypted must never be returned in the API response")

	var stored models.NotificationConfig
	require.NoError(t, db.Where("org_id = ? AND name = ?", org.ID, "splunk").First(&stored).Error)
	require.NotEmpty(t, stored.AuthTokenEncrypted)
	require.NotEqual(t, "plaintext-secret", stored.AuthTokenEncrypted, "token must be stored encrypted, not plaintext")
}

func TestNotificationHandler_Create_SIEM_WithoutCredentialKeyConfigured(t *testing.T) {
	handlers.SetNotificationCredentialKey(nil)

	db := newTestDB(t)
	log := zap.NewNop().Sugar()
	org := seedOrg(t, db)
	user := seedUser(t, db, org.ID)

	h := handlers.NewNotificationHandler(db, log)
	r := newRouter(http.MethodPost, "/notifications", h.Create, &user)

	body, _ := json.Marshal(map[string]any{
		"channel":     "siem",
		"name":        "splunk",
		"webhook_url": "https://splunk.example.com/services/collector",
		"auth_token":  "plaintext-secret",
	})
	req := httptest.NewRequest(http.MethodPost, "/notifications", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)

	require.Equal(t, http.StatusServiceUnavailable, w.Code)
}
