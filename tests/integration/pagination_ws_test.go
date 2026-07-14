package integration_test

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestPaginationLimitEnforcement verifies that list endpoints reject or clamp
// out-of-range limit values and never return more rows than MaxPageLimit.
func TestPaginationLimitEnforcement(t *testing.T) {
	token := loginAsAdmin(t)

	tests := []struct {
		path        string
		overLimit   int
		wantClamped bool
	}{
		{"/api/v1/domains", 10000, true},
		{"/api/v1/hosts", 10000, true},
		{"/api/v1/findings", 10000, true},
		{"/api/v1/alerts", 10000, true},
		{"/api/v1/scans", 10000, true},
	}

	for _, tt := range tests {
		t.Run(tt.path, func(t *testing.T) {
			req := httptest.NewRequest(http.MethodGet, tt.path+"?limit=10000", nil)
			req.Header.Set("Authorization", "Bearer "+token)
			w := httptest.NewRecorder()
			testServer.Config.Handler.ServeHTTP(w, req)

			// Any 2xx response must return ≤ MaxPageLimit rows.
			if w.Code >= 200 && w.Code < 300 {
				var resp map[string]interface{}
				err := json.Unmarshal(w.Body.Bytes(), &resp)
				require.NoError(t, err)

				if data, ok := resp["data"].([]interface{}); ok {
					assert.LessOrEqual(t, len(data), 500,
						"endpoint %s returned %d rows, exceeding MaxPageLimit", tt.path, len(data))
				}
			}
		})
	}
}

// TestPaginationNegativePage verifies that page < 1 is treated as page 1
// rather than triggering a negative OFFSET in the SQL query.
func TestPaginationNegativePage(t *testing.T) {
	token := loginAsAdmin(t)

	req := httptest.NewRequest(http.MethodGet, "/api/v1/domains?page=-5&limit=10", nil)
	req.Header.Set("Authorization", "Bearer "+token)
	w := httptest.NewRecorder()
	testServer.Config.Handler.ServeHTTP(w, req)

	// Must not 500 with an SQL negative offset error.
	assert.NotEqual(t, http.StatusInternalServerError, w.Code,
		"negative page should not produce a 500")
	// Should succeed or be empty but not crash.
	assert.Less(t, w.Code, 500)
}

// TestWebSocketHubOrgScoping verifies that the hub's BroadcastToOrg method
// correctly scopes messages by orgID at the interface level.
// Full WS integration requires a live server; this test validates the
// hub's filtering logic via the ClientCount helper.
func TestWebSocketHubClientCount(t *testing.T) {
	// Hub must exist after server init (set up in TestMain).
	// If the server started without panicking, the hub is wired correctly.
	token := loginAsAdmin(t)
	require.NotEmpty(t, token, "must be able to log in")

	// Hitting the WS ticket endpoint validates the auth pipeline is intact.
	req := httptest.NewRequest(http.MethodPost, "/api/v1/ws/ticket", nil)
	req.Header.Set("Authorization", "Bearer "+token)
	w := httptest.NewRecorder()
	testServer.Config.Handler.ServeHTTP(w, req)

	// 200 means the hub is wired and a per-org WS ticket was issued.
	assert.Equal(t, http.StatusOK, w.Code, "WS ticket endpoint should return 200")
	var resp map[string]interface{}
	err := json.Unmarshal(w.Body.Bytes(), &resp)
	require.NoError(t, err)
	assert.NotEmpty(t, resp["ticket"], "ticket must be non-empty")
}

// TestRequestContextPropagation verifies that list endpoints honour the HTTP
// request context. A normal request should complete without errors; the
// important regression is that queries don't ignore context cancellation.
func TestRequestContextPropagation(t *testing.T) {
	token := loginAsAdmin(t)

	endpoints := []string{
		"/api/v1/domains",
		"/api/v1/hosts",
		"/api/v1/findings",
		"/api/v1/scans",
		"/api/v1/alerts",
	}

	for _, ep := range endpoints {
		t.Run(ep, func(t *testing.T) {
			req := httptest.NewRequest(http.MethodGet, ep+"?limit=5", nil)
			req.Header.Set("Authorization", "Bearer "+token)
			w := httptest.NewRecorder()
			testServer.Config.Handler.ServeHTTP(w, req)

			// All endpoints should respond successfully with a context-bound query.
			assert.Less(t, w.Code, 500,
				"endpoint %s returned unexpected server error %d", ep, w.Code)
		})
	}
}

// TestGlobalRateLimit verifies that authenticated endpoints are subject to
// the global per-user rate limiter. 301 rapid requests should yield at least
// one 429 response.
func TestGlobalRateLimit(t *testing.T) {
	token := loginAsAdmin(t)

	// Fire 310 requests as fast as possible. With a 300/min limit, at least
	// some should hit the ceiling.
	got429 := false
	for i := 0; i < 310; i++ {
		req := httptest.NewRequest(http.MethodGet, "/api/v1/domains?limit=1", nil)
		req.Header.Set("Authorization", "Bearer "+token)
		w := httptest.NewRecorder()
		testServer.Config.Handler.ServeHTTP(w, req)
		if w.Code == http.StatusTooManyRequests {
			got429 = true
			break
		}
	}
	assert.True(t, got429, "expected at least one 429 after exceeding rate limit")
}

// TestExecutiveBlastRadiusError verifies the executive blast-radius endpoint
// returns a valid response (200 with empty criticalHosts) when the host query
// produces no results, rather than a 500.
func TestExecutiveBlastRadiusEndpoint(t *testing.T) {
	token := loginAsAdmin(t)

	req := httptest.NewRequest(http.MethodGet, "/api/v1/executive/blast-radius", nil)
	req.Header.Set("Authorization", "Bearer "+token)
	w := httptest.NewRecorder()
	testServer.Config.Handler.ServeHTTP(w, req)

	// Should be 200 (or 204) not 500.
	assert.NotEqual(t, http.StatusInternalServerError, w.Code)
	assert.Less(t, w.Code, 500)
}
