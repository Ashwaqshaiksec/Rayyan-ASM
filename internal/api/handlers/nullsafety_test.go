package handlers_test

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/ShadooowX/rayyan-asm/internal/api/handlers"
	"github.com/ShadooowX/rayyan-asm/internal/models"
	"github.com/ShadooowX/rayyan-asm/internal/modules/riskscore"
	"github.com/stretchr/testify/require"
	"go.uber.org/zap"
)

// TestDiscoveryAssets_AllKeysAlwaysPresent guards against the same bug
// class found in /search: a result key that's only ever set inside a
// conditional branch (`if include(t) { result[t] = ... }`) is entirely
// absent from the JSON response — not just empty — for any request that
// excludes that type via `?type=`. The frontend (DiscoveryPages.tsx)
// already guards this with Array.isArray(), so it wasn't visibly broken,
// but the API contract should hold regardless of any particular caller's
// defensive coding, the same way /search now always sends real arrays.
func TestDiscoveryAssets_AllKeysAlwaysPresent(t *testing.T) {
	db := newTestDB(t)
	org := seedOrg(t, db)
	user := seedUser(t, db, org.ID)

	require.NoError(t, db.Create(&models.Domain{OrgID: org.ID, Name: "example.com"}).Error)

	h := handlers.NewDiscoveryHandler(db, nil, zap.NewNop().Sugar())
	r := newRouter(http.MethodGet, "/discovery/assets", h.Assets, &user)

	// Requesting only "domains" must not cause the other four keys to
	// disappear from the response.
	req := httptest.NewRequest(http.MethodGet, "/discovery/assets?type=domains", nil)
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)
	require.Equal(t, http.StatusOK, w.Code)

	var raw map[string]json.RawMessage
	require.NoError(t, json.Unmarshal(w.Body.Bytes(), &raw))

	for _, key := range []string{"domains", "subdomains", "ips", "certificates", "services"} {
		val, present := raw[key]
		require.True(t, present, "key %q must always be present in the response, even when excluded by ?type=", key)
		require.NotEqual(t, "null", string(val), "key %q must be an empty array, not null, when excluded by ?type=", key)
	}
}

// TestRiskAssets_NeverReturnsNullData guards the same class of bug in
// /risk/assets: `rows` is built by appending across three independent,
// conditionally-run sections (hosts/subdomains/domains); if an org has no
// risk-scored assets of any kind, `rows` previously stayed a nil slice and
// marshaled as `"data": null`. RiskScorePage.tsx already guards this with
// `?? []`, but the endpoint should hold the same "always a real array"
// contract as everything else.
func TestRiskAssets_NeverReturnsNullData(t *testing.T) {
	db := newTestDB(t)
	org := seedOrg(t, db)
	user := seedUser(t, db, org.ID)
	// Deliberately no hosts/subdomains/domains seeded — this org has
	// nothing risk-scored yet, which is the exact condition that produced
	// a nil `rows` slice before the fix.

	engine := riskscore.New(db, zap.NewNop().Sugar())
	h := handlers.NewRiskScoreHandler(db, zap.NewNop().Sugar(), engine)
	r := newRouter(http.MethodGet, "/risk/assets", h.Assets, &user)

	req := httptest.NewRequest(http.MethodGet, "/risk/assets", nil)
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)
	require.Equal(t, http.StatusOK, w.Code)

	var raw map[string]json.RawMessage
	require.NoError(t, json.Unmarshal(w.Body.Bytes(), &raw))
	require.NotEqual(t, "null", string(raw["data"]), "data must be [] when an org has no risk-scored assets, not null")

	var rows []map[string]any
	require.NoError(t, json.Unmarshal(raw["data"], &rows))
	require.Empty(t, rows)
}
