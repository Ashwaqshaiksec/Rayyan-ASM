package handlers_test

import (
	"encoding/json"
	"net/http/httptest"
	"net/url"
	"testing"

	"github.com/ShadooowX/rayyan-asm/internal/api/handlers"
	"github.com/ShadooowX/rayyan-asm/internal/models"
	"github.com/stretchr/testify/require"
	"go.uber.org/zap"
)

func TestSearch_FieldFilterNarrowsResults(t *testing.T) {
	db := newTestDB(t)
	org := seedOrg(t, db)
	user := seedUser(t, db, org.ID)

	for _, f := range []models.Finding{
		{OrgID: org.ID, Title: "sql injection in login", Severity: "critical", Status: "open"},
		{OrgID: org.ID, Title: "sql injection in search", Severity: "low", Status: "open"},
	} {
		f := f
		require.NoError(t, db.Create(&f).Error)
	}

	h := handlers.NewSearchHandler(db, zap.NewNop().Sugar())
	r := newRouter("GET", "/search", h.Search, &user)

	// Previously "sql injection" (free text) would return both findings
	// regardless of severity — there was no way to narrow within a search.
	req := httptest.NewRequest("GET", "/search?q="+url.QueryEscape("severity:critical sql injection"), nil)
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)

	require.Equal(t, 200, w.Code)
	var resp struct {
		Findings []models.Finding `json:"findings"`
	}
	require.NoError(t, json.Unmarshal(w.Body.Bytes(), &resp))
	require.Len(t, resp.Findings, 1)
	require.Equal(t, "sql injection in login", resp.Findings[0].Title)
}

func TestSearch_TypeFilterRestrictsGroups(t *testing.T) {
	db := newTestDB(t)
	org := seedOrg(t, db)
	user := seedUser(t, db, org.ID)

	dom := models.Domain{OrgID: org.ID, Name: "admin.example.com"}
	require.NoError(t, db.Create(&dom).Error)
	f := models.Finding{OrgID: org.ID, Title: "admin panel exposed", Severity: "high", Status: "open"}
	require.NoError(t, db.Create(&f).Error)

	h := handlers.NewSearchHandler(db, zap.NewNop().Sugar())
	r := newRouter("GET", "/search", h.Search, &user)

	// "admin" alone would match both the domain and the finding; type:
	// restricts the search to just one group.
	req := httptest.NewRequest("GET", "/search?q="+url.QueryEscape("type:findings admin"), nil)
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)

	require.Equal(t, 200, w.Code)
	var resp struct {
		Domains  []models.Domain  `json:"domains"`
		Findings []models.Finding `json:"findings"`
	}
	require.NoError(t, json.Unmarshal(w.Body.Bytes(), &resp))
	require.Empty(t, resp.Domains, "domains should be excluded by type:findings")
	require.Len(t, resp.Findings, 1)
}

func TestSuggestions_FieldNameCompletion(t *testing.T) {
	db := newTestDB(t)
	org := seedOrg(t, db)
	user := seedUser(t, db, org.ID)

	h := handlers.NewSearchHandler(db, zap.NewNop().Sugar())
	r := newRouter("GET", "/search/suggestions", h.Suggestions, &user)

	req := httptest.NewRequest("GET", "/search/suggestions?q="+url.QueryEscape("sev"), nil)
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)

	require.Equal(t, 200, w.Code)
	var resp struct {
		Suggestions []string `json:"suggestions"`
	}
	require.NoError(t, json.Unmarshal(w.Body.Bytes(), &resp))
	require.Contains(t, resp.Suggestions, "severity:")
}

func TestSuggestions_FieldValueCompletion(t *testing.T) {
	db := newTestDB(t)
	org := seedOrg(t, db)
	user := seedUser(t, db, org.ID)

	f := models.Finding{OrgID: org.ID, Title: "x", Severity: "critical", Status: "open"}
	require.NoError(t, db.Create(&f).Error)

	h := handlers.NewSearchHandler(db, zap.NewNop().Sugar())
	r := newRouter("GET", "/search/suggestions", h.Suggestions, &user)

	// Once a field prefix is typed, suggestions should offer real values
	// for that field rather than domain names or field names again.
	req := httptest.NewRequest("GET", "/search/suggestions?q="+url.QueryEscape("severity:cr"), nil)
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)

	require.Equal(t, 200, w.Code)
	var resp struct {
		Suggestions []string `json:"suggestions"`
	}
	require.NoError(t, json.Unmarshal(w.Body.Bytes(), &resp))
	require.Contains(t, resp.Suggestions, "severity:critical")
}

func TestSearch_ASNFilterNarrowsHosts(t *testing.T) {
	db := newTestDB(t)
	org := seedOrg(t, db)
	user := seedUser(t, db, org.ID)

	for _, h := range []models.Host{
		{OrgID: org.ID, IP: "1.1.1.1", ASN: "AS13335"},
		{OrgID: org.ID, IP: "8.8.8.8", ASN: "AS15169"},
	} {
		h := h
		require.NoError(t, db.Create(&h).Error)
	}

	h := handlers.NewSearchHandler(db, zap.NewNop().Sugar())
	r := newRouter("GET", "/search", h.Search, &user)

	req := httptest.NewRequest("GET", "/search?q="+url.QueryEscape("asn:AS15169"), nil)
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)

	require.Equal(t, 200, w.Code)
	var resp struct {
		Hosts []models.Host `json:"hosts"`
	}
	require.NoError(t, json.Unmarshal(w.Body.Bytes(), &resp))
	require.Len(t, resp.Hosts, 1)
	require.Equal(t, "8.8.8.8", resp.Hosts[0].IP)
}

func TestSearch_CloudAccountFilterReturnsCloudAssets(t *testing.T) {
	db := newTestDB(t)
	org := seedOrg(t, db)
	user := seedUser(t, db, org.ID)

	for _, a := range []models.CloudAsset{
		{OrgID: org.ID, Provider: "aws", AccountID: "111111111111", ResourceID: "i-abc123", ResourceType: "ec2", Name: "web-1"},
		{OrgID: org.ID, Provider: "aws", AccountID: "222222222222", ResourceID: "i-def456", ResourceType: "ec2", Name: "web-2"},
	} {
		a := a
		require.NoError(t, db.Create(&a).Error)
	}

	h := handlers.NewSearchHandler(db, zap.NewNop().Sugar())
	r := newRouter("GET", "/search", h.Search, &user)

	req := httptest.NewRequest("GET", "/search?q="+url.QueryEscape("cloud_account:111111111111"), nil)
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)

	require.Equal(t, 200, w.Code)
	var resp struct {
		CloudAssets []models.CloudAsset `json:"cloud_assets"`
	}
	require.NoError(t, json.Unmarshal(w.Body.Bytes(), &resp))
	require.Len(t, resp.CloudAssets, 1)
	require.Equal(t, "i-abc123", resp.CloudAssets[0].ResourceID)
}

func TestSuggestions_ASNAndCloudAccountValueCompletion(t *testing.T) {
	db := newTestDB(t)
	org := seedOrg(t, db)
	user := seedUser(t, db, org.ID)

	require.NoError(t, db.Create(&models.Host{OrgID: org.ID, IP: "1.1.1.1", ASN: "AS13335"}).Error)
	require.NoError(t, db.Create(&models.CloudAsset{
		OrgID: org.ID, Provider: "aws", AccountID: "999999999999", ResourceID: "r-1", ResourceType: "s3",
	}).Error)

	h := handlers.NewSearchHandler(db, zap.NewNop().Sugar())
	r := newRouter("GET", "/search/suggestions", h.Suggestions, &user)

	req := httptest.NewRequest("GET", "/search/suggestions?q="+url.QueryEscape("asn:AS133"), nil)
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)
	require.Equal(t, 200, w.Code)
	var resp struct {
		Suggestions []string `json:"suggestions"`
	}
	require.NoError(t, json.Unmarshal(w.Body.Bytes(), &resp))
	require.Contains(t, resp.Suggestions, "asn:AS13335")

	req2 := httptest.NewRequest("GET", "/search/suggestions?q="+url.QueryEscape("cloud_account:9999"), nil)
	w2 := httptest.NewRecorder()
	r.ServeHTTP(w2, req2)
	require.Equal(t, 200, w2.Code)
	var resp2 struct {
		Suggestions []string `json:"suggestions"`
	}
	require.NoError(t, json.Unmarshal(w2.Body.Bytes(), &resp2))
	require.Contains(t, resp2.Suggestions, "cloud_account:999999999999")
}

// TestSearch_NeverReturnsNullArrays guards against a real bug found in
// production behavior: a Go `var x []T` slice that's never populated (e.g.
// because its section's query was skipped entirely for a given query
// shape) stays nil and marshals as JSON `null`, not `[]`. The frontend
// calls `.map()` directly on every one of these fields (in both
// SearchPage's flatten() and CommandPalette's result builder) with no
// `?? []` guard, so a `null` here crashes the results view outright rather
// than just showing "no results" — and it silently only affects
// filter-only queries (no free text), which is exactly the shape of every
// example hint chip the UI suggests (severity:critical, asn:AS15169,
// cloud_account:...). This asserts every result field is always a real
// JSON array, regardless of which entity types actually matched.
func TestSearch_NeverReturnsNullArrays(t *testing.T) {
	db := newTestDB(t)
	org := seedOrg(t, db)
	user := seedUser(t, db, org.ID)

	h := handlers.NewSearchHandler(db, zap.NewNop().Sugar())
	r := newRouter("GET", "/search", h.Search, &user)

	queries := []string{
		"severity:critical", // filters only, no domains/subdomains/technologies match condition
		"asn:AS15169",       // hosts-only filter
		"cloud_account:111111111111",
		"port:443",
		"cve:CVE-2024-0001",
		"nonexistent-free-text-query",
	}

	for _, q := range queries {
		t.Run(q, func(t *testing.T) {
			req := httptest.NewRequest("GET", "/search?q="+url.QueryEscape(q), nil)
			w := httptest.NewRecorder()
			r.ServeHTTP(w, req)
			require.Equal(t, 200, w.Code)

			var raw map[string]json.RawMessage
			require.NoError(t, json.Unmarshal(w.Body.Bytes(), &raw))

			for _, field := range []string{"domains", "hosts", "subdomains", "services", "technologies", "findings", "cloud_assets"} {
				require.NotEqual(t, "null", string(raw[field]),
					"field %q must never be JSON null for query %q — the frontend calls .map() on it directly with no guard", field, q)
			}
		})
	}
}
