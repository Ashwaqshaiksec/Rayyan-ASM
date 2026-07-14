package handlers_test

import (
	"encoding/json"
	"net/http/httptest"
	"testing"

	"github.com/ShadooowX/rayyan-asm/internal/api/handlers"
	"github.com/ShadooowX/rayyan-asm/internal/models"
	"github.com/stretchr/testify/require"
	"go.uber.org/zap"
)

func TestFindingList_MultiValueSeverityFilter(t *testing.T) {
	db := newTestDB(t)
	org := seedOrg(t, db)
	user := seedUser(t, db, org.ID)

	for _, f := range []models.Finding{
		{OrgID: org.ID, Title: "f-critical", Severity: "critical", Status: "open"},
		{OrgID: org.ID, Title: "f-high", Severity: "high", Status: "open"},
		{OrgID: org.ID, Title: "f-medium", Severity: "medium", Status: "open"},
		{OrgID: org.ID, Title: "f-low", Severity: "low", Status: "open"},
	} {
		f := f
		require.NoError(t, db.Create(&f).Error)
	}

	h := handlers.NewFindingHandler(db, zap.NewNop().Sugar())

	// Previously severity only accepted a single value ("severity=critical").
	// It must now also accept a comma-separated list and match any of them
	// (an IN clause), which is what a multi-select facet filter needs.
	r := newRouter("GET", "/findings", h.List, &user)
	req := httptest.NewRequest("GET", "/findings?severity=critical,high", nil)
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)

	require.Equal(t, 200, w.Code)
	var resp struct {
		Data []models.Finding `json:"data"`
	}
	require.NoError(t, json.Unmarshal(w.Body.Bytes(), &resp))
	require.Len(t, resp.Data, 2)
	for _, f := range resp.Data {
		if f.Severity != "critical" && f.Severity != "high" {
			t.Errorf("unexpected severity %q returned for severity=critical,high filter", f.Severity)
		}
	}
}

func TestFindingSummary_IncludesCategoryCounts(t *testing.T) {
	db := newTestDB(t)
	org := seedOrg(t, db)
	user := seedUser(t, db, org.ID)

	for _, f := range []models.Finding{
		{OrgID: org.ID, Title: "f1", Severity: "high", Status: "open", Category: "injection"},
		{OrgID: org.ID, Title: "f2", Severity: "medium", Status: "open", Category: "injection"},
		{OrgID: org.ID, Title: "f3", Severity: "low", Status: "open", Category: "misconfiguration"},
	} {
		f := f
		require.NoError(t, db.Create(&f).Error)
	}

	h := handlers.NewFindingHandler(db, zap.NewNop().Sugar())
	r := newRouter("GET", "/findings/summary", h.Summary, &user)
	req := httptest.NewRequest("GET", "/findings/summary", nil)
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)

	require.Equal(t, 200, w.Code)
	var resp struct {
		ByCategory []struct {
			Category string `json:"category"`
			Count    int64  `json:"count"`
		} `json:"by_category"`
	}
	require.NoError(t, json.Unmarshal(w.Body.Bytes(), &resp))

	counts := map[string]int64{}
	for _, c := range resp.ByCategory {
		counts[c.Category] = c.Count
	}
	// This field didn't exist before — the Category facet in the frontend
	// filter bar has nothing to populate its option counts from without it.
	require.Equal(t, int64(2), counts["injection"])
	require.Equal(t, int64(1), counts["misconfiguration"])
}
