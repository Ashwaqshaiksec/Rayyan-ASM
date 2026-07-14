package handlers_test

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/ShadooowX/rayyan-asm/internal/api/handlers"
	dbmodels "github.com/ShadooowX/rayyan-asm/internal/database/models"
	"github.com/ShadooowX/rayyan-asm/internal/models"
	"github.com/ShadooowX/rayyan-asm/internal/modules/toolrunner"
	"github.com/ShadooowX/rayyan-asm/internal/modules/toolrunner/types"
	"github.com/google/uuid"
	"github.com/stretchr/testify/require"
	"go.uber.org/zap"
)

func TestToolHandler_Runs_DoesNotLeakAcrossOrgs(t *testing.T) {
	db := newTestDB(t)
	log := zap.NewNop().Sugar()

	orgA := seedOrg(t, db)
	orgB := seedOrg(t, db)
	userA := seedUser(t, db, orgA.ID)

	// Scan job belonging to org A (the caller's own org).
	scanA := models.ScanJob{
		OrgID:     orgA.ID,
		CreatedBy: userA.ID,
		Name:      "scan-a",
		Type:      "discovery",
		Targets:   models.JSONB{},
	}
	require.NoError(t, db.Create(&scanA).Error)

	// Scan job belonging to org B (a different tenant).
	scanB := models.ScanJob{
		OrgID:     orgB.ID,
		CreatedBy: userA.ID,
		Name:      "scan-b",
		Type:      "discovery",
		Targets:   models.JSONB{},
	}
	require.NoError(t, db.Create(&scanB).Error)

	runA := dbmodels.ToolRunResult{ID: uuid.New(), ScanID: scanA.ID, ToolName: "nmap", ResultCount: 3, ResultData: []byte("[]")}
	require.NoError(t, db.Create(&runA).Error)
	runB := dbmodels.ToolRunResult{ID: uuid.New(), ScanID: scanB.ID, ToolName: "nmap", ResultCount: 7, ResultData: []byte("[]")}
	require.NoError(t, db.Create(&runB).Error)

	registry := types.NewRegistry()
	registry.Register(types.ToolInfo{Name: "nmap", Category: "port"})

	h := handlers.NewToolHandler((*toolrunner.Registry)(registry), nil, db, log)

	r := newRouter(http.MethodGet, "/tools/:name/runs", h.Runs, &userA)
	req := httptest.NewRequest(http.MethodGet, "/tools/nmap/runs", nil)
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)

	require.Equal(t, http.StatusOK, w.Code)

	var resp struct {
		Data []map[string]any `json:"data"`
	}
	require.NoError(t, json.Unmarshal(w.Body.Bytes(), &resp))

	// Org A's admin must only ever see org A's own run, never org B's.
	require.Len(t, resp.Data, 1, "expected exactly one run scoped to the caller's org, got cross-tenant leakage")
	require.Equal(t, scanA.ID.String(), resp.Data[0]["scan_id"])
}
