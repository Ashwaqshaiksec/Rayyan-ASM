package handlers_test

import (
	"encoding/json"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/ShadooowX/rayyan-asm/internal/api/handlers"
	"github.com/ShadooowX/rayyan-asm/internal/models"
	"github.com/google/uuid"
	"github.com/stretchr/testify/require"
	"go.uber.org/zap"
)

func TestDashboardTrends_IncludesRiskScoreOnDaysWithData(t *testing.T) {
	db := newTestDB(t)
	org := seedOrg(t, db)
	user := seedUser(t, db, org.ID)

	today := time.Now().UTC()
	rh := models.AssetRiskHistory{
		ID: uuid.New(), OrgID: org.ID, AssetType: "host", AssetID: uuid.New(),
		AssetLabel: "1.2.3.4", Score: 80, Tier: "critical", ComputedAt: today,
	}
	require.NoError(t, db.Create(&rh).Error)

	h := handlers.NewDashboardHandler(db, zap.NewNop().Sugar())
	r := newRouter("GET", "/dashboard/trends", h.Trends, &user)
	req := httptest.NewRequest("GET", "/dashboard/trends", nil)
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)

	require.Equal(t, 200, w.Code)
	var resp struct {
		Data []struct {
			Date         string   `json:"date"`
			AvgRiskScore *float64 `json:"avg_risk_score"`
		} `json:"data"`
	}
	require.NoError(t, json.Unmarshal(w.Body.Bytes(), &resp))
	require.Len(t, resp.Data, 30)

	// Previously this endpoint only ever returned hosts/services/alerts
	// counts — there was no way to see whether risk posture was trending
	// up or down over time. Today's point should now carry the score we
	// seeded; most other days should have no data point (nil), not a
	// fabricated zero.
	last := resp.Data[len(resp.Data)-1]
	require.NotNil(t, last.AvgRiskScore, "expected today's point to carry the seeded risk score")
	require.InDelta(t, 80.0, *last.AvgRiskScore, 0.01)

	nilCount := 0
	for _, d := range resp.Data {
		if d.AvgRiskScore == nil {
			nilCount++
		}
	}
	require.Equal(t, 29, nilCount, "days without a risk-scoring run should have a nil point, not a fabricated 0")
}
