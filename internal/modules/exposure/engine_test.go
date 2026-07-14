package exposure_test

import (
	"testing"
	"time"

	"github.com/ShadooowX/rayyan-asm/internal/config"
	"github.com/ShadooowX/rayyan-asm/internal/database"
	"github.com/ShadooowX/rayyan-asm/internal/models"
	"github.com/ShadooowX/rayyan-asm/internal/modules/exposure"
	"github.com/google/uuid"
	"github.com/stretchr/testify/require"
	"go.uber.org/zap"
	"gorm.io/gorm"
)

func newTestDB(t *testing.T) *gorm.DB {
	t.Helper()
	db, err := database.New(config.DatabaseConfig{Driver: "sqlite", FilePath: ":memory:"})
	require.NoError(t, err)
	require.NoError(t, database.Migrate(db))
	return db
}

func TestRecomputeOrg_CrownJewelHostWithAttackPathScoresHighOrCritical(t *testing.T) {
	db := newTestDB(t)
	log := zap.NewNop().Sugar()
	engine := exposure.New(db, log)

	org := models.Organization{Name: "ExposureTestOrg1", Slug: "exposure-test-org-1"}
	require.NoError(t, db.Create(&org).Error)

	exposedHost := models.Host{
		OrgID:        org.ID,
		IP:           "203.0.113.10",
		Hostname:     "edge.acme.test",
		Environment:  "production",
		BusinessUnit: "payments",
		Owner:        "secops",
		Monitored:    true,
		RiskScore:    95,
		RiskTier:     "critical",
		RiskFactors: models.JSONB{
			"internet_exposed": true,
			"sensitive_asset":  true,
			"cert_issues":      1,
			"expiring_certs":   0,
		},
		FirstSeenAt: time.Now(),
		LastSeenAt:  time.Now(),
	}
	require.NoError(t, db.Create(&exposedHost).Error)

	crownJewel := models.Host{
		OrgID:       org.ID,
		IP:          "203.0.113.20",
		Hostname:    "db.acme.test",
		Environment: "production",
		Monitored:   true,
		RiskScore:   40,
		RiskTier:    "medium",
		RiskFactors: models.JSONB{"sensitive_asset": true},
		FirstSeenAt: time.Now(),
		LastSeenAt:  time.Now(),
	}
	require.NoError(t, db.Create(&crownJewel).Error)

	quietHost := models.Host{
		OrgID:       org.ID,
		IP:          "203.0.113.30",
		Hostname:    "quiet.acme.test",
		Environment: "production",
		Monitored:   true,
		RiskScore:   10,
		RiskTier:    "low",
		FirstSeenAt: time.Now(),
		LastSeenAt:  time.Now(),
	}
	require.NoError(t, db.Create(&quietHost).Error)

	for i := 0; i < 3; i++ {
		f := models.Finding{
			OrgID:    org.ID,
			HostID:   &exposedHost.ID,
			Title:    "Remote Code Execution",
			Severity: "critical",
			Status:   "open",
			CVSS:     9.8,
		}
		require.NoError(t, db.Create(&f).Error)
	}

	for i := 0; i < 3; i++ {
		path := models.AttackPath{
			ID:           uuid.New(),
			OrgID:        org.ID,
			EntryType:    "host",
			EntryID:      exposedHost.ID,
			EntryLabel:   exposedHost.Hostname,
			TargetType:   "host",
			TargetID:     crownJewel.ID,
			TargetLabel:  crownJewel.Hostname,
			WeakestScore: 95,
			WeakestType:  "host",
			WeakestID:    exposedHost.ID,
			WeakestLabel: exposedHost.Hostname,
			HopCount:     2,
			Hops:         models.JSONB{},
			ComputedAt:   time.Now(),
		}
		require.NoError(t, db.Create(&path).Error)
	}

	rel := models.AssetRelationship{
		ID:           uuid.New(),
		OrgID:        org.ID,
		FromType:     "host",
		FromID:       exposedHost.ID,
		FromLabel:    exposedHost.Hostname,
		ToType:       "host",
		ToID:         crownJewel.ID,
		ToLabel:      crownJewel.Hostname,
		RelationType: "shared_asn",
		Confidence:   1,
		ComputedAt:   time.Now(),
	}
	require.NoError(t, db.Create(&rel).Error)

	summary, err := engine.RecomputeOrg(org.ID)
	require.NoError(t, err)
	require.Equal(t, 3, summary.AssetsScored)

	var scores []models.AssetExposureScore
	require.NoError(t, db.Where("org_id = ?", org.ID).Order("exposure_score DESC").Find(&scores).Error)
	require.Len(t, scores, 3)

	byHost := map[uuid.UUID]models.AssetExposureScore{}
	for _, s := range scores {
		byHost[s.AssetID] = s
	}

	exposedScore := byHost[exposedHost.ID]
	quietScore := byHost[quietHost.ID]

	require.Contains(t, []string{"critical", "high"}, exposedScore.ExposureLevel,
		"internet-facing crown-jewel host with critical findings, attack paths, and a sensitive neighbor should score critical/high, got %v (%v)",
		exposedScore.ExposureLevel, exposedScore.ExposureScore)
	require.True(t, exposedScore.ExposureScore > quietScore.ExposureScore,
		"exposed host (%v) should outscore the quiet host (%v)", exposedScore.ExposureScore, quietScore.ExposureScore)
	require.Equal(t, 3, exposedScore.AttackPathCount)
	require.Equal(t, 3, exposedScore.CriticalFindings)
	require.True(t, exposedScore.InternetExposed)
	require.Equal(t, "informational", quietScore.ExposureLevel)

	// A second recompute should fully replace the rows for the org, not
	// append duplicates.
	_, err = engine.RecomputeOrg(org.ID)
	require.NoError(t, err)
	var count int64
	require.NoError(t, db.Model(&models.AssetExposureScore{}).Where("org_id = ?", org.ID).Count(&count).Error)
	require.Equal(t, int64(3), count)
}

func TestDashboard_AggregatesAndFiltersCorrectly(t *testing.T) {
	db := newTestDB(t)
	log := zap.NewNop().Sugar()
	engine := exposure.New(db, log)

	org := models.Organization{Name: "ExposureTestOrg2", Slug: "exposure-test-org-2"}
	require.NoError(t, db.Create(&org).Error)

	host := models.Host{
		OrgID:       org.ID,
		IP:          "203.0.113.50",
		Hostname:    "public.acme.test",
		Environment: "production",
		Monitored:   true,
		RiskScore:   90,
		RiskTier:    "critical",
		RiskFactors: models.JSONB{"internet_exposed": true, "sensitive_asset": true},
		FirstSeenAt: time.Now(),
		LastSeenAt:  time.Now(),
	}
	require.NoError(t, db.Create(&host).Error)

	_, err := engine.RecomputeOrg(org.ID)
	require.NoError(t, err)

	dash, err := engine.Dashboard(org.ID)
	require.NoError(t, err)
	require.Equal(t, 1, dash.TotalScored)
	require.Equal(t, 1, dash.PublicFacingCount)
	require.Len(t, dash.PublicFacingAssets, 1)
	require.True(t, dash.AvgExposureScore > 0)
}
