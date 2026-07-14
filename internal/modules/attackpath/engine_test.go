package attackpath_test

import (
	"testing"

	"github.com/ShadooowX/rayyan-asm/internal/config"
	"github.com/ShadooowX/rayyan-asm/internal/database"
	"github.com/ShadooowX/rayyan-asm/internal/models"
	"github.com/ShadooowX/rayyan-asm/internal/modules/attackpath"
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

func seedOrg(t *testing.T, db *gorm.DB, name string) models.Organization {
	t.Helper()
	org := models.Organization{Name: name, Slug: name}
	require.NoError(t, db.Create(&org).Error)
	return org
}

func seedGraph(t *testing.T, db *gorm.DB, rows []models.AssetRelationship) {
	t.Helper()
	if len(rows) > 0 {
		require.NoError(t, db.Create(&rows).Error)
	}
}

func TestRecomputeOrg_NoGraph(t *testing.T) {
	db := newTestDB(t)
	org := seedOrg(t, db, t.Name())
	engine := attackpath.New(db, zap.NewNop().Sugar())

	summary, err := engine.RecomputeOrg(org.ID)
	require.NoError(t, err)
	require.Equal(t, 0, summary.PathsFound)
}

func TestRecomputeOrg_NoEntryOrTarget(t *testing.T) {
	db := newTestDB(t)
	org := seedOrg(t, db, t.Name())

	domain := models.Domain{OrgID: org.ID, Name: "example.com", Environment: "production"}
	require.NoError(t, db.Create(&domain).Error)
	sub := models.Subdomain{OrgID: org.ID, DomainID: domain.ID, Name: "app", FQDN: "app.example.com"}
	require.NoError(t, db.Create(&sub).Error)
	host := models.Host{OrgID: org.ID, IP: "10.0.0.1"}
	require.NoError(t, db.Create(&host).Error)

	seedGraph(t, db, []models.AssetRelationship{{
		ID: uuid.New(), OrgID: org.ID,
		FromType: "subdomain", FromID: sub.ID, FromLabel: sub.FQDN,
		ToType: "host", ToID: host.ID, ToLabel: host.IP,
		RelationType: "resolves_to", Confidence: 1,
	}})

	engine := attackpath.New(db, zap.NewNop().Sugar())
	summary, err := engine.RecomputeOrg(org.ID)
	require.NoError(t, err)
	require.Equal(t, 0, summary.PathsFound)
}

func TestRecomputeOrg_FindsPath(t *testing.T) {
	db := newTestDB(t)
	org := seedOrg(t, db, t.Name())

	entryHost := models.Host{
		OrgID: org.ID, IP: "203.0.113.5",
		RiskScore: 60, RiskTier: "high",
		RiskFactors: models.JSONB{"internet_exposed": true, "sensitive_asset": false},
	}
	require.NoError(t, db.Create(&entryHost).Error)

	targetHost := models.Host{
		OrgID: org.ID, IP: "10.0.0.50",
		RiskScore: 80, RiskTier: "critical",
		RiskFactors: models.JSONB{"internet_exposed": false, "sensitive_asset": true},
	}
	require.NoError(t, db.Create(&targetHost).Error)

	domain := models.Domain{OrgID: org.ID, Name: "example.com"}
	require.NoError(t, db.Create(&domain).Error)
	pivot := models.Subdomain{
		OrgID: org.ID, DomainID: domain.ID,
		Name: "internal", FQDN: "internal.example.com",
		RiskScore: 50, RiskTier: "medium",
		RiskFactors: models.JSONB{"internet_exposed": false, "sensitive_asset": false},
	}
	require.NoError(t, db.Create(&pivot).Error)

	seedGraph(t, db, []models.AssetRelationship{
		{
			ID: uuid.New(), OrgID: org.ID,
			FromType: "host", FromID: entryHost.ID, FromLabel: entryHost.IP,
			ToType: "subdomain", ToID: pivot.ID, ToLabel: pivot.FQDN,
			RelationType: "resolves_to", Confidence: 1,
		},
		{
			ID: uuid.New(), OrgID: org.ID,
			FromType: "subdomain", FromID: pivot.ID, FromLabel: pivot.FQDN,
			ToType: "host", ToID: targetHost.ID, ToLabel: targetHost.IP,
			RelationType: "resolves_to", Confidence: 1,
		},
	})

	engine := attackpath.New(db, zap.NewNop().Sugar())
	summary, err := engine.RecomputeOrg(org.ID)
	require.NoError(t, err)
	require.Equal(t, 1, summary.PathsFound)

	paths, err := engine.List(org.ID, 10)
	require.NoError(t, err)
	require.Len(t, paths, 1)

	p := paths[0]
	require.Equal(t, entryHost.ID, p.EntryID)
	require.Equal(t, targetHost.ID, p.TargetID)
	require.Equal(t, 3, p.HopCount)
	require.InDelta(t, 50.0, p.WeakestScore, 0.01)
}

func TestRecomputeOrg_WeakestLinkIsCorrect(t *testing.T) {
	db := newTestDB(t)
	org := seedOrg(t, db, t.Name())

	entry := models.Host{
		OrgID: org.ID, IP: "1.2.3.4",
		RiskScore: 90, RiskTier: "critical",
		RiskFactors: models.JSONB{"internet_exposed": true},
	}
	require.NoError(t, db.Create(&entry).Error)

	target := models.Host{
		OrgID: org.ID, IP: "10.0.0.1",
		RiskScore: 85, RiskTier: "critical",
		RiskFactors: models.JSONB{"sensitive_asset": true},
	}
	require.NoError(t, db.Create(&target).Error)

	domain := models.Domain{OrgID: org.ID, Name: "corp.com"}
	require.NoError(t, db.Create(&domain).Error)
	lowRisk := models.Subdomain{
		OrgID: org.ID, DomainID: domain.ID,
		Name: "lo", FQDN: "lo.corp.com",
		RiskScore: 5, RiskTier: "low",
		RiskFactors: models.JSONB{},
	}
	require.NoError(t, db.Create(&lowRisk).Error)

	seedGraph(t, db, []models.AssetRelationship{
		{
			ID: uuid.New(), OrgID: org.ID,
			FromType: "host", FromID: entry.ID, FromLabel: entry.IP,
			ToType: "subdomain", ToID: lowRisk.ID, ToLabel: lowRisk.FQDN,
			RelationType: "resolves_to", Confidence: 1,
		},
		{
			ID: uuid.New(), OrgID: org.ID,
			FromType: "subdomain", FromID: lowRisk.ID, FromLabel: lowRisk.FQDN,
			ToType: "host", ToID: target.ID, ToLabel: target.IP,
			RelationType: "resolves_to", Confidence: 1,
		},
	})

	engine := attackpath.New(db, zap.NewNop().Sugar())
	_, err := engine.RecomputeOrg(org.ID)
	require.NoError(t, err)

	paths, err := engine.List(org.ID, 10)
	require.NoError(t, err)
	require.Len(t, paths, 1)
	require.InDelta(t, 5.0, paths[0].WeakestScore, 0.01)
	require.Equal(t, lowRisk.ID, paths[0].WeakestID)
}

func TestRecomputeOrg_PublicIPFallback(t *testing.T) {
	db := newTestDB(t)
	org := seedOrg(t, db, t.Name())

	entry := models.Host{
		OrgID: org.ID, IP: "8.8.8.8",
		RiskScore: 40, RiskTier: "medium",
		RiskFactors: models.JSONB{},
	}
	require.NoError(t, db.Create(&entry).Error)

	target := models.Host{
		OrgID: org.ID, IP: "10.0.0.5",
		RiskScore: 75, RiskTier: "high",
		RiskFactors: models.JSONB{"sensitive_asset": true},
	}
	require.NoError(t, db.Create(&target).Error)

	seedGraph(t, db, []models.AssetRelationship{{
		ID: uuid.New(), OrgID: org.ID,
		FromType: "host", FromID: entry.ID, FromLabel: entry.IP,
		ToType: "host", ToID: target.ID, ToLabel: target.IP,
		RelationType: "shared_asn", Confidence: 0.6,
	}})

	engine := attackpath.New(db, zap.NewNop().Sugar())
	summary, err := engine.RecomputeOrg(org.ID)
	require.NoError(t, err)
	require.Equal(t, 1, summary.PathsFound)
}

func TestList_LimitRespected(t *testing.T) {
	db := newTestDB(t)
	org := seedOrg(t, db, t.Name())
	engine := attackpath.New(db, zap.NewNop().Sugar())

	for i := 0; i < 5; i++ {
		ap := models.AttackPath{
			ID: uuid.New(), OrgID: org.ID,
			EntryType: "host", EntryID: uuid.New(),
			TargetType: "host", TargetID: uuid.New(),
			WeakestScore: float64(i * 10),
			HopCount:     2,
			Hops:         models.JSONB{"hops": []interface{}{}},
		}
		require.NoError(t, db.Create(&ap).Error)
	}

	paths, err := engine.List(org.ID, 3)
	require.NoError(t, err)
	require.Len(t, paths, 3)
	require.GreaterOrEqual(t, paths[0].WeakestScore, paths[1].WeakestScore)
}

func TestRecomputeOrg_DropsOldPaths(t *testing.T) {
	db := newTestDB(t)
	org := seedOrg(t, db, t.Name())
	engine := attackpath.New(db, zap.NewNop().Sugar())

	stale := models.AttackPath{
		ID: uuid.New(), OrgID: org.ID,
		EntryType: "host", EntryID: uuid.New(),
		TargetType: "host", TargetID: uuid.New(),
		WeakestScore: 99, HopCount: 1,
		Hops: models.JSONB{"hops": []interface{}{}},
	}
	require.NoError(t, db.Create(&stale).Error)

	_, err := engine.RecomputeOrg(org.ID)
	require.NoError(t, err)

	paths, err := engine.List(org.ID, 100)
	require.NoError(t, err)
	require.Empty(t, paths)
}
