package riskscore_test

import (
	"testing"
	"time"

	"github.com/ShadooowX/rayyan-asm/internal/config"
	"github.com/ShadooowX/rayyan-asm/internal/database"
	"github.com/ShadooowX/rayyan-asm/internal/models"
	"github.com/ShadooowX/rayyan-asm/internal/modules/riskscore"
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

func TestRecomputeOrg_HostWithHighRiskPortAndCriticalFinding(t *testing.T) {
	db := newTestDB(t)
	log := zap.NewNop().Sugar()
	engine := riskscore.New(db, log)

	org := models.Organization{Name: "Acme", Slug: "acme"}
	require.NoError(t, db.Create(&org).Error)

	host := models.Host{
		OrgID:       org.ID,
		IP:          "203.0.113.10",
		Environment: "production",
		Monitored:   true,
		Tags:        models.StringArray{"crown-jewel"},
		FirstSeenAt: time.Now(),
		LastSeenAt:  time.Now(),
	}
	require.NoError(t, db.Create(&host).Error)

	svc := models.Service{
		OrgID:       org.ID,
		HostID:      host.ID,
		Port:        3389,
		Protocol:    "tcp",
		State:       "open",
		FirstSeenAt: time.Now(),
		LastSeenAt:  time.Now(),
	}
	require.NoError(t, db.Create(&svc).Error)

	finding := models.Finding{
		OrgID:    org.ID,
		HostID:   &host.ID,
		Title:    "Remote Code Execution",
		Severity: "critical",
		CVSS:     9.8,
		Status:   "open",
	}
	require.NoError(t, db.Create(&finding).Error)

	finding2 := models.Finding{
		OrgID:    org.ID,
		HostID:   &host.ID,
		Title:    "SQL Injection",
		Severity: "critical",
		CVSS:     9.1,
		Status:   "open",
	}
	require.NoError(t, db.Create(&finding2).Error)

	summary, err := engine.RecomputeOrg(org.ID)
	require.NoError(t, err)
	require.Equal(t, 1, summary.HostsScored)

	var scored models.Host
	require.NoError(t, db.First(&scored, "id = ?", host.ID).Error)

	require.Greater(t, scored.RiskScore, 25.0)
	require.NotEqual(t, "low", scored.RiskTier)
	require.NotNil(t, scored.RiskScoredAt)
	require.Equal(t, true, scored.RiskFactors["internet_exposed"])
	require.Equal(t, true, scored.RiskFactors["sensitive_asset"])

	var history []models.AssetRiskHistory
	require.NoError(t, db.Where("org_id = ? AND asset_type = 'host'", org.ID).Find(&history).Error)
	require.Len(t, history, 1)
	require.Equal(t, scored.RiskScore, history[0].Score)
}

func TestRecomputeOrg_CleanHostScoresLow(t *testing.T) {
	db := newTestDB(t)
	log := zap.NewNop().Sugar()
	engine := riskscore.New(db, log)

	org := models.Organization{Name: "Acme2", Slug: "acme2"}
	require.NoError(t, db.Create(&org).Error)

	host := models.Host{
		OrgID:       org.ID,
		IP:          "203.0.113.20",
		Environment: "production",
		Monitored:   true,
		FirstSeenAt: time.Now(),
		LastSeenAt:  time.Now(),
	}
	require.NoError(t, db.Create(&host).Error)

	_, err := engine.RecomputeOrg(org.ID)
	require.NoError(t, err)

	var scored models.Host
	require.NoError(t, db.First(&scored, "id = ?", host.ID).Error)
	require.Equal(t, 0.0, scored.RiskScore)
	require.Equal(t, "low", scored.RiskTier)
}

func TestRecomputeOrg_DomainInheritsRiskiestSubdomain(t *testing.T) {
	db := newTestDB(t)
	log := zap.NewNop().Sugar()
	engine := riskscore.New(db, log)

	org := models.Organization{Name: "Acme3", Slug: "acme3"}
	require.NoError(t, db.Create(&org).Error)

	domain := models.Domain{OrgID: org.ID, Name: "example.com", Environment: "production", Monitored: true}
	require.NoError(t, db.Create(&domain).Error)

	quiet := models.Subdomain{
		OrgID: org.ID, DomainID: domain.ID, Name: "quiet", FQDN: "quiet.example.com",
		Status: "active", FirstSeenAt: time.Now(), LastSeenAt: time.Now(),
	}
	require.NoError(t, db.Create(&quiet).Error)

	risky := models.Subdomain{
		OrgID: org.ID, DomainID: domain.ID, Name: "risky", FQDN: "risky.example.com",
		Status: "active", FirstSeenAt: time.Now(), LastSeenAt: time.Now(),
	}
	require.NoError(t, db.Create(&risky).Error)

	riskySvc := models.Service{
		OrgID: org.ID, HostRef: "risky.example.com", Port: 6379, Protocol: "tcp",
		State: "open", FirstSeenAt: time.Now(), LastSeenAt: time.Now(),
	}
	require.NoError(t, db.Create(&riskySvc).Error)

	finding := models.Finding{
		OrgID: org.ID, SubdomainID: &risky.ID, Title: "Exposed Redis", Severity: "high", Status: "open",
	}
	require.NoError(t, db.Create(&finding).Error)

	_, err := engine.RecomputeOrg(org.ID)
	require.NoError(t, err)

	var scoredDomain models.Domain
	require.NoError(t, db.First(&scoredDomain, "id = ?", domain.ID).Error)

	var scoredRisky, scoredQuiet models.Subdomain
	require.NoError(t, db.First(&scoredRisky, "id = ?", risky.ID).Error)
	require.NoError(t, db.First(&scoredQuiet, "id = ?", quiet.ID).Error)

	require.Greater(t, scoredRisky.RiskScore, scoredQuiet.RiskScore)
	require.Equal(t, scoredRisky.RiskScore, scoredDomain.RiskScore)
}

func TestRecomputeOrg_NoAssetsIsNoOp(t *testing.T) {
	db := newTestDB(t)
	log := zap.NewNop().Sugar()
	engine := riskscore.New(db, log)

	org := models.Organization{Name: "Empty", Slug: "empty"}
	require.NoError(t, db.Create(&org).Error)

	summary, err := engine.RecomputeOrg(org.ID)
	require.NoError(t, err)
	require.Equal(t, 0, summary.HostsScored)
	require.Equal(t, 0, summary.SubdomainsScored)
	require.Equal(t, 0, summary.DomainsScored)
}

func TestRecomputeAll_IteratesAllOrgs(t *testing.T) {
	db := newTestDB(t)
	log := zap.NewNop().Sugar()
	engine := riskscore.New(db, log)

	var orgIDs []uuid.UUID
	for i := 0; i < 2; i++ {
		org := models.Organization{Name: uuid.New().String(), Slug: uuid.New().String()}
		require.NoError(t, db.Create(&org).Error)
		host := models.Host{OrgID: org.ID, IP: "10.0.0.1", FirstSeenAt: time.Now(), LastSeenAt: time.Now()}
		require.NoError(t, db.Create(&host).Error)
		orgIDs = append(orgIDs, org.ID)
	}

	engine.RecomputeAll()

	var count int64
	db.Model(&models.AssetRiskHistory{}).
		Where("asset_type = 'host' AND org_id IN ?", orgIDs).
		Count(&count)
	require.Equal(t, int64(2), count)
}
