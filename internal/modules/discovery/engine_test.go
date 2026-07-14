package discovery_test

import (
	"context"
	"testing"

	"github.com/ShadooowX/rayyan-asm/internal/config"
	"github.com/ShadooowX/rayyan-asm/internal/database"
	"github.com/ShadooowX/rayyan-asm/internal/models"
	"github.com/ShadooowX/rayyan-asm/internal/modules/discovery"
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

// Job lifecycle tests only — Run() itself does live DNS/HTTP lookups, so
// it belongs in the integration suite behind a network-access build tag,
// not this fast unit suite.

func TestStartJob_RequiresSeedDomains(t *testing.T) {
	db := newTestDB(t)
	engine := discovery.New(db, zap.NewNop().Sugar(), nil)
	org := seedOrg(t, db, "no-seeds")

	_, err := engine.StartJob(org.ID, discovery.Options{})
	require.Error(t, err)
}

func TestStartJob_CreatesPendingJobWithDefaults(t *testing.T) {
	db := newTestDB(t)
	engine := discovery.New(db, zap.NewNop().Sugar(), nil)
	org := seedOrg(t, db, "defaults")

	job, err := engine.StartJob(org.ID, discovery.Options{
		SeedDomains: []string{"Example.com", "https://Sub.Example.com/"},
	})
	require.NoError(t, err)
	require.Equal(t, "pending", job.Status)
	require.Equal(t, "manual", job.Cadence)
	require.Equal(t, 2, job.Depth) // default depth
	require.Equal(t, []string{"example.com", "sub.example.com"}, []string(job.SeedDomains))

	var loaded models.DiscoveryJob
	require.NoError(t, db.First(&loaded, "id = ?", job.ID).Error)
	require.Equal(t, org.ID, loaded.OrgID)
}

func TestStartJob_ClampsDepthAndCadence(t *testing.T) {
	db := newTestDB(t)
	engine := discovery.New(db, zap.NewNop().Sugar(), nil)
	org := seedOrg(t, db, "cadence")

	job, err := engine.StartJob(org.ID, discovery.Options{
		SeedDomains: []string{"example.com"},
		Depth:       0, // should fall back to default
		Cadence:     "weekly",
	})
	require.NoError(t, err)
	require.Equal(t, 2, job.Depth)
	require.Equal(t, "weekly", job.Cadence)
}

func TestRun_UnknownJobReturnsError(t *testing.T) {
	db := newTestDB(t)
	engine := discovery.New(db, zap.NewNop().Sugar(), nil)

	err := engine.Run(context.Background(), uuid.New())
	require.Error(t, err)
}
