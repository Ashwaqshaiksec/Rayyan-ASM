package correlation_test

import (
	"testing"

	"github.com/ShadooowX/rayyan-asm/internal/config"
	"github.com/ShadooowX/rayyan-asm/internal/database"
	"github.com/ShadooowX/rayyan-asm/internal/models"
	"github.com/ShadooowX/rayyan-asm/internal/modules/correlation"
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

func TestRecomputeOrg_BuildsFullChain(t *testing.T) {
	db := newTestDB(t)
	log := zap.NewNop().Sugar()
	engine := correlation.New(db, log)
	org := seedOrg(t, db, "acme")

	domain := models.Domain{OrgID: org.ID, Name: "example.com"}
	require.NoError(t, db.Create(&domain).Error)

	sub := models.Subdomain{
		OrgID: org.ID, DomainID: domain.ID, Name: "app", FQDN: "app.example.com",
		IPs: models.StringArray{"203.0.113.5"},
	}
	require.NoError(t, db.Create(&sub).Error)

	host := models.Host{OrgID: org.ID, IP: "203.0.113.5", ASN: "AS64500", ASNOrg: "Acme Networks"}
	require.NoError(t, db.Create(&host).Error)

	svc := models.Service{OrgID: org.ID, HostID: host.ID, Port: 443, Protocol: "tcp"}
	require.NoError(t, db.Create(&svc).Error)

	cert := models.Certificate{
		OrgID: org.ID, ServiceID: &svc.ID, Fingerprint: "abc123", Subject: "app.example.com",
	}
	require.NoError(t, db.Create(&cert).Error)

	summary, err := engine.RecomputeOrg(org.ID)
	require.NoError(t, err)
	require.Greater(t, summary.EdgesBuilt, 0)

	var rows []models.AssetRelationship
	require.NoError(t, db.Where("org_id = ?", org.ID).Find(&rows).Error)

	relations := map[string]int{}
	for _, r := range rows {
		relations[r.RelationType]++
	}
	require.Equal(t, 4, relations["parent_child"]) // domain->sub, host->service, service->cert, asn->host
	require.Equal(t, 1, relations["resolves_to"])  // sub->host
}

func TestRecomputeOrg_DropsStaleEdges(t *testing.T) {
	db := newTestDB(t)
	log := zap.NewNop().Sugar()
	engine := correlation.New(db, log)
	org := seedOrg(t, db, "stale")

	domain := models.Domain{OrgID: org.ID, Name: "stale.com"}
	require.NoError(t, db.Create(&domain).Error)
	sub := models.Subdomain{OrgID: org.ID, DomainID: domain.ID, Name: "www", FQDN: "www.stale.com"}
	require.NoError(t, db.Create(&sub).Error)

	_, err := engine.RecomputeOrg(org.ID)
	require.NoError(t, err)

	var before int64
	db.Model(&models.AssetRelationship{}).Where("org_id = ?", org.ID).Count(&before)
	require.Equal(t, int64(1), before)

	require.NoError(t, db.Delete(&sub).Error)

	_, err = engine.RecomputeOrg(org.ID)
	require.NoError(t, err)

	var after int64
	db.Model(&models.AssetRelationship{}).Where("org_id = ?", org.ID).Count(&after)
	require.Equal(t, int64(0), after)
}

func TestRecomputeOrg_InfersSharedASN(t *testing.T) {
	db := newTestDB(t)
	log := zap.NewNop().Sugar()
	engine := correlation.New(db, log)
	org := seedOrg(t, db, "asnorg")

	h1 := models.Host{OrgID: org.ID, IP: "198.51.100.1", ASN: "AS13335"}
	h2 := models.Host{OrgID: org.ID, IP: "198.51.100.2", ASN: "AS13335"}
	require.NoError(t, db.Create(&h1).Error)
	require.NoError(t, db.Create(&h2).Error)

	_, err := engine.RecomputeOrg(org.ID)
	require.NoError(t, err)

	var sharedCount int64
	db.Model(&models.AssetRelationship{}).
		Where("org_id = ? AND relation_type = 'shared_asn'", org.ID).Count(&sharedCount)
	require.Equal(t, int64(2), sharedCount)
}

func TestRecomputeOrg_InfersCertSANMatch(t *testing.T) {
	db := newTestDB(t)
	log := zap.NewNop().Sugar()
	engine := correlation.New(db, log)
	org := seedOrg(t, db, "certorg")

	domain := models.Domain{OrgID: org.ID, Name: "certorg.com"}
	require.NoError(t, db.Create(&domain).Error)

	api := models.Subdomain{OrgID: org.ID, DomainID: domain.ID, Name: "api", FQDN: "api.certorg.com"}
	app := models.Subdomain{OrgID: org.ID, DomainID: domain.ID, Name: "app", FQDN: "app.certorg.com"}
	require.NoError(t, db.Create(&api).Error)
	require.NoError(t, db.Create(&app).Error)

	cert := models.Certificate{
		OrgID: org.ID, Fingerprint: "wildcard1", Subject: "*.certorg.com",
		SubjectAltNames: models.StringArray{"*.certorg.com"},
	}
	require.NoError(t, db.Create(&cert).Error)

	_, err := engine.RecomputeOrg(org.ID)
	require.NoError(t, err)

	var matches int64
	db.Model(&models.AssetRelationship{}).
		Where("org_id = ? AND relation_type = 'cert_san_match'", org.ID).Count(&matches)
	require.Equal(t, int64(2), matches)
}

func TestRecomputeOrg_InfersSharedRegistrant(t *testing.T) {
	db := newTestDB(t)
	log := zap.NewNop().Sugar()
	engine := correlation.New(db, log)
	org := seedOrg(t, db, "regorg")

	d1 := models.Domain{OrgID: org.ID, Name: "one.com"}
	d2 := models.Domain{OrgID: org.ID, Name: "two.com"}
	require.NoError(t, db.Create(&d1).Error)
	require.NoError(t, db.Create(&d2).Error)

	w1 := models.WHOISHistory{ID: uuid.New(), OrgID: org.ID, Domain: "one.com", Registrant: "Acme Holdings LLC"}
	w2 := models.WHOISHistory{ID: uuid.New(), OrgID: org.ID, Domain: "two.com", Registrant: "Acme Holdings LLC"}
	require.NoError(t, db.Create(&w1).Error)
	require.NoError(t, db.Create(&w2).Error)

	_, err := engine.RecomputeOrg(org.ID)
	require.NoError(t, err)

	var matches int64
	db.Model(&models.AssetRelationship{}).
		Where("org_id = ? AND relation_type = 'shared_registrant'", org.ID).Count(&matches)
	require.Equal(t, int64(2), matches)
}

func TestGraph_FocusedSubgraphRespectsDepth(t *testing.T) {
	db := newTestDB(t)
	log := zap.NewNop().Sugar()
	engine := correlation.New(db, log)
	org := seedOrg(t, db, "graphorg")

	domain := models.Domain{OrgID: org.ID, Name: "graphorg.com"}
	require.NoError(t, db.Create(&domain).Error)
	sub := models.Subdomain{OrgID: org.ID, DomainID: domain.ID, Name: "www", FQDN: "www.graphorg.com", IPs: models.StringArray{"192.0.2.10"}}
	require.NoError(t, db.Create(&sub).Error)
	host := models.Host{OrgID: org.ID, IP: "192.0.2.10"}
	require.NoError(t, db.Create(&host).Error)
	svc := models.Service{OrgID: org.ID, HostID: host.ID, Port: 22, Protocol: "tcp"}
	require.NoError(t, db.Create(&svc).Error)

	_, err := engine.RecomputeOrg(org.ID)
	require.NoError(t, err)

	g1, err := engine.Graph(org.ID, "domain", domain.ID, 1)
	require.NoError(t, err)
	require.Len(t, g1.Edges, 1)

	g2, err := engine.Graph(org.ID, "domain", domain.ID, 3)
	require.NoError(t, err)
	require.Len(t, g2.Edges, 3)

	full, err := engine.Graph(org.ID, "", uuid.Nil, 0)
	require.NoError(t, err)
	require.Len(t, full.Edges, 3)
}

func TestRelated_DistinguishesParentChildAndPeer(t *testing.T) {
	db := newTestDB(t)
	log := zap.NewNop().Sugar()
	engine := correlation.New(db, log)
	org := seedOrg(t, db, "relorg")

	domain := models.Domain{OrgID: org.ID, Name: "relorg.com"}
	require.NoError(t, db.Create(&domain).Error)
	sub := models.Subdomain{OrgID: org.ID, DomainID: domain.ID, Name: "www", FQDN: "www.relorg.com"}
	require.NoError(t, db.Create(&sub).Error)

	h1 := models.Host{OrgID: org.ID, IP: "203.0.113.1", ASN: "AS999"}
	h2 := models.Host{OrgID: org.ID, IP: "203.0.113.2", ASN: "AS999"}
	require.NoError(t, db.Create(&h1).Error)
	require.NoError(t, db.Create(&h2).Error)

	_, err := engine.RecomputeOrg(org.ID)
	require.NoError(t, err)

	domainRelated, err := engine.Related(org.ID, "domain", domain.ID)
	require.NoError(t, err)
	require.Len(t, domainRelated, 1)
	require.Equal(t, "child", domainRelated[0].Direction)
	require.Equal(t, "subdomain", domainRelated[0].Asset.Type)

	subRelated, err := engine.Related(org.ID, "subdomain", sub.ID)
	require.NoError(t, err)
	require.Len(t, subRelated, 1)
	require.Equal(t, "parent", subRelated[0].Direction)

	hostRelated, err := engine.Related(org.ID, "host", h1.ID)
	require.NoError(t, err)
	found := false
	for _, r := range hostRelated {
		if r.RelationType == "shared_asn" {
			require.Equal(t, "peer", r.Direction)
			found = true
		}
	}
	require.True(t, found, "expected a shared_asn peer relation")
}

func TestExposurePath_FindsChainAcrossAssetTypes(t *testing.T) {
	db := newTestDB(t)
	log := zap.NewNop().Sugar()
	engine := correlation.New(db, log)
	org := seedOrg(t, db, "pathorg")

	domain := models.Domain{OrgID: org.ID, Name: "pathorg.com"}
	require.NoError(t, db.Create(&domain).Error)
	sub := models.Subdomain{OrgID: org.ID, DomainID: domain.ID, Name: "internal", FQDN: "internal.pathorg.com", IPs: models.StringArray{"10.0.0.5"}}
	require.NoError(t, db.Create(&sub).Error)
	host := models.Host{OrgID: org.ID, IP: "10.0.0.5"}
	require.NoError(t, db.Create(&host).Error)
	svc := models.Service{OrgID: org.ID, HostID: host.ID, Port: 8080, Protocol: "tcp"}
	require.NoError(t, db.Create(&svc).Error)

	_, err := engine.RecomputeOrg(org.ID)
	require.NoError(t, err)

	path, err := engine.ExposurePath(org.ID, "domain", domain.ID, "service", svc.ID)
	require.NoError(t, err)
	require.NotNil(t, path)
	require.Len(t, path, 4)
	require.Equal(t, "domain", path[0].Node.Type)
	require.Equal(t, "subdomain", path[1].Node.Type)
	require.Equal(t, "host", path[2].Node.Type)
	require.Equal(t, "service", path[3].Node.Type)
}

func TestExposurePath_NoPathReturnsNil(t *testing.T) {
	db := newTestDB(t)
	log := zap.NewNop().Sugar()
	engine := correlation.New(db, log)
	org := seedOrg(t, db, "nopathorg")

	d1 := models.Domain{OrgID: org.ID, Name: "isolated-a.com"}
	d2 := models.Domain{OrgID: org.ID, Name: "isolated-b.com"}
	require.NoError(t, db.Create(&d1).Error)
	require.NoError(t, db.Create(&d2).Error)

	_, err := engine.RecomputeOrg(org.ID)
	require.NoError(t, err)

	path, err := engine.ExposurePath(org.ID, "domain", d1.ID, "domain", d2.ID)
	require.NoError(t, err)
	require.Nil(t, path)
}
