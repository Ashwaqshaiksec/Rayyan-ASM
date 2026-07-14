package discovery_test

// Regression test for the bug where a discovery run only ever produced
// subdomain/DNS output: processHop ran the ASN/reverse-DNS/DNS-intel/
// port-scan pipeline only for *newly discovered child subdomains*, never
// for the frontier item (seed domain or seed IP) itself. A literal IP
// seed produced zero "discovered" children (CT/wayback/brute-force all
// need a real registrable domain), so it got nothing at all; a domain
// seed got subdomain enumeration but its own apex IP was never scanned.
//
// Hermetic: in-memory SQLite, mock Resolver (no real DNS/HTTP), so this
// only checks engine-internal behavior, not live network results.

import (
	"context"
	"net"
	"testing"

	"github.com/ShadooowX/rayyan-asm/internal/database"
	"github.com/ShadooowX/rayyan-asm/internal/models"
	disc "github.com/ShadooowX/rayyan-asm/internal/modules/discovery"
	"github.com/google/uuid"
	"github.com/stretchr/testify/require"
	"go.uber.org/zap"
	"gorm.io/gorm"
)

func openSelfResolveDB(t *testing.T) *gorm.DB {
	t.Helper()
	db, err := database.OpenSQLiteMemory()
	require.NoError(t, err)
	require.NoError(t, db.AutoMigrate(
		&models.Domain{}, &models.Subdomain{}, &models.Host{}, &models.Service{},
		&models.Certificate{}, &models.DNSRecord{}, &models.ASNRange{},
		&models.DiscoveryJob{}, &models.DiscoveryEvent{}, &models.DiscoveryRiskFlag{},
	))
	return db
}

// stubResolver resolves only the exact configured hostname to a fixed
// IP and NXDOMAINs everything else (in particular the dns-brute/
// permutation wordlist candidates), so the test exercises the
// self-resolution path without spuriously "discovering" every
// wordlist guess as a live subdomain.
type stubResolver struct {
	host string
	ip   string
}

func (s stubResolver) ResolveHost(_ context.Context, name string) ([]string, error) {
	if name == s.host {
		return []string{s.ip}, nil
	}
	return nil, &net.DNSError{Err: "no such host", IsNotFound: true}
}

func (s stubResolver) ReverseDNSLookup(_ context.Context, _ string) ([]string, error) {
	return nil, &net.DNSError{Err: "no such host", IsNotFound: true}
}

// TestProcessHop_IPLiteralSeed_GetsHostRecord is the literal-IP-seed
// case: before the fix, "discovered" stayed empty for an IP seed (CT log
// / wayback / brute-force all need a domain), so the whole IP/ASN/port
// pipeline never ran and no Host row was ever created.
func TestProcessHop_IPLiteralSeed_GetsHostRecord(t *testing.T) {
	db := openSelfResolveDB(t)
	log, _ := zap.NewDevelopment()
	engine := disc.New(db, log.Sugar(), nil)
	orgID := uuid.New()

	job, err := engine.CreateJob(context.Background(), orgID, disc.Options{
		SeedDomains:   []string{"93.184.216.34"}, // literal IP, no DNS needed
		ScanPorts:     false,                     // keep test fast/hermetic
		ProbeApexCert: disc.BoolPtr(false),       // avoid dialing a real external IP
	})
	require.NoError(t, err)

	_, err = engine.RunHopForBenchWithResolver(context.Background(), job.ID, orgID,
		[]string{"93.184.216.34"}, stubResolver{host: "93.184.216.34", ip: "93.184.216.34"})
	require.NoError(t, err)

	var host models.Host
	err = db.Where("org_id = ? AND ip = ?", orgID, "93.184.216.34").First(&host).Error
	require.NoError(t, err, "expected a Host row for the literal IP seed — this is exactly what the bug fix adds")
}

// TestProcessHop_DomainSeed_ApexGetsHostRecordEvenWithNoSubdomains is the
// domain-seed case: before the fix, the apex domain's own resolved IP was
// never run through the host/ASN/port pipeline — only children found via
// CT/wayback/brute-force were. With a stub resolver that finds zero CT/
// wayback/brute hits, "discovered" is empty, so the apex's own Host row
// only exists now because of the new self-resolution stage.
func TestProcessHop_DomainSeed_ApexGetsHostRecordEvenWithNoSubdomains(t *testing.T) {
	db := openSelfResolveDB(t)
	log, _ := zap.NewDevelopment()
	engine := disc.New(db, log.Sugar(), nil)
	orgID := uuid.New()

	job, err := engine.CreateJob(context.Background(), orgID, disc.Options{
		SeedDomains:        []string{"selfresolve-test.invalid"},
		ScanPorts:          false,
		ProbeApexCert:      disc.BoolPtr(false),
		SkipPassiveSources: disc.BoolPtr(true),
	})
	require.NoError(t, err)

	_, err = engine.RunHopForBenchWithResolver(context.Background(), job.ID, orgID,
		[]string{"selfresolve-test.invalid"}, stubResolver{host: "selfresolve-test.invalid", ip: "203.0.113.7"})
	require.NoError(t, err)

	var host models.Host
	err = db.Where("org_id = ? AND ip = ?", orgID, "203.0.113.7").First(&host).Error
	require.NoError(t, err, "expected the apex domain's own resolved IP to get a Host row")
}
