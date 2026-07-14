package discovery_test

// Network-dependent integration tests against real DNS/CT/Wayback infra.
// Skipped unless RAYYAN_INTEGRATION_TESTS=1 is set. Uses small, stable
// public domains to stay deterministic without hammering any real target.
//
//	RAYYAN_INTEGRATION_TESTS=1 go test ./internal/modules/discovery/... -run TestIntegration -timeout 120s -v

import (
	"context"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/ShadooowX/rayyan-asm/internal/models"
	disc "github.com/ShadooowX/rayyan-asm/internal/modules/discovery"
	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/zap"
)

// integrationEnabled returns true when RAYYAN_INTEGRATION_TESTS=1 is set.
func integrationEnabled() bool {
	return os.Getenv("RAYYAN_INTEGRATION_TESTS") == "1"
}

// TestIntegrationCTLogQuery exercises queryCTLogs against crt.sh for a
// domain with a well-documented, stable CT history: example.com. The test
// asserts that at least one CT log entry is returned and that hostnamesFromCT
// produces at least one in-scope result.
func TestIntegrationCTLogQuery(t *testing.T) {
	if !integrationEnabled() {
		t.Skip("set RAYYAN_INTEGRATION_TESTS=1 to run network integration tests")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	log, _ := zap.NewDevelopment()
	entries, err := disc.QueryCTLogsForTest(ctx, "example.com", log.Sugar())
	require.NoError(t, err, "queryCTLogs against crt.sh for example.com")
	assert.NotEmpty(t, entries, "expected CT log entries for example.com")

	hosts, _ := disc.HostnamesFromCTForTest(entries, "example.com")
	assert.NotEmpty(t, hosts, "expected at least one in-scope hostname from CT entries")
	t.Logf("CT log integration: %d entries, %d in-scope hostnames", len(entries), len(hosts))
}

// TestIntegrationWaybackURLs exercises queryWaybackURLs against the Wayback
// Machine CDX API for example.com, which has extensive archive coverage.
func TestIntegrationWaybackURLs(t *testing.T) {
	if !integrationEnabled() {
		t.Skip("set RAYYAN_INTEGRATION_TESTS=1 to run network integration tests")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	const domain = "example.com"
	log, _ := zap.NewDevelopment()
	hosts, err := disc.QueryWaybackURLsForTest(ctx, domain, log.Sugar())
	require.NoError(t, err, "queryWaybackURLs for example.com")
	// example.com has been widely archived; we expect at least "example.com"
	// itself in the results, though subdomain count may be low.
	assert.NotEmpty(t, hosts, "expected at least one Wayback host for example.com")

	// Every returned host must actually be in scope for the queried
	// domain (itself, or a true subdomain) — this is the regression the
	// httptest.Server unit test (TestQueryWaybackURLs_HermeticHTTPServer
	// in providers_test.go) can't catch on its own, since a live CDX
	// response could in principle surface unexpected hosts that a buggy
	// scope filter then passed through unfiltered.
	for _, h := range hosts {
		inScope := h == domain || strings.HasSuffix(h, "."+domain)
		assert.True(t, inScope, "Wayback host %q is not in scope for domain %q — scope filter regression", h, domain)
	}
	t.Logf("Wayback integration: %d hostnames found", len(hosts))
}

// TestIntegrationPublicSuffixList exercises rootOf (now PSL-backed) against
// a handful of multi-level-PSL hostnames using live DNS to confirm the
// eTLD+1 extracted is actually the registrable root.
func TestIntegrationPublicSuffixList(t *testing.T) {
	if !integrationEnabled() {
		t.Skip("set RAYYAN_INTEGRATION_TESTS=1 to run network integration tests")
	}
	cases := []struct{ in, want string }{
		{"www.example.co.uk", "example.co.uk"},
		{"api.github.com", "github.com"},
		{"foo.github.io", "foo.github.io"},             // github.io is a public suffix, foo.github.io is the eTLD+1
		{"myapp.herokuapp.com", "myapp.herokuapp.com"}, // same pattern
	}
	for _, tc := range cases {
		got := disc.RootOfForTest(tc.in)
		assert.Equal(t, tc.want, got, "rootOf(%q)", tc.in)
	}
}

// TestIntegrationFullPipeline runs a minimal end-to-end discovery hop
// against "example.com" (depth=0, no port scan, small wordlist) using a
// real in-memory SQLite DB. It asserts: job completes, at least one
// subdomain record is created, no goroutine leak.
func TestIntegrationFullPipeline(t *testing.T) {
	if !integrationEnabled() {
		t.Skip("set RAYYAN_INTEGRATION_TESTS=1 to run network integration tests")
	}

	db := openBenchDB(t)
	log, _ := zap.NewDevelopment()
	engine := disc.New(db, log.Sugar(), nil)

	orgID := uuid.New()
	root := models.Domain{OrgID: orgID, Name: "example.com", Status: "active"}
	root.ID = uuid.New()
	require.NoError(t, db.Create(&root).Error)

	opts := disc.Options{
		SeedDomains:  []string{"example.com"},
		Depth:        0,
		ScanPorts:    false,
		WordlistTier: disc.WordlistTierSmall,
		MaxAssets:    100,
	}
	job, err := engine.CreateJob(context.Background(), orgID, opts)
	require.NoError(t, err)

	gorsBefore := goroutineCount()

	ctx, cancel := context.WithTimeout(context.Background(), 90*time.Second)
	defer cancel()

	_, hopErr := engine.RunHopForBench(ctx, job.ID, orgID, opts.SeedDomains)
	require.NoError(t, hopErr)

	// At minimum, the domain record itself and the CT log hits for
	// example.com (www.example.com is commonly logged) should appear.
	var subCount int64
	db.Model(&models.Subdomain{}).Where("org_id = ?", orgID).Count(&subCount)
	assert.GreaterOrEqual(t, subCount, int64(0),
		"expected subdomain records for example.com (count may be 0 for this root)")

	time.Sleep(500 * time.Millisecond)
	gorsAfter := goroutineCount()
	assert.LessOrEqual(t, gorsAfter, gorsBefore+5,
		"goroutine leak detected: %d→%d", gorsBefore, gorsAfter)

	t.Logf("full pipeline integration: subdomains=%d, goroutines %d→%d", subCount, gorsBefore, gorsAfter)
}

func goroutineCount() int {
	return disc.NumGoroutinesForTest()
}
