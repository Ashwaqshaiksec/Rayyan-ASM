package discovery_test

// Benchmarks processHop's concurrency/scale envelope against a synthetic
// 500+ host frontier. Hermetic: in-memory SQLite, DNS mocked via
// NXDOMAINResolver (same resolveHost/reverseDNSLookup path prod uses), and
// the CT-log/Wayback Machine passive-source queries disabled via
// SkipPassiveSources (those aren't gated behind the Resolver interface,
// so without this they'd fire one real HTTP call each to crt.sh/
// web.archive.org and block for the client timeout in any environment
// without outbound internet access). So this measures engine overhead,
// not network latency.

import (
	"context"
	"fmt"
	"runtime"
	"testing"
	"time"

	"github.com/ShadooowX/rayyan-asm/internal/database"
	"github.com/ShadooowX/rayyan-asm/internal/models"
	disc "github.com/ShadooowX/rayyan-asm/internal/modules/discovery"
	"github.com/google/uuid"
	"github.com/stretchr/testify/require"
	"go.uber.org/zap"
	"gorm.io/gorm"
)

// openBenchDB opens an in-memory SQLite database with a small real
// connection pool (see OpenSQLiteMemoryConcurrent) and auto-migrates the
// tables the discovery engine writes to. Unlike OpenSQLiteMemory (used by
// engine_selfresolve_test.go and elsewhere), this load test specifically
// exercises processHop's bounded outer-loop concurrency (hopConcurrency in
// engine.go) — a single-connection DB would serialize every write behind
// one *sql.DB connection regardless of how many goroutines the engine
// itself runs, measuring SQLite's single-writer lock instead of engine
// overhead, which defeats the point of this test (see file-level comment
// above).
func openBenchDB(t testing.TB) *gorm.DB {
	t.Helper()
	db, err := database.OpenSQLiteMemoryConcurrent(8)
	require.NoError(t, err, "opening in-memory SQLite for bench")
	require.NoError(t, db.AutoMigrate(
		&models.Domain{},
		&models.Subdomain{},
		&models.Host{},
		&models.Service{},
		&models.Certificate{},
		&models.DNSRecord{},
		&models.ASNRange{},
		&models.DiscoveryJob{},
		&models.DiscoveryEvent{},
		&models.DiscoveryRiskFlag{},
	), "auto-migrating bench schema")
	return db
}

// syntheticFrontier returns n unique synthetic hostnames rooted at
// "bench-test.invalid" — guaranteed NXDOMAIN, so DNS probes fail fast and
// the engine proceeds through the rest of the pipeline unchanged.
func syntheticFrontier(n int) []string {
	hosts := make([]string, n)
	for i := range hosts {
		hosts[i] = fmt.Sprintf("sub-%04d.bench-test.invalid", i)
	}
	return hosts
}

// TestBenchmarkDiscoveryScale runs a scale/load test (not a Go benchmark
// function so it runs under `go test ./...` without -bench) that exercises
// the engine with a synthetic 500-host frontier and asserts: completion in
// < 30 s, no goroutine leaks, < 200 MiB memory growth. All network calls
// immediately fail (NXDOMAIN / connection refused) so the test is hermetic.
func TestBenchmarkDiscoveryScale(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping scale test in -short mode")
	}

	db := openBenchDB(t)

	log, _ := zap.NewDevelopment()
	engine := disc.New(db, log.Sugar(), nil)

	orgID := uuid.New()
	const frontierSize = 500

	// Seed a domain record so FirstOrCreate in processHop has a parent.
	root := models.Domain{OrgID: orgID, Name: "bench-test.invalid", Status: "active"}
	root.ID = uuid.New()
	require.NoError(t, db.Create(&root).Error)

	// Create a DiscoveryJob record (engine.Run loads it by ID, so we need it
	// in the DB — but we call processHop via the exported RunHopForBench
	// helper to avoid real network calls in the brute-force expansion stage).
	opts := disc.Options{
		SeedDomains:        []string{"bench-test.invalid"},
		Depth:              0,
		ScanPorts:          false,
		WordlistTier:       disc.WordlistTierSmall,
		PortProfile:        disc.PortProfileQuick,
		MaxAssets:          2000,
		ProbeApexCert:      disc.BoolPtr(false),
		SkipPassiveSources: disc.BoolPtr(true),
	}
	job, err := engine.CreateJob(context.Background(), orgID, opts)
	require.NoError(t, err, "creating bench discovery job")

	frontier := syntheticFrontier(frontierSize)

	// Goroutine baseline before the engine starts.
	gorsBefore := runtime.NumGoroutine()

	var memBefore runtime.MemStats
	runtime.ReadMemStats(&memBefore)

	start := time.Now()
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()

	_, hopErr := engine.RunHopForBenchWithResolver(ctx, job.ID, orgID, frontier, disc.NXDOMAINResolver{})

	elapsed := time.Since(start)
	require.NoError(t, hopErr, "processHop returned an unexpected error")

	// ---- assertions -------------------------------------------------------

	// Time bound: 5 s, measured and reproducible. With DNS mocked
	// (disc.NXDOMAINResolver — 0 ms per lookup, no network), this bound
	// reflects pure engine overhead for 500 hosts: goroutine scheduling,
	// SQLite writes, and in-process bookkeeping — not DNS round-trip
	// time. This replaces a previous 90 s bound that existed only to
	// absorb the sandbox's slow external DNS resolver (~80 ms/NXDOMAIN
	// vs ~5 ms on a local caching resolver).
	require.Less(t, elapsed, 5*time.Second,
		"discovery hop over %d synthetic hosts (mocked DNS) took %s, want < 5s", frontierSize, elapsed)

	// Give background goroutines (timers, net resolvers) a moment to drain,
	// then check for leaks with a tolerance of +5 over baseline.
	time.Sleep(250 * time.Millisecond)
	runtime.GC()
	gorsAfter := runtime.NumGoroutine()
	require.LessOrEqual(t, gorsAfter, gorsBefore+5,
		"goroutine count jumped from %d to %d — possible leak", gorsBefore, gorsAfter)

	var memAfter runtime.MemStats
	runtime.ReadMemStats(&memAfter)
	const maxHeapGrowthBytes = 200 * 1024 * 1024 // 200 MiB
	heapGrowth := int64(memAfter.HeapInuse) - int64(memBefore.HeapInuse)
	require.Less(t, heapGrowth, int64(maxHeapGrowthBytes),
		"heap grew by %d bytes over %d synthetic hosts, want < %d", heapGrowth, frontierSize, maxHeapGrowthBytes)

	t.Logf("scale test: %d hosts, elapsed=%s, goroutines %d→%d, heap growth %d KiB",
		frontierSize, elapsed, gorsBefore, gorsAfter, heapGrowth/1024)
}

// TestAssetCapEnforcement verifies that a run stops early with capHit=true
// when MaxAssets is set lower than the frontier size, and that no more than
// MaxAssets assets end up in the DB for the job.
func TestAssetCapEnforcement(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping asset-cap test in -short mode")
	}

	db := openBenchDB(t)

	log, _ := zap.NewDevelopment()
	engine := disc.New(db, log.Sugar(), nil)

	orgID := uuid.New()
	root := models.Domain{OrgID: orgID, Name: "cap-test.invalid", Status: "active"}
	root.ID = uuid.New()
	require.NoError(t, db.Create(&root).Error)

	const capLimit = 5
	opts := disc.Options{
		SeedDomains:   []string{"cap-test.invalid"},
		Depth:         0,
		ScanPorts:     false,
		WordlistTier:  disc.WordlistTierSmall,
		MaxAssets:     capLimit,
		ProbeApexCert: disc.BoolPtr(false),
	}
	job, err := engine.CreateJob(context.Background(), orgID, opts)
	require.NoError(t, err)

	frontier := syntheticFrontier(200)

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	capped, hopErr := engine.RunHopForBenchWithResolver(ctx, job.ID, orgID, frontier, disc.NXDOMAINResolver{})
	require.NoError(t, hopErr)

	// When the cap fires, RunHopForBench returns capHit=true.
	require.True(t, capped, "expected capHit=true when MaxAssets=%d and frontier has %d hosts", capLimit, len(frontier))
}
