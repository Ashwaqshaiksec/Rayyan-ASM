package discovery

// export_test.go exports internal engine methods and types for use in
// _test.go files in this package only (the file is in package "discovery"
// not "discovery_test" so it can reach unexported symbols, but Go only
// compiles it during `go test` so it never appears in the production
// binary). This is the standard Go pattern for test-only access to
// package internals without a separate testexport package.

import (
	"context"
	"net"
	"runtime"
	"strings"

	"github.com/ShadooowX/rayyan-asm/internal/models"
	"github.com/google/uuid"
	"go.uber.org/zap"
)

// CreateJob is exported for bench/integration tests so they can create a
// DiscoveryJob record without reaching through the REST API layer.
func (e *Engine) CreateJob(ctx context.Context, orgID uuid.UUID, opts Options) (*models.DiscoveryJob, error) {
	return e.createJob(ctx, orgID, opts)
}

// RunHopForBench runs exactly one processHop against the given frontier on
// an already-created DiscoveryJob and returns (capHit, error), using the
// real (network) DNS resolver. It constructs its runState via the same
// newRunState helper Run() uses, so the bench test exercises the real
// engine code, not a stub. capHit=true means the per-run asset cap was
// reached during the hop.
func (e *Engine) RunHopForBench(ctx context.Context, jobID, orgID uuid.UUID, frontier []string) (capHit bool, err error) {
	return e.RunHopForBenchWithResolver(ctx, jobID, orgID, frontier, defaultResolver{})
}

// RunHopForBenchWithResolver is RunHopForBench with an injectable
// Resolver, letting the hermetic scale/bench test supply a mock that
// returns canned (e.g. instant NXDOMAIN) responses instead of hitting
// real DNS — see Resolver in providers.go. Both this and Run() build
// their runState via newRunState, so the mock is exercised by the exact
// same code path (runState.resolveHost / runState.reverseDNSLookup) that
// production uses, not a separate stub branch. scanPorts always comes
// from the job's options here, matching Run()'s behavior; bench tests
// that want no port scanning should pass ScanPorts: false in Options.
func (e *Engine) RunHopForBenchWithResolver(ctx context.Context, jobID, orgID uuid.UUID, frontier []string, resolver Resolver) (capHit bool, err error) {
	var job models.DiscoveryJob
	if err := e.db.First(&job, "id = ?", jobID).Error; err != nil {
		return false, err
	}

	run := newRunState(e, &job)
	if resolver != nil {
		run.resolver = resolver
	}
	for _, d := range job.SeedDomains {
		run.seedDomains[strings.ToLower(d)] = true
	}

	_, hopErr := run.processHop(ctx, frontier, 0)
	return run.capReached(), hopErr
}

// NXDOMAINResolver is a Resolver that returns NXDOMAIN-equivalent errors
// instantly for every lookup — no real DNS, no network, 0ms latency. Used
// by the hermetic scale/bench test (engine_bench_test.go) so its timing
// assertions measure pure engine overhead rather than DNS RTT.
type NXDOMAINResolver struct{}

// errNXDOMAIN mirrors the shape of a real resolver's "no such host" error
// closely enough for callers that only check err == nil / err != nil
// (which is everywhere in this package — DNS failures are expected and
// handled by simply not recursing on that candidate).
var errNXDOMAIN = &net.DNSError{Err: "no such host", IsNotFound: true}

func (NXDOMAINResolver) ResolveHost(_ context.Context, _ string) ([]string, error) {
	return nil, errNXDOMAIN
}

func (NXDOMAINResolver) ReverseDNSLookup(_ context.Context, _ string) ([]string, error) {
	return nil, errNXDOMAIN
}

// Integration test helpers (expose internal functions by their real names).

// QueryCTLogsForTest exposes queryCTLogs for integration tests.
func QueryCTLogsForTest(ctx context.Context, domain string, log *zap.SugaredLogger) ([]CTEntry, error) {
	return queryCTLogs(ctx, domain, log)
}

// HostnamesFromCTForTest exposes hostnamesFromCT for integration tests.
func HostnamesFromCTForTest(entries []CTEntry, domain string) ([]string, []string) {
	return hostnamesFromCT(entries, domain)
}

// QueryWaybackURLsForTest exposes queryWaybackURLs for integration tests.
func QueryWaybackURLsForTest(ctx context.Context, domain string, log *zap.SugaredLogger) ([]string, error) {
	return queryWaybackURLs(ctx, domain, log)
}

// RootOfForTest exposes rootOf (now PSL-backed) for integration tests.
func RootOfForTest(fqdn string) string {
	return rootOf(fqdn)
}

// NumGoroutinesForTest is used by integration tests (package discovery_test)
// to check for goroutine leaks — they can't call runtime directly through
// the unexported numGoroutines.
func NumGoroutinesForTest() int {
	return numGoroutines()
}

// numGoroutines is used by integration tests to check for goroutine leaks.
func numGoroutines() int {
	return runtime.NumGoroutine()
}
