package discovery

import (
	"context"
	"encoding/json"
	"net"
	"net/http"
	"net/http/httptest"
	"reflect"
	"sort"
	"testing"
	"time"

	"go.uber.org/zap"
)

// TestQueryWaybackURLs_HermeticHTTPServer exercises queryWaybackURLs
// end-to-end against an httptest.Server serving a canned CDX JSON
// response — no network needed. waybackBaseURL (providers.go) is
// test-overridable for exactly this purpose: it's restored after the
// test so other tests/production code keep hitting the real Wayback
// Machine CDX API at https://web.archive.org.
func TestQueryWaybackURLs_HermeticHTTPServer(t *testing.T) {
	canned := [][]string{
		{"original"}, // CDX header row
		{"http://api.example.com/v1/health"},
		{"https://OLD.example.com/path?x=1"},
		{"http://api.example.com/v1/dup"}, // duplicate host, different path
		{"https://unrelated.other.com/"},  // out of scope, must be filtered
	}

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/cdx/search/cdx" {
			t.Errorf("unexpected request path %q", r.URL.Path)
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(canned)
	}))
	defer srv.Close()

	prevBaseURL := waybackBaseURL
	waybackBaseURL = srv.URL
	defer func() { waybackBaseURL = prevBaseURL }()

	log, _ := zap.NewDevelopment()
	hosts, err := queryWaybackURLs(context.Background(), "example.com", log.Sugar())
	if err != nil {
		t.Fatalf("queryWaybackURLs against hermetic test server: %v", err)
	}

	want := []string{"api.example.com", "old.example.com"}
	sort.Strings(hosts)
	if !reflect.DeepEqual(hosts, want) {
		t.Errorf("queryWaybackURLs hosts = %v, want %v", hosts, want)
	}
}

// TestQueryWaybackURLs_NonOKStatusIsError covers the graceful-degradation
// path: a non-200 CDX response (e.g. the 403 the sandbox saw against the
// real API) must surface as an error rather than panicking or returning
// spurious hosts, so callers can log-and-continue per the package's
// best-effort convention.
func TestQueryWaybackURLs_NonOKStatusIsError(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusForbidden)
	}))
	defer srv.Close()

	prevBaseURL := waybackBaseURL
	waybackBaseURL = srv.URL
	defer func() { waybackBaseURL = prevBaseURL }()

	log, _ := zap.NewDevelopment()
	hosts, err := queryWaybackURLs(context.Background(), "example.com", log.Sugar())
	if err == nil {
		t.Fatal("expected an error for a non-200 CDX response, got nil")
	}
	if len(hosts) != 0 {
		t.Errorf("expected no hosts on error, got %v", hosts)
	}
}

// TestQueryWaybackURLs_MalformedJSONIsError covers a CDX response that
// returns 200 but with a body that isn't the expected array-of-arrays
// shape — must surface as a decode error, not a panic.
func TestQueryWaybackURLs_MalformedJSONIsError(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"not": "an array of arrays"}`))
	}))
	defer srv.Close()

	prevBaseURL := waybackBaseURL
	waybackBaseURL = srv.URL
	defer func() { waybackBaseURL = prevBaseURL }()

	log, _ := zap.NewDevelopment()
	_, err := queryWaybackURLs(context.Background(), "example.com", log.Sugar())
	if err == nil {
		t.Fatal("expected a decode error for malformed CDX JSON, got nil")
	}
}

// TestFetchLiveCert_HonorsContextCancellation proves fetchLiveCert's TLS
// dial actually stops when its ctx is cancelled, instead of riding out
// its own internal timeout regardless of the caller's deadline.
//
// Regression coverage: fetchLiveCert took a ctx parameter but never
// passed it to either of its two tls.DialWithDialer calls, so callers
// that cancel ctx — including the queue worker's 30-minute per-job
// timeout and its shutdown-triggered context cancellation in
// internal/queue/queue.go — couldn't actually cut off a dial already in
// flight; it kept blocking for its own fixed 8s/5s timeout regardless.
// fetchLiveCert now uses tls.Dialer.DialContext, which does respect ctx.
//
// The listener here accepts the TCP connection but never writes a TLS
// ServerHello, so the handshake hangs indefinitely; the test deliberately
// cancels ctx well before fetchLiveCert's own 8s dial timeout would fire,
// so the only way this test can pass quickly is if cancellation is
// actually wired through — proving the fix rather than asserting it.
func TestFetchLiveCert_HonorsContextCancellation(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("failed to start test listener: %v", err)
	}
	defer ln.Close()

	accepted := make(chan struct{})
	go func() {
		conn, acceptErr := ln.Accept()
		close(accepted)
		if acceptErr != nil {
			return
		}
		// Hold the connection open without ever speaking TLS, so a real
		// handshake attempt blocks until the dial/ctx is cancelled — not
		// until the server says something.
		<-accepted
		_ = conn
	}()

	addr := ln.Addr().(*net.TCPAddr)

	ctx, cancel := context.WithTimeout(context.Background(), 300*time.Millisecond)
	defer cancel()

	start := time.Now()
	_, err = fetchLiveCert(ctx, "127.0.0.1", addr.Port)
	elapsed := time.Since(start)

	if err == nil {
		t.Fatal("expected fetchLiveCert to fail against a non-TLS-speaking listener, got nil error")
	}
	// fetchLiveCert's own internal dial timeout is 8s; if cancellation
	// weren't wired through, this would take ~8s instead of ~300ms. Give
	// generous slack (well under 8s) so the test isn't flaky under load
	// while still clearly distinguishing "ctx worked" from "ctx ignored".
	if elapsed > 3*time.Second {
		t.Errorf("fetchLiveCert took %v after a 300ms context timeout; "+
			"expected it to return promptly once ctx was cancelled, not "+
			"ride out its own internal dial timeout", elapsed)
	}
}
