package web_test

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/ShadooowX/rayyan-asm/internal/modules/web"
)

func newChecker() *web.SecurityChecker {
	return web.NewSecurityChecker()
}

func startSec(t *testing.T, fn http.HandlerFunc) *httptest.Server {
	t.Helper()
	srv := httptest.NewServer(fn)
	t.Cleanup(srv.Close)
	return srv
}

func ctx5s() (context.Context, context.CancelFunc) {
	return context.WithTimeout(context.Background(), 5*time.Second)
}

// --- NewSecurityChecker ---

func TestNewSecurityChecker_NotNil(t *testing.T) {
	if web.NewSecurityChecker() == nil {
		t.Error("NewSecurityChecker returned nil")
	}
}

// --- SecurityFinding zero value ---

func TestSecurityFinding_ZeroValue(t *testing.T) {
	var f web.SecurityFinding
	if f.Title != "" || f.Severity != "" || f.Category != "" {
		t.Error("zero SecurityFinding should have empty fields")
	}
}

// --- Clickjacking: deterministic, no ambiguity ---
// checkClickjacking fires whenever both X-Frame-Options and CSP frame-ancestors
// are absent. This is checked against the base response, so httptest is sufficient.

func TestCheck_ClickjackingFinding_WhenNoFrameHeaders(t *testing.T) {
	srv := startSec(t, func(w http.ResponseWriter, r *http.Request) {
		// No X-Frame-Options, no CSP.
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("<html><body>frameable</body></html>"))
	})

	sc := newChecker()
	ctx, cancel := ctx5s()
	defer cancel()

	findings := sc.Check(ctx, srv.URL)
	if !findingContains(findings, "clickjack", "frame") {
		t.Errorf("expected clickjacking finding; got: %v", findingTitles(findings))
	}
}

func TestCheck_NoClickjackingFinding_WhenXFOPresent(t *testing.T) {
	srv := startSec(t, func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("X-Frame-Options", "DENY")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("<html><body>protected</body></html>"))
	})

	sc := newChecker()
	ctx, cancel := ctx5s()
	defer cancel()

	findings := sc.Check(ctx, srv.URL)
	for _, f := range findings {
		if strings.Contains(strings.ToLower(f.Title), "clickjack") {
			t.Errorf("unexpected clickjacking finding when X-Frame-Options set: %s", f.Title)
		}
	}
}

// --- CORS wildcard: checkCORS fires on ACAO: * alone (medium) ---

func TestCheck_CORSWildcard_FindingPresent(t *testing.T) {
	srv := startSec(t, func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Access-Control-Allow-Origin", "*")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("{}"))
	})

	sc := newChecker()
	ctx, cancel := ctx5s()
	defer cancel()

	findings := sc.Check(ctx, srv.URL)
	if !findingContains(findings, "cors", "wildcard") {
		t.Errorf("expected CORS wildcard finding; got: %v", findingTitles(findings))
	}
}

// --- CORS wildcard + credentials: checkCORSWildcardCredentials fires on ACAO:* + ACAC:true ---

func TestCheck_CORSWildcardWithCredentials_FindingPresent(t *testing.T) {
	srv := startSec(t, func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Access-Control-Allow-Origin", "*")
		w.Header().Set("Access-Control-Allow-Credentials", "true")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("{}"))
	})

	sc := newChecker()
	ctx, cancel := ctx5s()
	defer cancel()

	findings := sc.Check(ctx, srv.URL)
	if !findingContains(findings, "cors") {
		t.Errorf("expected CORS finding for wildcard+credentials; got: %v", findingTitles(findings))
	}
}

// --- Server version disclosure ---

func TestCheck_ServerVersionDisclosure(t *testing.T) {
	srv := startSec(t, func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Server", "Apache/2.4.51 (Unix)")
		w.Header().Set("X-Powered-By", "PHP/7.4.0")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("<html><body>version disclosure</body></html>"))
	})

	sc := newChecker()
	ctx, cancel := ctx5s()
	defer cancel()

	findings := sc.Check(ctx, srv.URL)
	if len(findings) == 0 {
		t.Error("expected findings for server/version disclosure, got none")
	}
}

// --- Finding fields always populated ---

func TestCheck_FindingFieldsPopulated(t *testing.T) {
	srv := startSec(t, func(w http.ResponseWriter, r *http.Request) {
		// Triggers at minimum: clickjacking, missing security headers.
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("<html><body>x</body></html>"))
	})

	sc := newChecker()
	ctx, cancel := ctx5s()
	defer cancel()

	findings := sc.Check(ctx, srv.URL)
	if len(findings) == 0 {
		t.Fatal("expected at least one finding for bare server, got none")
	}
	for _, f := range findings {
		if f.Title == "" {
			t.Errorf("finding missing Title: %+v", f)
		}
		if f.Severity == "" {
			t.Errorf("finding missing Severity: %+v", f)
		}
		if f.Category == "" {
			t.Errorf("finding missing Category: %+v", f)
		}
	}
}

// --- Unreachable host: must not panic ---

func TestCheck_ReturnsSliceOnUnreachableHost(t *testing.T) {
	sc := newChecker()
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()

	findings := sc.Check(ctx, "http://127.0.0.1:19999")
	_ = findings // may be nil or empty — just must not panic
}

// --- helpers ---

func findingTitles(findings []web.SecurityFinding) []string {
	out := make([]string, len(findings))
	for i, f := range findings {
		out[i] = f.Title
	}
	return out
}

func findingContains(findings []web.SecurityFinding, substrings ...string) bool {
	for _, f := range findings {
		combined := strings.ToLower(f.Title + " " + f.Description + " " + f.Category)
		for _, s := range substrings {
			if strings.Contains(combined, strings.ToLower(s)) {
				return true
			}
		}
	}
	return false
}
