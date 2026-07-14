package modules

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/ShadooowX/rayyan-asm/internal/models"
	"github.com/ShadooowX/rayyan-asm/internal/modules/cloud"
	"github.com/google/uuid"
)

// newSubdomainChainTestDispatcher is like newTestDispatcher but also
// migrates Subdomain + ScanResult, which persistSubdomainResult needs.
func newSubdomainChainTestDispatcher(t *testing.T) (*Dispatcher, func()) {
	t.Helper()
	d, cleanup := newTestDispatcher(t)
	if err := d.db.AutoMigrate(&models.Subdomain{}, &models.ScanResult{}); err != nil {
		t.Fatalf("AutoMigrate: %v", err)
	}
	return d, cleanup
}

func seedTestDomain(t *testing.T, d *Dispatcher, orgID uuid.UUID, name string) models.Domain {
	t.Helper()
	dom := models.Domain{OrgID: orgID, Name: name}
	dom.ID = uuid.New()
	if err := d.db.Create(&dom).Error; err != nil {
		t.Fatalf("seed domain: %v", err)
	}
	return dom
}

// ── persistSubdomainResult ───────────────────────────────────────────────

func TestPersistSubdomainResult_CreatesNewRow(t *testing.T) {
	d, cleanup := newSubdomainChainTestDispatcher(t)
	defer cleanup()
	orgID := seedOrg(t, d)
	dom := seedTestDomain(t, d, orgID, "example.com")
	scanJob := &models.ScanJob{OrgID: orgID}
	scanJob.ID = uuid.New()

	ok := d.persistSubdomainResult(scanJob, dom, "example.com", "api.example.com", []string{"1.2.3.4"}, "subfinder")
	if !ok {
		t.Fatal("persistSubdomainResult: expected true for a new subdomain")
	}

	var sub models.Subdomain
	if err := d.db.Where("org_id = ? AND fqdn = ?", orgID, "api.example.com").First(&sub).Error; err != nil {
		t.Fatalf("expected subdomain row to exist: %v", err)
	}
	if sub.Name != "api" {
		t.Errorf("sub.Name = %q, want %q", sub.Name, "api")
	}
	if sub.Source != "subfinder" {
		t.Errorf("sub.Source = %q, want %q", sub.Source, "subfinder")
	}
}

func TestPersistSubdomainResult_DedupsAcrossSources(t *testing.T) {
	d, cleanup := newSubdomainChainTestDispatcher(t)
	defer cleanup()
	orgID := seedOrg(t, d)
	dom := seedTestDomain(t, d, orgID, "example.com")
	scanJob := &models.ScanJob{OrgID: orgID}
	scanJob.ID = uuid.New()

	d.persistSubdomainResult(scanJob, dom, "example.com", "www.example.com", nil, "crtsh")
	d.persistSubdomainResult(scanJob, dom, "example.com", "www.example.com", nil, "subfinder")
	d.persistSubdomainResult(scanJob, dom, "example.com", "WWW.EXAMPLE.COM", nil, "amass")

	var count int64
	d.db.Model(&models.Subdomain{}).Where("org_id = ? AND fqdn = ?", orgID, "www.example.com").Count(&count)
	if count != 1 {
		t.Fatalf("expected exactly 1 row after 3 discoveries of the same FQDN (case-insensitive), got %d", count)
	}

	// First discoverer's source should win — matches the existing
	// crt.sh/hackertarget/wordlist behavior where Assign() never touches
	// Source, only later-seen fields like LastSeenAt.
	var sub models.Subdomain
	d.db.Where("org_id = ? AND fqdn = ?", orgID, "www.example.com").First(&sub)
	if sub.Source != "crtsh" {
		t.Errorf("sub.Source = %q, want %q (first discoverer preserved)", sub.Source, "crtsh")
	}
}

func TestPersistSubdomainResult_EmptyFQDNSkipped(t *testing.T) {
	d, cleanup := newSubdomainChainTestDispatcher(t)
	defer cleanup()
	orgID := seedOrg(t, d)
	dom := seedTestDomain(t, d, orgID, "example.com")
	scanJob := &models.ScanJob{OrgID: orgID}
	scanJob.ID = uuid.New()

	if d.persistSubdomainResult(scanJob, dom, "example.com", "", nil, "subfinder") {
		t.Fatal("persistSubdomainResult: expected false for an empty FQDN")
	}
}

// ── chainExtraSubdomainSources ───────────────────────────────────────────

func TestChainExtraSubdomainSources_NoopWhenNothingConfigured(t *testing.T) {
	d, cleanup := newSubdomainChainTestDispatcher(t)
	defer cleanup()
	orgID := seedOrg(t, d)
	dom := seedTestDomain(t, d, orgID, "example.com")
	scanJob := &models.ScanJob{OrgID: orgID}
	scanJob.ID = uuid.New()

	// Wayback runs unconditionally (no API key gate, like crt.sh), so it
	// still needs a redirected base URL here to stay deterministic and
	// offline — point it at a server returning "no matches" (header row
	// only) rather than relying on the real web.archive.org.
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`[["original"]]`))
	}))
	defer srv.Close()
	restore := cloud.WaybackBaseURL
	cloud.WaybackBaseURL = srv.URL
	defer func() { cloud.WaybackBaseURL = restore }()

	// No tools installed in this test environment, no intel engine set,
	// no VT key set, and Wayback returns zero matches — every source
	// should be skipped gracefully rather than erroring or panicking.
	total := d.chainExtraSubdomainSources(context.Background(), scanJob, dom, "example.com")
	if total != 0 {
		t.Errorf("chainExtraSubdomainSources: expected 0 with nothing configured, got %d", total)
	}
}

func TestChainExtraSubdomainSources_Wayback(t *testing.T) {
	d, cleanup := newSubdomainChainTestDispatcher(t)
	defer cleanup()
	orgID := seedOrg(t, d)
	dom := seedTestDomain(t, d, orgID, "example.com")
	scanJob := &models.ScanJob{OrgID: orgID}
	scanJob.ID = uuid.New()

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`[
			["original"],
			["https://old.example.com/path"],
			["http://staging.example.com/"],
			["https://staging.example.com/other-page"],
			["https://notrelated.com/"]
		]`))
	}))
	defer srv.Close()

	restore := cloud.WaybackBaseURL
	cloud.WaybackBaseURL = srv.URL
	defer func() { cloud.WaybackBaseURL = restore }()

	total := d.chainExtraSubdomainSources(context.Background(), scanJob, dom, "example.com")
	// old.example.com + staging.example.com (deduped across its 2 archived
	// URLs) — notrelated.com must be filtered out as off-domain.
	if total != 2 {
		t.Fatalf("chainExtraSubdomainSources: expected 2 wayback subdomains persisted, got %d", total)
	}

	var count int64
	d.db.Model(&models.Subdomain{}).Where("org_id = ? AND source = ?", orgID, "wayback").Count(&count)
	if count != 2 {
		t.Errorf("expected 2 subdomain rows tagged source=wayback, got %d", count)
	}
}

func TestChainExtraSubdomainSources_VirusTotal(t *testing.T) {
	d, cleanup := newSubdomainChainTestDispatcher(t)
	defer cleanup()
	orgID := seedOrg(t, d)
	dom := seedTestDomain(t, d, orgID, "example.com")
	scanJob := &models.ScanJob{OrgID: orgID}
	scanJob.ID = uuid.New()

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"data":[{"id":"vt.example.com"},{"id":"mail.example.com"}]}`))
	}))
	defer srv.Close()

	restore := cloud.VirusTotalBaseURL
	cloud.VirusTotalBaseURL = srv.URL
	defer func() { cloud.VirusTotalBaseURL = restore }()

	wbSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`[["original"]]`))
	}))
	defer wbSrv.Close()
	restoreWB := cloud.WaybackBaseURL
	cloud.WaybackBaseURL = wbSrv.URL
	defer func() { cloud.WaybackBaseURL = restoreWB }()

	d.vtAPIKey = "test-key"
	total := d.chainExtraSubdomainSources(context.Background(), scanJob, dom, "example.com")
	if total != 2 {
		t.Fatalf("chainExtraSubdomainSources: expected 2 VirusTotal subdomains persisted, got %d", total)
	}

	var count int64
	d.db.Model(&models.Subdomain{}).Where("org_id = ? AND source = ?", orgID, "virustotal").Count(&count)
	if count != 2 {
		t.Errorf("expected 2 subdomain rows tagged source=virustotal, got %d", count)
	}
}
