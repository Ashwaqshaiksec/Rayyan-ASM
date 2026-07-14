package intelligence_test

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
	"time"

	"github.com/ShadooowX/rayyan-asm/internal/config"
	"github.com/ShadooowX/rayyan-asm/internal/database"
	"github.com/ShadooowX/rayyan-asm/internal/models"
	"github.com/ShadooowX/rayyan-asm/internal/modules/intelligence"
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

func newEngine(db *gorm.DB, cfg intelligence.Config) *intelligence.Engine {
	return intelligence.New(db, zap.NewNop().Sugar(), cfg)
}

// shodanOKHandler returns a minimal valid Shodan host JSON response.
func shodanOKHandler(ip string) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		fmt.Fprintf(w, `{"ip_str":%q,"hostnames":[],"org":"TestOrg","isp":"TestISP",`+
			`"country_name":"US","city":"NYC","asn":"AS1234","os":null,`+
			`"ports":[80,443],"tags":[],"data":[],"vulns":{}}`, ip)
	}
}

// censysOKHandler returns a minimal valid Censys host JSON response.
func censysOKHandler(ip string) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		fmt.Fprintf(w, `{"result":{"ip":%q,"autonomous_system":{"asns":1234},"services":[]}}`, ip)
	}
}

// errorHandler always returns 500.
func errorHandler(w http.ResponseWriter, r *http.Request) {
	http.Error(w, "internal error", http.StatusInternalServerError)
}

// ─── EnrichHost: both providers fail ─────────────────────────────────────

func TestEnrichHost_BothProvidersFail(t *testing.T) {
	shodanSrv := httptest.NewServer(http.HandlerFunc(errorHandler))
	defer shodanSrv.Close()
	censysSrv := httptest.NewServer(http.HandlerFunc(errorHandler))
	defer censysSrv.Close()

	prev1 := *intelligence.ShodanBaseURL
	prev2 := *intelligence.CensysBaseURL
	*intelligence.ShodanBaseURL = shodanSrv.URL
	*intelligence.CensysBaseURL = censysSrv.URL
	defer func() {
		*intelligence.ShodanBaseURL = prev1
		*intelligence.CensysBaseURL = prev2
	}()

	db := newTestDB(t)
	e := newEngine(db, intelligence.Config{ShodanKey: "k", CensysID: "id", CensysSecret: "sec"})

	_, err := e.EnrichHost(context.Background(), uuid.New(), "1.2.3.4")
	require.Error(t, err)
	require.Contains(t, err.Error(), "shodan")
	require.Contains(t, err.Error(), "censys")
}

// ─── EnrichHost: one succeeds, one fails (partial success) ───────────────

func TestEnrichHost_PartialSuccess(t *testing.T) {
	shodanSrv := httptest.NewServer(shodanOKHandler("1.2.3.4"))
	defer shodanSrv.Close()
	censysSrv := httptest.NewServer(http.HandlerFunc(errorHandler))
	defer censysSrv.Close()

	prev1 := *intelligence.ShodanBaseURL
	prev2 := *intelligence.CensysBaseURL
	*intelligence.ShodanBaseURL = shodanSrv.URL
	*intelligence.CensysBaseURL = censysSrv.URL
	defer func() {
		*intelligence.ShodanBaseURL = prev1
		*intelligence.CensysBaseURL = prev2
	}()

	db := newTestDB(t)
	e := newEngine(db, intelligence.Config{ShodanKey: "k", CensysID: "id", CensysSecret: "sec"})

	results, err := e.EnrichHost(context.Background(), uuid.New(), "1.2.3.4")
	require.NoError(t, err, "partial success must not return error")
	require.NotEmpty(t, results)
	require.Equal(t, "shodan", results[0].Provider)
}

// ─── EnrichDomain: both providers fail ───────────────────────────────────

func TestEnrichDomain_BothProvidersFail(t *testing.T) {
	htSrv := httptest.NewServer(http.HandlerFunc(errorHandler))
	defer htSrv.Close()

	prev := *intelligence.HackerTargetBaseURL
	*intelligence.HackerTargetBaseURL = htSrv.URL
	defer func() { *intelligence.HackerTargetBaseURL = prev }()

	db := newTestDB(t)
	// No ST key → only HackerTarget path runs (returns 500) → error.
	e := newEngine(db, intelligence.Config{})

	_, err := e.EnrichDomain(context.Background(), uuid.New(), "example.com")
	require.Error(t, err)
}

// ─── EnrichDomain: one succeeds, one fails ───────────────────────────────

func TestEnrichDomain_PartialSuccess(t *testing.T) {
	stSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/v1/domain/example.com/subdomains" {
			w.Header().Set("Content-Type", "application/json")
			fmt.Fprint(w, `{"subdomains":["www","api"],"endpoint":"/v1/domain/example.com/subdomains"}`)
			return
		}
		http.Error(w, "not found", http.StatusInternalServerError)
	}))
	defer stSrv.Close()

	prev := *intelligence.SecurityTrailsBaseURL
	*intelligence.SecurityTrailsBaseURL = stSrv.URL
	defer func() { *intelligence.SecurityTrailsBaseURL = prev }()

	db := newTestDB(t)
	org := models.Organization{Name: "Test", Slug: "test"}
	require.NoError(t, db.Create(&org).Error)
	dom := models.Domain{OrgID: org.ID, Name: "example.com", Status: "active"}
	require.NoError(t, db.Create(&dom).Error)

	e := newEngine(db, intelligence.Config{SecurityTrailsKey: "stkey"})

	results, err := e.EnrichDomain(context.Background(), org.ID, "example.com")
	require.NoError(t, err)
	require.NotEmpty(t, results)
}

// ─── RunDueMonitorJobs: Providers=["shodan"] only hits Shodan ────────────

func TestRunDueMonitorJobs_ShodanOnlyProvider(t *testing.T) {
	var shodanHits, censysHits int32

	shodanSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt32(&shodanHits, 1)
		shodanOKHandler("10.0.0.1")(w, r)
	}))
	defer shodanSrv.Close()

	censysSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt32(&censysHits, 1)
		censysOKHandler("10.0.0.1")(w, r)
	}))
	defer censysSrv.Close()

	prev1 := *intelligence.ShodanBaseURL
	prev2 := *intelligence.CensysBaseURL
	*intelligence.ShodanBaseURL = shodanSrv.URL
	*intelligence.CensysBaseURL = censysSrv.URL
	defer func() {
		*intelligence.ShodanBaseURL = prev1
		*intelligence.CensysBaseURL = prev2
	}()

	db := newTestDB(t)
	org := models.Organization{Name: "Org", Slug: "org"}
	require.NoError(t, db.Create(&org).Error)

	e := newEngine(db, intelligence.Config{ShodanKey: "k", CensysID: "id", CensysSecret: "sec"})

	job := intelligence.MonitorJob{
		ID:         uuid.New(),
		OrgID:      org.ID,
		Target:     "10.0.0.1",
		TargetType: "host",
		Providers:  models.StringArray{"shodan"},
		Cadence:    "daily",
		Enabled:    true,
		NextRunAt:  time.Now().Add(-time.Hour),
	}
	require.NoError(t, db.Create(&job).Error)

	e.RunDueMonitorJobs(context.Background())

	require.Greater(t, int(atomic.LoadInt32(&shodanHits)), 0, "shodan must be called")
	require.Equal(t, int32(0), atomic.LoadInt32(&censysHits), "censys must not be called")
}

// ─── RunDueMonitorJobs: Providers empty → both host providers hit ─────────

func TestRunDueMonitorJobs_EmptyProvidersHitsBoth(t *testing.T) {
	var shodanHits, censysHits int32

	shodanSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt32(&shodanHits, 1)
		shodanOKHandler("10.0.0.2")(w, r)
	}))
	defer shodanSrv.Close()

	censysSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt32(&censysHits, 1)
		censysOKHandler("10.0.0.2")(w, r)
	}))
	defer censysSrv.Close()

	prev1 := *intelligence.ShodanBaseURL
	prev2 := *intelligence.CensysBaseURL
	*intelligence.ShodanBaseURL = shodanSrv.URL
	*intelligence.CensysBaseURL = censysSrv.URL
	defer func() {
		*intelligence.ShodanBaseURL = prev1
		*intelligence.CensysBaseURL = prev2
	}()

	db := newTestDB(t)
	org := models.Organization{Name: "Org2", Slug: "org2"}
	require.NoError(t, db.Create(&org).Error)

	e := newEngine(db, intelligence.Config{ShodanKey: "k", CensysID: "id", CensysSecret: "sec"})

	job := intelligence.MonitorJob{
		ID:         uuid.New(),
		OrgID:      org.ID,
		Target:     "10.0.0.2",
		TargetType: "host",
		Providers:  models.StringArray{},
		Cadence:    "daily",
		Enabled:    true,
		NextRunAt:  time.Now().Add(-time.Hour),
	}
	require.NoError(t, db.Create(&job).Error)

	e.RunDueMonitorJobs(context.Background())

	require.Greater(t, int(atomic.LoadInt32(&shodanHits)), 0, "shodan must be called with empty providers")
	require.Greater(t, int(atomic.LoadInt32(&censysHits)), 0, "censys must be called with empty providers")
}

// ─── enrichHistoricalDNS: HackerTarget rate-limit body → no row ──────────

func TestEnrichHistoricalDNS_HackerTargetRateLimitNotPersisted(t *testing.T) {
	htSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		fmt.Fprint(w, "API count exceeded - visit https://hackertarget.com/")
	}))
	defer htSrv.Close()

	prev := *intelligence.HackerTargetBaseURL
	*intelligence.HackerTargetBaseURL = htSrv.URL
	defer func() { *intelligence.HackerTargetBaseURL = prev }()

	db := newTestDB(t)
	// No ST key → only HackerTarget fallback runs.
	e := newEngine(db, intelligence.Config{})

	orgID := uuid.New()
	results, _ := e.EnrichDomain(context.Background(), orgID, "example.com")

	for _, r := range results {
		if r.Provider == "historical_dns" {
			t.Fatalf("rate-limit body must not be stored as IntelResult: %+v", r)
		}
	}

	var count int64
	db.Model(&intelligence.IntelResult{}).
		Where("org_id = ? AND provider = ?", orgID, "historical_dns").
		Count(&count)
	require.Equal(t, int64(0), count)
}

// ─── enrichCensys: malformed/truncated body → error, no panic ────────────

func TestEnrichCensys_MalformedBody_ReturnsError(t *testing.T) {
	for _, tc := range []struct {
		name    string
		handler http.HandlerFunc
	}{
		{
			name: "malformed_json",
			handler: func(w http.ResponseWriter, r *http.Request) {
				w.WriteHeader(http.StatusOK)
				fmt.Fprint(w, `not-valid-json`)
			},
		},
		{
			name: "truncated_body",
			handler: func(w http.ResponseWriter, r *http.Request) {
				hj, ok := w.(http.Hijacker)
				if !ok {
					w.WriteHeader(http.StatusOK)
					fmt.Fprint(w, `{"result":`) // incomplete JSON
					return
				}
				conn, buf, _ := hj.Hijack()
				_, _ = buf.WriteString("HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: 9999\r\n\r\n{\"result\":")
				_ = buf.Flush()
				_ = conn.Close()
			},
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			srv := httptest.NewServer(tc.handler)
			defer srv.Close()

			prev := *intelligence.CensysBaseURL
			*intelligence.CensysBaseURL = srv.URL
			defer func() { *intelligence.CensysBaseURL = prev }()

			db := newTestDB(t)
			// Shodan key empty → enrichShodan fails with "key not configured".
			// Censys gets malformed data → enrichCensys returns error.
			// All providers fail → EnrichHost returns error.
			e := newEngine(db, intelligence.Config{CensysID: "id", CensysSecret: "sec"})

			require.NotPanics(t, func() {
				_, err := e.EnrichHost(context.Background(), uuid.New(), "1.2.3.5")
				require.Error(t, err)
			})
		})
	}
}

// ─── ASN persistence (regression coverage for the fix below) ─────────────
//
// Both enrichShodan and enrichCensys used to parse an ASN out of the
// provider's response and then throw it away — never used anywhere except
// a summary string that wasn't even shown for Shodan. These tests confirm
// EnrichHost now actually writes ASN/ASNOrg onto an existing Host row.

func TestEnrichHost_Shodan_PersistsASNToExistingHost(t *testing.T) {
	shodanSrv := httptest.NewServer(shodanOKHandler("1.2.3.4"))
	defer shodanSrv.Close()
	censysSrv := httptest.NewServer(http.HandlerFunc(errorHandler))
	defer censysSrv.Close()

	prev1 := *intelligence.ShodanBaseURL
	prev2 := *intelligence.CensysBaseURL
	*intelligence.ShodanBaseURL = shodanSrv.URL
	*intelligence.CensysBaseURL = censysSrv.URL
	defer func() {
		*intelligence.ShodanBaseURL = prev1
		*intelligence.CensysBaseURL = prev2
	}()

	db := newTestDB(t)
	orgID := uuid.New()
	host := models.Host{OrgID: orgID, IP: "1.2.3.4", Status: "active"}
	require.NoError(t, db.Create(&host).Error)

	e := newEngine(db, intelligence.Config{ShodanKey: "k"})
	_, err := e.EnrichHost(context.Background(), orgID, "1.2.3.4")
	require.NoError(t, err)

	var updated models.Host
	require.NoError(t, db.Where("org_id = ? AND ip = ?", orgID, "1.2.3.4").First(&updated).Error)
	require.Equal(t, "AS1234", updated.ASN)
	require.Equal(t, "TestOrg", updated.ASNOrg)
}

func TestEnrichHost_Censys_PersistsASNToExistingHost(t *testing.T) {
	censysSrv := httptest.NewServer(censysOKHandler("5.6.7.8"))
	defer censysSrv.Close()

	prev := *intelligence.CensysBaseURL
	*intelligence.CensysBaseURL = censysSrv.URL
	defer func() { *intelligence.CensysBaseURL = prev }()

	db := newTestDB(t)
	orgID := uuid.New()
	host := models.Host{OrgID: orgID, IP: "5.6.7.8", Status: "active"}
	require.NoError(t, db.Create(&host).Error)

	e := newEngine(db, intelligence.Config{CensysID: "id", CensysSecret: "sec"})
	_, err := e.EnrichHost(context.Background(), orgID, "5.6.7.8")
	require.NoError(t, err)

	var updated models.Host
	require.NoError(t, db.Where("org_id = ? AND ip = ?", orgID, "5.6.7.8").First(&updated).Error)
	require.Equal(t, "AS1234", updated.ASN)
}

func TestEnrichHost_Shodan_NoHostRowNoPanic(t *testing.T) {
	// No matching Host row exists at all — the update should just affect
	// zero rows, not error or panic. This is the common case for a
	// standalone Intelligence-page lookup that isn't tied to a scan.
	shodanSrv := httptest.NewServer(shodanOKHandler("9.9.9.9"))
	defer shodanSrv.Close()
	censysSrv := httptest.NewServer(http.HandlerFunc(errorHandler))
	defer censysSrv.Close()

	prev1 := *intelligence.ShodanBaseURL
	prev2 := *intelligence.CensysBaseURL
	*intelligence.ShodanBaseURL = shodanSrv.URL
	*intelligence.CensysBaseURL = censysSrv.URL
	defer func() {
		*intelligence.ShodanBaseURL = prev1
		*intelligence.CensysBaseURL = prev2
	}()

	db := newTestDB(t)
	e := newEngine(db, intelligence.Config{ShodanKey: "k"})

	require.NotPanics(t, func() {
		_, err := e.EnrichHost(context.Background(), uuid.New(), "9.9.9.9")
		require.NoError(t, err)
	})
}

// TestEnrichHost_Shodan_EmptyOrgDoesNotClobberExistingASNOrg guards against
// a bug caught while re-verifying the ASN-persistence fix: a naive
// map-based Updates() with both fields always present would overwrite
// ASNOrg with an empty string whenever Shodan returns an ASN without an
// Org (or the reverse). Only fields that actually came back non-empty
// should be touched.
func TestEnrichHost_Shodan_EmptyOrgDoesNotClobberExistingASNOrg(t *testing.T) {
	shodanSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		// ASN present, org deliberately empty.
		fmt.Fprint(w, `{"ip_str":"4.4.4.4","hostnames":[],"org":"",`+
			`"country_name":"US","city":"","asn":"AS9999","os":null,`+
			`"ports":[],"tags":[],"data":[],"vulns":{}}`)
	}))
	defer shodanSrv.Close()
	censysSrv := httptest.NewServer(http.HandlerFunc(errorHandler))
	defer censysSrv.Close()

	prev1 := *intelligence.ShodanBaseURL
	prev2 := *intelligence.CensysBaseURL
	*intelligence.ShodanBaseURL = shodanSrv.URL
	*intelligence.CensysBaseURL = censysSrv.URL
	defer func() {
		*intelligence.ShodanBaseURL = prev1
		*intelligence.CensysBaseURL = prev2
	}()

	db := newTestDB(t)
	orgID := uuid.New()
	// Host already has an ASNOrg from an earlier enrichment pass.
	host := models.Host{OrgID: orgID, IP: "4.4.4.4", Status: "active", ASNOrg: "PreviousOrg"}
	require.NoError(t, db.Create(&host).Error)

	e := newEngine(db, intelligence.Config{ShodanKey: "k"})
	_, err := e.EnrichHost(context.Background(), orgID, "4.4.4.4")
	require.NoError(t, err)

	var updated models.Host
	require.NoError(t, db.Where("org_id = ? AND ip = ?", orgID, "4.4.4.4").First(&updated).Error)
	require.Equal(t, "AS9999", updated.ASN, "ASN should be updated")
	require.Equal(t, "PreviousOrg", updated.ASNOrg, "ASNOrg must not be clobbered by an empty value from this pass")
}
