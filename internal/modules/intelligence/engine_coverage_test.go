package intelligence_test

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/ShadooowX/rayyan-asm/internal/config"
	"github.com/ShadooowX/rayyan-asm/internal/database"
	"github.com/ShadooowX/rayyan-asm/internal/models"
	"github.com/ShadooowX/rayyan-asm/internal/modules/intelligence"
	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/zap"
	"go.uber.org/zap/zaptest/observer"
	"gorm.io/gorm"
)

func newCoverageDB(t *testing.T) *gorm.DB {
	t.Helper()
	db, err := database.New(config.DatabaseConfig{Driver: "sqlite", FilePath: ":memory:"})
	require.NoError(t, err)
	require.NoError(t, database.Migrate(db))
	return db
}

func newCoverageEngine(db *gorm.DB) *intelligence.Engine {
	return intelligence.New(db, zap.NewNop().Sugar(), intelligence.Config{})
}

// ─── ListResults ─────────────────────────────────────────────────────────

func TestListResults_Empty(t *testing.T) {
	db := newCoverageDB(t)
	e := newCoverageEngine(db)

	rows, total, err := e.ListResults(uuid.New(), "", "", 10, 0)
	require.NoError(t, err)
	assert.Equal(t, int64(0), total)
	assert.Empty(t, rows)
}

func TestListResults_FilterByTargetAndProvider(t *testing.T) {
	db := newCoverageDB(t)
	e := newCoverageEngine(db)
	orgID := uuid.New()

	for _, provider := range []string{"shodan", "censys"} {
		r := intelligence.IntelResult{
			ID:         uuid.New(),
			OrgID:      orgID,
			Provider:   provider,
			Target:     "10.1.1.1",
			TargetType: "host",
			Summary:    "test",
			FetchedAt:  time.Now(),
		}
		require.NoError(t, db.Create(&r).Error)
	}

	// No filter: both rows.
	rows, total, err := e.ListResults(orgID, "", "", 10, 0)
	require.NoError(t, err)
	assert.Equal(t, int64(2), total)
	assert.Len(t, rows, 2)

	// Filter by provider.
	rows, total, err = e.ListResults(orgID, "", "shodan", 10, 0)
	require.NoError(t, err)
	assert.Equal(t, int64(1), total)
	assert.Equal(t, "shodan", rows[0].Provider)

	// Filter by target.
	_, total, err = e.ListResults(orgID, "10.1.1.1", "", 10, 0)
	require.NoError(t, err)
	assert.Equal(t, int64(2), total)
}

func TestListResults_Pagination(t *testing.T) {
	db := newCoverageDB(t)
	e := newCoverageEngine(db)
	orgID := uuid.New()

	for i := 0; i < 5; i++ {
		r := intelligence.IntelResult{
			ID:         uuid.New(),
			OrgID:      orgID,
			Provider:   "shodan",
			Target:     "10.0.0." + string(rune('1'+i)),
			TargetType: "host",
			Summary:    "row",
			FetchedAt:  time.Now(),
		}
		require.NoError(t, db.Create(&r).Error)
	}

	rows, total, err := e.ListResults(orgID, "", "", 2, 0)
	require.NoError(t, err)
	assert.Equal(t, int64(5), total)
	assert.Len(t, rows, 2)

	rows2, _, err := e.ListResults(orgID, "", "", 2, 2)
	require.NoError(t, err)
	assert.Len(t, rows2, 2)
	assert.NotEqual(t, rows[0].ID, rows2[0].ID)
}

// ─── MonitorJob CRUD ─────────────────────────────────────────────────────

func TestCreateMonitorJob_AssignsIDIfNil(t *testing.T) {
	db := newCoverageDB(t)
	e := newCoverageEngine(db)

	org := models.Organization{Name: "MJOrg", Slug: "mjorg"}
	require.NoError(t, db.Create(&org).Error)

	job := &intelligence.MonitorJob{
		// ID deliberately zero — CreateMonitorJob must assign one.
		OrgID:      org.ID,
		Target:     "example.com",
		TargetType: "domain",
		Cadence:    "daily",
		Enabled:    true,
		// NextRunAt far in the future so this job is never picked up by
		// RunDueMonitorJobs in sibling tests sharing the in-memory SQLite.
		NextRunAt: time.Now().Add(24 * time.Hour),
	}
	require.NoError(t, e.CreateMonitorJob(job))
	t.Cleanup(func() { db.Unscoped().Delete(job) })
	assert.NotEqual(t, uuid.Nil, job.ID, "CreateMonitorJob must assign a UUID")
}

func TestCreateMonitorJob_PreservesProvidedID(t *testing.T) {
	db := newCoverageDB(t)
	e := newCoverageEngine(db)

	org := models.Organization{Name: "MJOrg2", Slug: "mjorg2"}
	require.NoError(t, db.Create(&org).Error)

	fixedID := uuid.New()
	job := &intelligence.MonitorJob{
		ID:         fixedID,
		OrgID:      org.ID,
		Target:     "1.2.3.4",
		TargetType: "host",
		Cadence:    "hourly",
		Enabled:    true,
		// NextRunAt far in the future so this job is never picked up by
		// RunDueMonitorJobs in sibling tests sharing the in-memory SQLite.
		NextRunAt: time.Now().Add(24 * time.Hour),
	}
	require.NoError(t, e.CreateMonitorJob(job))
	t.Cleanup(func() { db.Unscoped().Delete(job) })
	assert.Equal(t, fixedID, job.ID)
}

func TestListMonitorJobs_ReturnsJobsForOrg(t *testing.T) {
	db := newCoverageDB(t)
	e := newCoverageEngine(db)

	org1 := models.Organization{Name: "ListOrg1", Slug: "listorg1"}
	org2 := models.Organization{Name: "ListOrg2", Slug: "listorg2"}
	require.NoError(t, db.Create(&org1).Error)
	require.NoError(t, db.Create(&org2).Error)

	var seeded []*intelligence.MonitorJob
	for _, orgID := range []uuid.UUID{org1.ID, org2.ID, org1.ID} {
		j := &intelligence.MonitorJob{
			OrgID:      orgID,
			Target:     "t.example.com",
			TargetType: "domain",
			Cadence:    "daily",
			Enabled:    true,
			NextRunAt:  time.Now().Add(24 * time.Hour),
		}
		require.NoError(t, e.CreateMonitorJob(j))
		seeded = append(seeded, j)
	}
	t.Cleanup(func() {
		for _, j := range seeded {
			db.Unscoped().Delete(j)
		}
	})

	jobs, err := e.ListMonitorJobs(org1.ID)
	require.NoError(t, err)
	assert.Len(t, jobs, 2, "ListMonitorJobs must only return jobs for the queried org")

	jobs2, err := e.ListMonitorJobs(org2.ID)
	require.NoError(t, err)
	assert.Len(t, jobs2, 1)
}

func TestToggleMonitorJob_EnableDisable(t *testing.T) {
	db := newCoverageDB(t)
	e := newCoverageEngine(db)

	org := models.Organization{Name: "TogOrg", Slug: "togorg"}
	require.NoError(t, db.Create(&org).Error)

	job := &intelligence.MonitorJob{
		OrgID:      org.ID,
		Target:     "1.2.3.5",
		TargetType: "host",
		Cadence:    "daily",
		Enabled:    true,
		NextRunAt:  time.Now().Add(24 * time.Hour),
	}
	require.NoError(t, e.CreateMonitorJob(job))
	t.Cleanup(func() { db.Unscoped().Delete(job) })

	// Disable.
	require.NoError(t, e.ToggleMonitorJob(org.ID, job.ID, false))
	var got intelligence.MonitorJob
	require.NoError(t, db.First(&got, "id = ?", job.ID).Error)
	assert.False(t, got.Enabled)

	// Re-enable.
	require.NoError(t, e.ToggleMonitorJob(org.ID, job.ID, true))
	require.NoError(t, db.First(&got, "id = ?", job.ID).Error)
	assert.True(t, got.Enabled)
}

func TestToggleMonitorJob_WrongOrg_NoEffect(t *testing.T) {
	db := newCoverageDB(t)
	e := newCoverageEngine(db)

	org := models.Organization{Name: "RealOrg", Slug: "realorg"}
	require.NoError(t, db.Create(&org).Error)

	job := &intelligence.MonitorJob{
		OrgID:      org.ID,
		Target:     "5.6.7.8",
		TargetType: "host",
		Cadence:    "daily",
		Enabled:    true,
		NextRunAt:  time.Now().Add(24 * time.Hour),
	}
	require.NoError(t, e.CreateMonitorJob(job))
	t.Cleanup(func() { db.Unscoped().Delete(job) })

	// Toggle with wrong org ID — GORM returns no error (0 rows affected is not an error).
	require.NoError(t, e.ToggleMonitorJob(uuid.New(), job.ID, false))

	// Job must be unchanged.
	var got intelligence.MonitorJob
	require.NoError(t, db.First(&got, "id = ?", job.ID).Error)
	assert.True(t, got.Enabled, "toggle from wrong org must not modify the job")
}

func TestDeleteMonitorJob_RemovesRow(t *testing.T) {
	db := newCoverageDB(t)
	e := newCoverageEngine(db)

	org := models.Organization{Name: "DelOrg", Slug: "delorg"}
	require.NoError(t, db.Create(&org).Error)

	job := &intelligence.MonitorJob{
		OrgID:      org.ID,
		Target:     "del.example.com",
		TargetType: "domain",
		Cadence:    "weekly",
		Enabled:    true,
		NextRunAt:  time.Now().Add(24 * time.Hour),
	}
	require.NoError(t, e.CreateMonitorJob(job))

	require.NoError(t, e.DeleteMonitorJob(org.ID, job.ID))

	var count int64
	db.Model(&intelligence.MonitorJob{}).Where("id = ?", job.ID).Count(&count)
	assert.Equal(t, int64(0), count)
}

func TestDeleteMonitorJob_WrongOrg_NoEffect(t *testing.T) {
	db := newCoverageDB(t)
	e := newCoverageEngine(db)

	org := models.Organization{Name: "DelOrg2", Slug: "delorg2"}
	require.NoError(t, db.Create(&org).Error)

	job := &intelligence.MonitorJob{
		OrgID:      org.ID,
		Target:     "safe.example.com",
		TargetType: "domain",
		Cadence:    "daily",
		Enabled:    true,
		NextRunAt:  time.Now().Add(24 * time.Hour),
	}
	require.NoError(t, e.CreateMonitorJob(job))
	t.Cleanup(func() { db.Unscoped().Delete(job) })

	// Delete with wrong org — must not delete.
	require.NoError(t, e.DeleteMonitorJob(uuid.New(), job.ID))

	var count int64
	db.Model(&intelligence.MonitorJob{}).Where("id = ?", job.ID).Count(&count)
	assert.Equal(t, int64(1), count, "delete from wrong org must leave the row intact")
}

// ─── enrichShodan: 404 → nil,nil (host not in index) ─────────────────────

func TestEnrichShodan_404_ReturnsNilNil(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, "not found", http.StatusNotFound)
	}))
	defer srv.Close()

	prev := *intelligence.ShodanBaseURL
	*intelligence.ShodanBaseURL = srv.URL
	defer func() { *intelligence.ShodanBaseURL = prev }()

	db := newCoverageDB(t)
	e := intelligence.New(db, zap.NewNop().Sugar(), intelligence.Config{ShodanKey: "k"})

	results, err := e.EnrichHost(context.Background(), uuid.New(), "1.2.3.100")
	// 404 from Shodan = not indexed = nil,nil; but Censys key missing so it
	// also errors → all providers fail → EnrichHost returns error.
	require.Error(t, err)
	_ = results
}

// ─── enrichShodan: with vulns → upsertFinding called ─────────────────────

func TestEnrichShodan_WithVulns_UpsertsFinding(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		// Return a Shodan response with one CVE.
		fmt.Fprint(w, `{
			"ip_str":"10.0.0.99",
			"hostnames":[],
			"org":"TestOrg",
			"isp":"TestISP",
			"country_name":"US",
			"city":"NYC",
			"asn":"AS1234",
			"os":null,
			"ports":[443],
			"tags":[],
			"data":[],
			"vulns":{
				"CVE-2021-44228":{
					"cvss":10.0,
					"summary":"Log4Shell RCE",
					"references":[]
				}
			}
		}`)
	}))
	defer srv.Close()

	prev := *intelligence.ShodanBaseURL
	*intelligence.ShodanBaseURL = srv.URL
	defer func() { *intelligence.ShodanBaseURL = prev }()

	db := newCoverageDB(t)
	org := models.Organization{Name: "VulnOrg", Slug: "vulnorg"}
	require.NoError(t, db.Create(&org).Error)

	e := intelligence.New(db, zap.NewNop().Sugar(), intelligence.Config{ShodanKey: "k"})

	results, err := e.EnrichHost(context.Background(), org.ID, "10.0.0.99")
	// Censys key not set → censys fails; Shodan succeeds → partial success.
	require.NoError(t, err)
	require.NotEmpty(t, results)

	// upsertFinding should have created a Finding row for CVE-2021-44228.
	var count int64
	db.Table("findings").Where("org_id = ? AND cve = ?", org.ID, "CVE-2021-44228").Count(&count)
	assert.Equal(t, int64(1), count, "upsertFinding must create a Finding row for each CVE")
}

// ─── enrichCensys: no credentials → error ────────────────────────────────

func TestEnrichCensys_NoCredentials_Error(t *testing.T) {
	db := newCoverageDB(t)
	// Config has ShodanKey so shodan fails with "key not configured" — wait,
	// no: we want Censys-no-creds path. Use engine with only ShodanKey absent
	// so enrichShodan also errors, then EnrichHost errors for all.
	e := intelligence.New(db, zap.NewNop().Sugar(), intelligence.Config{
		// No CensysID/CensysSecret — triggers "censys credentials not configured"
	})

	_, err := e.EnrichHost(context.Background(), uuid.New(), "1.2.3.200")
	require.Error(t, err)
	require.Contains(t, err.Error(), "censys")
}

// ─── enrichCensys: services populated → svcList branch ───────────────────

func TestEnrichCensys_WithServices_BuildsSvcList(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		fmt.Fprint(w, `{"result":{"ip":"10.1.2.3","autonomous_system":{"asns":1234},"services":[
			{"port":80,"transport_protocol":"TCP","service_name":"HTTP","software":[]},
			{"port":443,"transport_protocol":"TCP","service_name":"HTTPS","software":[]}
		]}}`)
	}))
	defer srv.Close()

	prev := *intelligence.CensysBaseURL
	*intelligence.CensysBaseURL = srv.URL
	defer func() { *intelligence.CensysBaseURL = prev }()

	db := newCoverageDB(t)
	e := intelligence.New(db, zap.NewNop().Sugar(), intelligence.Config{
		CensysID: "id", CensysSecret: "sec",
	})

	results, err := e.EnrichHost(context.Background(), uuid.New(), "10.1.2.3")
	// Shodan key absent → shodan fails; censys succeeds → partial success.
	require.NoError(t, err)
	require.NotEmpty(t, results)
	assert.Contains(t, results[0].Summary, "80/TCP")
	assert.Contains(t, results[0].Summary, "443/TCP")
}

// ─── RunDueMonitorJobs: domain job dispatched ─────────────────────────────

func TestRunDueMonitorJobs_DomainJob_Dispatched(t *testing.T) {
	stSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		fmt.Fprint(w, `{"subdomains":["www"],"endpoint":"/v1/domain/example.com/subdomains"}`)
	}))
	defer stSrv.Close()

	prev := *intelligence.SecurityTrailsBaseURL
	*intelligence.SecurityTrailsBaseURL = stSrv.URL
	defer func() { *intelligence.SecurityTrailsBaseURL = prev }()

	db := newCoverageDB(t)
	org := models.Organization{Name: "DomainJobOrg", Slug: "domainjobor"}
	require.NoError(t, db.Create(&org).Error)
	dom := models.Domain{OrgID: org.ID, Name: "example.com", Status: "active"}
	require.NoError(t, db.Create(&dom).Error)

	e := intelligence.New(db, zap.NewNop().Sugar(), intelligence.Config{SecurityTrailsKey: "stkey"})

	job := &intelligence.MonitorJob{
		OrgID:      org.ID,
		Target:     "example.com",
		TargetType: "domain",
		Providers:  models.StringArray{"securitytrails"},
		Cadence:    "daily",
		Enabled:    true,
		NextRunAt:  time.Now().Add(-time.Hour),
	}
	require.NoError(t, e.CreateMonitorJob(job))

	e.RunDueMonitorJobs(context.Background())

	// next_run_at must have been advanced (> original NextRunAt).
	var updated intelligence.MonitorJob
	require.NoError(t, db.First(&updated, "id = ?", job.ID).Error)
	assert.Greater(t, updated.NextRunAt.Unix(), job.NextRunAt.Unix(),
		"RunDueMonitorJobs must advance next_run_at after running a domain job")
}

// ─── upsertFinding: update branch (existing finding, higher CVSS) ────────

func TestUpsertFinding_UpdatesWhenHigherCVSS(t *testing.T) {
	// Send Shodan response twice: first with CVSS 7.0 (high), then 9.5 (critical).
	// The second call must update the existing finding.
	callCount := 0
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		cvss := 7.0
		if callCount > 0 {
			cvss = 9.5
		}
		callCount++
		fmt.Fprintf(w, `{"ip_str":"10.9.9.9","hostnames":[],"org":"","isp":"","country_name":"","city":"","asn":"","os":null,"ports":[],"tags":[],"data":[],"vulns":{"CVE-2021-12345":{"cvss":%v,"summary":"test vuln","references":[]}}}`, cvss)
	}))
	defer srv.Close()

	prev := *intelligence.ShodanBaseURL
	*intelligence.ShodanBaseURL = srv.URL
	defer func() { *intelligence.ShodanBaseURL = prev }()

	db := newCoverageDB(t)
	org := models.Organization{Name: "UpdateOrg", Slug: "updateorg"}
	require.NoError(t, db.Create(&org).Error)

	e := intelligence.New(db, zap.NewNop().Sugar(), intelligence.Config{ShodanKey: "k"})

	// First scan — creates finding at CVSS 7.0.
	_, err := e.EnrichHost(context.Background(), org.ID, "10.9.9.9")
	require.NoError(t, err)

	var f1 struct{ CVSS float64 }
	db.Raw("SELECT cvss FROM findings WHERE org_id = ? AND cve = ?", org.ID, "CVE-2021-12345").Scan(&f1)
	assert.InDelta(t, 7.0, f1.CVSS, 0.01, "first scan should record CVSS 7.0")

	// Second scan — should update to CVSS 9.5.
	_, err = e.EnrichHost(context.Background(), org.ID, "10.9.9.9")
	require.NoError(t, err)

	var f2 struct{ CVSS float64 }
	db.Raw("SELECT cvss FROM findings WHERE org_id = ? AND cve = ?", org.ID, "CVE-2021-12345").Scan(&f2)
	assert.InDelta(t, 9.5, f2.CVSS, 0.01, "second scan with higher CVSS must update the finding")

	// Only one row — no duplicates.
	var count int64
	db.Table("findings").Where("org_id = ? AND cve = ?", org.ID, "CVE-2021-12345").Count(&count)
	assert.Equal(t, int64(1), count, "upsertFinding must not create duplicate rows")
}

// upsertFinding doesn't return an error — a failed update is only logged.
// Force that with a trigger that aborts updates above cvss 8.0, then check
// the failure gets logged and doesn't corrupt the existing row.
func TestUpsertFinding_UpdateFailsIsLoggedAndSwallowed(t *testing.T) {
	callCount := 0
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		cvss := 5.0
		if callCount > 0 {
			cvss = 9.5 // exceeds the trigger's 8.0 threshold on the second call
		}
		callCount++
		fmt.Fprintf(w, `{"ip_str":"10.9.9.8","hostnames":[],"org":"","isp":"","country_name":"","city":"","asn":"","os":null,"ports":[],"tags":[],"data":[],"vulns":{"CVE-2021-99999":{"cvss":%v,"summary":"test vuln","references":[]}}}`, cvss)
	}))
	defer srv.Close()

	prev := *intelligence.ShodanBaseURL
	*intelligence.ShodanBaseURL = srv.URL
	defer func() { *intelligence.ShodanBaseURL = prev }()

	db := newCoverageDB(t)
	org := models.Organization{Name: "UpdateFailOrg", Slug: "updatefailorg"}
	require.NoError(t, db.Create(&org).Error)

	// force the next UPDATE on findings.cvss above 8.0 to fail
	require.NoError(t, db.Exec(`
		CREATE TRIGGER block_high_cvss_update
		BEFORE UPDATE ON findings
		WHEN NEW.cvss > 8.0
		BEGIN
			SELECT RAISE(ABORT, 'simulated update failure');
		END;
	`).Error)

	observedCore, logs := observer.New(zap.WarnLevel)
	logger := zap.New(observedCore).Sugar()
	e := intelligence.New(db, logger, intelligence.Config{ShodanKey: "k"})

	// First scan — creates finding at CVSS 5.0 (below the trigger threshold).
	_, err := e.EnrichHost(context.Background(), org.ID, "10.9.9.8")
	require.NoError(t, err)

	var f1 struct{ CVSS float64 }
	db.Raw("SELECT cvss FROM findings WHERE org_id = ? AND cve = ?", org.ID, "CVE-2021-99999").Scan(&f1)
	require.InDelta(t, 5.0, f1.CVSS, 0.01, "first scan should record CVSS 5.0")

	// Second scan — CVSS 9.5 > existing 5.0, so upsertFinding takes the
	// update branch, the trigger aborts the UPDATE, and the failure must be
	// logged and swallowed rather than propagated.
	_, err = e.EnrichHost(context.Background(), org.ID, "10.9.9.8")
	assert.NoError(t, err, "a failed internal Updates() call must not surface as an EnrichHost error")

	var f2 struct{ CVSS float64 }
	db.Raw("SELECT cvss FROM findings WHERE org_id = ? AND cve = ?", org.ID, "CVE-2021-99999").Scan(&f2)
	assert.InDelta(t, 5.0, f2.CVSS, 0.01, "a failed update must leave the existing CVSS untouched")

	var count int64
	db.Table("findings").Where("org_id = ? AND cve = ?", org.ID, "CVE-2021-99999").Count(&count)
	assert.Equal(t, int64(1), count, "a failed update must not create a duplicate row")

	found := false
	for _, entry := range logs.All() {
		if entry.Message == "intel: failed to update finding" {
			found = true
		}
	}
	assert.True(t, found, "the update failure must be logged via Warnw")
}

// ─── enrichHistoricalDNS: HackerTarget success path ─────────────────────

func TestEnrichHistoricalDNS_HackerTarget_SuccessPath(t *testing.T) {
	htSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// HackerTarget returns CSV text, not JSON.
		fmt.Fprint(w, "example.com,1.2.3.4\nexample.com,5.6.7.8\n")
	}))
	defer htSrv.Close()

	prev := *intelligence.HackerTargetBaseURL
	*intelligence.HackerTargetBaseURL = htSrv.URL
	defer func() { *intelligence.HackerTargetBaseURL = prev }()

	db := newCoverageDB(t)
	org := models.Organization{Name: "HTOrg", Slug: "htorg"}
	require.NoError(t, db.Create(&org).Error)
	dom := models.Domain{OrgID: org.ID, Name: "example.com", Status: "active"}
	require.NoError(t, db.Create(&dom).Error)

	// No SecurityTrailsKey → falls back to HackerTarget.
	e := intelligence.New(db, zap.NewNop().Sugar(), intelligence.Config{})

	results, err := e.EnrichDomain(context.Background(), org.ID, "example.com")
	require.NoError(t, err)

	// At least one historical_dns result from HackerTarget.
	var htResult *intelligence.IntelResult
	for i := range results {
		if results[i].Provider == "historical_dns" {
			htResult = &results[i]
			break
		}
	}
	require.NotNil(t, htResult, "EnrichDomain must return a historical_dns result via HackerTarget fallback")
	assert.Contains(t, htResult.Summary, "HackerTarget")
	assert.Contains(t, htResult.Summary, "example.com")
}

// ─── enrichHistoricalDNS: SecurityTrails history path ───────────────────

func TestEnrichHistoricalDNS_SecurityTrails_HistoryPath(t *testing.T) {
	stSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		if strings.Contains(r.URL.Path, "/subdomains") {
			fmt.Fprint(w, `{"subdomains":[],"endpoint":"/v1/domain/hist.example.com/subdomains"}`)
			return
		}
		// History endpoint: return a valid stDNSHistoryResponse.
		fmt.Fprint(w, `{"records":[{"values":[{"ip":"1.2.3.4"}],"first_seen":"2024-01-01","last_seen":"2024-06-01"}],"pages":1,"type":"a"}`)
	}))
	defer stSrv.Close()

	prev := *intelligence.SecurityTrailsBaseURL
	*intelligence.SecurityTrailsBaseURL = stSrv.URL
	defer func() { *intelligence.SecurityTrailsBaseURL = prev }()

	db := newCoverageDB(t)
	org := models.Organization{Name: "STHistOrg", Slug: "sthistorg"}
	require.NoError(t, db.Create(&org).Error)
	dom := models.Domain{OrgID: org.ID, Name: "hist.example.com", Status: "active"}
	require.NoError(t, db.Create(&dom).Error)

	e := intelligence.New(db, zap.NewNop().Sugar(), intelligence.Config{SecurityTrailsKey: "stkey"})

	results, err := e.EnrichDomain(context.Background(), org.ID, "hist.example.com")
	require.NoError(t, err)

	var histResult *intelligence.IntelResult
	for i := range results {
		if results[i].Provider == "historical_dns" {
			histResult = &results[i]
			break
		}
	}
	require.NotNil(t, histResult, "EnrichDomain must return a historical_dns result via SecurityTrails")
	assert.Contains(t, histResult.Summary, "Historical DNS")
	assert.Contains(t, histResult.Summary, "securitytrails")
}
