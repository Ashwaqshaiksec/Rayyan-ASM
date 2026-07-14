package executive_test

import (
	"strconv"
	"testing"
	"time"

	"github.com/ShadooowX/rayyan-asm/internal/config"
	"github.com/ShadooowX/rayyan-asm/internal/database"
	"github.com/ShadooowX/rayyan-asm/internal/models"
	"github.com/ShadooowX/rayyan-asm/internal/modules/executive"
	"github.com/google/uuid"
	"go.uber.org/zap"
	"gorm.io/gorm"
)

// ── helpers ──────────────────────────────────────────────────────────────────

func newTestDB(t *testing.T) *gorm.DB {
	t.Helper()
	db, err := database.New(config.DatabaseConfig{Driver: "sqlite", FilePath: ":memory:"})
	if err != nil {
		t.Fatalf("database.New: %v", err)
	}
	if err := database.Migrate(db); err != nil {
		t.Fatalf("database.Migrate: %v", err)
	}
	return db
}

func newEngine(db *gorm.DB) *executive.Engine {
	return executive.New(db, zap.NewNop().Sugar())
}

func seedOrg(t *testing.T, db *gorm.DB, name string) models.Organization {
	t.Helper()
	org := models.Organization{Name: name, Slug: name, Active: true}
	if err := db.Create(&org).Error; err != nil {
		t.Fatalf("seedOrg %s: %v", name, err)
	}
	return org
}

func seedHost(t *testing.T, db *gorm.DB, orgID uuid.UUID, ip string) models.Host {
	t.Helper()
	now := time.Now()
	h := models.Host{
		OrgID:       orgID,
		IP:          ip,
		FirstSeenAt: now,
		LastSeenAt:  now,
	}
	if err := db.Create(&h).Error; err != nil {
		t.Fatalf("seedHost %s: %v", ip, err)
	}
	return h
}

func seedFinding(t *testing.T, db *gorm.DB, orgID uuid.UUID, severity, status string) models.Finding {
	t.Helper()
	f := models.Finding{
		OrgID:    orgID,
		Title:    "Test finding " + severity,
		Severity: severity,
		Status:   status,
	}
	if err := db.Create(&f).Error; err != nil {
		t.Fatalf("seedFinding: %v", err)
	}
	return f
}

func seedService(t *testing.T, db *gorm.DB, orgID uuid.UUID, hostID uuid.UUID, port int) models.Service {
	t.Helper()
	now := time.Now()
	svc := models.Service{
		OrgID:       orgID,
		HostID:      hostID,
		Port:        port,
		Protocol:    "tcp",
		State:       "open",
		FirstSeenAt: now,
		LastSeenAt:  now,
	}
	if err := db.Create(&svc).Error; err != nil {
		t.Fatalf("seedService port %d: %v", port, err)
	}
	return svc
}

// ── ComputeAllOrgs ────────────────────────────────────────────────────────────

func TestComputeAllOrgs_EmptyDB_ReturnsZeroNil(t *testing.T) {
	db := newTestDB(t)
	eng := newEngine(db)

	n, err := eng.ComputeAllOrgs()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if n != 0 {
		t.Fatalf("expected 0 orgs processed, got %d", n)
	}
}

func TestComputeAllOrgs_OneOrgWithData_SnapshotCreated(t *testing.T) {
	db := newTestDB(t)
	eng := newEngine(db)
	org := seedOrg(t, db, "snap-org")

	host := seedHost(t, db, org.ID, "10.0.0.1")
	seedService(t, db, org.ID, host.ID, 443)
	seedFinding(t, db, org.ID, "high", "open")

	n, err := eng.ComputeAllOrgs()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if n != 1 {
		t.Fatalf("expected 1 org processed, got %d", n)
	}

	var snap models.ExecutiveKPISnapshot
	if err := db.Where("org_id = ?", org.ID).First(&snap).Error; err != nil {
		t.Fatalf("snapshot not found: %v", err)
	}
	if snap.TotalHosts == 0 {
		t.Error("expected TotalHosts > 0")
	}
	if snap.TotalServices == 0 {
		t.Error("expected TotalServices > 0")
	}
	if snap.HighFindings == 0 {
		t.Error("expected HighFindings > 0")
	}
}

func TestComputeAllOrgs_CalledTwice_RowCountStaysOne(t *testing.T) {
	db := newTestDB(t)
	eng := newEngine(db)
	org := seedOrg(t, db, "upsert-org")
	seedHost(t, db, org.ID, "10.0.0.2")

	_, err := eng.ComputeAllOrgs()
	if err != nil {
		t.Fatalf("first call error: %v", err)
	}
	// Add another host before the second call so the values change.
	seedHost(t, db, org.ID, "10.0.0.3")
	_, err = eng.ComputeAllOrgs()
	if err != nil {
		t.Fatalf("second call error: %v", err)
	}

	var count int64
	db.Model(&models.ExecutiveKPISnapshot{}).Where("org_id = ?", org.ID).Count(&count)
	if count != 1 {
		t.Fatalf("expected 1 snapshot row per org per day (upsert), got %d", count)
	}

	// The updated snapshot should reflect the second host.
	var snap models.ExecutiveKPISnapshot
	db.Where("org_id = ?", org.ID).First(&snap)
	if snap.TotalHosts < 2 {
		t.Errorf("expected TotalHosts >= 2 after upsert, got %d", snap.TotalHosts)
	}
}

// ── Compute (single-org) ─────────────────────────────────────────────────────

func TestCompute_EmptyOrg_ReturnsZeroSnapshot(t *testing.T) {
	db := newTestDB(t)
	eng := newEngine(db)
	org := seedOrg(t, db, "compute-empty")

	snap, err := eng.Compute(org.ID)
	if err != nil {
		t.Fatalf("Compute error: %v", err)
	}
	if snap == nil {
		t.Fatal("expected non-nil snapshot")
	}
	if snap.OrgID != org.ID {
		t.Errorf("expected org_id %v, got %v", org.ID, snap.OrgID)
	}
	if snap.TotalHosts != 0 {
		t.Errorf("expected TotalHosts=0, got %d", snap.TotalHosts)
	}
	if snap.TotalServices != 0 {
		t.Errorf("expected TotalServices=0, got %d", snap.TotalServices)
	}
	if snap.CriticalFindings != 0 || snap.HighFindings != 0 {
		t.Error("expected zero findings on empty org")
	}
	// A snapshot row should exist in the DB.
	var dbSnap models.ExecutiveKPISnapshot
	if err := db.Where("org_id = ?", org.ID).First(&dbSnap).Error; err != nil {
		t.Fatalf("snapshot not persisted: %v", err)
	}
}

func TestCompute_OrgWithAssets_SnapshotCountsCorrect(t *testing.T) {
	db := newTestDB(t)
	eng := newEngine(db)
	org := seedOrg(t, db, "compute-assets")

	h1 := seedHost(t, db, org.ID, "10.1.0.1")
	h2 := seedHost(t, db, org.ID, "10.1.0.2")
	seedService(t, db, org.ID, h1.ID, 80)
	seedService(t, db, org.ID, h1.ID, 443)
	seedService(t, db, org.ID, h2.ID, 22)
	seedFinding(t, db, org.ID, "critical", "open")
	seedFinding(t, db, org.ID, "high", "open")
	seedFinding(t, db, org.ID, "medium", "open")
	seedFinding(t, db, org.ID, "high", "fixed") // fixed — should NOT count as open

	snap, err := eng.Compute(org.ID)
	if err != nil {
		t.Fatalf("Compute error: %v", err)
	}
	if snap.TotalHosts != 2 {
		t.Errorf("expected TotalHosts=2, got %d", snap.TotalHosts)
	}
	if snap.TotalServices != 3 {
		t.Errorf("expected TotalServices=3, got %d", snap.TotalServices)
	}
	if snap.CriticalFindings != 1 {
		t.Errorf("expected CriticalFindings=1, got %d", snap.CriticalFindings)
	}
	if snap.HighFindings != 1 { // only the open high; fixed doesn't count
		t.Errorf("expected HighFindings=1 (open only), got %d", snap.HighFindings)
	}
	if snap.MediumFindings != 1 {
		t.Errorf("expected MediumFindings=1, got %d", snap.MediumFindings)
	}
	if snap.OpenFindings != 3 {
		t.Errorf("expected OpenFindings=3, got %d", snap.OpenFindings)
	}
}

func TestCompute_Upsert_ReplacesTodaysSnapshot(t *testing.T) {
	db := newTestDB(t)
	eng := newEngine(db)
	org := seedOrg(t, db, "compute-upsert")
	seedHost(t, db, org.ID, "10.2.0.1")

	_, err := eng.Compute(org.ID)
	if err != nil {
		t.Fatalf("first Compute error: %v", err)
	}

	// Add a host and re-compute — should update (upsert) not insert a second row.
	seedHost(t, db, org.ID, "10.2.0.2")
	snapAfter, err := eng.Compute(org.ID)
	if err != nil {
		t.Fatalf("second Compute error: %v", err)
	}

	var count int64
	db.Model(&models.ExecutiveKPISnapshot{}).Where("org_id = ?", org.ID).Count(&count)
	if count != 1 {
		t.Fatalf("expected 1 snapshot row (upsert), got %d", count)
	}
	if snapAfter.TotalHosts != 2 {
		t.Errorf("expected TotalHosts=2 after upsert, got %d", snapAfter.TotalHosts)
	}
}

func TestCompute_DeltaFields_CorrectRelativeToPrevDay(t *testing.T) {
	db := newTestDB(t)
	eng := newEngine(db)
	org := seedOrg(t, db, "compute-delta")

	// Insert a previous-day snapshot manually with TotalAssets=5.
	yesterday := time.Now().UTC().AddDate(0, 0, -1).Truncate(24 * time.Hour)
	prevSnap := models.ExecutiveKPISnapshot{
		ID:          uuid.New(),
		OrgID:       org.ID,
		Date:        yesterday,
		TotalAssets: 5,
		ComputedAt:  yesterday,
	}
	if err := db.Create(&prevSnap).Error; err != nil {
		t.Fatalf("create prev snapshot: %v", err)
	}

	// Seed 7 hosts → TotalAssets should be 7; NewAssets = 7-5 = 2.
	for i := 0; i < 7; i++ {
		seedHost(t, db, org.ID, "10.3.0."+strconv.Itoa(i+1))
	}

	snap, err := eng.Compute(org.ID)
	if err != nil {
		t.Fatalf("Compute error: %v", err)
	}
	if snap.NewAssets != 2 {
		t.Errorf("expected NewAssets=2 (7-5), got %d", snap.NewAssets)
	}
	if snap.RemovedAssets != 0 {
		t.Errorf("expected RemovedAssets=0, got %d", snap.RemovedAssets)
	}
}

// ── Summary ───────────────────────────────────────────────────────────────────

func TestSummary_OrgWithNoData_ReturnsZeroValueWithoutError(t *testing.T) {
	db := newTestDB(t)
	eng := newEngine(db)
	// Use a random org ID that has no data seeded.
	emptyOrgID := uuid.New()

	live, err := eng.Summary(emptyOrgID)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if live.TotalAssets != 0 {
		t.Errorf("expected TotalAssets=0, got %d", live.TotalAssets)
	}
	if live.OpenFindings != 0 {
		t.Errorf("expected OpenFindings=0, got %d", live.OpenFindings)
	}
	if live.SLACompliancePct != 100 {
		t.Errorf("expected SLACompliancePct=100 with no findings, got %f", live.SLACompliancePct)
	}
}

// ── Trends ────────────────────────────────────────────────────────────────────

func TestTrends_MultipleSnapshots_ReturnedInOrder(t *testing.T) {
	db := newTestDB(t)
	eng := newEngine(db)
	org := seedOrg(t, db, "trends-org")

	// Manually insert snapshots on different days (engine Compute does
	// delete-then-create per date, so inserting distinct dates directly).
	base := time.Now().UTC().Truncate(24 * time.Hour)
	for i := 4; i >= 0; i-- {
		day := base.AddDate(0, 0, -i)
		snap := models.ExecutiveKPISnapshot{
			ID:          uuid.New(),
			OrgID:       org.ID,
			Date:        day,
			TotalAssets: i + 1,
			ComputedAt:  day,
		}
		if err := db.Create(&snap).Error; err != nil {
			t.Fatalf("create snapshot day -%d: %v", i, err)
		}
	}

	rows, err := eng.Trends(org.ID, "daily", 10)
	if err != nil {
		t.Fatalf("Trends error: %v", err)
	}
	if len(rows) != 5 {
		t.Fatalf("expected 5 trend rows, got %d", len(rows))
	}
	// Trends returns oldest first (ascending date).
	for i := 1; i < len(rows); i++ {
		if rows[i].Date.Before(rows[i-1].Date) {
			t.Errorf("rows not in ascending date order at index %d", i)
		}
	}
}
