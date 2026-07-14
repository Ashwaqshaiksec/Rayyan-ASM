package scheduler_test

import (
	"testing"
	"time"

	"github.com/ShadooowX/rayyan-asm/internal/config"
	"github.com/ShadooowX/rayyan-asm/internal/database"
	"github.com/ShadooowX/rayyan-asm/internal/models"
	"github.com/ShadooowX/rayyan-asm/internal/queue"
	"github.com/ShadooowX/rayyan-asm/internal/scheduler"
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

func newTestQueue() *queue.Queue {
	return queue.New(nil, config.QueueConfig{Workers: 1, BufferSize: 100})
}

func newTestScheduler(db *gorm.DB, q *queue.Queue) *scheduler.Scheduler {
	return scheduler.New(db, q, zap.NewNop().Sugar())
}

// seedOrg creates a minimal active organization and returns it.
func seedOrg(t *testing.T, db *gorm.DB, name string) models.Organization {
	t.Helper()
	org := models.Organization{Name: name, Slug: name, Active: true}
	if err := db.Create(&org).Error; err != nil {
		t.Fatalf("seedOrg: %v", err)
	}
	return org
}

// seedDiscoveryJob creates a DiscoveryJob with the given fields.
func seedDiscoveryJob(t *testing.T, db *gorm.DB, orgID uuid.UUID, status, cadence string, completedAt *time.Time) models.DiscoveryJob {
	t.Helper()
	job := models.DiscoveryJob{
		OrgID:       orgID,
		SeedDomains: models.StringArray{"example.com"},
		Status:      status,
		Cadence:     cadence,
		CompletedAt: completedAt,
	}
	if err := db.Create(&job).Error; err != nil {
		t.Fatalf("seedDiscoveryJob: %v", err)
	}
	return job
}

// countJobs returns the number of DiscoveryJob rows with the given status.
func countJobs(db *gorm.DB, orgID uuid.UUID, status string) int64 {
	var n int64
	db.Model(&models.DiscoveryJob{}).Where("org_id = ? AND status = ?", orgID, status).Count(&n)
	return n
}

// ── DispatchContinuousDiscovery ───────────────────────────────────────────────

func TestDispatchContinuousDiscovery_NoCandidates_NoJobsCreated(t *testing.T) {
	db := newTestDB(t)
	q := newTestQueue()
	s := newTestScheduler(db, q)

	// No jobs in DB at all.
	s.DispatchContinuousDiscovery()

	var total int64
	db.Model(&models.DiscoveryJob{}).Count(&total)
	if total != 0 {
		t.Fatalf("expected 0 jobs after dispatch with no candidates, got %d", total)
	}
}

func TestDispatchContinuousDiscovery_DailyJobCompletedOver24hAgo_NewJobCreated(t *testing.T) {
	db := newTestDB(t)
	q := newTestQueue()
	s := newTestScheduler(db, q)
	org := seedOrg(t, db, "acme")

	ago := time.Now().Add(-25 * time.Hour)
	seedDiscoveryJob(t, db, org.ID, "completed", "daily", &ago)

	s.DispatchContinuousDiscovery()

	pending := countJobs(db, org.ID, "pending")
	if pending != 1 {
		t.Fatalf("expected 1 new pending job, got %d", pending)
	}
}

func TestDispatchContinuousDiscovery_DailyJobCompletedUnder24hAgo_NoNewJob(t *testing.T) {
	db := newTestDB(t)
	q := newTestQueue()
	s := newTestScheduler(db, q)
	org := seedOrg(t, db, "beta")

	recent := time.Now().Add(-1 * time.Hour)
	seedDiscoveryJob(t, db, org.ID, "completed", "daily", &recent)

	s.DispatchContinuousDiscovery()

	pending := countJobs(db, org.ID, "pending")
	if pending != 0 {
		t.Fatalf("expected 0 new jobs (not yet due), got %d", pending)
	}
}

func TestDispatchContinuousDiscovery_ManualCadence_NeverReenqueued(t *testing.T) {
	db := newTestDB(t)
	q := newTestQueue()
	s := newTestScheduler(db, q)
	org := seedOrg(t, db, "gamma")

	// Manual jobs should never be auto-re-run, regardless of completed_at age.
	ago := time.Now().Add(-48 * time.Hour)
	seedDiscoveryJob(t, db, org.ID, "completed", "manual", &ago)

	s.DispatchContinuousDiscovery()

	pending := countJobs(db, org.ID, "pending")
	if pending != 0 {
		t.Fatalf("expected 0 jobs for manual cadence, got %d", pending)
	}
}

func TestDispatchContinuousDiscovery_TwoOrgs_BothDue_TwoJobsCreated(t *testing.T) {
	db := newTestDB(t)
	q := newTestQueue()
	s := newTestScheduler(db, q)

	org1 := seedOrg(t, db, "org1")
	org2 := seedOrg(t, db, "org2")

	ago := time.Now().Add(-30 * time.Hour)
	seedDiscoveryJob(t, db, org1.ID, "completed", "daily", &ago)
	seedDiscoveryJob(t, db, org2.ID, "completed", "daily", &ago)

	s.DispatchContinuousDiscovery()

	p1 := countJobs(db, org1.ID, "pending")
	p2 := countJobs(db, org2.ID, "pending")
	if p1 != 1 {
		t.Fatalf("org1: expected 1 pending job, got %d", p1)
	}
	if p2 != 1 {
		t.Fatalf("org2: expected 1 pending job, got %d", p2)
	}
}

// ── checkSLABreaches ─────────────────────────────────────────────────────────

func TestCheckSLABreaches_OpenFindingPastDue_MarkedBreachedAndAlertCreated(t *testing.T) {
	db := newTestDB(t)
	q := newTestQueue()
	s := newTestScheduler(db, q)
	org := seedOrg(t, db, "sla-org")

	pastDue := time.Now().Add(-2 * time.Hour)
	finding := models.Finding{
		OrgID:    org.ID,
		Title:    "Test vuln",
		Severity: "high",
		Status:   "open",
		SLADueAt: &pastDue,
	}
	if err := db.Create(&finding).Error; err != nil {
		t.Fatalf("create finding: %v", err)
	}

	s.CheckSLABreaches()

	var updated models.Finding
	db.First(&updated, "id = ?", finding.ID)
	if !updated.SLABreached {
		t.Fatal("expected sla_breached=true")
	}

	var alertCount int64
	db.Model(&models.Alert{}).Where("org_id = ? AND type = 'sla_breach'", org.ID).Count(&alertCount)
	if alertCount != 1 {
		t.Fatalf("expected 1 sla_breach alert, got %d", alertCount)
	}
}

func TestCheckSLABreaches_AlreadyBreached_NotDoubleAlerted(t *testing.T) {
	db := newTestDB(t)
	q := newTestQueue()
	s := newTestScheduler(db, q)
	org := seedOrg(t, db, "dbl-org")

	pastDue := time.Now().Add(-2 * time.Hour)
	finding := models.Finding{
		OrgID:       org.ID,
		Title:       "Already breached",
		Severity:    "medium",
		Status:      "open",
		SLADueAt:    &pastDue,
		SLABreached: true,
	}
	if err := db.Create(&finding).Error; err != nil {
		t.Fatalf("create finding: %v", err)
	}

	s.CheckSLABreaches()

	var alertCount int64
	db.Model(&models.Alert{}).Where("org_id = ? AND type = 'sla_breach'", org.ID).Count(&alertCount)
	if alertCount != 0 {
		t.Fatalf("expected 0 new alerts (already breached), got %d", alertCount)
	}
}

func TestCheckSLABreaches_FixedFinding_NotBreached(t *testing.T) {
	db := newTestDB(t)
	q := newTestQueue()
	s := newTestScheduler(db, q)
	org := seedOrg(t, db, "fixed-org")

	pastDue := time.Now().Add(-2 * time.Hour)
	finding := models.Finding{
		OrgID:    org.ID,
		Title:    "Fixed vuln",
		Severity: "low",
		Status:   "fixed",
		SLADueAt: &pastDue,
	}
	if err := db.Create(&finding).Error; err != nil {
		t.Fatalf("create finding: %v", err)
	}

	s.CheckSLABreaches()

	var updated models.Finding
	db.First(&updated, "id = ?", finding.ID)
	if updated.SLABreached {
		t.Fatal("fixed finding should not be marked sla_breached")
	}
}

// ── purgeExpiredVerificationTokens ───────────────────────────────────────────

func newUser(t *testing.T, db *gorm.DB) models.User {
	t.Helper()
	id := uuid.NewString()
	u := models.User{
		Email:        id + "@example.com",
		Username:     "user_" + id,
		PasswordHash: "hash",
		Role:         "member",
	}
	if err := db.Create(&u).Error; err != nil {
		t.Fatalf("create user: %v", err)
	}
	return u
}

func TestPurgeExpiredVerificationTokens_ExpiredToken_Deleted(t *testing.T) {
	db := newTestDB(t)
	q := newTestQueue()
	s := newTestScheduler(db, q)
	u := newUser(t, db)

	expired := time.Now().Add(-1 * time.Hour)
	tok := models.EmailVerificationToken{
		UserID:    u.ID,
		TokenHash: "hash-expired",
		ExpiresAt: expired,
	}
	if err := db.Create(&tok).Error; err != nil {
		t.Fatalf("create token: %v", err)
	}

	s.PurgeExpiredVerificationTokens()

	var count int64
	db.Model(&models.EmailVerificationToken{}).Where("user_id = ?", u.ID).Count(&count)
	if count != 0 {
		t.Fatalf("expected expired token to be deleted, got %d remaining", count)
	}
}

func TestPurgeExpiredVerificationTokens_UsedToken_Deleted(t *testing.T) {
	db := newTestDB(t)
	q := newTestQueue()
	s := newTestScheduler(db, q)
	u := newUser(t, db)

	future := time.Now().Add(24 * time.Hour)
	usedAt := time.Now().Add(-30 * time.Minute)
	tok := models.EmailVerificationToken{
		UserID:    u.ID,
		TokenHash: "hash-used",
		ExpiresAt: future,
		UsedAt:    &usedAt,
	}
	if err := db.Create(&tok).Error; err != nil {
		t.Fatalf("create token: %v", err)
	}

	s.PurgeExpiredVerificationTokens()

	var count int64
	db.Model(&models.EmailVerificationToken{}).Where("user_id = ?", u.ID).Count(&count)
	if count != 0 {
		t.Fatalf("expected used token to be deleted, got %d remaining", count)
	}
}

func TestPurgeExpiredVerificationTokens_ValidToken_Kept(t *testing.T) {
	db := newTestDB(t)
	q := newTestQueue()
	s := newTestScheduler(db, q)
	u := newUser(t, db)

	future := time.Now().Add(24 * time.Hour)
	tok := models.EmailVerificationToken{
		UserID:    u.ID,
		TokenHash: "hash-valid",
		ExpiresAt: future,
	}
	if err := db.Create(&tok).Error; err != nil {
		t.Fatalf("create token: %v", err)
	}

	s.PurgeExpiredVerificationTokens()

	var count int64
	db.Model(&models.EmailVerificationToken{}).Where("user_id = ?", u.ID).Count(&count)
	if count != 1 {
		t.Fatalf("expected valid token to be kept, got %d remaining", count)
	}
}
