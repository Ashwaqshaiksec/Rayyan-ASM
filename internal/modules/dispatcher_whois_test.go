package modules

import (
	"testing"

	"github.com/ShadooowX/rayyan-asm/internal/models"
	"github.com/google/uuid"
)

func newWHOISTestDispatcher(t *testing.T) (*Dispatcher, func()) {
	t.Helper()
	d, cleanup := newTestDispatcher(t)
	if err := d.db.AutoMigrate(&models.WHOISHistory{}); err != nil {
		t.Fatalf("AutoMigrate: %v", err)
	}
	return d, cleanup
}

// TestSnapWHOIS_PersistsWithExplicitID guards against the bug caught while
// wiring this in: WHOISHistory doesn't embed models.Base (which has the
// BeforeCreate hook that auto-generates a UUID), so ID must be set
// explicitly — matching what AdminOpsHandler.SnapWHOIS already does.
// Without it, gorm would either error on a null primary key or, in an
// AutoMigrate'd test DB without a NOT NULL constraint, silently persist a
// zero UUID that could collide across multiple snapshots.
func TestSnapWHOIS_PersistsWithExplicitID(t *testing.T) {
	d, cleanup := newWHOISTestDispatcher(t)
	defer cleanup()
	orgID := seedOrg(t, d)
	scanJob := &models.ScanJob{OrgID: orgID}
	scanJob.ID = uuid.New()

	// Real network access isn't available/reliable in this test
	// environment, so this exercises the failure path (RDAP lookup fails)
	// which whois.FetchData already turns into a non-error, non-empty
	// "raw" string rather than an exception — snapWHOIS should still
	// persist a row either way rather than silently doing nothing.
	d.snapWHOIS(scanJob, "example-does-not-matter.test")

	var record models.WHOISHistory
	if err := d.db.Where("org_id = ? AND domain = ?", orgID, "example-does-not-matter.test").First(&record).Error; err != nil {
		t.Fatalf("expected a WHOISHistory row to be persisted even on lookup failure: %v", err)
	}
	if record.ID == uuid.Nil {
		t.Fatal("WHOISHistory.ID is nil — explicit UUID assignment is missing")
	}
	if record.Raw == "" {
		t.Fatal("expected Raw to describe the lookup outcome (even a failure), got empty string")
	}
}

func TestSnapWHOIS_NoPanicOnRepeatedCalls(t *testing.T) {
	d, cleanup := newWHOISTestDispatcher(t)
	defer cleanup()
	orgID := seedOrg(t, d)
	scanJob := &models.ScanJob{OrgID: orgID}
	scanJob.ID = uuid.New()

	// Snapshots are intentionally append-only (WHOIS *history*), so calling
	// this twice for the same domain should produce two rows, not error or
	// dedupe away the second one.
	d.snapWHOIS(scanJob, "repeat.test")
	d.snapWHOIS(scanJob, "repeat.test")

	var count int64
	d.db.Model(&models.WHOISHistory{}).Where("org_id = ? AND domain = ?", orgID, "repeat.test").Count(&count)
	if count != 2 {
		t.Fatalf("expected 2 append-only snapshot rows, got %d", count)
	}
}
