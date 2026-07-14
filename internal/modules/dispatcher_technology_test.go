package modules

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/ShadooowX/rayyan-asm/internal/models"
	"github.com/ShadooowX/rayyan-asm/internal/modules/web"
	"github.com/google/uuid"
	"go.uber.org/zap"
)

// newWebScanTestDispatcher is like newTestDispatcher but also migrates
// everything runWeb touches (WebAsset, Finding, Alert, Technology,
// ScanResult) and wires up a real web.Scanner, since newTestDispatcher
// builds a bare Dispatcher{db, log} without any of the sub-scanners
// NewDispatcher normally sets up.
func newWebScanTestDispatcher(t *testing.T) (*Dispatcher, func()) {
	t.Helper()
	d, cleanup := newTestDispatcher(t)
	if err := d.db.AutoMigrate(
		&models.Service{}, &models.WebAsset{}, &models.Finding{},
		&models.Alert{}, &models.Technology{}, &models.ScanResult{},
	); err != nil {
		t.Fatalf("AutoMigrate: %v", err)
	}
	d.web = web.NewScanner(zap.NewNop().Sugar())
	return d, cleanup
}

// wordpressServer returns an httptest.Server whose body contains the
// wp-content marker that detectTechnologies uses to flag "WordPress".
func wordpressServer() *httptest.Server {
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprint(w, `<html><body><img src="/wp-content/uploads/logo.png"></body></html>`)
	}))
}

// hostPort strips the http:// scheme from an httptest.Server URL, since
// runWeb's targets are bare host:port strings that it tries under both
// https:// and http://.
func hostPort(serverURL string) string {
	return strings.TrimPrefix(strings.TrimPrefix(serverURL, "http://"), "https://")
}

func TestRunWeb_TechnologyPersistedPerService(t *testing.T) {
	srv := wordpressServer()
	defer srv.Close()

	d, cleanup := newWebScanTestDispatcher(t)
	defer cleanup()
	orgID := seedOrg(t, d)

	scanJob := &models.ScanJob{OrgID: orgID, Targets: models.JSONB{"targets": []string{hostPort(srv.URL)}}}
	scanJob.ID = uuid.New()

	if err := d.runWeb(context.Background(), scanJob); err != nil {
		t.Fatalf("runWeb: unexpected error: %v", err)
	}

	var techs []models.Technology
	if err := d.db.Where("org_id = ? AND name = ?", orgID, "WordPress").Find(&techs).Error; err != nil {
		t.Fatalf("querying technologies: %v", err)
	}
	if len(techs) != 1 {
		t.Fatalf("expected exactly 1 WordPress technology row, got %d", len(techs))
	}
	if techs[0].ServiceID == nil || *techs[0].ServiceID == uuid.Nil {
		t.Fatal("expected Technology.ServiceID to be set to a real service, got nil/zero")
	}

	// The row must actually be linked to a real, existing Service — this
	// is the whole point of the fix (previously ServiceID was never set
	// at all, and dedup ignored it, so a technology detected on many
	// different hosts collapsed into a single unlinked row).
	var svcCount int64
	d.db.Model(&models.Service{}).Where("id = ?", *techs[0].ServiceID).Count(&svcCount)
	if svcCount != 1 {
		t.Fatalf("Technology.ServiceID does not reference a real Service row")
	}
}

func TestRunWeb_TechnologySeparateRowsPerHost(t *testing.T) {
	srv1 := wordpressServer()
	defer srv1.Close()
	srv2 := wordpressServer()
	defer srv2.Close()

	d, cleanup := newWebScanTestDispatcher(t)
	defer cleanup()
	orgID := seedOrg(t, d)

	scanJob := &models.ScanJob{
		OrgID:   orgID,
		Targets: models.JSONB{"targets": []string{hostPort(srv1.URL), hostPort(srv2.URL)}},
	}
	scanJob.ID = uuid.New()

	if err := d.runWeb(context.Background(), scanJob); err != nil {
		t.Fatalf("runWeb: unexpected error: %v", err)
	}

	var count int64
	d.db.Model(&models.Technology{}).Where("org_id = ? AND name = ?", orgID, "WordPress").Count(&count)
	// Before the fix this would always be 1, regardless of how many
	// distinct hosts actually run WordPress — the whole bug in a nutshell.
	if count != 2 {
		t.Fatalf("expected 2 separate WordPress rows (one per host), got %d", count)
	}
}
