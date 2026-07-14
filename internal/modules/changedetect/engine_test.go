package changedetect_test

import (
	"testing"
	"time"

	"github.com/ShadooowX/rayyan-asm/internal/config"
	"github.com/ShadooowX/rayyan-asm/internal/database"
	"github.com/ShadooowX/rayyan-asm/internal/models"
	"github.com/ShadooowX/rayyan-asm/internal/modules/changedetect"
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

func seedOrg(t *testing.T, db *gorm.DB, name string) models.Organization {
	t.Helper()
	org := models.Organization{Name: name, Slug: name}
	require.NoError(t, db.Create(&org).Error)
	return org
}

func eventsByType(events []models.AssetChangeEvent) map[string]int {
	out := map[string]int{}
	for _, e := range events {
		out[e.ChangeType]++
	}
	return out
}

func TestRunDetection_FirstRunMarksEverythingNew(t *testing.T) {
	db := newTestDB(t)
	engine := changedetect.New(db, zap.NewNop().Sugar())
	org := seedOrg(t, db, "firstrun")

	domain := models.Domain{OrgID: org.ID, Name: "first.com", Status: "active"}
	require.NoError(t, db.Create(&domain).Error)
	host := models.Host{OrgID: org.ID, IP: "203.0.113.9", Status: "active"}
	require.NoError(t, db.Create(&host).Error)

	summary, err := engine.RunDetection(org.ID)
	require.NoError(t, err)
	require.Equal(t, 2, summary.EventsFound)
	require.Equal(t, 1, summary.ByType["domain"])
	require.Equal(t, 1, summary.ByType["host"])

	var events []models.AssetChangeEvent
	require.NoError(t, db.Where("org_id = ?", org.ID).Order("detected_at asc, asset_type asc").Find(&events).Error)
	for _, e := range events {
		require.Equal(t, "new", e.ChangeType)
	}
}

func TestRunDetection_SecondRunWithNoChangesProducesNoEvents(t *testing.T) {
	db := newTestDB(t)
	engine := changedetect.New(db, zap.NewNop().Sugar())
	org := seedOrg(t, db, "stable")

	domain := models.Domain{OrgID: org.ID, Name: "stable.com", Status: "active"}
	require.NoError(t, db.Create(&domain).Error)

	_, err := engine.RunDetection(org.ID)
	require.NoError(t, err)

	summary, err := engine.RunDetection(org.ID)
	require.NoError(t, err)
	require.Equal(t, 0, summary.EventsFound)
}

func TestRunDetection_DetectsFieldChange(t *testing.T) {
	db := newTestDB(t)
	engine := changedetect.New(db, zap.NewNop().Sugar())
	org := seedOrg(t, db, "changeorg")

	domain := models.Domain{OrgID: org.ID, Name: "changeorg.com", Status: "active"}
	require.NoError(t, db.Create(&domain).Error)

	_, err := engine.RunDetection(org.ID)
	require.NoError(t, err)

	require.NoError(t, db.Model(&domain).Update("status", "inactive").Error)

	summary, err := engine.RunDetection(org.ID)
	require.NoError(t, err)
	require.Equal(t, 1, summary.EventsFound)

	var events []models.AssetChangeEvent
	require.NoError(t, db.Where("org_id = ? AND change_type = 'changed'", org.ID).Order("detected_at asc").Find(&events).Error)
	require.Len(t, events, 1)
	require.Equal(t, "status", events[0].Field)
	require.Equal(t, "active", events[0].OldValue)
	require.Equal(t, "inactive", events[0].NewValue)
}

func TestRunDetection_DetectsRemovedAsset(t *testing.T) {
	db := newTestDB(t)
	engine := changedetect.New(db, zap.NewNop().Sugar())
	org := seedOrg(t, db, "removeorg")

	host := models.Host{OrgID: org.ID, IP: "198.51.100.20", Status: "active"}
	require.NoError(t, db.Create(&host).Error)

	_, err := engine.RunDetection(org.ID)
	require.NoError(t, err)

	require.NoError(t, db.Delete(&host).Error)

	summary, err := engine.RunDetection(org.ID)
	require.NoError(t, err)
	require.Equal(t, 1, summary.EventsFound)

	var snaps int64
	db.Model(&models.AssetStateSnapshot{}).Where("org_id = ? AND asset_type = 'host'", org.ID).Count(&snaps)
	require.Equal(t, int64(0), snaps)
}

func TestRunDetection_CertificateReissueAndExpiryStatusChange(t *testing.T) {
	db := newTestDB(t)
	engine := changedetect.New(db, zap.NewNop().Sugar())
	org := seedOrg(t, db, "certorg")

	cert := models.Certificate{
		OrgID: org.ID, Fingerprint: "fp-original", Subject: "secure.certorg.com",
		NotAfter: time.Now().Add(60 * 24 * time.Hour),
	}
	require.NoError(t, db.Create(&cert).Error)

	_, err := engine.RunDetection(org.ID)
	require.NoError(t, err)

	require.NoError(t, db.Model(&cert).Updates(map[string]interface{}{
		"fingerprint": "fp-reissued",
		"not_after":   time.Now().Add(10 * 24 * time.Hour),
	}).Error)

	summary, err := engine.RunDetection(org.ID)
	require.NoError(t, err)
	require.Equal(t, 2, summary.ByType["certificate"])

	var events []models.AssetChangeEvent
	require.NoError(t, db.Where("org_id = ? AND asset_type = 'certificate'", org.ID).Order("detected_at asc").Find(&events).Error)
	fields := map[string]bool{}
	for _, e := range events {
		fields[e.Field] = true
	}
	require.True(t, fields["fingerprint"])
	require.True(t, fields["expiry_status"])
}

func TestRunDetection_DNSRecordAddAndRemove(t *testing.T) {
	db := newTestDB(t)
	engine := changedetect.New(db, zap.NewNop().Sugar())
	org := seedOrg(t, db, "dnsorg")

	domain := models.Domain{OrgID: org.ID, Name: "dnsorg.com"}
	require.NoError(t, db.Create(&domain).Error)
	rec := models.DNSRecord{OrgID: org.ID, DomainID: domain.ID, Name: "dnsorg.com", Type: "A", Value: "192.0.2.1"}
	require.NoError(t, db.Create(&rec).Error)

	_, err := engine.RunDetection(org.ID)
	require.NoError(t, err)

	require.NoError(t, db.Delete(&rec).Error)
	rec2 := models.DNSRecord{OrgID: org.ID, DomainID: domain.ID, Name: "dnsorg.com", Type: "A", Value: "192.0.2.2"}
	require.NoError(t, db.Create(&rec2).Error)

	cutoff := time.Now()
	summary, err := engine.RunDetection(org.ID)
	require.NoError(t, err)

	var events []models.AssetChangeEvent
	require.NoError(t, db.Where("org_id = ? AND asset_type = 'dns_record' AND detected_at >= ?", org.ID, cutoff).Order("detected_at asc").Find(&events).Error)
	counts := eventsByType(events)
	require.Equal(t, 1, counts["new"])
	require.Equal(t, 1, counts["removed"])
	require.Equal(t, 2, summary.ByType["dns_record"])
}

func TestRunDetection_TechnologyTrackedPerService(t *testing.T) {
	db := newTestDB(t)
	engine := changedetect.New(db, zap.NewNop().Sugar())
	org := seedOrg(t, db, "techorg")

	host := models.Host{OrgID: org.ID, IP: "203.0.113.50"}
	require.NoError(t, db.Create(&host).Error)
	svc := models.Service{OrgID: org.ID, HostID: host.ID, Port: 443, Protocol: "tcp"}
	require.NoError(t, db.Create(&svc).Error)
	tech := models.Technology{OrgID: org.ID, ServiceID: &svc.ID, Name: "nginx", Version: "1.24.0"}
	require.NoError(t, db.Create(&tech).Error)

	_, err := engine.RunDetection(org.ID)
	require.NoError(t, err)

	require.NoError(t, db.Model(&tech).Update("version", "1.25.0").Error)

	summary, err := engine.RunDetection(org.ID)
	require.NoError(t, err)
	require.Equal(t, 1, summary.ByType["technology"])

	var event models.AssetChangeEvent
	require.NoError(t, db.Where("org_id = ? AND asset_type = 'technology' AND change_type = 'changed'", org.ID).First(&event).Error)
	require.Equal(t, "version", event.Field)
	require.Equal(t, "1.24.0", event.OldValue)
	require.Equal(t, "1.25.0", event.NewValue)
}

func TestTimeline_FiltersByTypeAndChangeType(t *testing.T) {
	db := newTestDB(t)
	engine := changedetect.New(db, zap.NewNop().Sugar())
	org := seedOrg(t, db, "timelineorg")

	domain := models.Domain{OrgID: org.ID, Name: "timelineorg.com"}
	require.NoError(t, db.Create(&domain).Error)
	host := models.Host{OrgID: org.ID, IP: "203.0.113.99"}
	require.NoError(t, db.Create(&host).Error)

	_, err := engine.RunDetection(org.ID)
	require.NoError(t, err)

	domainEvents, err := engine.Timeline(org.ID, "domain", "", 0)
	require.NoError(t, err)
	require.Len(t, domainEvents, 1)
	require.Equal(t, "domain", domainEvents[0].AssetType)

	newEvents, err := engine.Timeline(org.ID, "", "new", 0)
	require.NoError(t, err)
	require.Len(t, newEvents, 2)

	removedEvents, err := engine.Timeline(org.ID, "", "removed", 0)
	require.NoError(t, err)
	require.Len(t, removedEvents, 0)
}
