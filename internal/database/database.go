package database

import (
	"fmt"

	"github.com/ShadooowX/rayyan-asm/internal/config"
	dbmodels "github.com/ShadooowX/rayyan-asm/internal/database/models"
	"github.com/ShadooowX/rayyan-asm/internal/models"
	"github.com/ShadooowX/rayyan-asm/internal/modules/intelligence"
	"gorm.io/driver/postgres"
	"gorm.io/driver/sqlite"
	"gorm.io/gorm"
	"gorm.io/gorm/logger"
)

func New(cfg config.DatabaseConfig) (*gorm.DB, error) {
	gormCfg := &gorm.Config{
		Logger: logger.Default.LogMode(logger.Silent),
	}

	var db *gorm.DB
	var err error

	switch cfg.Driver {
	case "postgres":
		db, err = gorm.Open(postgres.Open(cfg.DSN()), gormCfg)
	case "sqlite":
		db, err = gorm.Open(sqlite.Open(cfg.DSN()), gormCfg)
	default:
		return nil, fmt.Errorf("unsupported database driver: %s", cfg.Driver)
	}

	if err != nil {
		return nil, fmt.Errorf("opening database: %w", err)
	}

	sqlDB, err := db.DB()
	if err != nil {
		return nil, err
	}

	if cfg.Driver == "sqlite" {
		// SQLite allows only one writer at a time. Letting database/sql open
		// multiple pooled connections to it causes both the multi-connection
		// ":memory:" isolation issue (see DSN) and intermittent
		// "database is locked" errors under concurrent requests on
		// file-based DBs. A single connection lets SQLite's own locking do
		// the serialization safely.
		sqlDB.SetMaxOpenConns(1)
		sqlDB.SetMaxIdleConns(1)
	} else {
		sqlDB.SetMaxOpenConns(cfg.MaxOpen)
		sqlDB.SetMaxIdleConns(cfg.MaxIdle)
	}
	sqlDB.SetConnMaxLifetime(cfg.MaxLife)

	return db, nil
}

// OpenSQLiteMemory opens a single-connection, in-memory SQLite database
// suitable for hermetic unit/bench tests. The unique URI per call
// ("?cache=shared&mode=memory") prevents the "file:" memory DB sharing
// issue across test packages while keeping isolation between test cases.
// Callers are responsible for running AutoMigrate on the tables they need.
func OpenSQLiteMemory() (*gorm.DB, error) {
	gormCfg := &gorm.Config{
		Logger: logger.Default.LogMode(logger.Silent),
	}
	db, err := gorm.Open(sqlite.Open("file::memory:?cache=shared"), gormCfg)
	if err != nil {
		return nil, fmt.Errorf("opening in-memory SQLite: %w", err)
	}
	sqlDB, err := db.DB()
	if err != nil {
		return nil, err
	}
	sqlDB.SetMaxOpenConns(1)
	sqlDB.SetMaxIdleConns(1)
	return db, nil
}

// OpenSQLiteMemoryConcurrent opens an in-memory SQLite database for tests
// that specifically need to exercise real concurrent writers (e.g. a
// scale/load test parallelizing work across many goroutines), unlike
// OpenSQLiteMemory's single-connection handle. SQLite is still
// single-writer at the engine level, so this does not remove lock
// contention — concurrent writers still serialize inside SQLite itself —
// but it does let database/sql hand out multiple connections instead of
// queueing every caller behind one *sql.DB-level connection, and the
// _busy_timeout means a writer that finds the database locked retries
// for up to 10s instead of failing immediately with SQLITE_BUSY.
//
// Do not use this for tests asserting on serialization behavior itself;
// use OpenSQLiteMemory for those.
func OpenSQLiteMemoryConcurrent(maxOpenConns int) (*gorm.DB, error) {
	gormCfg := &gorm.Config{
		Logger: logger.Default.LogMode(logger.Silent),
	}
	db, err := gorm.Open(sqlite.Open("file::memory:?cache=shared&_busy_timeout=10000"), gormCfg)
	if err != nil {
		return nil, fmt.Errorf("opening in-memory SQLite: %w", err)
	}
	sqlDB, err := db.DB()
	if err != nil {
		return nil, err
	}
	if maxOpenConns <= 0 {
		maxOpenConns = 4
	}
	sqlDB.SetMaxOpenConns(maxOpenConns)
	sqlDB.SetMaxIdleConns(maxOpenConns)
	return db, nil
}

func Migrate(db *gorm.DB) error {
	return db.AutoMigrate(
		&models.Organization{},
		&models.User{},
		&models.APIKey{},
		&models.Domain{},
		&models.Subdomain{},
		&models.Host{},
		&models.Service{},
		&models.Certificate{},
		&models.DNSRecord{},
		&models.Technology{},
		&models.WebAsset{},
		&models.CloudAsset{},
		&models.TakeoverFinding{},
		&models.ScanJob{},
		&models.ScanResult{},
		&models.Alert{},
		&models.Report{},
		&models.AuditLog{},
		&models.Finding{},
		&models.ToolCredential{},
		&models.Project{},
		&models.Note{},
		&models.Todo{},
		&models.NotificationConfig{},
		&models.SavedSearch{},
		&models.ASNRange{},
		&models.WHOISHistory{},
		&models.WebhookDelivery{},
		&models.ServiceHistory{},
		&models.AssetRiskHistory{},
		&models.AssetRelationship{},
		&models.AssetStateSnapshot{},
		&models.AssetChangeEvent{},
		&models.AttackPath{},
		&models.AssetExposureScore{},
		&models.ExecutiveKPISnapshot{},
		&dbmodels.ToolRunResult{},
		&models.PasswordResetToken{},
		&models.EmailVerificationToken{},
		&models.FailedJob{},
		&models.DiscoveryJob{},
		&models.DiscoveryEvent{},
		&models.DiscoveryRiskFlag{},
		&models.CloudProviderCredential{},
		&intelligence.IntelResult{},
		&intelligence.MonitorJob{},
	)
}
