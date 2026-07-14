package toolrunner

import (
	"time"

	"go.uber.org/zap"
	"gorm.io/gorm"
	"gorm.io/gorm/clause"
)

// toolRegistryRow mirrors the tool_registry database table for GORM.
type toolRegistryRow struct {
	ID          string     `gorm:"primaryKey;type:uuid;default:gen_random_uuid()"`
	Name        string     `gorm:"uniqueIndex;not null"`
	Category    string     `gorm:"not null"`
	Description string     `gorm:"not null;default:''"`
	BinaryPath  string     `gorm:"not null;default:''"`
	Version     string     `gorm:"not null;default:''"`
	Status      string     `gorm:"not null;default:'missing'"`
	Enabled     bool       `gorm:"not null;default:true"`
	LastRunAt   *time.Time `gorm:"column:last_run_at"`
	LastRunOK   bool       `gorm:"not null;default:false"`
	CreatedAt   time.Time
	UpdatedAt   time.Time
}

func (toolRegistryRow) TableName() string { return "tool_registry" }

// SyncRegistryFromDB loads enabled/disabled overrides from the tool_registry
// table and applies them to the in-memory DefaultRegistry.
// Call this after RegisterAll() + VerifyAll() at startup.
func SyncRegistryFromDB(db *gorm.DB, log *zap.SugaredLogger) {
	var rows []toolRegistryRow
	if err := db.Find(&rows).Error; err != nil {
		log.Warnw("tool registry DB sync: query failed", "error", err)
		return
	}
	applied := 0
	for _, row := range rows {
		if DefaultRegistry.SetEnabled(row.Name, row.Enabled) {
			applied++
		}
	}
	log.Infow("tool registry DB sync complete", "rows", len(rows), "applied", applied)
}

// PersistRegistryToDB upserts the current in-memory registry state to the DB.
// Called after VerifyAll() so the DB reflects the actual installation state.
//
// AutoMigrate is called here rather than added to database.Migrate()'s list:
// toolRegistryRow is unexported and lives in this package, and
// database.Migrate() lives in package database — exporting it purely to
// list it there would be a larger, more invasive change than migrating it
// at its own point of use. AutoMigrate is idempotent (safe to call every
// startup, same as database.Migrate() itself), so this has no downside
// beyond the first call actually creating the table. Confirmed via a live
// run that db.Migrate() never created tool_registry: PersistRegistryToDB
// failed with "ERROR: relation \"tool_registry\" does not exist" on every
// startup, which is why the Tools page's enable/disable/history state was
// never actually persisting.
func PersistRegistryToDB(db *gorm.DB, log *zap.SugaredLogger) {
	if err := db.AutoMigrate(&toolRegistryRow{}); err != nil {
		log.Warnw("tool registry: migration failed, skipping persist", "error", err)
		return
	}

	tools := DefaultRegistry.List()
	rows := make([]toolRegistryRow, 0, len(tools))
	for _, t := range tools {
		rows = append(rows, toolRegistryRow{
			Name:        t.Name,
			Category:    string(t.Category),
			Description: t.Description,
			BinaryPath:  t.BinaryPath,
			Version:     t.Version,
			Status:      string(t.Status),
			Enabled:     t.Enabled,
		})
	}
	result := db.Clauses(clause.OnConflict{
		Columns:   []clause.Column{{Name: "name"}},
		DoUpdates: clause.AssignmentColumns([]string{"binary_path", "version", "status", "updated_at"}),
	}).Create(&rows)
	if result.Error != nil {
		log.Warnw("tool registry persist failed", "error", result.Error)
		return
	}
	log.Infow("tool registry persisted to DB", "count", len(rows))
}
