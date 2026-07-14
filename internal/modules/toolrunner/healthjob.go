package toolrunner

import (
	"encoding/json"
	"fmt"
	"time"

	"github.com/google/uuid"
	"go.uber.org/zap"
	"gorm.io/gorm"
)

// alertRow is a minimal struct for inserting into the alerts table.
// Column names match the models.Alert GORM model exactly so inserts succeed
// without importing the models package (which would create an import cycle).
type alertRow struct {
	ID        string `gorm:"primaryKey;type:uuid"`
	OrgID     string `gorm:"column:org_id;type:uuid;not null"`
	Type      string `gorm:"column:type;not null"`
	Severity  string `gorm:"column:severity;not null"`
	Title     string `gorm:"column:title;not null"`
	Message   string `gorm:"column:message"`
	Data      string `gorm:"column:data;type:jsonb"`
	Status    string `gorm:"column:status;not null;default:'open'"`
	CreatedAt time.Time
	UpdatedAt time.Time
}

func (alertRow) TableName() string { return "alerts" }

// systemOrgID is a sentinel UUID used for system-generated alerts that are
// not tied to a specific org. Admins can filter on this value.
var systemOrgID = uuid.Nil.String()

// ToolHealthJob checks all registered tools and creates DB alerts for any that
// have transitioned from installed → missing since the last check.
// Intended to be called daily by the scheduler (e.g. at 03:00).
type ToolHealthJob struct {
	db  *gorm.DB
	log *zap.SugaredLogger
}

// NewToolHealthJob creates a ToolHealthJob.
func NewToolHealthJob(db *gorm.DB, log *zap.SugaredLogger) *ToolHealthJob {
	return &ToolHealthJob{db: db, log: log}
}

// Run performs the health check.
func (j *ToolHealthJob) Run() {
	j.log.Info("running tool health check job")

	// Snapshot current statuses before re-verify
	before := make(map[string]ToolStatus)
	for _, t := range DefaultRegistry.List() {
		before[t.Name] = t.Status
	}

	DefaultRegistry.VerifyAll()

	// Find tools that were previously installed and are now missing
	var newlyMissing []string
	for _, t := range DefaultRegistry.List() {
		if before[t.Name] == StatusInstalled && t.Status == StatusMissing {
			newlyMissing = append(newlyMissing, t.Name)
		}
	}

	if len(newlyMissing) == 0 {
		j.log.Info("tool health check: all tools OK")
		return
	}

	for _, name := range newlyMissing {
		j.log.Warnw("tool became missing — creating alert", "tool", name)
		meta, _ := json.Marshal(map[string]string{"tool": name, "previous_status": "installed"})
		alert := alertRow{
			ID:       uuid.New().String(),
			OrgID:    systemOrgID,
			Type:     "tool_health",
			Severity: "medium",
			Title:    fmt.Sprintf("Tool '%s' is no longer installed", name),
			Message:  fmt.Sprintf("The external tool '%s' was previously installed but can no longer be found on the system. Re-run install-tools.sh or verify the binary path.", name),
			Data:     string(meta),
			Status:   "open",
		}
		if err := j.db.Create(&alert).Error; err != nil {
			j.log.Warnw("failed to create tool health alert", "tool", name, "error", err)
		}
	}

	// Persist updated status to DB
	PersistRegistryToDB(j.db, j.log)

	j.log.Warnw("tool health check complete", "newly_missing", newlyMissing)
}
