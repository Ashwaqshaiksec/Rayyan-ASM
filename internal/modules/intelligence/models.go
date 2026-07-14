package intelligence

import (
	"database/sql/driver"
	"encoding/json"
	"fmt"
	"time"

	"github.com/ShadooowX/rayyan-asm/internal/models"
	"github.com/google/uuid"
)

// RawJSON is a []byte alias that stores as a jsonb column in Postgres and
// serialises as raw JSON in API responses (no double-encoding).
// It implements driver.Valuer, sql.Scanner, json.Marshaler, and
// gorm.GormDataTypeInterface.
type RawJSON []byte

// MarshalJSON emits the raw bytes as-is so the API response isn't double-encoded.
func (r RawJSON) MarshalJSON() ([]byte, error) {
	if len(r) == 0 {
		return []byte("null"), nil
	}
	return r, nil
}

// Scan implements sql.Scanner — reads jsonb back from Postgres.
func (r *RawJSON) Scan(value interface{}) error {
	switch v := value.(type) {
	case []byte:
		*r = append((*r)[0:0], v...)
	case string:
		*r = RawJSON(v)
	case nil:
		*r = nil
	default:
		return fmt.Errorf("RawJSON.Scan: unsupported type %T", value)
	}
	return nil
}

// Value implements driver.Valuer — sends the raw bytes to Postgres as a string
// so Postgres interprets it as jsonb.
func (r RawJSON) Value() (driver.Value, error) {
	if len(r) == 0 {
		return nil, nil
	}
	return string(r), nil
}

// GormDataType tells GORM to create the column as jsonb.
func (RawJSON) GormDataType() string { return "jsonb" }

// TextToRawJSON wraps a plain text value (e.g. CSV) in a JSON object so it
// can be stored safely in a jsonb column.
func TextToRawJSON(text string) RawJSON {
	b, _ := json.Marshal(map[string]string{"raw": text})
	return RawJSON(b)
}

// IntelResult stores the raw + summarised output from a single provider
// query against a target (IP or domain).  One row per (org, provider,
// target) — upserted on each refresh.
type IntelResult struct {
	ID         uuid.UUID          `gorm:"type:uuid;primary_key"                                  json:"id"`
	OrgID      uuid.UUID          `gorm:"type:uuid;uniqueIndex:idx_intel_result_key;not null;index" json:"org_id"`
	Provider   string             `gorm:"uniqueIndex:idx_intel_result_key;not null"              json:"provider"`
	Target     string             `gorm:"uniqueIndex:idx_intel_result_key;not null"              json:"target"`
	TargetType string             `gorm:"not null"                                               json:"target_type"`
	Summary    string             `json:"summary"`
	Severity   string             `gorm:"default:'info'"                                         json:"severity"`
	RawData    RawJSON            `gorm:"type:jsonb"                                             json:"raw_data,omitempty"`
	Tags       models.StringArray `gorm:"type:text[]"                                            json:"tags,omitempty"`
	FetchedAt  time.Time          `gorm:"index;not null"                                         json:"fetched_at"`
	CreatedAt  time.Time          `json:"created_at"`
	UpdatedAt  time.Time          `json:"updated_at"`
}

func (IntelResult) TableName() string { return "intel_results" }

// MonitorJob represents a continuous-monitoring schedule for a target.
type MonitorJob struct {
	ID         uuid.UUID          `gorm:"type:uuid;primary_key"  json:"id"`
	OrgID      uuid.UUID          `gorm:"type:uuid;index;not null" json:"org_id"`
	CreatedBy  uuid.UUID          `gorm:"type:uuid"              json:"created_by"`
	Target     string             `gorm:"not null"               json:"target"`
	TargetType string             `gorm:"not null"               json:"target_type"`
	Providers  models.StringArray `gorm:"type:text[]"            json:"providers"`
	Cadence    string             `gorm:"default:'daily'"        json:"cadence"`
	Enabled    bool               `gorm:"default:true"           json:"enabled"`
	LastRunAt  *time.Time         `json:"last_run_at,omitempty"`
	NextRunAt  time.Time          `gorm:"index"                  json:"next_run_at"`
	RunCount   int                `gorm:"default:0"              json:"run_count"`
	Notes      string             `json:"notes,omitempty"`
	CreatedAt  time.Time          `json:"created_at"`
	UpdatedAt  time.Time          `json:"updated_at"`
}

func (MonitorJob) TableName() string { return "intel_monitor_jobs" }
