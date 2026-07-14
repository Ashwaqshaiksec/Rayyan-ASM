package models

import (
	"encoding/json"
	"time"

	"github.com/google/uuid"
)

// ToolRunResult persists the output of a single tool execution within a scan.
// result_data holds the raw JSON payload whose shape varies by tool category
// ([]SubdomainResult, []PortResult, []VulnResult, etc.).
type ToolRunResult struct {
	ID     uuid.UUID `gorm:"type:uuid;primaryKey" json:"id"`
	ScanID uuid.UUID `gorm:"type:uuid;not null;index"                       json:"scan_id"`

	ToolName string `gorm:"not null"            json:"tool_name"`
	Category string `gorm:"not null;default:''" json:"category"`

	// Unified payload — shape depends on category
	ResultData json.RawMessage `gorm:"type:jsonb;not null;default:'[]'" json:"result_data,omitempty"`

	ResultCount  int    `gorm:"not null;default:0"     json:"result_count"`
	DurationMS   int64  `gorm:"not null;default:0"     json:"duration_ms"`
	Status       string `gorm:"not null;default:'ok'"  json:"status"`
	ErrorMessage string `gorm:"not null;default:''"    json:"error_message"`
	Truncated    bool   `gorm:"not null;default:false" json:"truncated"`

	CreatedAt time.Time `json:"created_at"`
}

func (ToolRunResult) TableName() string { return "tool_run_results" }
