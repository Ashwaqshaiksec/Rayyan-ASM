// Package exposure scores assets on real attackability instead of just
// CVSS — blends the risk score with internet exposure, attack path
// presence, finding severity, asset criticality, cert/tech risk, cloud
// exposure and graph centrality into one 0-100 number. Separate from
// riskscore's own numbers, doesn't touch them.
package exposure

import (
	"time"

	"github.com/google/uuid"
)

// Factors is the per-asset breakdown behind a score, stored as JSONB
// alongside it so the UI can show why an asset scored the way it did.
// Each field is already normalized to 0-100 (see calculator.go).
type Factors struct {
	ExistingRiskScore float64 `json:"existing_risk_score"`
	InternetExposure  float64 `json:"internet_exposure"`
	AttackPathScore   float64 `json:"attack_path_score"`
	FindingsScore     float64 `json:"findings_score"`
	CriticalityScore  float64 `json:"criticality_score"`
	CertificateScore  float64 `json:"certificate_score"`
	TechnologyScore   float64 `json:"technology_score"`
	CloudScore        float64 `json:"cloud_score"`
	RelationshipScore float64 `json:"relationship_score"`
	BusinessImpact    float64 `json:"business_impact_score"`

	// context surfaced alongside the breakdown
	InternetExposed     bool     `json:"internet_exposed"`
	AttackPathCount     int      `json:"attack_path_count"`
	CriticalFindings    int      `json:"critical_findings"`
	HighFindings        int      `json:"high_findings"`
	RelationshipCount   int      `json:"relationship_count"`
	ConnectedToCritical bool     `json:"connected_to_critical_asset"`
	CloudExposed        bool     `json:"cloud_exposed"`
	RiskyTechnologies   []string `json:"risky_technologies,omitempty"`
}

// scoredAsset is the working result for one host/subdomain/domain before
// it gets persisted to asset_exposure_scores.
type scoredAsset struct {
	assetType   string
	id          uuid.UUID
	label       string
	riskScore   float64
	criticality string
	score       float64
	level       string
	factors     Factors
}

// Summary — result of a recompute run, mirrors the Summary shape used by
// riskscore/attackpath for consistency.
type Summary struct {
	OrgID         uuid.UUID `json:"org_id"`
	AssetsScored  int       `json:"assets_scored"`
	Critical      int       `json:"critical"`
	High          int       `json:"high"`
	Medium        int       `json:"medium"`
	Low           int       `json:"low"`
	Informational int       `json:"informational"`
	DurationMS    int64     `json:"duration_ms"`
}

// AssetRow is the API/list shape for one scored asset.
type AssetRow struct {
	ID               uuid.UUID `json:"id"`
	AssetType        string    `json:"asset_type"`
	AssetID          uuid.UUID `json:"asset_id"`
	Label            string    `json:"label"`
	RiskScore        float64   `json:"risk_score"`
	ExposureScore    float64   `json:"exposure_score"`
	ExposureLevel    string    `json:"exposure_level"`
	InternetExposed  bool      `json:"internet_exposed"`
	AttackPathCount  int       `json:"attack_path_count"`
	CriticalFindings int       `json:"critical_findings"`
	Criticality      string    `json:"criticality"`
	CalculatedAt     time.Time `json:"calculated_at"`
}

// AssetDetail adds the full factor breakdown to an AssetRow.
type AssetDetail struct {
	AssetRow
	Factors Factors `json:"factors"`
}

// Dashboard is the response for GET /exposure/dashboard.
type Dashboard struct {
	TotalScored           int               `json:"total_scored"`
	Critical              int               `json:"critical"`
	High                  int               `json:"high"`
	Medium                int               `json:"medium"`
	Low                   int               `json:"low"`
	Informational         int               `json:"informational"`
	AvgExposureScore      float64           `json:"avg_exposure_score"`
	AvgRiskScore          float64           `json:"avg_risk_score"`
	PublicFacingCount     int               `json:"public_facing_count"`
	TopExposedAssets      []AssetRow        `json:"top_exposed_assets"`
	CriticalExposures     []AssetRow        `json:"critical_exposures"`
	PublicFacingAssets    []AssetRow        `json:"public_facing_assets"`
	HighRiskServices      []ServiceExposure `json:"high_risk_services"`
	DangerousTechnologies []TechExposure    `json:"most_dangerous_technologies"`
	AttackPathExposure    []AssetRow        `json:"attack_path_exposure"`
	RiskVsExposureMatrix  []MatrixCell      `json:"risk_vs_exposure_matrix"`
	CalculatedAt          time.Time         `json:"calculated_at"`
}

// ServiceExposure ranks a service by the exposure of the asset it runs on.
type ServiceExposure struct {
	ServiceID     uuid.UUID `json:"service_id"`
	HostRef       string    `json:"host_ref"`
	Port          int       `json:"port"`
	Protocol      string    `json:"protocol"`
	Product       string    `json:"product"`
	ExposureScore float64   `json:"exposure_score"`
}

// TechExposure ranks a technology by how often it shows up on exposed assets.
type TechExposure struct {
	Name        string  `json:"name"`
	Category    string  `json:"category"`
	AssetCount  int     `json:"asset_count"`
	AvgExposure float64 `json:"avg_exposure_score"`
}

// MatrixCell is one cell of the risk-tier x exposure-level grid.
type MatrixCell struct {
	RiskTier      string `json:"risk_tier"`
	ExposureLevel string `json:"exposure_level"`
	Count         int    `json:"count"`
}
