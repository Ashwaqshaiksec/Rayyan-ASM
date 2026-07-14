package toolrunner

import (
	"time"

	"github.com/ShadooowX/rayyan-asm/internal/modules/toolrunner/types"
)

const DefaultTimeout = 5 * time.Minute
const DefaultMaxLines = 100_000

// Re-export all shared types so existing callers don't change.
type ToolStatus = types.ToolStatus
type RunResult = types.RunResult
type RunOptions = types.RunOptions
type ToolCredentials = types.ToolCredentials
type Category = types.Category
type ToolInfo = types.ToolInfo
type Registry = types.Registry

const (
	StatusInstalled    = types.StatusInstalled
	StatusMissing      = types.StatusMissing
	StatusWrongVersion = types.StatusWrongVersion

	CategorySubdomain     = types.CategorySubdomain
	CategoryDNS           = types.CategoryDNS
	CategoryNetwork       = types.CategoryNetwork
	CategoryWeb           = types.CategoryWeb
	CategoryContent       = types.CategoryContent
	CategoryVulnerability = types.CategoryVulnerability
	CategoryWAF           = types.CategoryWAF
	CategorySMB           = types.CategorySMB
	CategoryOriginIP      = types.CategoryOriginIP
	CategoryInjection     = types.CategoryInjection
	CategorySecrets       = types.CategorySecrets
	CategoryFingerprint   = types.CategoryFingerprint
	CategoryJSAnalysis    = types.CategoryJSAnalysis
	CategoryAuth          = types.CategoryAuth
	CategoryParams        = types.CategoryParams
	CategoryTakeover      = types.CategoryTakeover
	CategoryCloud         = types.CategoryCloud
	CategoryScreenshot    = types.CategoryScreenshot
)

// ValidateArg and ValidateArgs re-exported from types.
var ValidateArg = types.ValidateArg
var ValidateArgs = types.ValidateArgs

// NewRegistry re-exported.
var NewRegistry = types.NewRegistry

// DefaultRegistry is the package-level singleton.
var DefaultRegistry = types.DefaultRegistry

// DetectBinary and DetectVersion re-exported.
var DetectBinary = types.DetectBinary
var DetectVersion = types.DetectVersion

// Run is defined in types to avoid import cycles; re-exported here for callers
// that import toolrunner directly.
var Run = types.Run
