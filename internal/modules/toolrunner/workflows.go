package toolrunner

import (
	"fmt"
	"time"

	"go.uber.org/zap"
)

// WorkflowStage is a single tool execution step in a workflow.
type WorkflowStage struct {
	Name     string
	ToolName string
	Category Category
}

// WorkflowType identifies a predefined scanning workflow.
type WorkflowType string

const (
	WorkflowExternalASM        WorkflowType = "external_asm"
	WorkflowBugBounty          WorkflowType = "bug_bounty"
	WorkflowInternalAssessment WorkflowType = "internal_assessment"
	WorkflowDNSAssessment      WorkflowType = "dns_assessment"
	WorkflowWebAssessment      WorkflowType = "web_assessment"
	WorkflowWebFull            WorkflowType = "web_full"
	WorkflowAPIAudit           WorkflowType = "api_audit"
	WorkflowJSRecon            WorkflowType = "js_recon"
	WorkflowCMSDetect          WorkflowType = "cms_detect"
	WorkflowInjectionSuite     WorkflowType = "injection_suite"
	WorkflowGitSecrets         WorkflowType = "git_secrets" // git URL or local path only
	WorkflowTakeoverScan       WorkflowType = "takeover_scan"
	WorkflowNucleiFullScan     WorkflowType = "nuclei_full_scan"
	WorkflowScreenshot         WorkflowType = "screenshot"
	WorkflowCloudEnum          WorkflowType = "cloud_enum"
)

// WorkflowStageResult holds the outcome of one stage.
type WorkflowStageResult struct {
	Stage    string        `json:"stage"`
	Tool     string        `json:"tool"`
	Status   string        `json:"status"` // "ok", "skipped", "error"
	Duration time.Duration `json:"duration_ms"`
	Error    string        `json:"error,omitempty"`
	Count    int           `json:"result_count"`
}

// WorkflowResult is the aggregated result of a full workflow run.
type WorkflowResult struct {
	Workflow WorkflowType          `json:"workflow"`
	Target   string                `json:"target"`
	Started  time.Time             `json:"started"`
	Finished time.Time             `json:"finished"`
	Stages   []WorkflowStageResult `json:"stages"`
	Error    string                `json:"error,omitempty"`
}

// StageFunc is the signature for a workflow stage executor.
// It receives the target and returns (resultCount, error).
type StageFunc func(target string) (int, error)

// WorkflowEngine executes sequential stage-based workflows.
type WorkflowEngine struct {
	registry *Registry
	log      *zap.SugaredLogger
	timeout  time.Duration
}

// NewWorkflowEngine returns a WorkflowEngine using the provided registry.
func NewWorkflowEngine(registry *Registry, log *zap.SugaredLogger) *WorkflowEngine {
	return &WorkflowEngine{
		registry: registry,
		log:      log,
		timeout:  DefaultTimeout,
	}
}

// WorkflowStageConfig is a single stage entry in a workflow definition.
// When RunAll is true, the engine runs ALL installed+enabled tools in the
// category rather than stopping at the first match. This is used for
// WorkflowInjectionSuite so every injection tool executes in priority order.
type WorkflowStageConfig struct {
	Category Category
	RunAll   bool
}

// workflowStages defines ordered tool categories for each workflow.
var workflowStages = map[WorkflowType][]WorkflowStageConfig{
	WorkflowExternalASM: {
		{CategorySubdomain, false},
		{CategoryDNS, false},
		{CategoryNetwork, false},
		{CategoryWeb, false},
		{CategoryWeb, false}, // crawl pass
		{CategoryContent, false},
		{CategoryVulnerability, false},
	},
	WorkflowBugBounty: {
		{CategorySubdomain, false},
		{CategoryDNS, false},
		{CategoryWeb, false},
		{CategoryWeb, false},         // crawl pass
		{CategoryFingerprint, false}, // tech detection to inform vuln selection
		{CategoryParams, false},      // parameter discovery before fuzzing
		{CategoryContent, false},
		{CategoryVulnerability, false},
	},
	WorkflowInternalAssessment: {
		{CategoryNetwork, false},
		{CategorySMB, false},
		{CategoryVulnerability, false},
	},
	WorkflowDNSAssessment: {
		{CategoryDNS, false},
	},
	WorkflowWebAssessment: {
		{CategoryWeb, false},
		{CategoryContent, false},
		{CategoryVulnerability, false},
	},
	WorkflowWebFull: {
		{CategoryWeb, false},           // HTTP probe + crawl
		{CategoryWeb, false},           // second crawl pass (gau/wayback)
		{CategoryContent, false},       // directory/file discovery
		{CategoryFingerprint, false},   // tech fingerprinting
		{CategoryParams, false},        // parameter discovery
		{CategoryInjection, false},     // active injection testing
		{CategoryVulnerability, false}, // nuclei + nikto
		{CategoryJSAnalysis, false},    // linkfinder + secretfinder + retire.js
	},
	WorkflowAPIAudit: {
		{CategoryContent, false},   // endpoint discovery via wordlists
		{CategoryParams, false},    // HTTP parameter discovery (arjun/paramspider)
		{CategoryAuth, false},      // JWT + CORS misconfig
		{CategoryInjection, false}, // SQLi + SSRF + SSTI
		{CategoryVulnerability, false},
	},
	WorkflowJSRecon: {
		{CategoryJSAnalysis, false}, // linkfinder → secretfinder → retire.js
	},
	// WorkflowCMSDetect: fingerprint first; wpscan/droopescan only fire
	// if the fingerprint stage recorded a known CMS. The dispatcher handles
	// the conditional logic by reading prior tool_run_results from the DB.
	WorkflowCMSDetect: {
		{CategoryFingerprint, false},   // whatweb / wappalyzer — detect CMS
		{CategoryVulnerability, false}, // wpscan / droopescan — conditional on CMS match
	},
	// WorkflowInjectionSuite: RunAll=true so every installed injection tool
	// runs in priority order (sqlmap → dalfox → … → gopherus), not just the first.
	WorkflowInjectionSuite: {
		{CategoryInjection, true},
	},
	// WorkflowGitSecrets: target must be a git repo URL (https://github.com/…)
	// or a local absolute path. Passing a domain name will return 0 results.
	WorkflowGitSecrets: {
		{CategorySecrets, false}, // trufflehog → gitleaks
	},

	// WorkflowTakeoverScan: enumerates subdomains first, then checks every
	// discovered subdomain for dangling CNAME / takeover vulnerability.
	// dns-takeover-check always runs (no extra binary needed); subjack/subzy
	// and nuclei-takeover run if their binaries are installed.
	WorkflowTakeoverScan: {
		{CategorySubdomain, false}, // subfinder/amass — build the subdomain list
		{CategoryDNS, false},       // dnsx — resolve CNAMEs used by takeover check
		{CategoryTakeover, true},   // RunAll=true: run all installed takeover tools
	},

	// WorkflowNucleiFullScan: runs the complete Nuclei template library with
	// all severity levels and key template tags. Intended as a targeted deep
	// vulnerability scan after initial discovery has mapped the surface.
	WorkflowNucleiFullScan: {
		{CategoryWeb, false},           // httpx — probe which hosts are live
		{CategoryFingerprint, false},   // whatweb/wappalyzer — tech context for nuclei
		{CategoryVulnerability, false}, // nuclei (full), nikto, testssl
	},

	// WorkflowScreenshot: HTTP-probes the target with httpx to confirm live
	// hosts, then captures screenshots with gowitness (primary) and aquatone
	// (secondary). Results are persisted to web_assets and tool_run_results.
	WorkflowScreenshot: {
		{CategoryWeb, false},        // httpx — confirm live HTTP hosts first
		{CategoryScreenshot, false}, // gowitness → aquatone
	},

	// WorkflowCloudEnum: enumerates cloud resources via native CLI tools.
	// Credentials must be pre-configured in the environment; the dispatcher
	// picks up the provider context from the scan target string
	// ("aws", "azure", or "gcp") and falls back to trying all three.
	WorkflowCloudEnum: {
		{CategoryCloud, false}, // aws → az → gcloud
	},
}

// workflowToolOrder defines the preferred tool ordering within each category
// for workflow execution. The first installed+enabled tool is used per category.
var workflowToolOrder = map[Category][]string{
	CategorySubdomain:     {"subfinder", "amass", "assetfinder", "findomain"},
	CategoryDNS:           {"dnsx", "dnsrecon", "dnsenum", "dnstwist"},
	CategoryNetwork:       {"nmap", "naabu", "rustscan", "masscan"},
	CategoryWeb:           {"httpx", "katana", "hakrawler", "gau", "waybackurls"},
	CategoryContent:       {"ffuf", "feroxbuster", "gobuster", "dirsearch"},
	CategoryVulnerability: {"nuclei", "nikto", "testssl.sh", "wpscan", "droopescan"},
	CategoryWAF:           {"wafw00f"},
	CategorySMB:           {"smbclient", "enum4linux-ng", "crackmapexec"},
	CategoryOriginIP:      {"cloudflair", "hakoriginfinder", "cloakquest3r"},
	CategoryInjection:     {"sqlmap", "dalfox", "xsstrike", "commix", "tplmap", "crlfuzz", "smuggler", "h2csmuggler", "ssrfmap", "gopherus"},
	CategorySecrets:       {"trufflehog", "gitleaks"},
	CategoryFingerprint:   {"whatweb", "wappalyzer"},
	CategoryJSAnalysis:    {"linkfinder", "secretfinder", "retire", "snyk"},
	CategoryAuth:          {"jwt_tool", "corsy"},
	CategoryParams:        {"arjun", "paramspider"},
	CategoryTakeover:      {"subjack", "subzy", "nuclei-takeover", "dns-takeover-check"},
	CategoryScreenshot:    {"gowitness", "aquatone"},
	CategoryCloud:         {"aws", "az", "gcloud"},
}

// Run executes a named workflow against the target, running stages sequentially.
// Each stage either picks the first installed+enabled tool (default) or, when
// RunAll is true, iterates all installed+enabled tools in the category.
func (e *WorkflowEngine) Run(workflowType WorkflowType, target string, stageFuncs map[string]StageFunc) WorkflowResult {
	result := WorkflowResult{
		Workflow: workflowType,
		Target:   target,
		Started:  time.Now(),
	}

	stages, ok := workflowStages[workflowType]
	if !ok {
		result.Error = fmt.Sprintf("unknown workflow: %s", workflowType)
		result.Finished = time.Now()
		return result
	}

	for _, stageCfg := range stages {
		cat := stageCfg.Category
		toolNames := workflowToolOrder[cat]

		// Collect all installed+enabled tools for this category.
		var installedTools []string
		for _, name := range toolNames {
			info, found := e.registry.Get(name)
			if found && info.Status == StatusInstalled && info.Enabled {
				installedTools = append(installedTools, name)
			}
		}

		if len(installedTools) == 0 {
			stageResult := WorkflowStageResult{
				Stage:  string(cat),
				Tool:   "",
				Status: "skipped",
				Error:  "no installed+enabled tool found for category " + string(cat),
			}
			result.Stages = append(result.Stages, stageResult)
			// Bug 8: When cms_detect skips the fingerprint stage, warn that
			// downstream CMS scanners (wpscan/droopescan) will also produce no
			// results — they rely on fingerprint data to decide whether to run.
			if workflowType == WorkflowCMSDetect && cat == CategoryFingerprint {
				e.log.Warnw("workflow stage skipped — downstream CMS scanners will also be skipped",
					"workflow", workflowType,
					"category", cat,
					"reason", "no installed+enabled tool found for category "+string(cat),
				)
			} else {
				e.log.Warnw("workflow stage skipped", "workflow", workflowType, "category", cat)
			}
			continue
		}

		// Determine which tools to run: all (RunAll) or just the first match.
		var toRun []string
		if stageCfg.RunAll {
			toRun = installedTools
		} else {
			toRun = installedTools[:1]
		}

		for _, selectedTool := range toRun {
			stageResult := WorkflowStageResult{
				Stage: string(cat),
				Tool:  selectedTool,
			}

			fn, hasFn := stageFuncs[selectedTool]
			if !hasFn {
				stageResult.Status = "skipped"
				stageResult.Error = "no executor registered for tool: " + selectedTool
				result.Stages = append(result.Stages, stageResult)
				continue
			}

			start := time.Now()
			e.log.Infow("workflow stage starting", "workflow", workflowType, "stage", cat, "tool", selectedTool)
			count, err := fn(target)
			stageResult.Duration = time.Since(start)
			stageResult.Count = count
			if err != nil {
				stageResult.Status = "error"
				stageResult.Error = err.Error()
				e.log.Warnw("workflow stage error", "workflow", workflowType, "tool", selectedTool, "error", err)
			} else {
				stageResult.Status = "ok"
			}
			result.Stages = append(result.Stages, stageResult)
		}
	}

	result.Finished = time.Now()
	return result
}

// ValidateWorkflow returns an error if the workflow type is not recognised.
func ValidateWorkflow(wf string) (WorkflowType, error) {
	switch WorkflowType(wf) {
	case WorkflowExternalASM, WorkflowBugBounty, WorkflowInternalAssessment,
		WorkflowDNSAssessment, WorkflowWebAssessment,
		WorkflowWebFull, WorkflowAPIAudit, WorkflowJSRecon,
		WorkflowCMSDetect, WorkflowInjectionSuite, WorkflowGitSecrets,
		WorkflowTakeoverScan, WorkflowNucleiFullScan,
		WorkflowScreenshot, WorkflowCloudEnum:
		return WorkflowType(wf), nil
	case "":
		return "", nil
	default:
		return "", fmt.Errorf("unknown workflow type: %q (valid: external_asm, bug_bounty, internal_assessment, dns_assessment, web_assessment, web_full, api_audit, js_recon, cms_detect, injection_suite, git_secrets, takeover_scan, nuclei_full_scan, screenshot, cloud_enum)", wf)
	}
}

// AllWorkflows returns all valid workflow type strings.
func AllWorkflows() []string {
	return []string{
		string(WorkflowExternalASM),
		string(WorkflowBugBounty),
		string(WorkflowInternalAssessment),
		string(WorkflowDNSAssessment),
		string(WorkflowWebAssessment),
		string(WorkflowWebFull),
		string(WorkflowAPIAudit),
		string(WorkflowJSRecon),
		string(WorkflowCMSDetect),
		string(WorkflowInjectionSuite),
		string(WorkflowGitSecrets),
		string(WorkflowTakeoverScan),
		string(WorkflowNucleiFullScan),
		string(WorkflowScreenshot),
		string(WorkflowCloudEnum),
	}
}
