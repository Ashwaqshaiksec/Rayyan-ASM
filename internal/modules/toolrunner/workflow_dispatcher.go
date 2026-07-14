package toolrunner

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"
	"time"

	"github.com/ShadooowX/rayyan-asm/internal/models"
	"github.com/ShadooowX/rayyan-asm/internal/modules/discovery"
	"github.com/ShadooowX/rayyan-asm/internal/modules/toolrunner/tools"
	"github.com/google/uuid"
	"go.uber.org/zap"
	"gorm.io/gorm"
)

// WSHub is the minimal interface for the WebSocket hub used to broadcast events.
// BroadcastToOrg scopes messages to a single organisation so that scan
// progress events are never visible to users from other tenants.
// BroadcastRaw is kept for admin-level events that are legitimately global
// (e.g. tool-installer progress sent only to admin users).
type WSHub interface {
	BroadcastRaw(message []byte)
	BroadcastToOrg(orgID string, data []byte)
}

// toolProgressEvent is the JSON shape broadcast after each workflow stage.
type toolProgressEvent struct {
	Type     string `json:"type"`
	Stage    string `json:"stage"`
	Tool     string `json:"tool"`
	Status   string `json:"status"`
	Count    int    `json:"count"`
	Duration int64  `json:"duration_ms"`
	ScanID   string `json:"scan_id"`
}

// toolRunResultRow is the lightweight DB struct for tool_run_results.
// It avoids importing the models package to keep the toolrunner self-contained.
// NOTE: ID must be set by the caller (uuid.New().String()) before Create —
// no database-side default is used so this struct works with both SQLite and Postgres.
type toolRunResultRow struct {
	ID           string        `gorm:"primaryKey;type:uuid"`
	ScanID       string        `gorm:"type:uuid;not null;index"`
	ToolName     string        `gorm:"not null"`
	Category     string        `gorm:"not null;default:''"`
	ResultData   datatypesJSON `gorm:"column:result_data;type:jsonb"`
	ResultCount  int           `gorm:"not null;default:0"`
	DurationMS   int64         `gorm:"not null;default:0"`
	Status       string        `gorm:"not null;default:'ok'"`
	ErrorMessage string        `gorm:"not null;default:''"`
	Truncated    bool          `gorm:"not null;default:false"`
	CreatedAt    time.Time
}

// datatypesJSON is a []byte alias for JSONB columns.
type datatypesJSON []byte

func (toolRunResultRow) TableName() string { return "tool_run_results" }

// RunWorkflowForScan executes a named workflow for a scan, persisting each stage
// result to the DB and broadcasting WebSocket progress events.
//
// credKey is the decoded 32-byte AES-256 key used to load stored tool
// credentials; pass nil to disable credential lookup (SMB tools
// will fall back to unauthenticated/null-session execution).
func RunWorkflowForScan(
	ctx context.Context,
	db *gorm.DB,
	hub WSHub,
	engine *WorkflowEngine,
	workflowType WorkflowType,
	scanID uuid.UUID,
	orgID uuid.UUID,
	target string,
	credKey []byte,
	log *zap.SugaredLogger,
) WorkflowResult {
	stageFuncs := buildStageFuncs(ctx, db, hub, scanID, orgID, target, credKey, log, workflowType)
	return engine.Run(workflowType, target, stageFuncs)
}

// buildStageFuncs returns the stage executor map, wiring each tool to DB persistence
// and WebSocket broadcast.
func buildStageFuncs(
	ctx context.Context,
	db *gorm.DB,
	hub WSHub,
	scanID uuid.UUID,
	orgID uuid.UUID,
	target string,
	credKey []byte,
	log *zap.SugaredLogger,
	workflowType WorkflowType,
) map[string]StageFunc {
	persist := func(toolName, category string, count int, dur time.Duration, data interface{}, truncated bool, runErr error) {
		status := "ok"
		errMsg := ""
		if runErr != nil {
			status = "error"
			errMsg = runErr.Error()
		}
		raw, _ := json.Marshal(data)
		row := toolRunResultRow{
			ID:           uuid.New().String(),
			ScanID:       scanID.String(),
			ToolName:     toolName,
			Category:     category,
			ResultData:   raw,
			ResultCount:  count,
			DurationMS:   dur.Milliseconds(),
			Status:       status,
			ErrorMessage: errMsg,
			Truncated:    truncated,
		}
		if err := db.Create(&row).Error; err != nil {
			log.Warnw("failed to persist tool run result", "tool", toolName, "error", err)
		}
	}

	// persistTakeover writes TakeoverResult rows to the takeover_findings table
	// in addition to the generic scan_results row written by persist().
	persistTakeover := func(toolName string, results []tools.TakeoverResult, runErr error) {
		if runErr != nil || len(results) == 0 {
			return
		}
		for _, r := range results {
			if !r.Vulnerable {
				continue
			}
			finding := models.TakeoverFinding{
				OrgID:       orgID,
				Subdomain:   r.Subdomain,
				CNAME:       r.CNAME,
				Provider:    r.Provider,
				Fingerprint: r.Fingerprint,
				Vulnerable:  r.Vulnerable,
				Confidence:  r.Confidence,
				Source:      r.Source,
				ScanID:      &scanID,
			}
			// Upsert: if the same subdomain finding already exists for this org, update it.
			if err := db.Where(models.TakeoverFinding{
				OrgID:     orgID,
				Subdomain: r.Subdomain,
				Source:    r.Source,
			}).Assign(models.TakeoverFinding{
				CNAME:       r.CNAME,
				Provider:    r.Provider,
				Fingerprint: r.Fingerprint,
				Confidence:  r.Confidence,
				ScanID:      &scanID,
			}).FirstOrCreate(&finding).Error; err != nil {
				log.Warnw("failed to persist takeover finding", "tool", toolName, "subdomain", r.Subdomain, "error", err)
			}
		}
	}

	// persistTechnology writes TechFingerprintResult rows (whatweb/wappalyzer)
	// into the technologies table in addition to the generic scan_results row
	// written by persist(). Previously fingerprint-stage results only ever
	// landed in the raw tool_run_results JSON blob — the Technologies page
	// reads from the technologies table, so every workflow that included a
	// "fingerprint" stage (External ASM, Bug Bounty, CMS Detect, ...) showed
	// zero technologies no matter how much whatweb/wappalyzer actually found.
	// ServiceID is left nil: whatweb/wappalyzer report by URL, not by the
	// host/port pairing a Service row is keyed on, and Technology.ServiceID
	// is nullable for exactly this best-effort-enrichment case.
	persistTechnology := func(toolName string, results []tools.TechFingerprintResult, runErr error) {
		if runErr != nil || len(results) == 0 {
			return
		}
		for _, r := range results {
			if r.Technology == "" {
				continue
			}
			category := strings.Join(r.Categories, ", ")
			tech := models.Technology{
				OrgID:      orgID,
				Name:       r.Technology,
				Category:   category,
				Version:    r.Version,
				Confidence: r.Confidence,
				Source:     toolName,
			}
			if err := db.Where("org_id = ? AND name = ? AND source = ?", orgID, r.Technology, toolName).
				Assign(models.Technology{Category: category, Version: r.Version, Confidence: r.Confidence}).
				FirstOrCreate(&tech).Error; err != nil {
				log.Warnw("failed to persist technology", "tool", toolName, "technology", r.Technology, "error", err)
			}
		}
	}

	broadcast := func(stage, toolName, status string, count int, dur time.Duration) {
		if hub == nil {
			return
		}
		evt := toolProgressEvent{
			Type:     "tool_progress",
			Stage:    stage,
			Tool:     toolName,
			Status:   status,
			Count:    count,
			Duration: dur.Milliseconds(),
			ScanID:   scanID.String(),
		}
		if msg, err := json.Marshal(evt); err == nil {
			hub.BroadcastToOrg(orgID.String(), msg)
		}
	}

	// toolTimeout returns the effective timeout for a named tool.
	// It uses the per-tool TimeoutSeconds if set, falling back to the category default.
	toolTimeout := func(name string) time.Duration {
		if info, ok := DefaultRegistry.Get(name); ok {
			return info.EffectiveTimeout()
		}
		return 10 * time.Minute
	}

	m := map[string]StageFunc{}

	for _, name := range []string{"subfinder", "amass", "assetfinder", "findomain", "theHarvester", "sublist3r", "subbrute", "SubDomainizer"} {
		name := name // capture
		m[name] = func(t string) (int, error) {
			start := time.Now()
			release := DefaultRegistry.Acquire(name)
			defer release()
			var results []tools.SubdomainResult
			var err error
			switch name {
			case "subfinder":
				results, err = tools.RunSubfinder(t, toolTimeout(name))
			case "amass":
				results, err = tools.RunAmass(t, toolTimeout(name))
			case "assetfinder":
				results, err = tools.RunAssetfinder(t, toolTimeout(name))
			case "findomain":
				results, err = tools.RunFindomain(t, toolTimeout(name))
			case "theHarvester":
				results, err = tools.RunTheHarvester(t, toolTimeout(name))
			case "sublist3r":
				results, err = tools.RunSublist3r(t, toolTimeout(name))
			case "subbrute":
				results, err = tools.RunSubbrute(t, toolTimeout(name))
			case "SubDomainizer":
				results, err = tools.RunSubDomainizer(t, toolTimeout(name))
			}
			dur := time.Since(start)
			persist(name, "subdomain", len(results), dur, results, false, err)
			broadcast("subdomain", name, statusStr(err), len(results), dur)
			return len(results), err
		}
	}

	for _, name := range []string{"dnsx", "dnsrecon", "dnsenum", "dnstwist"} {
		name := name
		m[name] = func(t string) (int, error) {
			start := time.Now()
			release := DefaultRegistry.Acquire(name)
			defer release()
			var records interface{}
			var count int
			var err error
			switch name {
			case "dnsx":
				r, e := tools.RunDnsx([]string{t}, toolTimeout(name))
				records, count, err = r, len(r), e
			case "dnsrecon":
				r, e := tools.RunDnsrecon(t, toolTimeout(name))
				records, count, err = r, len(r), e
			case "dnsenum":
				r, e := tools.RunDnsenum(t, toolTimeout(name))
				records, count, err = r, len(r), e
			case "dnstwist":
				r, e := tools.RunDnstwist(t, toolTimeout(name))
				records, count, err = r, len(r), e
			}
			dur := time.Since(start)
			persist(name, "dns", count, dur, records, false, err)
			broadcast("dns", name, statusStr(err), count, dur)
			return count, err
		}
	}

	for _, name := range []string{"nmap", "naabu", "rustscan", "masscan"} {
		name := name
		m[name] = func(t string) (int, error) {
			start := time.Now()
			release := DefaultRegistry.Acquire(name)
			defer release()
			var results []tools.PortResult
			var err error
			switch name {
			case "nmap":
				results, err = tools.RunNmap(t, "", toolTimeout(name))
			case "naabu":
				results, err = tools.RunNaabu(t, toolTimeout(name))
			case "rustscan":
				results, err = tools.RunRustscan(t, toolTimeout(name))
			case "masscan":
				results, err = tools.RunMasscan(t, "1000", toolTimeout(name))
			}
			dur := time.Since(start)
			// Upsert each discovered port as a Service row and snapshot history.
			if err == nil {
				now := time.Now()
				hostIDs := make(map[string]uuid.UUID, len(results))
				for _, r := range results {
					// Resolve (and ASN-enrich) the Host row once per unique
					// IP in this batch, before creating any Service for it,
					// so the Service can be linked by host_id — the
					// host-detail page's service list filters strictly on
					// that FK, not on host_ref, so without this every
					// service found by nmap/naabu/rustscan/masscan here
					// was invisible there even though it existed in the DB.
					hostID, seen := hostIDs[r.Host]
					if !seen {
						hostID = enrichHostASN(ctx, db, orgID, r.Host, log)
						hostIDs[r.Host] = hostID
					}

					svc := models.Service{
						OrgID:    orgID,
						HostID:   hostID,
						HostRef:  r.Host,
						Port:     r.Port,
						Protocol: r.Protocol,
						Service:  r.Service,
						Version:  r.Version,
						State: func() string {
							if r.State == "" {
								return "open"
							}
							return r.State
						}(),
						FirstSeenAt: now,
						LastSeenAt:  now,
					}
					if err := db.Where("org_id = ? AND host_ref = ? AND port = ? AND protocol = ?",
						orgID, r.Host, r.Port, r.Protocol).
						Assign(models.Service{
							Service:    r.Service,
							Version:    r.Version,
							State:      svc.State,
							LastSeenAt: now,
							HostID:     hostID,
						}).FirstOrCreate(&svc).Error; err != nil {
						log.Warnw("workflow: failed to persist service", "host", r.Host, "port", r.Port, "error", err)
						continue
					}
					models.RecordServiceHistory(db, svc, &scanID)
				}
			}
			persist(name, "network", len(results), dur, results, false, err)
			broadcast("network", name, statusStr(err), len(results), dur)
			return len(results), err
		}
	}

	for _, name := range []string{"httpx", "katana", "hakrawler", "gau", "waybackurls"} {
		name := name
		// Archive-URL tools get a tighter line cap (10k)
		maxLines := 0
		if name == "gau" || name == "waybackurls" {
			maxLines = 10_000
		}
		m[name] = func(t string) (int, error) {
			start := time.Now()
			release := DefaultRegistry.Acquire(name)
			defer release()
			var results interface{}
			var count int
			var err error
			switch name {
			case "httpx":
				r, e := tools.RunHTTPx([]string{t}, toolTimeout(name))
				results, count, err = r, len(r), e
			case "katana":
				r, e := tools.RunKatana(t, 3, toolTimeout(name))
				results, count, err = r, len(r), e
			case "hakrawler":
				r, e := tools.RunHakrawler(t, toolTimeout(name))
				results, count, err = r, len(r), e
			case "gau":
				r, e := tools.RunGau(t, toolTimeout(name), maxLines)
				results, count, err = r, len(r), e
			case "waybackurls":
				r, e := tools.RunWaybackurls(t, toolTimeout(name), maxLines)
				results, count, err = r, len(r), e
			}
			dur := time.Since(start)
			persist(name, "web", count, dur, results, false, err)
			broadcast("web", name, statusStr(err), count, dur)
			return count, err
		}
	}

	for _, name := range []string{"ffuf", "feroxbuster", "gobuster", "dirsearch"} {
		name := name
		m[name] = func(t string) (int, error) {
			start := time.Now()
			release := DefaultRegistry.Acquire(name)
			defer release()
			var results []tools.ContentResult
			var err error
			switch name {
			case "ffuf":
				results, err = tools.RunFFUF(t, "", toolTimeout(name))
			case "feroxbuster":
				results, err = tools.RunFeroxbuster(t, "", toolTimeout(name))
			case "gobuster":
				results, err = tools.RunGobuster(t, "", toolTimeout(name))
			case "dirsearch":
				results, err = tools.RunDirsearch(t, "", toolTimeout(name))
			}
			dur := time.Since(start)
			persist(name, "content", len(results), dur, results, false, err)
			broadcast("content", name, statusStr(err), len(results), dur)
			return len(results), err
		}
	}

	for _, name := range []string{"nuclei", "nikto", "testssl.sh"} {
		name := name
		m[name] = func(t string) (int, error) {
			start := time.Now()
			release := DefaultRegistry.Acquire(name)
			defer release()
			var results []tools.VulnResult
			var err error
			switch name {
			case "nuclei":
				results, err = tools.RunNuclei(t, "", toolTimeout(name))
			case "nikto":
				results, err = tools.RunNikto(t, toolTimeout(name))
			case "testssl.sh":
				results, err = tools.RunTestssl(t, toolTimeout(name))
			}
			dur := time.Since(start)
			persist(name, "vulnerability", len(results), dur, results, false, err)
			broadcast("vulnerability", name, statusStr(err), len(results), dur)
			return len(results), err
		}
	}

	m["wafw00f"] = func(t string) (int, error) {
		start := time.Now()
		release := DefaultRegistry.Acquire("wafw00f")
		defer release()
		results, err := tools.RunWafw00f(t, toolTimeout("wafw00f"))
		dur := time.Since(start)
		persist("wafw00f", "waf", len(results), dur, results, false, err)
		broadcast("waf", "wafw00f", statusStr(err), len(results), dur)
		return len(results), err
	}

	for _, name := range []string{"smbclient", "enum4linux-ng", "crackmapexec"} {
		name := name
		m[name] = func(t string) (int, error) {
			start := time.Now()
			release := DefaultRegistry.Acquire(name)
			defer release()

			// load stored, decrypted credentials for this tool (if any).
			creds, credErr := LoadCredentials(db, credKey, orgID, name)
			if credErr != nil {
				log.Warnw("failed to load stored credentials, proceeding without", "tool", name, "error", credErr)
				creds = nil
			}

			var results []tools.SMBResult
			var err error
			switch name {
			case "smbclient":
				results, err = tools.RunSmbclientWithCreds(t, creds, toolTimeout(name))
			case "enum4linux-ng":
				results, err = tools.RunEnum4linuxNgWithCreds(t, creds, toolTimeout(name))
			case "crackmapexec":
				results, err = tools.RunCrackMapExecWithCreds(t, creds, toolTimeout(name))
			}
			dur := time.Since(start)
			persist(name, "smb", len(results), dur, results, false, err)
			broadcast("smb", name, statusStr(err), len(results), dur)
			return len(results), err
		}
	}

	for _, name := range []string{"cloudflair", "hakoriginfinder", "cloakquest3r"} {
		name := name
		m[name] = func(t string) (int, error) {
			start := time.Now()
			release := DefaultRegistry.Acquire(name)
			defer release()
			var results []tools.OriginIPResult
			var err error
			switch name {
			case "cloudflair":
				results, err = tools.RunCloudflair(t, toolTimeout(name))
			case "hakoriginfinder":
				results, err = tools.RunHakoriginfinder(t, toolTimeout(name))
			case "cloakquest3r":
				results, err = tools.RunCloakquest3r(t, toolTimeout(name))
			}
			dur := time.Since(start)
			persist(name, "origin_ip", len(results), dur, results, false, err)
			broadcast("origin_ip", name, statusStr(err), len(results), dur)
			return len(results), err
		}
	}

	// gopherus: load a protocol hint from stored credentials (Domain field).
	// Falls back to "http" if no credential is configured.
	gopherusProtocol := "http"
	if gCreds, gErr := LoadCredentials(db, credKey, orgID, "gopherus"); gErr == nil && gCreds != nil && gCreds.Domain != "" {
		gopherusProtocol = gCreds.Domain
	}
	for _, name := range []string{"sqlmap", "dalfox", "xsstrike", "commix", "tplmap", "crlfuzz", "smuggler", "h2csmuggler", "ssrfmap", "gopherus"} {
		name := name
		m[name] = func(t string) (int, error) {
			start := time.Now()
			release := DefaultRegistry.Acquire(name)
			defer release()
			var results []tools.InjectionResult
			var err error
			switch name {
			case "sqlmap":
				results, err = tools.RunSQLMap(t, toolTimeout(name))
			case "dalfox":
				results, err = tools.RunDalfox(t, toolTimeout(name))
			case "xsstrike":
				results, err = tools.RunXSStrike(t, toolTimeout(name))
			case "commix":
				results, err = tools.RunCommix(t, toolTimeout(name))
			case "tplmap":
				results, err = tools.RunTplmap(t, toolTimeout(name))
			case "crlfuzz":
				results, err = tools.RunCRLFuzz(t, toolTimeout(name))
			case "smuggler":
				results, err = tools.RunSmuggler(t, toolTimeout(name))
			case "h2csmuggler":
				results, err = tools.RunH2CSmuggler(t, toolTimeout(name))
			case "ssrfmap":
				results, err = tools.RunSSRFMap(t, toolTimeout(name))
			case "gopherus":
				// gopherusProtocol is set from stored credentials or defaults to "http"
				results, err = tools.RunGopherus(t, gopherusProtocol, toolTimeout(name))
			}
			dur := time.Since(start)
			persist(name, "injection", len(results), dur, results, false, err)
			broadcast("injection", name, statusStr(err), len(results), dur)
			return len(results), err
		}
	}

	for _, name := range []string{"whatweb", "wappalyzer"} {
		name := name
		m[name] = func(t string) (int, error) {
			start := time.Now()
			release := DefaultRegistry.Acquire(name)
			defer release()
			var results []tools.TechFingerprintResult
			var err error
			switch name {
			case "whatweb":
				results, err = tools.RunWhatWeb(t, toolTimeout(name))
			case "wappalyzer":
				results, err = tools.RunWappalyzerCLI(t, toolTimeout(name))
			}
			dur := time.Since(start)
			persist(name, "fingerprint", len(results), dur, results, false, err)
			persistTechnology(name, results, err)
			broadcast("fingerprint", name, statusStr(err), len(results), dur)
			return len(results), err
		}
	}

	// snyk requires a local project path, not a URL. It is skipped gracefully
	// when the target looks like a domain or HTTP URL.
	for _, name := range []string{"linkfinder", "secretfinder", "retire", "snyk"} {
		name := name
		m[name] = func(t string) (int, error) {
			// snyk is a dependency scanner — it needs a local project dir, not a web target.
			// Skip it silently when the target is a URL or bare domain so the workflow
			// stage records 0 results rather than a confusing error.
			if name == "snyk" && (strings.HasPrefix(t, "http") || !strings.HasPrefix(t, "/")) {
				log.Infow("skipping snyk: target is not a local project path", "target", t)
				dur := time.Duration(0)
				persist(name, "js_analysis", 0, dur, nil, false, nil)
				broadcast("js_analysis", name, "skipped", 0, dur)
				return 0, nil
			}
			start := time.Now()
			release := DefaultRegistry.Acquire(name)
			defer release()
			var count int
			var data interface{}
			var err error
			switch name {
			case "linkfinder":
				r, e := tools.RunLinkFinder(t, toolTimeout(name))
				data, count, err = r, len(r), e
			case "secretfinder":
				r, e := tools.RunSecretFinder(t, toolTimeout(name))
				data, count, err = r, len(r), e
			case "retire":
				r, e := tools.RunRetireJS(t, toolTimeout(name))
				data, count, err = r, len(r), e
			case "snyk":
				r, e := tools.RunSnyk(t, toolTimeout(name))
				data, count, err = r, len(r), e
			}
			dur := time.Since(start)
			persist(name, "js_analysis", count, dur, data, false, err)
			broadcast("js_analysis", name, statusStr(err), count, dur)
			return count, err
		}
	}

	// jwt_tool: load a stored JWT from credentials (Username field stores the token).
	// If no credential is stored, skip jwt_tool gracefully rather than passing a
	// dummy token that produces meaningless results.
	for _, name := range []string{"jwt_tool", "corsy"} {
		name := name
		m[name] = func(t string) (int, error) {
			start := time.Now()
			release := DefaultRegistry.Acquire(name)
			defer release()
			var results []tools.AuthResult
			var err error
			switch name {
			case "jwt_tool":
				// Load the JWT from stored credentials (Username field).
				jwtCreds, credErr := LoadCredentials(db, credKey, orgID, "jwt_tool")
				token := ""
				if credErr != nil {
					log.Warnw("jwt_tool: could not load stored credential", "error", credErr)
				} else if jwtCreds != nil {
					token = jwtCreds.Username // Username field carries the raw JWT string
				}
				if token == "" {
					// No token configured — skip rather than test with a dummy value.
					log.Infow("skipping jwt_tool: no JWT credential stored for org", "org_id", orgID)
					dur := time.Since(start)
					persist(name, "auth", 0, dur, nil, false, nil)
					broadcast("auth", name, "skipped", 0, dur)
					return 0, nil
				}
				results, err = tools.RunJWTTool(token, t, toolTimeout(name))
			case "corsy":
				results, err = tools.RunCorsy(t, toolTimeout(name))
			}
			dur := time.Since(start)
			persist(name, "auth", len(results), dur, results, false, err)
			broadcast("auth", name, statusStr(err), len(results), dur)
			return len(results), err
		}
	}

	// trufflehog and gitleaks operate on git repositories or local filesystem
	// paths, NOT on HTTP targets or bare domain names. They are only meaningful
	// in the git_secrets workflow where the target is a git URL or local path.
	// For the git_secrets workflow, we trust the operator's target and only
	// require it to be non-empty. For all other workflows, we validate the URL.
	isGitTarget := func(t string) bool {
		if workflowType == WorkflowGitSecrets {
			// In git_secrets workflow, trust the operator: skip URL validation,
			// only require a non-empty target.
			return t != ""
		}
		// For all other workflows: only run if the target looks like a git repo.
		// Matches ssh, https/http on known hosts, self-hosted instances, and
		// any URL path ending in .git (covers Gitea, Gogs, Bitbucket Server, etc.).
		return strings.HasPrefix(t, "git@") ||
			strings.HasPrefix(t, "https://github.com") ||
			strings.HasPrefix(t, "http://github.com") ||
			strings.HasPrefix(t, "https://gitlab.") ||
			strings.HasPrefix(t, "http://gitlab.") ||
			strings.HasPrefix(t, "https://bitbucket.org") ||
			strings.HasPrefix(t, "http://bitbucket.") ||
			strings.HasSuffix(t, ".git") || // any host with a .git path suffix
			strings.HasPrefix(t, "/") // absolute local path
	}
	for _, name := range []string{"trufflehog", "gitleaks"} {
		name := name
		m[name] = func(t string) (int, error) {
			if !isGitTarget(t) {
				log.Infow("skipping git secrets tool: target is not a git URL or local path",
					"tool", name, "target", t)
				dur := time.Duration(0)
				persist(name, "secrets", 0, dur, nil, false, nil)
				broadcast("secrets", name, "skipped", 0, dur)
				return 0, nil
			}
			start := time.Now()
			release := DefaultRegistry.Acquire(name)
			defer release()
			var results []tools.SecretResult
			var err error
			switch name {
			case "trufflehog":
				results, err = tools.RunTruffleHog(t, toolTimeout(name))
			case "gitleaks":
				results, err = tools.RunGitleaks(t, toolTimeout(name))
			}
			dur := time.Since(start)
			persist(name, "secrets", len(results), dur, results, false, err)
			broadcast("secrets", name, statusStr(err), len(results), dur)
			return len(results), err
		}
	}

	// wpscan and droopescan only fire if a prior fingerprint stage in this scan
	// detected a known CMS. We check tool_run_results for fingerprint entries
	// containing WordPress, Drupal, Joomla, or similar CMS names. If none were
	// detected, the stage is skipped — prevents running a WordPress scanner
	// against a React SPA or a plain nginx server.
	cmsDetectedInScan := func(cmsName string) bool {
		var rows []toolRunResultRow
		if err := db.Where("scan_id = ? AND category = ?", scanID.String(), "fingerprint").
			Find(&rows).Error; err != nil {
			return false
		}
		cmsLower := strings.ToLower(cmsName)
		for _, row := range rows {
			if strings.Contains(strings.ToLower(string(row.ResultData)), cmsLower) {
				return true
			}
		}
		return false
	}
	for _, name := range []string{"wpscan", "droopescan"} {
		name := name
		m[name] = func(t string) (int, error) {
			// Conditional execution: only run CMS scanners if fingerprinting
			// confirmed a matching CMS on this target.
			switch name {
			case "wpscan":
				// Guard: only run if WordPress was detected by a prior fingerprint stage.
				if !cmsDetectedInScan("wordpress") {
					log.Infow("skipping wpscan: WordPress not detected by fingerprinting", "scan_id", scanID)
					dur := time.Duration(0)
					persist(name, "vulnerability", 0, dur, nil, false, nil)
					broadcast("vulnerability", name, "skipped", 0, dur)
					return 0, nil
				}
			case "droopescan":
				// droopescan covers Drupal, Joomla, WordPress, SilverStripe, Moodle
				// — run if ANY of these was detected.
				var targetCMS string
				for _, cms := range []string{"drupal", "joomla", "silverstripe", "moodle", "wordpress"} {
					if cmsDetectedInScan(cms) {
						targetCMS = cms
						break
					}
				}
				if targetCMS == "" {
					log.Infow("skipping droopescan: no supported CMS detected by fingerprinting", "scan_id", scanID)
					dur := time.Duration(0)
					persist(name, "vulnerability", 0, dur, nil, false, nil)
					broadcast("vulnerability", name, "skipped", 0, dur)
					return 0, nil
				}
			}
			start := time.Now()
			release := DefaultRegistry.Acquire(name)
			defer release()
			var results []tools.CMSResult
			var err error
			switch name {
			case "wpscan":
				results, err = tools.RunWPScan(t, toolTimeout(name))
			case "droopescan":
				results, err = tools.RunDroopeScan(t, toolTimeout(name))
			}
			dur := time.Since(start)
			persist(name, "vulnerability", len(results), dur, results, false, err)
			broadcast("vulnerability", name, statusStr(err), len(results), dur)
			return len(results), err
		}
	}

	// These are HTTP parameter fuzzers (arjun, paramspider) — semantically
	// distinct from content/directory fuzzers (ffuf, feroxbuster). They live
	// under CategoryParams so they never compete with or displace directory tools.
	for _, name := range []string{"arjun", "paramspider"} {
		name := name
		m[name] = func(t string) (int, error) {
			start := time.Now()
			release := DefaultRegistry.Acquire(name)
			defer release()
			var results []tools.ParamResult
			var err error
			switch name {
			case "arjun":
				results, err = tools.RunArjun(t, toolTimeout(name))
			case "paramspider":
				results, err = tools.RunParamSpider(t, toolTimeout(name))
			}
			dur := time.Since(start)
			persist(name, "params", len(results), dur, results, false, err)
			broadcast("params", name, statusStr(err), len(results), dur)
			return len(results), err
		}
	}

	// ── Takeover scanners ──────────────────────────────────────────────────
	// Pull subdomains discovered for the domain THIS scan targets, scoped via
	// the domains table (not just org_id, which would pull in subdomains
	// belonging to every other domain in the org too).
	// Falls back to the target domain if no subdomain stage has run yet.
	resolveSubdomains := func() []string {
		var rows []struct{ Name string }
		db.Raw(`
			SELECT DISTINCT s.fqdn AS name
			FROM subdomains s
			JOIN domains d ON d.id = s.domain_id
			JOIN scan_jobs sj ON sj.org_id = d.org_id
			WHERE sj.id = ? AND d.name = ?
		`, scanID, target).Scan(&rows)
		names := make([]string, 0, len(rows))
		for _, r := range rows {
			names = append(names, r.Name)
		}
		if len(names) == 0 {
			names = []string{target}
		}
		return names
	}

	for _, name := range []string{"subjack", "subzy"} {
		name := name
		m[name] = func(t string) (int, error) {
			subs := resolveSubdomains()
			start := time.Now()
			release := DefaultRegistry.Acquire(name)
			defer release()
			var results []tools.TakeoverResult
			var err error
			switch name {
			case "subjack":
				results, err = tools.RunSubjack(subs, toolTimeout(name))
			case "subzy":
				results, err = tools.RunSubzy(subs, toolTimeout(name))
			}
			dur := time.Since(start)
			persist(name, "takeover", len(results), dur, results, false, err)
			persistTakeover(name, results, err)
			broadcast("takeover", name, statusStr(err), len(results), dur)
			return len(results), err
		}
	}

	// dns-takeover-check: lightweight built-in, no binary required.
	m["dns-takeover-check"] = func(t string) (int, error) {
		subs := resolveSubdomains()
		start := time.Now()
		results, err := tools.RunDNSTakeoverCheck(subs, toolTimeout("dnsx"))
		dur := time.Since(start)
		persist("dns-takeover-check", "takeover", len(results), dur, results, false, err)
		persistTakeover("dns-takeover-check", results, err)
		broadcast("takeover", "dns-takeover-check", statusStr(err), len(results), dur)
		return len(results), err
	}

	// nuclei-takeover: nuclei binary, takeovers/ template pack only.
	m["nuclei-takeover"] = func(t string) (int, error) {
		subs := resolveSubdomains()
		start := time.Now()
		release := DefaultRegistry.Acquire("nuclei")
		defer release()
		results, err := tools.RunNucleiTakeover(subs, toolTimeout("nuclei"))
		dur := time.Since(start)
		persist("nuclei-takeover", "takeover", len(results), dur, results, false, err)
		persistTakeover("nuclei-takeover", results, err)
		broadcast("takeover", "nuclei-takeover", statusStr(err), len(results), dur)
		return len(results), err
	}

	// nuclei-full-scan: runs all NucleiFullScanGroups sequentially.
	// Used by WorkflowNucleiFullScan; has its own entry so it doesn't clash
	// with the single-pass "nuclei" entry in the vulnerability stage.
	m["nuclei-full-scan"] = func(t string) (int, error) {
		start := time.Now()
		release := DefaultRegistry.Acquire("nuclei")
		defer release()
		results, err := tools.RunNucleiFullScan(t, toolTimeout("nuclei"))
		dur := time.Since(start)
		persist("nuclei-full-scan", "vulnerability", len(results), dur, results, false, err)
		broadcast("vulnerability", "nuclei-full-scan", statusStr(err), len(results), dur)
		return len(results), err
	}

	// Screenshot tools — gowitness (primary) then aquatone (secondary).
	// Both write PNGs under /var/rayyan-asm/screenshots/<orgID>/<scanID>/ and
	// update web_assets rows with screenshotted=true + screenshot_path.
	screenshotOutDir := fmt.Sprintf("/var/rayyan-asm/screenshots/%s/%s", orgID, scanID)
	for _, name := range []string{"gowitness", "aquatone"} {
		name := name
		m[name] = func(t string) (int, error) {
			// Collect live HTTP targets from web_assets for this scan.
			var rows []struct{ URL string }
			db.Raw(`
				SELECT DISTINCT wa.url
				FROM web_assets wa
				JOIN services svc ON svc.id = wa.service_id
				JOIN hosts h ON h.id = svc.host_id
				JOIN scan_jobs sj ON sj.org_id = h.org_id
				WHERE sj.id = ? AND wa.url != ''
			`, scanID).Scan(&rows)
			targets := make([]string, 0, len(rows))
			for _, r := range rows {
				targets = append(targets, r.URL)
			}
			if len(targets) == 0 {
				// Fall back to the raw target if no web_assets exist yet.
				if !strings.HasPrefix(t, "http") {
					targets = []string{"http://" + t, "https://" + t}
				} else {
					targets = []string{t}
				}
			}

			start := time.Now()
			release := DefaultRegistry.Acquire(name)
			defer release()

			var results []tools.ScreenshotResult
			var err error
			switch name {
			case "gowitness":
				results, err = tools.RunGowitness(targets, screenshotOutDir, toolTimeout(name))
			case "aquatone":
				results, err = tools.RunAquatone(targets, screenshotOutDir, toolTimeout(name))
			}
			dur := time.Since(start)

			// Update web_assets rows with screenshot paths. Screenshot tools
			// can return the final URL after redirects (e.g. http -> https,
			// or a trailing slash added), which may not match the URL the
			// web-probe stage originally stored — so try a couple of
			// reasonable variants before giving up on a result.
			for _, res := range results {
				if res.FilePath == "" || res.URL == "" {
					continue
				}
				candidates := []string{res.URL, strings.TrimSuffix(res.URL, "/")}
				if !strings.HasSuffix(res.URL, "/") {
					candidates = append(candidates, res.URL+"/")
				}
				matched := false
				for _, u := range candidates {
					r := db.Table("web_assets").
						Where("org_id = ? AND (url = ? OR final_url = ?)", orgID, u, u).
						Updates(map[string]interface{}{
							"screenshotted":   true,
							"screenshot_path": res.FilePath,
						})
					if r.RowsAffected > 0 {
						matched = true
						break
					}
				}
				if !matched {
					log.Warnw("screenshot: captured file could not be linked to a web_asset",
						"scan_id", scanID, "tool", name, "url", res.URL, "file", res.FilePath)
				}
			}

			persist(name, "screenshot", len(results), dur, results, false, err)
			broadcast("screenshot", name, statusStr(err), len(results), dur)
			return len(results), err
		}
	}

	// Cloud CLI enumeration tools — aws, az (Azure), gcloud (GCP).
	// The scan target is interpreted as either a provider hint ("aws", "azure", "gcp")
	// or an account/project/subscription ID.  Credentials must be available in
	// the process environment before a cloud_enum scan is started.
	for _, name := range []string{"aws", "az", "gcloud"} {
		name := name
		m[name] = func(t string) (int, error) {
			start := time.Now()
			release := DefaultRegistry.Acquire(name)
			defer release()

			var results []tools.CloudAssetResult
			var err error

			switch name {
			case "aws":
				// t may be a region name (e.g. "us-east-1") or provider hint — pass as region.
				region := ""
				if t != "aws" && !strings.Contains(t, ".") {
					region = t
				}
				results, err = tools.RunAWSEnum(region, toolTimeout(name))
			case "az":
				// t may be a subscription ID or provider hint.
				sub := ""
				if t != "azure" && !strings.Contains(t, ".") {
					sub = t
				}
				results, err = tools.RunAzureEnum(sub, toolTimeout(name))
			case "gcloud":
				// t may be a GCP project ID or provider hint.
				project := ""
				if t != "gcp" && !strings.Contains(t, ".") {
					project = t
				}
				results, err = tools.RunGCPEnum(project, toolTimeout(name))
			}

			dur := time.Since(start)

			// Upsert discovered cloud assets into cloud_assets table.
			for _, res := range results {
				ipsJSON, err := json.Marshal(res.IPs)
				if err != nil {
					log.Warnw("cloud asset upsert: failed to marshal IPs", "resource_id", res.ResourceID, "error", err)
					continue
				}
				if r := db.Exec(`
					INSERT INTO cloud_assets
						(id, org_id, provider, resource_id, resource_type, name, region, account_id, ips, status, created_at, updated_at)
					VALUES
						(gen_random_uuid(), ?, ?, ?, ?, ?, ?, ?, ?::jsonb, 'active', NOW(), NOW())
					ON CONFLICT (org_id, provider, resource_id) DO UPDATE SET
						resource_type = EXCLUDED.resource_type,
						name          = EXCLUDED.name,
						region        = EXCLUDED.region,
						account_id    = EXCLUDED.account_id,
						ips           = EXCLUDED.ips,
						status        = 'active',
						updated_at    = NOW()
				`, orgID, res.Provider, res.ResourceID, res.ResourceType,
					res.Name, res.Region, res.AccountID, string(ipsJSON)); r.Error != nil {
					log.Warnw("cloud asset upsert failed", "resource_id", res.ResourceID, "error", r.Error)
				}
			}

			persist(name, "cloud", len(results), dur, results, false, err)
			broadcast("cloud", name, statusStr(err), len(results), dur)
			return len(results), err
		}
	}

	return m
}

// enrichHostASN upserts a Host row for a workflow-discovered IP and, if the
// host has no ASN on record yet, resolves and persists it (mirroring
// discovery.Engine.enrichHostASNAndGeo, but as a single best-effort call
// with no retry/cache/circuit-breaker — this runs once per unique host per
// stage invocation, not once per newly-discovered host across a whole run,
// so that machinery isn't worth pulling in here). Newly-seen ASNs also get
// their full prefix list written to asn_ranges, same as the discovery
// engine, so the ASN Ranges page and the correlation engine's "asn_range"
// edges work the same way regardless of which pipeline found the host.
func enrichHostASN(ctx context.Context, db *gorm.DB, orgID uuid.UUID, ip string, log *zap.SugaredLogger) uuid.UUID {
	now := time.Now()
	var host models.Host
	err := db.Where("org_id = ? AND ip = ?", orgID, ip).
		Attrs(models.Host{OrgID: orgID, IP: ip, Status: "active", FirstSeenAt: now, LastSeenAt: now}).
		FirstOrCreate(&host).Error
	if err != nil {
		log.Warnw("workflow: failed to upsert host for ASN enrichment", "ip", ip, "error", err)
		return uuid.UUID{}
	}
	if uerr := db.Model(&host).Updates(map[string]any{"last_seen_at": now, "status": "active"}).Error; uerr != nil {
		log.Warnw("workflow: failed to refresh host last-seen", "ip", ip, "error", uerr)
	}
	if host.ASN != "" {
		return host.ID
	}

	info, lookupErr := discovery.LookupASNForIP(ctx, ip)
	if lookupErr != nil {
		log.Warnw("workflow: ASN lookup failed, host will have no ASN/geo data", "ip", ip, "error", lookupErr)
		return host.ID
	}
	if info == nil || info.ASN == "" {
		return host.ID
	}
	if uerr := db.Model(&host).Updates(map[string]any{
		"asn": info.ASN, "asn_org": info.ASNOrg, "cidr": info.CIDR, "country": info.Country,
	}).Error; uerr != nil {
		log.Warnw("workflow: failed to persist host ASN enrichment", "ip", ip, "asn", info.ASN, "error", uerr)
	}

	var existing int64
	if cerr := db.Model(&models.ASNRange{}).Where("org_id = ? AND asn = ?", orgID, info.ASN).Count(&existing).Error; cerr != nil {
		log.Warnw("workflow: failed to count existing ASN ranges", "org_id", orgID, "asn", info.ASN, "error", cerr)
		return host.ID
	}
	if existing > 0 {
		return host.ID
	}

	asnNum := strings.TrimPrefix(info.ASN, "AS")
	cidrs, asnOrg := discovery.ExpandASNPrefixes(ctx, asnNum)
	if asnOrg == "" {
		asnOrg = info.ASNOrg
	}
	for _, cidr := range cidrs {
		rr := models.ASNRange{OrgID: orgID, ASN: info.ASN, ASNOrg: asnOrg, CIDR: cidr, Country: info.Country}
		rr.ID = uuid.New()
		rr.CreatedAt = time.Now()
		if err := db.Where("org_id = ? AND asn = ? AND cidr = ?", orgID, info.ASN, cidr).FirstOrCreate(&rr).Error; err != nil {
			log.Warnw("workflow: failed to persist ASN range", "org_id", orgID, "asn", info.ASN, "cidr", cidr, "error", err)
		}
	}
	return host.ID
}

func statusStr(err error) string {

	if err != nil {
		return "error"
	}
	return "ok"
}

// UpdateScanProgress updates the scan's progress field in the DB after a workflow completes.
func UpdateScanProgress(db *gorm.DB, scanID uuid.UUID, result WorkflowResult) error {
	progress := map[string]interface{}{
		"workflow":    string(result.Workflow),
		"started":     result.Started,
		"finished":    result.Finished,
		"stage_count": len(result.Stages),
		"stages":      result.Stages,
	}
	data, err := json.Marshal(progress)
	if err != nil {
		return fmt.Errorf("marshal progress: %w", err)
	}
	return db.Table("scans").
		Where("id = ?", scanID).
		Updates(map[string]interface{}{
			"workflow_progress": string(data),
			"updated_at":        time.Now(),
		}).Error
}
