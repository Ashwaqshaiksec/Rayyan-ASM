package handlers

import (
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"os/exec"
	"strings"
	"time"

	"github.com/ShadooowX/rayyan-asm/internal/api/middleware"
	"github.com/ShadooowX/rayyan-asm/internal/whois"
	"github.com/gin-gonic/gin"
	"go.uber.org/zap"
	"gorm.io/gorm"
)

// Lightweight on-demand tools: whois, CMS detect, CVE lookup, related domains/TLDs.

type ToolboxHandler struct {
	db  *gorm.DB
	log *zap.SugaredLogger
}

func NewToolboxHandler(db *gorm.DB, log *zap.SugaredLogger) *ToolboxHandler {
	return &ToolboxHandler{db: db, log: log}
}

// Status reports which external CLI tools the toolbox endpoints depend on
// are actually installed and reachable on PATH, so the frontend can show
// users which features will work versus degrade gracefully.
func (h *ToolboxHandler) Status(c *gin.Context) {
	if middleware.GetUser(c) == nil {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "unauthorized"})
		return
	}
	binaries := []string{"whois", "whatweb", "dnstwist"}
	tools := make(gin.H, len(binaries))
	for _, bin := range binaries {
		_, err := exec.LookPath(bin)
		tools[bin] = err == nil
	}
	c.JSON(http.StatusOK, gin.H{"tools": tools})
}

// Whois looks up domain registration data via RDAP (internal/whois — the
// same HTTPS-based lookup the scan dispatcher uses for automated recon, see
// that package's doc comment) and falls back to the system `whois` binary
// only when RDAP has nothing useful to say (IP targets, thin ccTLD
// registries that don't run an RDAP server, etc).
//
// This replaces the old implementation, which shelled out to the system
// `whois` binary directly: that made the endpoint fail outright whenever
// (a) whois wasn't installed — true of the `dev` Docker target, which has
// no scanning binaries at all, see docker-compose.dev.yml — or (b) the
// container's network doesn't allow outbound TCP/43, which some network
// policies block while leaving 80/443 open. RDAP runs entirely over HTTPS,
// so it works in both of those situations without any extra installation.
// GET /toolbox/whois?target=example.com
func (h *ToolboxHandler) Whois(c *gin.Context) {
	if middleware.GetUser(c) == nil {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "unauthorized"})
		return
	}
	target := strings.TrimSpace(c.Query("target"))
	if target == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "target required"})
		return
	}
	// Strip a scheme/path if someone pastes a full URL rather than a bare
	// domain — RDAP's /domain/{name} endpoint expects just the hostname.
	target = strings.TrimPrefix(target, "https://")
	target = strings.TrimPrefix(target, "http://")
	if slash := strings.Index(target, "/"); slash != -1 {
		target = target[:slash]
	}

	isIP := net.ParseIP(target) != nil

	var rdapData map[string]string
	rdapOK := false
	if !isIP {
		rdapData = whois.FetchData(target)
		// FetchData always sets "raw"; it only sets the structured fields
		// (registrar, registration_date, ...) on a genuine RDAP hit. Any of
		// those being present means the lookup actually succeeded, rather
		// than just returning a failure string in "raw".
		_, rdapOK = rdapData["registrar"]
		if !rdapOK {
			_, rdapOK = rdapData["registration_date"]
		}
		if !rdapOK {
			_, rdapOK = rdapData["nameservers"]
		}
	}

	if rdapOK {
		c.JSON(http.StatusOK, gin.H{
			"target":            target,
			"source":            "rdap",
			"registrar":         rdapData["registrar"],
			"registrar_iana_id": rdapData["registrar_iana_id"],
			"registration_date": rdapData["registration_date"],
			"expiry_date":       rdapData["expiry_date"],
			"updated_date":      rdapData["updated_date"],
			"nameservers":       strings.Split(rdapData["nameservers"], ","),
			"raw":               rdapData["raw"],
		})
		return
	}

	// Fall back to system whois — covers IP targets (RDAP here is domain-only)
	// and the handful of ccTLDs with no public RDAP server. If the binary
	// isn't present or the lookup fails, report that clearly rather than
	// silently returning an empty result.
	ctx := c.Request.Context()
	out, err := exec.CommandContext(ctx, "whois", target).Output()
	if err != nil {
		resp := gin.H{"target": target, "source": "whois_fallback", "output": "", "error": err.Error()}
		if rdapData != nil {
			resp["rdap_error"] = rdapData["raw"]
		}
		c.JSON(http.StatusOK, resp)
		return
	}
	c.JSON(http.StatusOK, gin.H{"target": target, "source": "whois_fallback", "output": string(out)})
}

// CMSDetect uses whatweb to detect CMS / tech stack
func (h *ToolboxHandler) CMSDetect(c *gin.Context) {
	if middleware.GetUser(c) == nil {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "unauthorized"})
		return
	}
	target := strings.TrimSpace(c.Query("target"))
	if target == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "target required"})
		return
	}
	if !strings.HasPrefix(target, "http") {
		target = "https://" + target
	}
	ctx := c.Request.Context()
	out, err := exec.CommandContext(ctx, "whatweb", "--log-json=-", target).Output()
	if err != nil {
		// Fallback: return raw output
		raw, _ := exec.CommandContext(ctx, "whatweb", target).Output()
		c.JSON(http.StatusOK, gin.H{"target": target, "raw": string(raw), "error": err.Error()})
		return
	}
	// whatweb --log-json=- emits one JSON obj per line
	var results []interface{}
	for _, line := range strings.Split(strings.TrimSpace(string(out)), "\n") {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		var obj interface{}
		if json.Unmarshal([]byte(line), &obj) == nil {
			results = append(results, obj)
		}
	}
	c.JSON(http.StatusOK, gin.H{"target": target, "results": results})
}

// CVELookup queries the NVD API for a CVE ID
func (h *ToolboxHandler) CVELookup(c *gin.Context) {
	if middleware.GetUser(c) == nil {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "unauthorized"})
		return
	}
	cveID := strings.ToUpper(strings.TrimSpace(c.Param("cve_id")))
	if cveID == "" || !strings.HasPrefix(cveID, "CVE-") {
		c.JSON(http.StatusBadRequest, gin.H{"error": "valid CVE ID required (e.g. CVE-2021-44228)"})
		return
	}
	url := fmt.Sprintf("https://services.nvd.nist.gov/rest/json/cves/2.0?cveId=%s", cveID)
	client := &http.Client{Timeout: 15 * time.Second}
	resp, err := client.Get(url)
	if err != nil {
		c.JSON(http.StatusBadGateway, gin.H{"error": "NVD lookup failed: " + err.Error()})
		return
	}
	defer func() { _ = resp.Body.Close() }()
	body, _ := io.ReadAll(resp.Body)
	var result interface{}
	if err := json.Unmarshal(body, &result); err != nil {
		c.JSON(http.StatusOK, gin.H{"cve_id": cveID, "raw": string(body)})
		return
	}
	c.JSON(http.StatusOK, gin.H{"cve_id": cveID, "data": result})
}

// RelatedDomains returns related TLDs and common permutations for a base domain
func (h *ToolboxHandler) RelatedDomains(c *gin.Context) {
	if middleware.GetUser(c) == nil {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "unauthorized"})
		return
	}
	target := strings.TrimSpace(c.Query("target"))
	if target == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "target required"})
		return
	}
	// Strip existing TLD to get base name
	parts := strings.Split(target, ".")
	baseName := parts[0]
	if len(parts) >= 2 {
		baseName = strings.Join(parts[:len(parts)-1], ".")
	}

	commonTLDs := []string{
		".com", ".net", ".org", ".io", ".co", ".info", ".biz", ".us", ".uk",
		".de", ".fr", ".jp", ".cn", ".ru", ".br", ".ca", ".au", ".in", ".nl",
		".eu", ".es", ".it", ".se", ".no", ".dk", ".fi", ".pl", ".cz", ".sk",
		".me", ".tv", ".cc", ".ly", ".app", ".dev", ".tech", ".cloud", ".ai",
		".security", ".systems", ".network", ".online", ".site", ".web",
	}
	permutationPrefixes := []string{"", "www.", "mail.", "portal.", "vpn.", "api.", "admin.", "dev.", "staging."}

	var related []string
	for _, tld := range commonTLDs {
		related = append(related, baseName+tld)
	}
	// Typosquatting permutations on same TLD
	for _, prefix := range permutationPrefixes {
		if prefix != "" {
			related = append(related, prefix+target)
		}
	}

	// Use dnstwist if available for more thorough permutations
	ctx := c.Request.Context()
	out, err := exec.CommandContext(ctx, "dnstwist", "--format", "json", "--registered", target).Output()
	var dnstwistResults interface{}
	if err == nil {
		_ = json.Unmarshal(out, &dnstwistResults)
	}

	c.JSON(http.StatusOK, gin.H{
		"target":         target,
		"base_name":      baseName,
		"tld_variations": related,
		"tld_prefixed": func() []string {
			p := []string{}
			for _, px := range permutationPrefixes {
				if px != "" {
					p = append(p, px+target)
				}
			}
			return p
		}(),
		"dnstwist_results": dnstwistResults,
	})
}

// FindingsInsights returns actionable stats: most common vulns, CVEs, vulnerable targets
func (h *ToolboxHandler) FindingsInsights(c *gin.Context) {
	user := middleware.GetUser(c)
	if user == nil {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "unauthorized"})
		return
	}

	type CategoryCount struct {
		Category string `json:"category"`
		Count    int64  `json:"count"`
	}
	type CVECount struct {
		CVE   string `json:"cve"`
		Count int64  `json:"count"`
	}
	type TargetCount struct {
		Target string `json:"target"`
		Count  int64  `json:"count"`
	}
	type SevCount struct {
		Severity string `json:"severity"`
		Count    int64  `json:"count"`
	}

	var topCategories []CategoryCount
	h.db.Raw(`SELECT category, COUNT(*) as count FROM findings WHERE org_id = ? AND deleted_at IS NULL AND status = 'open' GROUP BY category ORDER BY count DESC LIMIT 10`, user.OrgID).Scan(&topCategories)

	var topCVEs []CVECount
	h.db.Raw(`SELECT cve, COUNT(*) as count FROM findings WHERE org_id = ? AND deleted_at IS NULL AND cve != '' GROUP BY cve ORDER BY count DESC LIMIT 10`, user.OrgID).Scan(&topCVEs)

	var topTargets []TargetCount
	h.db.Raw(`SELECT url as target, COUNT(*) as count FROM findings WHERE org_id = ? AND deleted_at IS NULL AND status = 'open' GROUP BY url ORDER BY count DESC LIMIT 10`, user.OrgID).Scan(&topTargets)

	var bySeverity []SevCount
	h.db.Raw(`SELECT severity, COUNT(*) as count FROM findings WHERE org_id = ? AND deleted_at IS NULL AND status = 'open' GROUP BY severity ORDER BY count DESC`, user.OrgID).Scan(&bySeverity)

	var total, open, falsePos, fixed int64
	h.db.Raw(`SELECT COUNT(*) FROM findings WHERE org_id = ? AND deleted_at IS NULL`, user.OrgID).Scan(&total)
	h.db.Raw(`SELECT COUNT(*) FROM findings WHERE org_id = ? AND deleted_at IS NULL AND status = 'open'`, user.OrgID).Scan(&open)
	h.db.Raw(`SELECT COUNT(*) FROM findings WHERE org_id = ? AND deleted_at IS NULL AND status = 'false_positive'`, user.OrgID).Scan(&falsePos)
	h.db.Raw(`SELECT COUNT(*) FROM findings WHERE org_id = ? AND deleted_at IS NULL AND status = 'fixed'`, user.OrgID).Scan(&fixed)

	c.JSON(http.StatusOK, gin.H{
		"total_findings":          total,
		"open":                    open,
		"false_positives":         falsePos,
		"fixed":                   fixed,
		"by_severity":             bySeverity,
		"top_categories":          topCategories,
		"top_cves":                topCVEs,
		"most_vulnerable_targets": topTargets,
	})
}
