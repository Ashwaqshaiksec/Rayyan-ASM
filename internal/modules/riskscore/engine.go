package riskscore

import (
	"net/url"
	"strings"
	"time"

	"github.com/ShadooowX/rayyan-asm/internal/models"
	"github.com/google/uuid"
	"go.uber.org/zap"
	"gorm.io/gorm"
)

type Engine struct {
	db  *gorm.DB
	log *zap.SugaredLogger
}

func New(db *gorm.DB, log *zap.SugaredLogger) *Engine {
	return &Engine{db: db, log: log}
}

// Factors is the breakdown behind a score, stored as JSONB alongside it.
type Factors struct {
	ExposedServices   int     `json:"exposed_services"`
	HighRiskPorts     int     `json:"high_risk_ports"`
	CriticalFindings  int     `json:"critical_findings"`
	HighFindings      int     `json:"high_findings"`
	MediumFindings    int     `json:"medium_findings"`
	LowFindings       int     `json:"low_findings"`
	MissingHeaders    int     `json:"missing_headers"`
	CertIssues        int     `json:"cert_issues"`
	ExpiringCerts     int     `json:"expiring_certs"`
	VulnSeverityScore float64 `json:"vuln_severity_score"`
	InternetExposed   bool    `json:"internet_exposed"`
	SensitiveAsset    bool    `json:"sensitive_asset"`
}

type Summary struct {
	OrgID            uuid.UUID `json:"org_id"`
	HostsScored      int       `json:"hosts_scored"`
	SubdomainsScored int       `json:"subdomains_scored"`
	DomainsScored    int       `json:"domains_scored"`
	DurationMS       int64     `json:"duration_ms"`
}

type scoredAsset struct {
	id      uuid.UUID
	label   string
	score   float64
	tier    string
	factors Factors
}

// Management ports, DBs, and legacy protocols that raise risk on their own.
var highRiskPorts = map[int]bool{
	21: true, 22: true, 23: true, 25: true, 135: true, 139: true, 445: true,
	1433: true, 1521: true, 2375: true, 2376: true, 3306: true, 3389: true,
	5432: true, 5900: true, 5984: true, 6379: true, 7001: true, 8009: true,
	9200: true, 9300: true, 11211: true, 27017: true, 50070: true,
}

var requiredHeaders = []string{
	"strict-transport-security", "content-security-policy",
	"x-frame-options", "x-content-type-options",
}

var sensitiveTagKeywords = []string{
	"crown-jewel", "crown jewel", "critical", "pci", "pii", "phi",
	"payment", "sensitive", "confidential",
}

// RecomputeAll recomputes every org's risk scores. Called from the scheduler cron.
func (e *Engine) RecomputeAll() {
	var orgs []models.Organization
	if err := e.db.Find(&orgs).Error; err != nil {
		e.log.Warnw("riskscore: failed to load organizations", "error", err)
		return
	}
	for _, o := range orgs {
		if _, err := e.RecomputeOrg(o.ID); err != nil {
			e.log.Warnw("riskscore: recompute failed", "org_id", o.ID, "error", err)
		}
	}
}

func (e *Engine) RecomputeOrg(orgID uuid.UUID) (Summary, error) {
	start := time.Now()

	var hosts []models.Host
	if err := e.db.Where("org_id = ?", orgID).Find(&hosts).Error; err != nil {
		return Summary{}, err
	}
	var subdomains []models.Subdomain
	if err := e.db.Where("org_id = ?", orgID).Find(&subdomains).Error; err != nil {
		return Summary{}, err
	}
	var domains []models.Domain
	if err := e.db.Where("org_id = ?", orgID).Find(&domains).Error; err != nil {
		return Summary{}, err
	}
	var services []models.Service
	if err := e.db.Where("org_id = ?", orgID).Find(&services).Error; err != nil {
		return Summary{}, err
	}
	var certs []models.Certificate
	if err := e.db.Where("org_id = ?", orgID).Find(&certs).Error; err != nil {
		return Summary{}, err
	}
	var webAssets []models.WebAsset
	if err := e.db.Where("org_id = ?", orgID).Find(&webAssets).Error; err != nil {
		return Summary{}, err
	}
	var findings []models.Finding
	if err := e.db.Where("org_id = ? AND status = 'open'", orgID).Find(&findings).Error; err != nil {
		return Summary{}, err
	}

	servicesByHostID := map[uuid.UUID][]models.Service{}
	servicesByFQDN := map[string][]models.Service{}
	for _, s := range services {
		if s.HostID != uuid.Nil {
			servicesByHostID[s.HostID] = append(servicesByHostID[s.HostID], s)
		}
		if s.HostRef != "" {
			key := strings.ToLower(s.HostRef)
			servicesByFQDN[key] = append(servicesByFQDN[key], s)
		}
	}

	certsByServiceID := map[uuid.UUID][]models.Certificate{}
	for _, c := range certs {
		if c.ServiceID != nil {
			certsByServiceID[*c.ServiceID] = append(certsByServiceID[*c.ServiceID], c)
		}
	}

	webAssetsByServiceID := map[uuid.UUID][]models.WebAsset{}
	for _, w := range webAssets {
		webAssetsByServiceID[w.ServiceID] = append(webAssetsByServiceID[w.ServiceID], w)
	}

	subByFQDN := map[string]models.Subdomain{}
	for _, sd := range subdomains {
		subByFQDN[strings.ToLower(sd.FQDN)] = sd
	}
	hostByIP := map[string]models.Host{}
	for _, h := range hosts {
		hostByIP[h.IP] = h
	}
	domainByID := map[uuid.UUID]models.Domain{}
	for _, d := range domains {
		domainByID[d.ID] = d
	}

	findingsByHost := map[uuid.UUID][]models.Finding{}
	findingsBySub := map[uuid.UUID][]models.Finding{}
	for _, f := range findings {
		matched := false
		if f.HostID != nil {
			findingsByHost[*f.HostID] = append(findingsByHost[*f.HostID], f)
			matched = true
		}
		if f.SubdomainID != nil {
			findingsBySub[*f.SubdomainID] = append(findingsBySub[*f.SubdomainID], f)
			matched = true
		}
		// no FK set, fall back to matching the URL's host
		if !matched && f.URL != "" {
			if host := extractHost(f.URL); host != "" {
				lower := strings.ToLower(host)
				if sd, ok := subByFQDN[lower]; ok {
					findingsBySub[sd.ID] = append(findingsBySub[sd.ID], f)
				} else if h, ok := hostByIP[host]; ok {
					findingsByHost[h.ID] = append(findingsByHost[h.ID], f)
				}
			}
		}
	}

	now := time.Now()

	hostResults := make([]scoredAsset, 0, len(hosts))
	for _, h := range hosts {
		f := buildFactors(servicesByHostID[h.ID], certsByServiceID, webAssetsByServiceID, findingsByHost[h.ID], now)
		score, tier := scoreFromFactors(&f, h.Environment, h.Monitored, h.Tags)
		hostResults = append(hostResults, scoredAsset{id: h.ID, label: h.IP, score: score, tier: tier, factors: f})
	}

	// subdomains inherit exposure context (env, monitored, tags) from the parent domain
	subResultsByID := map[uuid.UUID]scoredAsset{}
	for _, sd := range subdomains {
		f := buildFactors(servicesByFQDN[strings.ToLower(sd.FQDN)], certsByServiceID, webAssetsByServiceID, findingsBySub[sd.ID], now)
		parent := domainByID[sd.DomainID]
		monitored := parent.Monitored && !sd.Dead && sd.Status != "inactive"
		tags := make(models.StringArray, 0, len(parent.Tags)+len(sd.Tags))
		tags = append(tags, parent.Tags...)
		tags = append(tags, sd.Tags...)
		score, tier := scoreFromFactors(&f, parent.Environment, monitored, tags)
		subResultsByID[sd.ID] = scoredAsset{id: sd.ID, label: sd.FQDN, score: score, tier: tier, factors: f}
	}
	subResults := make([]scoredAsset, 0, len(subResultsByID))
	for _, r := range subResultsByID {
		subResults = append(subResults, r)
	}

	// a domain's score is its riskiest subdomain's score
	subsByDomain := map[uuid.UUID][]uuid.UUID{}
	for _, sd := range subdomains {
		subsByDomain[sd.DomainID] = append(subsByDomain[sd.DomainID], sd.ID)
	}
	domainResults := make([]scoredAsset, 0, len(domains))
	for _, d := range domains {
		best := scoredAsset{tier: "low"}
		for _, sid := range subsByDomain[d.ID] {
			if r, ok := subResultsByID[sid]; ok && r.score >= best.score {
				best = r
			}
		}
		domainResults = append(domainResults, scoredAsset{id: d.ID, label: d.Name, score: best.score, tier: tierFromScore(best.score), factors: best.factors})
	}

	if err := e.persist(orgID, "host", hostResults, now); err != nil {
		e.log.Warnw("riskscore: failed to persist host scores", "org_id", orgID, "error", err)
	}
	if err := e.persist(orgID, "subdomain", subResults, now); err != nil {
		e.log.Warnw("riskscore: failed to persist subdomain scores", "org_id", orgID, "error", err)
	}
	if err := e.persist(orgID, "domain", domainResults, now); err != nil {
		e.log.Warnw("riskscore: failed to persist domain scores", "org_id", orgID, "error", err)
	}

	return Summary{
		OrgID:            orgID,
		HostsScored:      len(hostResults),
		SubdomainsScored: len(subResults),
		DomainsScored:    len(domainResults),
		DurationMS:       time.Since(start).Milliseconds(),
	}, nil
}

func buildFactors(
	svcs []models.Service,
	certsByService map[uuid.UUID][]models.Certificate,
	webAssetsByService map[uuid.UUID][]models.WebAsset,
	findings []models.Finding,
	now time.Time,
) Factors {
	f := Factors{}
	for _, s := range svcs {
		if s.State == "open" || s.State == "" {
			f.ExposedServices++
			if highRiskPorts[s.Port] {
				f.HighRiskPorts++
			}
		}
		for _, c := range certsByService[s.ID] {
			switch {
			case c.IsExpired || c.IsSelfSigned:
				f.CertIssues++
			case !c.NotAfter.IsZero() && c.NotAfter.Before(now.Add(14*24*time.Hour)):
				f.ExpiringCerts++
			}
		}
		for _, w := range webAssetsByService[s.ID] {
			f.MissingHeaders += countMissingHeaders(w.SecurityHeaders)
		}
	}
	for _, find := range findings {
		switch find.Severity {
		case "critical":
			f.CriticalFindings++
		case "high":
			f.HighFindings++
		case "medium":
			f.MediumFindings++
		case "low":
			f.LowFindings++
		}
		f.VulnSeverityScore += find.CVSS
	}
	return f
}

func countMissingHeaders(headers models.JSONB) int {
	if headers == nil {
		return 0
	}
	present := make(map[string]bool, len(headers))
	for k := range headers {
		present[strings.ToLower(k)] = true
	}
	missing := 0
	for _, h := range requiredHeaders {
		if !present[h] {
			missing++
		}
	}
	return missing
}

func scoreFromFactors(f *Factors, environment string, monitored bool, tags models.StringArray) (float64, string) {
	score := 0.0
	score += float64(f.CriticalFindings) * 10.0
	score += float64(f.HighFindings) * 4.0
	score += float64(f.MediumFindings) * 1.5
	score += float64(f.LowFindings) * 0.5
	score += float64(f.CertIssues) * 8.0
	score += float64(f.ExpiringCerts) * 5.0
	score += float64(f.HighRiskPorts) * 6.0
	score += float64(f.MissingHeaders) * 2.0
	if f.ExposedServices > 20 {
		score += float64(f.ExposedServices-20) * 0.2
	}

	f.SensitiveAsset = hasSensitiveTag(tags)
	f.InternetExposed = environment == "production" && monitored

	if f.SensitiveAsset {
		score *= 1.25
	}
	if f.InternetExposed {
		score *= 1.1
	}
	if hasTag(tags, "internal") || hasTag(tags, "private") {
		score *= 0.75
	}

	if score > 100 {
		score = 100
	}
	if score < 0 {
		score = 0
	}
	return score, tierFromScore(score)
}

func tierFromScore(score float64) string {
	switch {
	case score >= 75:
		return "critical"
	case score >= 50:
		return "high"
	case score >= 25:
		return "medium"
	default:
		return "low"
	}
}

func hasSensitiveTag(tags models.StringArray) bool {
	for _, t := range tags {
		lt := strings.ToLower(t)
		for _, kw := range sensitiveTagKeywords {
			if strings.Contains(lt, kw) {
				return true
			}
		}
	}
	return false
}

func hasTag(tags models.StringArray, want string) bool {
	for _, t := range tags {
		if strings.EqualFold(t, want) {
			return true
		}
	}
	return false
}

func extractHost(raw string) string {
	u, err := url.Parse(raw)
	if err != nil || u.Host == "" {
		return ""
	}
	return u.Hostname()
}

// persist writes scores back onto the asset rows and appends history for trends.
func (e *Engine) persist(orgID uuid.UUID, assetType string, results []scoredAsset, now time.Time) error {
	if len(results) == 0 {
		return nil
	}

	history := make([]models.AssetRiskHistory, 0, len(results))
	for _, r := range results {
		factors := factorsToJSONB(r.factors)
		scoredAt := now

		updates := map[string]interface{}{
			"risk_score":     r.score,
			"risk_tier":      r.tier,
			"risk_factors":   factors,
			"risk_scored_at": &scoredAt,
		}

		var updateErr error
		switch assetType {
		case "host":
			updateErr = e.db.Model(&models.Host{}).Where("id = ?", r.id).Updates(updates).Error
		case "subdomain":
			updateErr = e.db.Model(&models.Subdomain{}).Where("id = ?", r.id).Updates(updates).Error
		case "domain":
			updateErr = e.db.Model(&models.Domain{}).Where("id = ?", r.id).Updates(updates).Error
		}
		if updateErr != nil {
			e.log.Warnw("riskscore: failed to update asset score", "asset_type", assetType, "asset_id", r.id, "error", updateErr)
		}

		history = append(history, models.AssetRiskHistory{
			ID:         uuid.New(),
			CreatedAt:  now,
			OrgID:      orgID,
			AssetType:  assetType,
			AssetID:    r.id,
			AssetLabel: r.label,
			Score:      r.score,
			Tier:       r.tier,
			Factors:    factors,
			ComputedAt: now,
		})
	}

	if err := e.db.Create(&history).Error; err != nil {
		return err
	}

	cutoff := now.AddDate(0, 0, -180)
	e.db.Where("org_id = ? AND asset_type = ? AND computed_at < ?", orgID, assetType, cutoff).
		Delete(&models.AssetRiskHistory{})

	return nil
}

func factorsToJSONB(f Factors) models.JSONB {
	return models.JSONB{
		"exposed_services":    f.ExposedServices,
		"high_risk_ports":     f.HighRiskPorts,
		"critical_findings":   f.CriticalFindings,
		"high_findings":       f.HighFindings,
		"medium_findings":     f.MediumFindings,
		"low_findings":        f.LowFindings,
		"missing_headers":     f.MissingHeaders,
		"cert_issues":         f.CertIssues,
		"expiring_certs":      f.ExpiringCerts,
		"vuln_severity_score": f.VulnSeverityScore,
		"internet_exposed":    f.InternetExposed,
		"sensitive_asset":     f.SensitiveAsset,
	}
}
