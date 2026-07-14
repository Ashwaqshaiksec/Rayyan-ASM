package exposure

import (
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

// RecomputeOrg drops and rebuilds asset_exposure_scores for one org.
// Same rebuild lifecycle as correlation/attackpath: delete the org's rows,
// bulk-insert the fresh set.
func (e *Engine) RecomputeOrg(orgID uuid.UUID) (Summary, error) {
	start := time.Now()

	ctx, err := e.loadContext(orgID)
	if err != nil {
		return Summary{}, err
	}

	now := time.Now()
	var results []scoredAsset

	for _, h := range ctx.hosts {
		results = append(results, e.scoreHost(ctx, h))
	}
	domainByID := make(map[uuid.UUID]models.Domain, len(ctx.domains))
	for _, d := range ctx.domains {
		domainByID[d.ID] = d
	}
	for _, sd := range ctx.subdomains {
		results = append(results, e.scoreSubdomain(ctx, sd, domainByID[sd.DomainID]))
	}
	for _, d := range ctx.domains {
		results = append(results, e.scoreDomain(ctx, d))
	}

	if err := e.db.Where("org_id = ?", orgID).Delete(&models.AssetExposureScore{}).Error; err != nil {
		return Summary{}, err
	}

	rows := make([]models.AssetExposureScore, 0, len(results))
	summary := Summary{OrgID: orgID}
	for _, r := range results {
		rows = append(rows, models.AssetExposureScore{
			ID:               uuid.New(),
			CreatedAt:        now,
			OrgID:            orgID,
			AssetType:        r.assetType,
			AssetID:          r.id,
			AssetLabel:       r.label,
			RiskScore:        r.riskScore,
			ExposureScore:    r.score,
			ExposureLevel:    r.level,
			InternetExposed:  r.factors.InternetExposed,
			AttackPathCount:  r.factors.AttackPathCount,
			CriticalFindings: r.factors.CriticalFindings,
			Criticality:      r.criticality,
			Factors:          factorsToJSONB(r.factors),
			CalculatedAt:     now,
		})
		summary.AssetsScored++
		switch r.level {
		case "critical":
			summary.Critical++
		case "high":
			summary.High++
		case "medium":
			summary.Medium++
		case "low":
			summary.Low++
		default:
			summary.Informational++
		}
	}

	if len(rows) > 0 {
		if err := e.db.CreateInBatches(&rows, 200).Error; err != nil {
			return Summary{}, err
		}
	}

	summary.DurationMS = time.Since(start).Milliseconds()
	return summary, nil
}

// RecomputeAllOrgs runs RecomputeOrg for every org. Called by the worker.
func (e *Engine) RecomputeAllOrgs() (int, error) {
	orgs, err := listOrgs(e.db)
	if err != nil {
		return 0, err
	}
	done := 0
	for _, o := range orgs {
		if _, err := e.RecomputeOrg(o.ID); err != nil {
			e.log.Warnw("exposure: recompute failed", "org_id", o.ID, "error", err)
			continue
		}
		done++
	}
	return done, nil
}

func (e *Engine) scoreHost(ctx *graphContext, h models.Host) scoredAsset {
	k := nodeKey{"host", h.ID}
	findings := ctx.findingsByHost[h.ID]
	crit, high, med := countFindings(findings)

	certIssues := numFactor(h.RiskFactors, "cert_issues")
	expiringCerts := numFactor(h.RiskFactors, "expiring_certs")
	internetExposed := boolFactor(h.RiskFactors, "internet_exposed")
	sensitiveAsset := boolFactor(h.RiskFactors, "sensitive_asset")

	techNames := ctx.techNamesByHost[h.ID]
	techScore, riskyTech := technologyFactorScore(techNames)

	criticalityScore, criticality := criticalityFactorScore(sensitiveAsset, h.Environment, h.BusinessUnit)
	relCount := ctx.relCount[k]
	connectedToCritical := ctx.connectedToCritical(k)
	pathCount := ctx.attackPathCount[k]
	cloudExposed := ctx.cloudIPs[h.IP]

	f := Factors{
		ExistingRiskScore:   h.RiskScore,
		InternetExposure:    boolScore(internetExposed),
		AttackPathScore:     attackPathFactorScore(pathCount),
		FindingsScore:       findingsFactorScore(crit, high, med),
		CriticalityScore:    criticalityScore,
		CertificateScore:    certificateFactorScore(certIssues, expiringCerts),
		TechnologyScore:     techScore,
		CloudScore:          boolScore(cloudExposed),
		RelationshipScore:   relationshipFactorScore(relCount, connectedToCritical),
		BusinessImpact:      businessImpactFactorScore(sensitiveAsset, h.BusinessUnit, h.Owner),
		InternetExposed:     internetExposed,
		AttackPathCount:     pathCount,
		CriticalFindings:    crit,
		HighFindings:        high,
		RelationshipCount:   relCount,
		ConnectedToCritical: connectedToCritical,
		CloudExposed:        cloudExposed,
		RiskyTechnologies:   riskyTech,
	}
	score, level := computeExposure(f)
	label := h.Hostname
	if label == "" {
		label = h.IP
	}
	return scoredAsset{assetType: "host", id: h.ID, label: label, riskScore: h.RiskScore, criticality: criticality, score: score, level: level, factors: f}
}

func (e *Engine) scoreSubdomain(ctx *graphContext, sd models.Subdomain, parent models.Domain) scoredAsset {
	k := nodeKey{"subdomain", sd.ID}
	findings := ctx.findingsBySub[sd.ID]
	crit, high, med := countFindings(findings)

	certIssues := numFactor(sd.RiskFactors, "cert_issues")
	expiringCerts := numFactor(sd.RiskFactors, "expiring_certs")
	internetExposed := boolFactor(sd.RiskFactors, "internet_exposed")
	sensitiveAsset := boolFactor(sd.RiskFactors, "sensitive_asset")

	techNames := ctx.techNamesBySub[sd.ID]
	techScore, riskyTech := technologyFactorScore(techNames)

	criticalityScore, criticality := criticalityFactorScore(sensitiveAsset, parent.Environment, parent.BusinessUnit)
	relCount := ctx.relCount[k]
	connectedToCritical := ctx.connectedToCritical(k)
	pathCount := ctx.attackPathCount[k]

	cloudExposed := false
	for _, ip := range sd.IPs {
		if ctx.cloudIPs[ip] {
			cloudExposed = true
			break
		}
	}

	f := Factors{
		ExistingRiskScore:   sd.RiskScore,
		InternetExposure:    boolScore(internetExposed),
		AttackPathScore:     attackPathFactorScore(pathCount),
		FindingsScore:       findingsFactorScore(crit, high, med),
		CriticalityScore:    criticalityScore,
		CertificateScore:    certificateFactorScore(certIssues, expiringCerts),
		TechnologyScore:     techScore,
		CloudScore:          boolScore(cloudExposed),
		RelationshipScore:   relationshipFactorScore(relCount, connectedToCritical),
		BusinessImpact:      businessImpactFactorScore(sensitiveAsset, parent.BusinessUnit, parent.Owner),
		InternetExposed:     internetExposed,
		AttackPathCount:     pathCount,
		CriticalFindings:    crit,
		HighFindings:        high,
		RelationshipCount:   relCount,
		ConnectedToCritical: connectedToCritical,
		CloudExposed:        cloudExposed,
		RiskyTechnologies:   riskyTech,
	}
	score, level := computeExposure(f)
	return scoredAsset{assetType: "subdomain", id: sd.ID, label: sd.FQDN, riskScore: sd.RiskScore, criticality: criticality, score: score, level: level, factors: f}
}

func (e *Engine) scoreDomain(ctx *graphContext, d models.Domain) scoredAsset {
	k := nodeKey{"domain", d.ID}
	certIssues := numFactor(d.RiskFactors, "cert_issues")
	expiringCerts := numFactor(d.RiskFactors, "expiring_certs")
	sensitiveAsset := boolFactor(d.RiskFactors, "sensitive_asset")

	criticalityScore, criticality := criticalityFactorScore(sensitiveAsset, d.Environment, d.BusinessUnit)
	relCount := ctx.relCount[k]
	connectedToCritical := ctx.connectedToCritical(k)
	pathCount := ctx.attackPathCount[k]

	// A domain's own internet-exposure signal is inherited from its
	// riskiest subdomain via risk_factors (set by the riskscore engine).
	internetExposed := boolFactor(d.RiskFactors, "internet_exposed")

	f := Factors{
		ExistingRiskScore:   d.RiskScore,
		InternetExposure:    boolScore(internetExposed),
		AttackPathScore:     attackPathFactorScore(pathCount),
		FindingsScore:       0,
		CriticalityScore:    criticalityScore,
		CertificateScore:    certificateFactorScore(certIssues, expiringCerts),
		TechnologyScore:     0,
		CloudScore:          0,
		RelationshipScore:   relationshipFactorScore(relCount, connectedToCritical),
		BusinessImpact:      businessImpactFactorScore(sensitiveAsset, d.BusinessUnit, d.Owner),
		InternetExposed:     internetExposed,
		AttackPathCount:     pathCount,
		RelationshipCount:   relCount,
		ConnectedToCritical: connectedToCritical,
	}
	score, level := computeExposure(f)
	return scoredAsset{assetType: "domain", id: d.ID, label: d.Name, riskScore: d.RiskScore, criticality: criticality, score: score, level: level, factors: f}
}

func countFindings(findings []models.Finding) (critical, high, medium int) {
	for _, f := range findings {
		switch f.Severity {
		case "critical":
			critical++
		case "high":
			high++
		case "medium":
			medium++
		}
	}
	return
}

func boolScore(b bool) float64 {
	if b {
		return 100
	}
	return 0
}

func factorsToJSONB(f Factors) models.JSONB {
	return models.JSONB{
		"existing_risk_score":         f.ExistingRiskScore,
		"internet_exposure":           f.InternetExposure,
		"attack_path_score":           f.AttackPathScore,
		"findings_score":              f.FindingsScore,
		"criticality_score":           f.CriticalityScore,
		"certificate_score":           f.CertificateScore,
		"technology_score":            f.TechnologyScore,
		"cloud_score":                 f.CloudScore,
		"relationship_score":          f.RelationshipScore,
		"business_impact_score":       f.BusinessImpact,
		"internet_exposed":            f.InternetExposed,
		"attack_path_count":           f.AttackPathCount,
		"critical_findings":           f.CriticalFindings,
		"high_findings":               f.HighFindings,
		"relationship_count":          f.RelationshipCount,
		"connected_to_critical_asset": f.ConnectedToCritical,
		"cloud_exposed":               f.CloudExposed,
		"risky_technologies":          f.RiskyTechnologies,
	}
}

// Assets — top exposed assets, optionally filtered by level.
func (e *Engine) Assets(orgID uuid.UUID, level string, limit int) ([]AssetRow, error) {
	q := e.db.Model(&models.AssetExposureScore{}).Where("org_id = ?", orgID)
	if level != "" {
		q = q.Where("exposure_level = ?", level)
	}
	q = q.Order("exposure_score DESC")
	if limit > 0 {
		q = q.Limit(limit)
	}
	var rows []models.AssetExposureScore
	if err := q.Find(&rows).Error; err != nil {
		return nil, err
	}
	return toAssetRows(rows), nil
}

// Detail — one scored asset with its full factor breakdown.
func (e *Engine) Detail(orgID uuid.UUID, id uuid.UUID) (*AssetDetail, error) {
	var row models.AssetExposureScore
	if err := e.db.Where("org_id = ? AND id = ?", orgID, id).First(&row).Error; err != nil {
		return nil, err
	}
	return toAssetDetail(row), nil
}

func toAssetRows(rows []models.AssetExposureScore) []AssetRow {
	out := make([]AssetRow, 0, len(rows))
	for _, r := range rows {
		out = append(out, AssetRow{
			ID:               r.ID,
			AssetType:        r.AssetType,
			AssetID:          r.AssetID,
			Label:            r.AssetLabel,
			RiskScore:        r.RiskScore,
			ExposureScore:    r.ExposureScore,
			ExposureLevel:    r.ExposureLevel,
			InternetExposed:  r.InternetExposed,
			AttackPathCount:  r.AttackPathCount,
			CriticalFindings: r.CriticalFindings,
			Criticality:      r.Criticality,
			CalculatedAt:     r.CalculatedAt,
		})
	}
	return out
}

func toAssetDetail(r models.AssetExposureScore) *AssetDetail {
	row := AssetRow{
		ID:               r.ID,
		AssetType:        r.AssetType,
		AssetID:          r.AssetID,
		Label:            r.AssetLabel,
		RiskScore:        r.RiskScore,
		ExposureScore:    r.ExposureScore,
		ExposureLevel:    r.ExposureLevel,
		InternetExposed:  r.InternetExposed,
		AttackPathCount:  r.AttackPathCount,
		CriticalFindings: r.CriticalFindings,
		Criticality:      r.Criticality,
		CalculatedAt:     r.CalculatedAt,
	}
	f := Factors{}
	if r.Factors != nil {
		f.ExistingRiskScore, _ = r.Factors["existing_risk_score"].(float64)
		f.InternetExposure, _ = r.Factors["internet_exposure"].(float64)
		f.AttackPathScore, _ = r.Factors["attack_path_score"].(float64)
		f.FindingsScore, _ = r.Factors["findings_score"].(float64)
		f.CriticalityScore, _ = r.Factors["criticality_score"].(float64)
		f.CertificateScore, _ = r.Factors["certificate_score"].(float64)
		f.TechnologyScore, _ = r.Factors["technology_score"].(float64)
		f.CloudScore, _ = r.Factors["cloud_score"].(float64)
		f.RelationshipScore, _ = r.Factors["relationship_score"].(float64)
		f.BusinessImpact, _ = r.Factors["business_impact_score"].(float64)
		f.InternetExposed, _ = r.Factors["internet_exposed"].(bool)
		f.ConnectedToCritical, _ = r.Factors["connected_to_critical_asset"].(bool)
		f.CloudExposed, _ = r.Factors["cloud_exposed"].(bool)
		if rt, ok := r.Factors["risky_technologies"].([]interface{}); ok {
			for _, v := range rt {
				if s, ok := v.(string); ok {
					f.RiskyTechnologies = append(f.RiskyTechnologies, s)
				}
			}
		}
		f.AttackPathCount = r.AttackPathCount
		f.CriticalFindings = r.CriticalFindings
	}
	return &AssetDetail{AssetRow: row, Factors: f}
}

// Dashboard returns the aggregated metrics behind the Exposure Center.
func (e *Engine) Dashboard(orgID uuid.UUID) (*Dashboard, error) {
	var rows []models.AssetExposureScore
	if err := e.db.Where("org_id = ?", orgID).Order("exposure_score DESC").Find(&rows).Error; err != nil {
		return nil, err
	}

	d := &Dashboard{CalculatedAt: time.Now()}
	d.TotalScored = len(rows)

	var sumExposure, sumRisk float64
	matrixCounts := map[[2]string]int{}

	for _, r := range rows {
		sumExposure += r.ExposureScore
		sumRisk += r.RiskScore
		switch r.ExposureLevel {
		case "critical":
			d.Critical++
		case "high":
			d.High++
		case "medium":
			d.Medium++
		case "low":
			d.Low++
		default:
			d.Informational++
		}
		if r.InternetExposed {
			d.PublicFacingCount++
		}

		riskTier := riskTierFromScore(r.RiskScore)
		matrixCounts[[2]string{riskTier, r.ExposureLevel}]++
	}

	if d.TotalScored > 0 {
		d.AvgExposureScore = sumExposure / float64(d.TotalScored)
		d.AvgRiskScore = sumRisk / float64(d.TotalScored)
	}

	d.TopExposedAssets = toAssetRows(limitRows(rows, 10))

	criticalRows := filterByLevel(rows, "critical")
	d.CriticalExposures = toAssetRows(limitRows(criticalRows, 25))

	publicRows := filterPublicFacing(rows)
	d.PublicFacingAssets = toAssetRows(limitRows(publicRows, 25))

	pathRows := filterByAttackPath(rows)
	d.AttackPathExposure = toAssetRows(limitRows(pathRows, 25))

	riskTiers := []string{"critical", "high", "medium", "low"}
	expLevels := []string{"critical", "high", "medium", "low", "informational"}
	for _, rt := range riskTiers {
		for _, el := range expLevels {
			d.RiskVsExposureMatrix = append(d.RiskVsExposureMatrix, MatrixCell{
				RiskTier:      rt,
				ExposureLevel: el,
				Count:         matrixCounts[[2]string{rt, el}],
			})
		}
	}

	hrs, err := e.highRiskServices(orgID, 10)
	if err == nil {
		d.HighRiskServices = hrs
	}
	techs, err := e.dangerousTechnologies(orgID, rows, 10)
	if err == nil {
		d.DangerousTechnologies = techs
	}

	return d, nil
}

func riskTierFromScore(score float64) string {
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

func filterByLevel(rows []models.AssetExposureScore, level string) []models.AssetExposureScore {
	var out []models.AssetExposureScore
	for _, r := range rows {
		if r.ExposureLevel == level {
			out = append(out, r)
		}
	}
	return out
}

func filterPublicFacing(rows []models.AssetExposureScore) []models.AssetExposureScore {
	var out []models.AssetExposureScore
	for _, r := range rows {
		if r.InternetExposed {
			out = append(out, r)
		}
	}
	return out
}

func filterByAttackPath(rows []models.AssetExposureScore) []models.AssetExposureScore {
	var out []models.AssetExposureScore
	for _, r := range rows {
		if r.AttackPathCount > 0 {
			out = append(out, r)
		}
	}
	return out
}

func limitRows(rows []models.AssetExposureScore, n int) []models.AssetExposureScore {
	if len(rows) <= n {
		return rows
	}
	return rows[:n]
}

// highRiskServices ranks open services by the exposure score of the
// host/subdomain they run on.
func (e *Engine) highRiskServices(orgID uuid.UUID, limit int) ([]ServiceExposure, error) {
	var services []models.Service
	if err := e.db.Where("org_id = ?", orgID).Find(&services).Error; err != nil {
		return nil, err
	}
	var scores []models.AssetExposureScore
	if err := e.db.Where("org_id = ?", orgID).Find(&scores).Error; err != nil {
		return nil, err
	}
	scoreByHost := map[uuid.UUID]float64{}
	for _, s := range scores {
		if s.AssetType == "host" {
			scoreByHost[s.AssetID] = s.ExposureScore
		}
	}

	out := make([]ServiceExposure, 0, len(services))
	for _, svc := range services {
		if svc.State != "open" && svc.State != "" {
			continue
		}
		score, ok := scoreByHost[svc.HostID]
		if !ok {
			continue
		}
		out = append(out, ServiceExposure{
			ServiceID:     svc.ID,
			HostRef:       svc.HostRef,
			Port:          svc.Port,
			Protocol:      svc.Protocol,
			Product:       svc.Product,
			ExposureScore: score,
		})
	}
	sortServiceExposureDesc(out)
	if len(out) > limit {
		out = out[:limit]
	}
	return out, nil
}

func sortServiceExposureDesc(s []ServiceExposure) {
	for i := 1; i < len(s); i++ {
		for j := i; j > 0 && s[j].ExposureScore > s[j-1].ExposureScore; j-- {
			s[j], s[j-1] = s[j-1], s[j]
		}
	}
}

// dangerousTechnologies ranks technologies by how often they show up on
// highly-exposed assets.
func (e *Engine) dangerousTechnologies(orgID uuid.UUID, scores []models.AssetExposureScore, limit int) ([]TechExposure, error) {
	scoreByHost := map[uuid.UUID]float64{}
	scoreBySub := map[uuid.UUID]float64{}
	for _, s := range scores {
		switch s.AssetType {
		case "host":
			scoreByHost[s.AssetID] = s.ExposureScore
		case "subdomain":
			scoreBySub[s.AssetID] = s.ExposureScore
		}
	}

	var services []models.Service
	if err := e.db.Where("org_id = ?", orgID).Find(&services).Error; err != nil {
		return nil, err
	}
	svcByID := make(map[uuid.UUID]models.Service, len(services))
	for _, s := range services {
		svcByID[s.ID] = s
	}
	var subs []models.Subdomain
	if err := e.db.Where("org_id = ?", orgID).Find(&subs).Error; err != nil {
		return nil, err
	}
	subByFQDN := make(map[string]uuid.UUID, len(subs))
	for _, sd := range subs {
		subByFQDN[strings.ToLower(sd.FQDN)] = sd.ID
	}

	var techs []models.Technology
	if err := e.db.Where("org_id = ?", orgID).Find(&techs).Error; err != nil {
		return nil, err
	}

	type agg struct {
		category string
		count    int
		total    float64
	}
	byName := map[string]*agg{}
	for _, t := range techs {
		if t.ServiceID == nil {
			continue
		}
		svc, ok := svcByID[*t.ServiceID]
		if !ok {
			continue
		}
		var score float64
		var hasScore bool
		if svc.HostID != uuid.Nil {
			if s, ok := scoreByHost[svc.HostID]; ok {
				score, hasScore = s, true
			}
		}
		if !hasScore && svc.HostRef != "" {
			if sid, ok := subByFQDN[strings.ToLower(svc.HostRef)]; ok {
				if s, ok := scoreBySub[sid]; ok {
					score, hasScore = s, true
				}
			}
		}
		if !hasScore {
			continue
		}
		a, ok := byName[t.Name]
		if !ok {
			a = &agg{category: t.Category}
			byName[t.Name] = a
		}
		a.count++
		a.total += score
	}

	out := make([]TechExposure, 0, len(byName))
	for name, a := range byName {
		out = append(out, TechExposure{
			Name:        name,
			Category:    a.category,
			AssetCount:  a.count,
			AvgExposure: a.total / float64(a.count),
		})
	}
	sortTechExposureDesc(out)
	if len(out) > limit {
		out = out[:limit]
	}
	return out, nil
}

func sortTechExposureDesc(t []TechExposure) {
	for i := 1; i < len(t); i++ {
		for j := i; j > 0 && t[j].AvgExposure > t[j-1].AvgExposure; j-- {
			t[j], t[j-1] = t[j-1], t[j]
		}
	}
}
