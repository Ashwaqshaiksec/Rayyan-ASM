package exposure

import "strings"

// weights sum to 100. risk score gets the biggest cut since it already
// folds in CVE severity and cert/header issues; everything else layers on
// the attackability/business-impact signal CVSS alone doesn't capture.
const (
	weightRiskScore    = 20.0
	weightInternet     = 15.0
	weightAttackPath   = 15.0
	weightFindings     = 15.0
	weightCriticality  = 10.0
	weightCertificate  = 5.0
	weightTechnology   = 5.0
	weightCloud        = 5.0
	weightRelationship = 5.0
	weightBusiness     = 5.0
)

// widely-exploited CMS/app-server/framework names — these raise
// attackability regardless of which specific CVE is open right now.
var riskyTechKeywords = []string{
	"wordpress", "drupal", "joomla", "jenkins", "struts", "apache struts",
	"tomcat", "weblogic", "jboss", "magento", "phpmyadmin", "confluence",
	"jira", "gitlab", "exchange", "citrix", "fortinet", "pulse secure",
	"log4j", "spring", "laravel debug",
}

// computeExposure blends the weighted factors into one 0-100 score and
// maps it to a level.
func computeExposure(f Factors) (float64, string) {
	score := f.ExistingRiskScore*(weightRiskScore/100) +
		f.InternetExposure*(weightInternet/100) +
		f.AttackPathScore*(weightAttackPath/100) +
		f.FindingsScore*(weightFindings/100) +
		f.CriticalityScore*(weightCriticality/100) +
		f.CertificateScore*(weightCertificate/100) +
		f.TechnologyScore*(weightTechnology/100) +
		f.CloudScore*(weightCloud/100) +
		f.RelationshipScore*(weightRelationship/100) +
		f.BusinessImpact*(weightBusiness/100)

	if score > 100 {
		score = 100
	}
	if score < 0 {
		score = 0
	}
	return score, levelFromScore(score)
}

// levelFromScore: Critical 95+, High 75+, Medium 50+, Low 25+, else Informational.
func levelFromScore(score float64) string {
	switch {
	case score >= 95:
		return "critical"
	case score >= 75:
		return "high"
	case score >= 50:
		return "medium"
	case score >= 25:
		return "low"
	default:
		return "informational"
	}
}

// attackPathFactorScore tiers on presence rather than scaling linearly
// with count — sitting on one path matters a lot more than a 10th path
// does on top of the first.
func attackPathFactorScore(count int) float64 {
	switch {
	case count <= 0:
		return 0
	case count == 1:
		return 50
	case count == 2:
		return 75
	default:
		return 100
	}
}

func findingsFactorScore(critical, high, medium int) float64 {
	score := float64(critical)*25 + float64(high)*10 + float64(medium)*3
	if score > 100 {
		score = 100
	}
	return score
}

// certificateFactorScore reuses cert_issues/expiring_certs from
// risk_factors (already computed by riskscore) so both engines agree.
func certificateFactorScore(certIssues, expiringCerts int) float64 {
	score := float64(certIssues)*30 + float64(expiringCerts)*15
	if score > 100 {
		score = 100
	}
	return score
}

// technologyFactorScore scales with footprint size and adds a flat bonus
// for any tech matching the risky-keyword list.
func technologyFactorScore(techNames []string) (float64, []string) {
	score := float64(len(techNames)) * 8
	var risky []string
	for _, name := range techNames {
		lower := strings.ToLower(name)
		for _, kw := range riskyTechKeywords {
			if strings.Contains(lower, kw) {
				risky = append(risky, name)
				score += 30
				break
			}
		}
	}
	if score > 100 {
		score = 100
	}
	return score, risky
}

func criticalityFactorScore(sensitiveAsset bool, environment string, businessUnit string) (float64, string) {
	switch {
	case sensitiveAsset:
		return 100, "crown_jewel"
	case environment == "production" && businessUnit != "":
		return 60, "sensitive"
	case environment == "production":
		return 40, "sensitive"
	default:
		return 15, "standard"
	}
}

// relationshipFactorScore rewards graph centrality and maxes out if the
// asset sits one hop from something sensitive/critical.
func relationshipFactorScore(count int, connectedToCritical bool) float64 {
	score := float64(count) * 10
	if connectedToCritical {
		score = 100
	}
	if score > 100 {
		score = 100
	}
	return score
}

func businessImpactFactorScore(sensitiveAsset bool, businessUnit, owner string) float64 {
	switch {
	case sensitiveAsset:
		return 100
	case businessUnit != "" && owner != "":
		return 50
	case businessUnit != "" || owner != "":
		return 25
	default:
		return 0
	}
}
