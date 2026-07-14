package dns

import (
	"context"
	"fmt"
	"net"
	"strings"
	"time"
)

// EmailSecurityResult holds the SPF, DKIM, and DMARC check results for a domain.
type EmailSecurityResult struct {
	Domain    string       `json:"domain"`
	ScannedAt time.Time    `json:"scanned_at"`
	SPF       SPFResult    `json:"spf"`
	DMARC     DMARCResult  `json:"dmarc"`
	DKIM      []DKIMResult `json:"dkim"`
	Score     int          `json:"score"` // 0-100
	Grade     string       `json:"grade"` // A, B, C, D, F
	Issues    []string     `json:"issues"`
}

// SPFResult holds the parsed SPF record.
type SPFResult struct {
	Present bool   `json:"present"`
	Record  string `json:"record"`
	Policy  string `json:"policy"` // pass, softfail, fail, neutral
	Valid   bool   `json:"valid"`
	Issue   string `json:"issue,omitempty"`
}

// DMARCResult holds the parsed DMARC record.
type DMARCResult struct {
	Present   bool   `json:"present"`
	Record    string `json:"record"`
	Policy    string `json:"policy"`        // none, quarantine, reject
	SubPolicy string `json:"sp,omitempty"`  // subdomain policy
	PCT       int    `json:"pct"`           // percentage of messages subjected to filtering
	RUA       string `json:"rua,omitempty"` // aggregate report URI
	Valid     bool   `json:"valid"`
	Issue     string `json:"issue,omitempty"`
}

// DKIMResult holds the result for a single DKIM selector check.
type DKIMResult struct {
	Selector string `json:"selector"`
	Present  bool   `json:"present"`
	Record   string `json:"record,omitempty"`
	Valid    bool   `json:"valid"`
	KeyType  string `json:"key_type,omitempty"` // rsa, ed25519
	Issue    string `json:"issue,omitempty"`
}

// commonDKIMSelectors are well-known DKIM selectors to probe.
var commonDKIMSelectors = []string{
	"default", "google", "mail", "dkim", "k1", "k2",
	"selector1", "selector2", "s1", "s2",
	"smtp", "email", "mta",
}

// txtResolver lets us swap in a fake resolver for tests.
type txtResolver interface {
	LookupTXT(ctx context.Context, name string) ([]string, error)
}

// CheckEmailSecurity performs SPF, DMARC, and DKIM checks for the given domain.
// It uses the system resolver with the provided timeout.
func CheckEmailSecurity(ctx context.Context, domain string, timeout time.Duration) EmailSecurityResult {
	if timeout <= 0 {
		timeout = 5 * time.Second
	}
	r := &net.Resolver{PreferGo: true}

	result := EmailSecurityResult{
		Domain:    domain,
		ScannedAt: time.Now(),
	}

	result.SPF = checkSPF(ctx, r, domain, timeout)
	result.DMARC = checkDMARC(ctx, r, domain, timeout)
	result.DKIM = checkDKIM(ctx, r, domain, timeout)
	result.Score, result.Grade, result.Issues = scoreEmailSecurity(result)

	return result
}

// checkSPF looks up and parses the SPF TXT record for the domain.
func checkSPF(ctx context.Context, r txtResolver, domain string, timeout time.Duration) SPFResult {
	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	txts, err := r.LookupTXT(ctx, domain)
	if err != nil {
		return SPFResult{Issue: fmt.Sprintf("DNS lookup failed: %v", err)}
	}

	for _, txt := range txts {
		if !strings.HasPrefix(txt, "v=spf1") {
			continue
		}
		res := SPFResult{
			Present: true,
			Record:  txt,
		}
		// Determine the policy (all mechanism).
		switch {
		case strings.Contains(txt, " -all"):
			res.Policy = "fail"
			res.Valid = true
		case strings.Contains(txt, " ~all"):
			res.Policy = "softfail"
			res.Valid = true
		case strings.Contains(txt, " +all"):
			res.Policy = "pass"
			res.Issue = "+all allows any sender — ineffective SPF policy"
		case strings.Contains(txt, " ?all"):
			res.Policy = "neutral"
			res.Issue = "?all is neutral — does not prevent spoofing"
		default:
			res.Policy = "unknown"
			res.Issue = "no 'all' mechanism found — SPF record is incomplete"
		}
		return res
	}

	return SPFResult{
		Present: false,
		Issue:   "no SPF record found",
	}
}

// checkDMARC looks up and parses the DMARC TXT record (_dmarc.<domain>).
func checkDMARC(ctx context.Context, r txtResolver, domain string, timeout time.Duration) DMARCResult {
	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	txts, err := r.LookupTXT(ctx, "_dmarc."+domain)
	if err != nil {
		return DMARCResult{Issue: fmt.Sprintf("DNS lookup failed: %v", err)}
	}

	for _, txt := range txts {
		if !strings.HasPrefix(txt, "v=DMARC1") {
			continue
		}
		res := DMARCResult{
			Present: true,
			Record:  txt,
			PCT:     100, // default per RFC 7489
		}
		for _, tag := range strings.Split(txt, ";") {
			tag = strings.TrimSpace(tag)
			switch {
			case strings.HasPrefix(tag, "p="):
				res.Policy = strings.TrimPrefix(tag, "p=")
			case strings.HasPrefix(tag, "sp="):
				res.SubPolicy = strings.TrimPrefix(tag, "sp=")
			case strings.HasPrefix(tag, "rua="):
				res.RUA = strings.TrimPrefix(tag, "rua=")
			case strings.HasPrefix(tag, "pct="):
				_, _ = fmt.Sscanf(strings.TrimPrefix(tag, "pct="), "%d", &res.PCT)
			}
		}
		switch res.Policy {
		case "reject":
			res.Valid = true
		case "quarantine":
			res.Valid = true
			if res.PCT < 100 {
				res.Issue = fmt.Sprintf("DMARC policy is quarantine but pct=%d — not applied to all messages", res.PCT)
			}
		case "none":
			res.Issue = "DMARC policy is 'none' — emails are not rejected or quarantined"
		default:
			res.Issue = fmt.Sprintf("unknown DMARC policy: %q", res.Policy)
		}
		return res
	}

	return DMARCResult{
		Present: false,
		Issue:   "no DMARC record found at _dmarc." + domain,
	}
}

// checkDKIM probes common selectors for DKIM TXT records.
func checkDKIM(ctx context.Context, r txtResolver, domain string, timeout time.Duration) []DKIMResult {
	var results []DKIMResult

	for _, sel := range commonDKIMSelectors {
		ctx2, cancel := context.WithTimeout(ctx, timeout)
		dkimDomain := fmt.Sprintf("%s._domainkey.%s", sel, domain)
		txts, err := r.LookupTXT(ctx2, dkimDomain)
		cancel()
		if err != nil {
			// NXDOMAIN / timeout — selector not present, skip silently.
			continue
		}
		for _, txt := range txts {
			if !strings.Contains(txt, "v=DKIM1") && !strings.Contains(txt, "k=") {
				continue
			}
			res := DKIMResult{
				Selector: sel,
				Present:  true,
				Record:   txt,
				Valid:    true,
			}
			for _, tag := range strings.Split(txt, ";") {
				tag = strings.TrimSpace(tag)
				if strings.HasPrefix(tag, "k=") {
					res.KeyType = strings.TrimPrefix(tag, "k=")
				}
			}
			if res.KeyType == "" {
				res.KeyType = "rsa" // default per RFC 6376
			}
			results = append(results, res)
		}
	}

	return results
}

// scoreEmailSecurity computes a 0-100 score and A-F grade.
// Scoring:
//
//	SPF present+valid(-all)  → 30 pts
//	SPF present+softfail     → 15 pts
//	DMARC reject             → 40 pts
//	DMARC quarantine         → 25 pts
//	DMARC none (present)     → 10 pts
//	At least one DKIM found  → 30 pts
func scoreEmailSecurity(r EmailSecurityResult) (score int, grade string, issues []string) {
	// SPF
	switch {
	case r.SPF.Present && r.SPF.Policy == "fail":
		score += 30
	case r.SPF.Present && r.SPF.Policy == "softfail":
		score += 15
		issues = append(issues, "SPF uses ~all (softfail) instead of -all (fail)")
	case r.SPF.Present && r.SPF.Policy == "pass":
		issues = append(issues, "SPF uses +all which allows any sender to pass")
	default:
		issues = append(issues, "SPF record missing or invalid")
	}
	if r.SPF.Issue != "" && r.SPF.Policy != "softfail" {
		issues = appendUniq(issues, r.SPF.Issue)
	}

	// DMARC
	switch {
	case r.DMARC.Present && r.DMARC.Policy == "reject":
		score += 40
	case r.DMARC.Present && r.DMARC.Policy == "quarantine":
		score += 25
		if r.DMARC.Issue != "" {
			issues = appendUniq(issues, r.DMARC.Issue)
		}
	case r.DMARC.Present && r.DMARC.Policy == "none":
		score += 10
		issues = append(issues, "DMARC policy is 'none' — no enforcement")
	default:
		issues = append(issues, "DMARC record missing")
	}

	// DKIM
	if len(r.DKIM) > 0 {
		score += 30
	} else {
		issues = append(issues, "no DKIM records found for common selectors")
	}

	// Grade
	switch {
	case score >= 90:
		grade = "A"
	case score >= 75:
		grade = "B"
	case score >= 55:
		grade = "C"
	case score >= 35:
		grade = "D"
	default:
		grade = "F"
	}
	return score, grade, issues
}

func appendUniq(slice []string, s string) []string {
	for _, existing := range slice {
		if existing == s {
			return slice
		}
	}
	return append(slice, s)
}
