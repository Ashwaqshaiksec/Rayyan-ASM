package discovery

import (
	"fmt"
	"strings"
)

// riskSignal is one detected risk indicator, ready to be persisted as a
// models.DiscoveryRiskFlag by the engine.
type riskSignal struct {
	FlagType string
	Severity string
	Evidence string
}

// adminPathHints / vpnHints / loginHints are small, high-signal keyword
// sets checked against discovered hostnames, page titles, and server
// banners. Kept intentionally short and pattern-level — these flag
// *candidates* for analyst review, not confirmed findings.
var adminHostHints = []string{"admin", "cpanel", "panel", "manage", "dashboard", "whm", "plesk", "webmin"}
var vpnHostHints = []string{"vpn", "remote", "gateway", "sslvpn", "anyconnect", "globalprotect", "fortigate"}
var loginTitleHints = []string{"login", "sign in", "log in", "authentication required"}
var vpnTitleHints = []string{"vpn", "ssl-vpn", "anyconnect", "remote access portal"}
var adminTitleHints = []string{"admin", "control panel", "dashboard", "cpanel", "webmin"}

func containsAny(haystack string, needles []string) bool {
	h := strings.ToLower(haystack)
	for _, n := range needles {
		if strings.Contains(h, n) {
			return true
		}
	}
	return false
}

// flagHostname checks a bare hostname against admin/VPN keyword hints —
// catches "Shadow IT" / "Unknown Assets" patterns before a service has
// even been probed.
func flagHostname(fqdn string) []riskSignal {
	var signals []riskSignal
	if containsAny(fqdn, adminHostHints) {
		signals = append(signals, riskSignal{
			FlagType: "admin_panel",
			Severity: "medium",
			Evidence: "hostname matches administrative naming pattern: " + fqdn,
		})
	}
	if containsAny(fqdn, vpnHostHints) {
		signals = append(signals, riskSignal{
			FlagType: "vpn_portal",
			Severity: "high",
			Evidence: "hostname matches VPN/remote-access naming pattern: " + fqdn,
		})
	}
	return signals
}

// flagWebService checks an HTTP(S) page title / status against
// login/VPN/admin hints — the "Public Admin Panels", "Exposed VPN
// Portals", and "Public Login Pages" indicators from the discovery
// brief, derived from the page actually being reachable and rendering
// recognizable content.
func flagWebService(url, title, server string, statusCode int) []riskSignal {
	var signals []riskSignal
	if statusCode == 0 || statusCode >= 400 {
		return signals
	}
	if containsAny(title, vpnTitleHints) {
		signals = append(signals, riskSignal{
			FlagType: "vpn_portal",
			Severity: "high",
			Evidence: "page title indicates a VPN/remote-access portal: \"" + title + "\" at " + url,
		})
	}
	if containsAny(title, adminTitleHints) {
		signals = append(signals, riskSignal{
			FlagType: "admin_panel",
			Severity: "medium",
			Evidence: "page title indicates an admin/control panel: \"" + title + "\" at " + url,
		})
	}
	if containsAny(title, loginTitleHints) {
		signals = append(signals, riskSignal{
			FlagType: "login_page",
			Severity: "low",
			Evidence: "publicly reachable login page: \"" + title + "\" at " + url,
		})
	}
	return signals
}

// flagCertificate checks a certificate for expiry — the "Expired
// Certificates" indicator.
// flagCertificate evaluates a retrieved certificate for security findings.
// isExpired is checked first (always a medium-severity finding), then
// tlsValid / tlsValidationError from fetchLiveCert's standard-verification
// pass: a cert that fails browser-grade chain validation is flagged as a
// high-severity "invalid_tls" finding, turning the previous "we ignore TLS
// errors" behavior into actionable ASM findings. A cert that is both
// expired and chain-invalid gets both flags.
func flagCertificate(subject string, isExpired bool, tlsValid bool, tlsValidationError string) []riskSignal {
	var sigs []riskSignal
	if isExpired {
		sigs = append(sigs, riskSignal{
			FlagType: "expired_cert",
			Severity: "medium",
			Evidence: "certificate for " + subject + " has expired",
		})
	}
	// A non-empty TLSValidationError means the standard-verification pass
	// failed (chain untrusted, hostname mismatch, revoked, etc.). We only
	// emit the flag when we know validation was actually *attempted and
	// failed* rather than just not-yet-checked (zero-value tlsValid &&
	// empty error = verification not attempted, e.g. non-TLS port).
	if !tlsValid && tlsValidationError != "" {
		sigs = append(sigs, riskSignal{
			FlagType: "invalid_tls",
			Severity: "high",
			Evidence: fmt.Sprintf("certificate for %s fails standard TLS validation: %s", subject, tlsValidationError),
		})
	}
	return sigs
}

// flagUnknownAsset marks an asset discovered through passive/indirect
// means (e.g. reverse DNS, ASN expansion) that doesn't correspond to any
// known, monitored domain — the "Unknown Assets" / "Shadow IT Assets"
// indicators. ownerKnown is true when the asset ties back to an explicit
// seed domain or already-tracked subdomain.
func flagUnknownAsset(label, source string, ownerKnown bool) []riskSignal {
	if ownerKnown {
		return nil
	}
	return []riskSignal{{
		FlagType: "unknown_asset",
		Severity: "low",
		Evidence: label + " discovered via " + source + " with no link back to a monitored seed domain — review for shadow IT",
	}}
}

// discoveryRiskScore assigns a coarse score so the dashboard can rank
// flags without re-deriving severity each time. Higher is worse.
func discoveryRiskScore(severity string) int {
	switch severity {
	case "critical":
		return 90
	case "high":
		return 70
	case "medium":
		return 45
	case "low":
		return 20
	default:
		return 10
	}
}
