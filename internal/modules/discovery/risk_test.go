package discovery

import "testing"

func TestFlagHostname(t *testing.T) {
	cases := []struct {
		name     string
		fqdn     string
		wantType string
		wantLen  int
	}{
		{"plain subdomain has no flags", "api.example.com", "", 0},
		{"admin-style hostname flags admin_panel", "admin.example.com", "admin_panel", 1},
		{"cpanel hostname flags admin_panel", "cpanel.example.com", "admin_panel", 1},
		{"vpn-style hostname flags vpn_portal", "vpn.example.com", "vpn_portal", 1},
		{"remote hostname flags vpn_portal", "remote.example.com", "vpn_portal", 1},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			signals := flagHostname(tc.fqdn)
			if len(signals) != tc.wantLen {
				t.Fatalf("flagHostname(%q) = %d signals, want %d (%+v)", tc.fqdn, len(signals), tc.wantLen, signals)
			}
			if tc.wantLen > 0 && signals[0].FlagType != tc.wantType {
				t.Fatalf("flagHostname(%q) flag type = %q, want %q", tc.fqdn, signals[0].FlagType, tc.wantType)
			}
		})
	}
}

func TestFlagWebService(t *testing.T) {
	t.Run("login page on success status flags login_page", func(t *testing.T) {
		signals := flagWebService("https://portal.example.com/", "Please Sign In", "nginx", 200)
		if !hasFlag(signals, "login_page") {
			t.Fatalf("expected login_page flag, got %+v", signals)
		}
	})

	t.Run("VPN title flags vpn_portal regardless of hostname", func(t *testing.T) {
		signals := flagWebService("https://gw.example.com/", "AnyConnect SSL VPN", "", 200)
		if !hasFlag(signals, "vpn_portal") {
			t.Fatalf("expected vpn_portal flag, got %+v", signals)
		}
	})

	t.Run("admin control panel title flags admin_panel", func(t *testing.T) {
		signals := flagWebService("https://x.example.com/", "Control Panel — Login", "", 200)
		if !hasFlag(signals, "admin_panel") {
			t.Fatalf("expected admin_panel flag, got %+v", signals)
		}
		if !hasFlag(signals, "login_page") {
			t.Fatalf("expected login_page flag alongside admin_panel, got %+v", signals)
		}
	})

	t.Run("error status produces no flags", func(t *testing.T) {
		signals := flagWebService("https://x.example.com/", "Admin Login", "", 404)
		if len(signals) != 0 {
			t.Fatalf("expected no flags for 404 status, got %+v", signals)
		}
	})

	t.Run("zero status produces no flags", func(t *testing.T) {
		signals := flagWebService("https://x.example.com/", "Admin Login", "", 0)
		if len(signals) != 0 {
			t.Fatalf("expected no flags for unreachable service, got %+v", signals)
		}
	})
}

func TestFlagCertificate(t *testing.T) {
	t.Run("expired certificate is flagged", func(t *testing.T) {
		signals := flagCertificate("old.example.com", true, true, "")
		if len(signals) != 1 || signals[0].FlagType != "expired_cert" {
			t.Fatalf("expected single expired_cert flag, got %+v", signals)
		}
	})

	t.Run("valid certificate is not flagged", func(t *testing.T) {
		signals := flagCertificate("fresh.example.com", false, true, "")
		if len(signals) != 0 {
			t.Fatalf("expected no flags for valid cert, got %+v", signals)
		}
	})

	t.Run("chain validation failure is flagged as invalid_tls", func(t *testing.T) {
		signals := flagCertificate("self-signed.example.com", false, false, "x509: certificate signed by unknown authority")
		if len(signals) != 1 || signals[0].FlagType != "invalid_tls" || signals[0].Severity != "high" {
			t.Fatalf("expected single high-severity invalid_tls flag, got %+v", signals)
		}
	})

	t.Run("expired AND chain-invalid cert gets both flags", func(t *testing.T) {
		signals := flagCertificate("bad.example.com", true, false, "x509: certificate has expired or is not yet valid")
		if len(signals) != 2 {
			t.Fatalf("expected 2 flags (expired_cert + invalid_tls), got %+v", signals)
		}
		types := map[string]bool{}
		for _, s := range signals {
			types[s.FlagType] = true
		}
		if !types["expired_cert"] || !types["invalid_tls"] {
			t.Fatalf("expected expired_cert + invalid_tls flags, got %+v", signals)
		}
	})

	t.Run("zero-value tlsValid with empty error does not emit invalid_tls (not yet checked)", func(t *testing.T) {
		// tlsValid=false && tlsValidationError="" means verification was not
		// attempted (non-TLS port, or port scan skipped), not that it failed.
		signals := flagCertificate("nocheck.example.com", false, false, "")
		if len(signals) != 0 {
			t.Fatalf("expected no flags when TLS validity not checked, got %+v", signals)
		}
	})
}

func TestFlagUnknownAsset(t *testing.T) {
	t.Run("owner known suppresses the flag", func(t *testing.T) {
		signals := flagUnknownAsset("mail.example.com", "reverse_dns", true)
		if len(signals) != 0 {
			t.Fatalf("expected no flags when owner is known, got %+v", signals)
		}
	})

	t.Run("owner unknown raises shadow IT style flag", func(t *testing.T) {
		signals := flagUnknownAsset("203.0.113.5", "asn_expand", false)
		if len(signals) != 1 || signals[0].FlagType != "unknown_asset" {
			t.Fatalf("expected single unknown_asset flag, got %+v", signals)
		}
	})
}

func TestDiscoveryRiskScore_OrdersBySeverity(t *testing.T) {
	scores := map[string]int{
		"critical": discoveryRiskScore("critical"),
		"high":     discoveryRiskScore("high"),
		"medium":   discoveryRiskScore("medium"),
		"low":      discoveryRiskScore("low"),
		"unknown":  discoveryRiskScore("something-else"),
	}
	if !(scores["critical"] > scores["high"] && scores["high"] > scores["medium"] && scores["medium"] > scores["low"] && scores["low"] > scores["unknown"]) {
		t.Fatalf("expected strictly descending severity scores, got %+v", scores)
	}
}

func hasFlag(signals []riskSignal, flagType string) bool {
	for _, s := range signals {
		if s.FlagType == flagType {
			return true
		}
	}
	return false
}
