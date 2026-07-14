package tools_test

import (
	"testing"

	trtypes "github.com/ShadooowX/rayyan-asm/internal/modules/toolrunner/types"
)

// TestValidateArgAllowedChars verifies that previously blocked characters
// needed by specific tools are now permitted by the safe-arg pattern.
func TestValidateArgAllowedChars(t *testing.T) {
	allowed := []struct {
		name string
		arg  string
	}{
		// Nuclei severity tags: comma-separated
		{"nuclei severity", "low,medium,high,critical"},
		// Nmap port ranges: colon-separated
		{"nmap port range", "1-65535"},
		{"nmap ports comma", "80,443,8080"},
		// Masscan port bracket notation
		{"masscan port range", "1-65535"},
		// General safe chars
		{"domain", "example.com"},
		{"IPv4", "192.168.1.1"},
		{"CIDR", "10.0.0.0/24"},
		{"rate value", "1000"},
		{"depth", "3"},
		{"wordlist path", "/usr/share/wordlists/common.txt"},
		{"URL fragment", "https://example.com/path"},
		{"at-sign", "user@example.com"},
		{"tilde", "~/tools/nuclei"},
		{"percent-encoded", "path%2Fsegment"},
		{"glob star", "*.example.com"},
		{"json-style", "{id:CVE-2021}"},
	}
	for _, tc := range allowed {
		t.Run("allow_"+tc.name, func(t *testing.T) {
			if err := trtypes.ValidateArg(tc.arg); err != nil {
				t.Errorf("expected %q to be allowed but got error: %v", tc.arg, err)
			}
		})
	}
}

// TestValidateArgBlockedChars verifies that shell-injection characters are rejected.
func TestValidateArgBlockedChars(t *testing.T) {
	blocked := []struct {
		name string
		arg  string
	}{
		{"semicolon", "arg;rm -rf /"},
		{"pipe", "arg|cat /etc/passwd"},
		{"backtick", "`id`"},
		{"dollar-subshell", "$(id)"},
		{"single-quote", "'evil'"},
		{"double-quote", "\"evil\""},
		{"newline", "arg\nmalicious"},
		{"space", "arg with spaces"},
		{"backslash", "arg\\path"},
		{"ampersand", "arg&&evil"},
		{"redirect-out", "arg>file"},
		{"redirect-in", "arg<file"},
	}
	for _, tc := range blocked {
		t.Run("block_"+tc.name, func(t *testing.T) {
			if err := trtypes.ValidateArg(tc.arg); err == nil {
				t.Errorf("expected %q to be blocked but it was allowed", tc.arg)
			}
		})
	}
}

// TestValidateArgEmpty verifies empty string is always allowed (skipped).
func TestValidateArgEmpty(t *testing.T) {
	if err := trtypes.ValidateArg(""); err != nil {
		t.Errorf("empty arg should be allowed, got: %v", err)
	}
}

// TestNmapPortArgFormat ensures nmap-style port args pass validation.
func TestNmapPortArgFormat(t *testing.T) {
	ports := []string{"80", "443", "80,443", "1-1024", "22,80,443,8080-8090"}
	for _, p := range ports {
		if err := trtypes.ValidateArg(p); err != nil {
			t.Errorf("nmap port arg %q should be valid: %v", p, err)
		}
	}
}

// TestNucleiSeverityTagFormat ensures nuclei severity tags pass validation.
func TestNucleiSeverityTagFormat(t *testing.T) {
	tags := []string{
		"critical",
		"high,critical",
		"low,medium,high,critical",
		"medium",
	}
	for _, tag := range tags {
		if err := trtypes.ValidateArg(tag); err != nil {
			t.Errorf("nuclei severity tag %q should be valid: %v", tag, err)
		}
	}
}
