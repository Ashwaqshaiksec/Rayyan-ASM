package types

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// makeScript writes a small shell script to a temp file and returns its path.
// The file is automatically removed when the test finishes.
func makeScript(t *testing.T, content string) string {
	t.Helper()
	f, err := os.CreateTemp(t.TempDir(), "types_test_*.sh")
	if err != nil {
		t.Fatalf("CreateTemp: %v", err)
	}
	fmt.Fprintf(f, "#!/bin/sh\n%s\n", content)
	_ = f.Close()
	if err := os.Chmod(f.Name(), 0755); err != nil {
		t.Fatalf("Chmod: %v", err)
	}
	return f.Name()
}

// ── capLines ──────────────────────────────────────────────────────────────────

func TestCapLines_UnderCap(t *testing.T) {
	input := "line1\nline2\nline3\n"
	got, capped := capLines(input, 5)
	if capped {
		t.Fatal("expected capped=false for input under cap")
	}
	if got != input {
		t.Fatalf("expected full string returned, got %q", got)
	}
}

func TestCapLines_ExactlyAtCap(t *testing.T) {
	input := "a\nb\nc\n"
	got, capped := capLines(input, 3)
	if capped {
		t.Fatal("expected capped=false when input exactly at cap")
	}
	if got != input {
		t.Fatalf("expected full string, got %q", got)
	}
}

func TestCapLines_OverCap(t *testing.T) {
	lines := []string{"one", "two", "three", "four", "five"}
	input := strings.Join(lines, "\n") + "\n"
	got, capped := capLines(input, 3)
	if !capped {
		t.Fatal("expected capped=true when over cap")
	}
	gotLines := strings.Split(strings.TrimRight(got, "\n"), "\n")
	if len(gotLines) != 3 {
		t.Fatalf("expected 3 lines, got %d: %v", len(gotLines), gotLines)
	}
	for i, want := range lines[:3] {
		if gotLines[i] != want {
			t.Fatalf("line[%d]: want %q got %q", i, want, gotLines[i])
		}
	}
}

func TestCapLines_MaxLinesZero(t *testing.T) {
	// maxLines=0 → capLines returns s unchanged (no truncation)
	var big strings.Builder
	for i := 0; i < 1_000; i++ {
		big.WriteString("x\n")
	}
	input := big.String()
	got, capped := capLines(input, 0)
	if capped {
		t.Fatal("expected capped=false when maxLines=0")
	}
	if got != input {
		t.Fatal("expected unmodified string when maxLines=0")
	}
}

// ── Run ───────────────────────────────────────────────────────────────────────

func TestRun_BinaryNotFound(t *testing.T) {
	res := Run("/nonexistent/binary/zzz", []string{}, RunOptions{Timeout: 2 * time.Second})
	if res.Error == nil {
		t.Fatal("expected non-nil Error when binary not found")
	}
}

func TestRun_NonZeroExit_StderrCaptured(t *testing.T) {
	// Script writes to stderr and exits non-zero.
	// Run's ExitError path: sets ExitCode != 0, captures Stderr, Error is nil.
	script := makeScript(t, "echo 'fail' >&2; exit 1")
	res := Run(script, []string{}, RunOptions{Timeout: 5 * time.Second})
	if res.ExitCode == 0 {
		t.Fatal("expected non-zero ExitCode")
	}
	if !strings.Contains(res.Stderr, "fail") {
		t.Fatalf("expected stderr to contain 'fail', got %q", res.Stderr)
	}
}

func TestRun_Success_StdoutCaptured(t *testing.T) {
	// /bin/echo is a clean binary with safe args — no metacharacters.
	res := Run("/bin/echo", []string{"hello"}, RunOptions{Timeout: 5 * time.Second})
	if res.Error != nil {
		t.Fatalf("unexpected error: %v", res.Error)
	}
	if !strings.Contains(res.Stdout, "hello") {
		t.Fatalf("expected stdout to contain 'hello', got %q", res.Stdout)
	}
}

func TestRun_MaxLinesHonoured(t *testing.T) {
	// seq outputs 20 lines; MaxLines=5 should truncate.
	res := Run("/usr/bin/seq", []string{"1", "20"},
		RunOptions{Timeout: 5 * time.Second, MaxLines: 5})
	if res.Error != nil {
		t.Fatalf("unexpected error: %v", res.Error)
	}
	if !res.Truncated {
		t.Fatal("expected Truncated=true")
	}
	lines := strings.Split(strings.TrimRight(res.Stdout, "\n"), "\n")
	if len(lines) != 5 {
		t.Fatalf("expected 5 lines, got %d", len(lines))
	}
}

func TestRun_TimeoutHonoured(t *testing.T) {
	// Use /usr/bin/sleep directly so exec.CommandContext can kill it.
	// Shell-wrapper scripts fork a child that outlives the sh process under
	// context cancel; a direct exec does not.
	start := time.Now()
	res := Run("/usr/bin/sleep", []string{"10"}, RunOptions{Timeout: 200 * time.Millisecond})
	elapsed := time.Since(start)
	if elapsed >= 2*time.Second {
		t.Fatalf("expected early return from timeout, elapsed=%v", elapsed)
	}
	// exec.CommandContext sends SIGKILL on timeout, which arrives as an
	// *exec.ExitError (code -1). Run's ExitError branch sets ExitCode but
	// does not populate Error; check ExitCode instead.
	if res.ExitCode != -1 {
		t.Fatalf("expected ExitCode=-1 for killed process, got %d (Error=%v)", res.ExitCode, res.Error)
	}
}

// ── ValidateArg ───────────────────────────────────────────────────────────────

func TestValidateArg_AcceptsSafe(t *testing.T) {
	safe := []string{
		"example.com",
		filepath.Join("/usr", "bin", "nmap"),
		"192.168.1.1",
		"output.json",
		"user@host",
		"key=value",
	}
	for _, a := range safe {
		if err := ValidateArg(a); err != nil {
			t.Errorf("ValidateArg(%q): unexpected error: %v", a, err)
		}
	}
}

func TestValidateArg_RejectsMeta(t *testing.T) {
	bad := []string{
		"arg;evil",
		"arg|pipe",
		"arg&bg",
		"arg`cmd`",
		"$var",
		"arg>file",
		"arg<file",
		"arg\ninjected",
		"arg\\evil",
	}
	for _, a := range bad {
		if err := ValidateArg(a); err == nil {
			t.Errorf("ValidateArg(%q): expected error, got nil", a)
		}
	}
}

func TestValidateArg_EmptyAllowed(t *testing.T) {
	if err := ValidateArg(""); err != nil {
		t.Fatalf("ValidateArg(\"\") should return nil, got %v", err)
	}
}

// ── ValidateArgs ─────────────────────────────────────────────────────────────

func TestValidateArgs_RejectsSliceWithBadArg(t *testing.T) {
	args := []string{"safe", "also-safe", "bad;cmd"}
	if err := ValidateArgs(args); err == nil {
		t.Fatal("ValidateArgs: expected error for slice containing bad arg")
	}
}

func TestValidateArgs_AcceptsAllSafe(t *testing.T) {
	args := []string{"192.168.1.1", "-p", "80,443"}
	if err := ValidateArgs(args); err != nil {
		t.Fatalf("ValidateArgs: unexpected error: %v", err)
	}
}

// ── DetectVersion ────────────────────────────────────────────────────────────
// Regression coverage for the gowitness bug: a version-flag output that
// leads with an ASCII-art banner (no digits) before the real version line
// must not report the banner as the "version".

func TestDetectVersion_SkipsBannerLine(t *testing.T) {
	script := makeScript(t, `echo " ___ ___ _ _ _|_| |_ __ ___ ___ ___ "
echo "gowitness: 3.0.5"`)
	got := DetectVersion(script, "version")
	if !strings.Contains(got, "3.0.5") {
		t.Fatalf("DetectVersion: expected banner line to be skipped and version returned, got %q", got)
	}
}

func TestDetectVersion_SimpleFirstLine(t *testing.T) {
	script := makeScript(t, `echo "nuclei 3.2.6"`)
	got := DetectVersion(script, "-version")
	if !strings.Contains(got, "3.2.6") {
		t.Fatalf("DetectVersion: expected version on first line to be returned, got %q", got)
	}
}

func TestDetectVersion_EmptyBinaryPath(t *testing.T) {
	if got := DetectVersion("", "--version"); got != "" {
		t.Fatalf("DetectVersion: expected empty string for empty binaryPath, got %q", got)
	}
}

func TestContainsDigit(t *testing.T) {
	cases := []struct {
		in   string
		want bool
	}{
		{"gowitness: 3.0.5", true},
		{" ___ ___ _ _ _|_| |_ __ ___ ___ ___ ", false},
		{"", false},
		{"Usage:", false},
		{"v1", true},
	}
	for _, c := range cases {
		if got := containsDigit(c.in); got != c.want {
			t.Errorf("containsDigit(%q) = %v, want %v", c.in, got, c.want)
		}
	}
}
