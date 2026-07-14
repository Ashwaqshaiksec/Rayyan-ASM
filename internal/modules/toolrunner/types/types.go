// Package types holds shared types and the tool registry used by both the
// toolrunner package and its tools sub-package. It exists to break the
// import cycle:
//
//	toolrunner → toolrunner/tools → toolrunner  (cycle)
//
// After refactor:
//
//	toolrunner        → toolrunner/types  (ok)
//	toolrunner/tools  → toolrunner/types  (ok)
package types

import (
	"bytes"
	"context"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
	"sync"
	"time"
)

// ToolStatus describes the installation state of a tool.
type ToolStatus string

const (
	StatusInstalled    ToolStatus = "installed"
	StatusMissing      ToolStatus = "missing"
	StatusWrongVersion ToolStatus = "wrong_version"
)

// RunResult holds the output from a single tool execution.
type RunResult struct {
	Stdout    string
	Stderr    string
	ExitCode  int
	Duration  time.Duration
	Error     error
	Truncated bool
}

// RunOptions configures a single tool execution.
type RunOptions struct {
	Timeout     time.Duration
	WorkingDir  string
	Env         []string
	MaxLines    int
	Credentials *ToolCredentials
}

// ToolCredentials carries optional authentication material.
type ToolCredentials struct {
	Username string
	Password string
	Domain   string
	NTHash   string
}

// safeArgPattern matches only characters safe in command arguments.
var safeArgPattern = regexp.MustCompile(`^[a-zA-Z0-9._/:\-@=,+~\[\]%*{}]+$`)

// ValidateArg returns an error if the argument contains dangerous characters.
func ValidateArg(arg string) error {
	if arg == "" {
		return nil
	}
	if !safeArgPattern.MatchString(arg) {
		return fmt.Errorf("unsafe argument: %q contains disallowed characters", arg)
	}
	return nil
}

// ValidateArgs validates all arguments in a slice.
func ValidateArgs(args []string) error {
	for _, a := range args {
		if err := ValidateArg(a); err != nil {
			return err
		}
	}
	return nil
}

// Category classifies a tool by its security function.
type Category string

const (
	CategorySubdomain     Category = "subdomain"
	CategoryDNS           Category = "dns"
	CategoryNetwork       Category = "network"
	CategoryWeb           Category = "web"
	CategoryContent       Category = "content"
	CategoryVulnerability Category = "vulnerability"
	CategoryWAF           Category = "waf"
	CategorySMB           Category = "smb"
	CategoryOriginIP      Category = "origin_ip"
	CategoryInjection     Category = "injection"
	CategorySecrets       Category = "secrets"
	CategoryFingerprint   Category = "fingerprint"
	CategoryJSAnalysis    Category = "js_analysis"
	CategoryAuth          Category = "auth"
	CategoryParams        Category = "params"
	CategoryTakeover      Category = "takeover"
	CategoryCloud         Category = "cloud"
	CategoryScreenshot    Category = "screenshot"
)

// ToolInfo describes a registered tool and its current state.
type ToolInfo struct {
	Name               string     `json:"name"`
	Category           Category   `json:"category"`
	BinaryPath         string     `json:"binary_path"`
	Version            string     `json:"version"`
	Status             ToolStatus `json:"status"`
	Enabled            bool       `json:"enabled"`
	LastRun            *time.Time `json:"last_run,omitempty"`
	LastRunOK          bool       `json:"last_run_ok"`
	Description        string     `json:"description"`
	MaxConcurrent      int        `json:"max_concurrent"`
	MinIntervalSeconds int        `json:"min_interval_seconds"`
	// TimeoutSeconds overrides the category default timeout for this tool.
	// 0 means use CategoryDefaultTimeout(Category). Set for slow tools.
	TimeoutSeconds int    `json:"timeout_seconds"`
	VersionFlag    string `json:"-"`
	AbsPath        string `json:"-"`
}

// CategoryDefaultTimeout returns the recommended default timeout for a category.
func CategoryDefaultTimeout(cat Category) time.Duration {
	switch cat {
	case CategorySubdomain:
		return 30 * time.Minute
	case CategoryVulnerability:
		return 45 * time.Minute
	case CategorySecrets:
		return 20 * time.Minute
	case CategoryContent:
		return 20 * time.Minute
	case CategoryWeb:
		return 15 * time.Minute
	default:
		return 10 * time.Minute
	}
}

// EffectiveTimeout returns the timeout to use when running this tool.
func (t *ToolInfo) EffectiveTimeout() time.Duration {
	if t.TimeoutSeconds > 0 {
		return time.Duration(t.TimeoutSeconds) * time.Second
	}
	return CategoryDefaultTimeout(t.Category)
}

// toolRateLimiter enforces per-tool concurrency and minimum interval between runs.
type toolRateLimiter struct {
	mu          sync.Mutex
	sem         chan struct{}
	minInterval time.Duration
	lastRelease time.Time
}

func newToolRateLimiter(maxConcurrent, minIntervalSeconds int) *toolRateLimiter {
	l := &toolRateLimiter{
		minInterval: time.Duration(minIntervalSeconds) * time.Second,
	}
	if maxConcurrent > 0 {
		l.sem = make(chan struct{}, maxConcurrent)
	}
	return l
}

func (l *toolRateLimiter) acquire() func() {
	if l.sem != nil {
		l.sem <- struct{}{}
	}
	if l.minInterval > 0 {
		for {
			l.mu.Lock()
			wait := time.Until(l.lastRelease.Add(l.minInterval))
			l.mu.Unlock()
			if wait <= 0 {
				break
			}
			time.Sleep(wait)
		}
	}
	return func() {
		if l.minInterval > 0 {
			l.mu.Lock()
			l.lastRelease = time.Now()
			l.mu.Unlock()
		}
		if l.sem != nil {
			<-l.sem
		}
	}
}

// Registry stores and manages all registered tools.
type Registry struct {
	mu       sync.RWMutex
	tools    map[string]*ToolInfo
	limiters map[string]*toolRateLimiter
}

// NewRegistry returns an empty Registry.
func NewRegistry() *Registry {
	return &Registry{
		tools:    make(map[string]*ToolInfo),
		limiters: make(map[string]*toolRateLimiter),
	}
}

// Register adds a tool to the registry. If the caller has not already set
// info.Status, the binary is auto-detected on disk (the normal production
// path — see RegisterAll, which never sets Status). If the caller HAS
// explicitly set a Status (e.g. tests pre-seeding a known state, or future
// callers wiring in tools whose presence is already known), that value is
// honored as-is and no filesystem probing occurs.
func (r *Registry) Register(info ToolInfo) {
	r.mu.Lock()
	defer r.mu.Unlock()

	if info.Status == "" {
		path, found := DetectBinary(info.Name, info.AbsPath)
		if found {
			info.BinaryPath = path
			info.Status = StatusInstalled
			if info.VersionFlag != "" {
				info.Version = DetectVersion(path, info.VersionFlag)
			}
		} else {
			info.Status = StatusMissing
		}
	}

	r.tools[info.Name] = &info
	r.limiters[info.Name] = newToolRateLimiter(info.MaxConcurrent, info.MinIntervalSeconds)
}

// Get returns a copy of ToolInfo for the given name.
func (r *Registry) Get(name string) (ToolInfo, bool) {
	r.mu.RLock()
	defer r.mu.RUnlock()
	t, ok := r.tools[name]
	if !ok {
		return ToolInfo{}, false
	}
	return *t, ok
}

// List returns all registered tools.
func (r *Registry) List() []ToolInfo {
	r.mu.RLock()
	defer r.mu.RUnlock()
	out := make([]ToolInfo, 0, len(r.tools))
	for _, t := range r.tools {
		out = append(out, *t)
	}
	return out
}

// SetEnabled enables or disables a tool by name.
func (r *Registry) SetEnabled(name string, enabled bool) bool {
	r.mu.Lock()
	defer r.mu.Unlock()
	t, ok := r.tools[name]
	if !ok {
		return false
	}
	t.Enabled = enabled
	return true
}

// SetRateLimits updates concurrency and interval limits for a tool.
func (r *Registry) SetRateLimits(name string, maxConcurrent, minIntervalSeconds int) bool {
	r.mu.Lock()
	defer r.mu.Unlock()
	t, ok := r.tools[name]
	if !ok {
		return false
	}
	t.MaxConcurrent = maxConcurrent
	t.MinIntervalSeconds = minIntervalSeconds
	r.limiters[name] = newToolRateLimiter(maxConcurrent, minIntervalSeconds)
	return true
}

// Acquire acquires the rate-limiter slot for the named tool.
func (r *Registry) Acquire(name string) func() {
	r.mu.RLock()
	lim := r.limiters[name]
	r.mu.RUnlock()
	if lim == nil {
		return func() {}
	}
	return lim.acquire()
}

// Verify re-detects binary + version for one tool and updates its status.
func (r *Registry) Verify(name string) (ToolInfo, bool) {
	r.mu.Lock()
	defer r.mu.Unlock()
	t, ok := r.tools[name]
	if !ok {
		return ToolInfo{}, false
	}
	path, found := DetectBinary(t.Name, t.AbsPath)
	if found {
		t.BinaryPath = path
		t.Status = StatusInstalled
		if t.VersionFlag != "" {
			t.Version = DetectVersion(path, t.VersionFlag)
		}
	} else {
		t.BinaryPath = ""
		t.Status = StatusMissing
		t.Version = ""
	}
	return *t, true
}

// VerifyAll re-checks all registered tools.
func (r *Registry) VerifyAll() {
	r.mu.Lock()
	names := make([]string, 0, len(r.tools))
	for n := range r.tools {
		names = append(names, n)
	}
	r.mu.Unlock()
	for _, n := range names {
		r.Verify(n)
	}
}

// RecordRun updates the last-run timestamp and success flag.
func (r *Registry) RecordRun(name string, ok bool) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if t, exists := r.tools[name]; exists {
		now := time.Now()
		t.LastRun = &now
		t.LastRunOK = ok
	}
}

// DefaultRegistry is the package-level singleton registry.
var DefaultRegistry = NewRegistry()

// DetectBinary resolves the full path of a binary.
func DetectBinary(name, absolutePath string) (string, bool) {
	if absolutePath != "" {
		if _, err := os.Stat(absolutePath); err == nil {
			return absolutePath, true
		}
	}
	if p, err := exec.LookPath(name); err == nil {
		return p, true
	}
	candidates := []string{
		filepath.Join("/usr/local/bin", name),
		filepath.Join("/usr/bin", name),
		filepath.Join("/opt/asm-tools/bin", name),
		filepath.Join(os.Getenv("HOME"), "go/bin", name),
		filepath.Join("/root/go/bin", name),
		filepath.Join("/snap/bin", name),
	}
	for _, c := range candidates {
		if _, err := os.Stat(c); err == nil {
			return c, true
		}
	}
	return "", false
}

// DetectVersion runs the binary with versionFlag and returns the first output line.
func DetectVersion(binaryPath, versionFlag string) string {
	if binaryPath == "" {
		return ""
	}
	// Use a simple exec with a 10s wall-clock limit via channel
	done := make(chan string, 1)
	go func() {
		cmd := exec.Command(binaryPath, versionFlag) // #nosec G204
		out, _ := cmd.CombinedOutput()
		base := filepath.Base(binaryPath)
		for _, line := range splitLines(string(out)) {
			if line != "" && containsDigit(line) {
				line = trimPrefix(line, base+" ")
				done <- line
				return
			}
		}
		done <- ""
	}()
	select {
	case v := <-done:
		return v
	case <-time.After(10 * time.Second):
		return ""
	}
}

func splitLines(s string) []string {
	var out []string
	cur := ""
	for _, c := range s {
		if c == '\n' {
			out = append(out, trimSpace(cur))
			cur = ""
		} else {
			cur += string(c)
		}
	}
	if cur != "" {
		out = append(out, trimSpace(cur))
	}
	return out
}

func trimSpace(s string) string {
	for len(s) > 0 && (s[0] == ' ' || s[0] == '\t' || s[0] == '\r') {
		s = s[1:]
	}
	for len(s) > 0 && (s[len(s)-1] == ' ' || s[len(s)-1] == '\t' || s[len(s)-1] == '\r') {
		s = s[:len(s)-1]
	}
	return s
}

func trimPrefix(s, prefix string) string {
	if len(s) >= len(prefix) && s[:len(prefix)] == prefix {
		return s[len(prefix):]
	}
	return s
}

// containsDigit reports whether s has at least one ASCII digit. Used to
// skip decorative banner/ASCII-art lines when scanning a tool's version
// output for the actual version line — a real version string always has
// a digit in it, banner art essentially never does.
func containsDigit(s string) bool {
	for _, c := range s {
		if c >= '0' && c <= '9' {
			return true
		}
	}
	return false
}

const defaultTimeout = 5 * time.Minute
const defaultMaxLines = 100_000

// Run executes the binary at binaryPath with args using exec.Command (no shell).
func Run(binaryPath string, args []string, opts RunOptions) RunResult {
	if opts.Timeout == 0 {
		opts.Timeout = defaultTimeout
	}
	maxLines := opts.MaxLines
	if maxLines == 0 {
		maxLines = defaultMaxLines
	}

	if err := ValidateArgs(args); err != nil {
		return RunResult{Error: fmt.Errorf("argument validation: %w", err)}
	}

	ctx, cancel := context.WithTimeout(context.Background(), opts.Timeout)
	defer cancel()

	cmd := exec.CommandContext(ctx, binaryPath, args...) // #nosec G204
	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr

	if opts.WorkingDir != "" {
		cmd.Dir = opts.WorkingDir
	}
	if len(opts.Env) > 0 {
		cmd.Env = append(os.Environ(), opts.Env...)
	}

	start := time.Now()
	runErr := cmd.Run()
	dur := time.Since(start)

	exitCode := 0
	if runErr != nil {
		if exitErr, ok := runErr.(*exec.ExitError); ok {
			exitCode = exitErr.ExitCode()
		} else {
			return RunResult{
				Stdout:   stdout.String(),
				Stderr:   stderr.String(),
				Duration: dur,
				ExitCode: -1,
				Error:    runErr,
			}
		}
	}

	out, truncated := capLines(stdout.String(), maxLines)
	return RunResult{
		Stdout:    out,
		Stderr:    stderr.String(),
		ExitCode:  exitCode,
		Duration:  dur,
		Truncated: truncated,
	}
}

// RunWithStdin executes the binary with args and writes stdinData to the process stdin.
// Used for tools like aquatone that read their target list from stdin.
func RunWithStdin(binaryPath string, args []string, stdinData string, opts RunOptions) RunResult {
	if opts.Timeout == 0 {
		opts.Timeout = defaultTimeout
	}
	maxLines := opts.MaxLines
	if maxLines == 0 {
		maxLines = defaultMaxLines
	}
	if err := ValidateArgs(args); err != nil {
		return RunResult{Error: fmt.Errorf("argument validation: %w", err)}
	}
	ctx, cancel := context.WithTimeout(context.Background(), opts.Timeout)
	defer cancel()

	cmd := exec.CommandContext(ctx, binaryPath, args...) // #nosec G204
	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr
	cmd.Stdin = strings.NewReader(stdinData)
	if opts.WorkingDir != "" {
		cmd.Dir = opts.WorkingDir
	}
	if len(opts.Env) > 0 {
		cmd.Env = append(os.Environ(), opts.Env...)
	}
	start := time.Now()
	runErr := cmd.Run()
	dur := time.Since(start)
	exitCode := 0
	if runErr != nil {
		if exitErr, ok := runErr.(*exec.ExitError); ok {
			exitCode = exitErr.ExitCode()
		} else {
			return RunResult{Stdout: stdout.String(), Stderr: stderr.String(), Duration: dur, ExitCode: -1, Error: runErr}
		}
	}
	out, truncated := capLines(stdout.String(), maxLines)
	return RunResult{Stdout: out, Stderr: stderr.String(), ExitCode: exitCode, Duration: dur, Truncated: truncated}
}

// capLines limits output to maxLines lines, returning (capped string, wasTruncated).
func capLines(s string, maxLines int) (string, bool) {
	if maxLines <= 0 {
		return s, false
	}
	lines := splitLines(s)
	if len(lines) <= maxLines {
		return s, false
	}
	result := ""
	for i := 0; i < maxLines; i++ {
		result += lines[i] + "\n"
	}
	return result, true
}
