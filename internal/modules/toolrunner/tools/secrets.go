package tools

import (
	"strings"
	"time"

	trtypes "github.com/ShadooowX/rayyan-asm/internal/modules/toolrunner/types"
)

// SecretResult holds a leaked secret or credential found by a scanning tool.
type SecretResult struct {
	Detector   string `json:"detector"`
	RawSecret  string `json:"raw_secret"`
	Verified   bool   `json:"verified"`
	File       string `json:"file"`
	Commit     string `json:"commit"`
	Repository string `json:"repository"`
	Severity   string `json:"severity"`
	Source     string `json:"source"`
}

// RunTruffleHog runs trufflehog to scan a git repository URL or local path for secrets.
func RunTruffleHog(target string, timeout time.Duration) ([]SecretResult, error) {
	info, ok := trtypes.DefaultRegistry.Get("trufflehog")
	if !ok || info.Status != trtypes.StatusInstalled || !info.Enabled {
		return nil, toolNotAvailable("trufflehog")
	}

	// Determine source type: git URL vs local filesystem path
	subcommand := "git"
	if !strings.HasPrefix(target, "http") && !strings.HasPrefix(target, "git@") {
		subcommand = "filesystem"
	}

	args := []string{
		subcommand, target,
		"--json",
		"--no-update",
		"--only-verified",
	}
	result := trtypes.Run(info.BinaryPath, args, trtypes.RunOptions{Timeout: timeout})
	trtypes.DefaultRegistry.RecordRun("trufflehog", result.Error == nil)

	var out []SecretResult
	for _, line := range parseLines(result.Stdout) {
		var obj struct {
			DetectorName   string `json:"DetectorName"`
			Raw            string `json:"Raw"`
			Verified       bool   `json:"Verified"`
			SourceMetadata struct {
				Data struct {
					Git struct {
						File       string `json:"file"`
						Commit     string `json:"commit"`
						Repository string `json:"repository"`
					} `json:"Git"`
					Filesystem struct {
						File string `json:"file"`
					} `json:"Filesystem"`
				} `json:"Data"`
			} `json:"SourceMetadata"`
		}
		if err := parseJSONLine(line, &obj); err != nil {
			continue
		}
		sev := "high"
		if obj.Verified {
			sev = "critical"
		}
		file := obj.SourceMetadata.Data.Git.File
		if file == "" {
			file = obj.SourceMetadata.Data.Filesystem.File
		}
		out = append(out, SecretResult{
			Detector:   obj.DetectorName,
			RawSecret:  obj.Raw,
			Verified:   obj.Verified,
			File:       file,
			Commit:     obj.SourceMetadata.Data.Git.Commit,
			Repository: obj.SourceMetadata.Data.Git.Repository,
			Severity:   sev,
			Source:     "trufflehog",
		})
	}
	return out, nil
}

// RunGitleaks runs gitleaks to detect secrets in a git repository or directory.
func RunGitleaks(target string, timeout time.Duration) ([]SecretResult, error) {
	info, ok := trtypes.DefaultRegistry.Get("gitleaks")
	if !ok || info.Status != trtypes.StatusInstalled || !info.Enabled {
		return nil, toolNotAvailable("gitleaks")
	}

	// gitleaks detect for directories/repos, git for git repos
	subcommand := "detect"
	args := []string{
		subcommand,
		"--source", target,
		"--report-format", "json",
		"--report-path", "/dev/stdout",
		"--no-banner",
		"-q",
	}
	result := trtypes.Run(info.BinaryPath, args, trtypes.RunOptions{Timeout: timeout})
	// gitleaks exits 1 when leaks are found; that is a valid result
	trtypes.DefaultRegistry.RecordRun("gitleaks", true)

	var out []SecretResult
	clean := extractJSON(result.Stdout)
	if clean == "" {
		return out, nil
	}
	var records []struct {
		Description string  `json:"Description"`
		Secret      string  `json:"Secret"`
		File        string  `json:"File"`
		Commit      string  `json:"Commit"`
		RuleID      string  `json:"RuleID"`
		Entropy     float64 `json:"Entropy"`
	}
	if err := parseJSONSlice(clean, &records); err != nil {
		return out, nil
	}
	for _, r := range records {
		sev := "high"
		if r.Entropy > 4.5 {
			sev = "critical"
		}
		out = append(out, SecretResult{
			Detector:  r.RuleID,
			RawSecret: r.Secret,
			File:      r.File,
			Commit:    r.Commit,
			Severity:  sev,
			Source:    "gitleaks",
		})
	}
	return out, nil
}
