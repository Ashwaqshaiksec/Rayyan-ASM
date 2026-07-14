package tools

import (
	"strings"
	"time"

	trtypes "github.com/ShadooowX/rayyan-asm/internal/modules/toolrunner/types"
)

// RunSmbclientWithCreds lists SMB shares optionally using credentials.
// When creds is nil or username is empty, falls back to null session (no-pass).
func RunSmbclientWithCreds(target string, creds *trtypes.ToolCredentials, timeout time.Duration) ([]SMBResult, error) {
	info, ok := trtypes.DefaultRegistry.Get("smbclient")
	if !ok || info.Status != trtypes.StatusInstalled || !info.Enabled {
		return nil, toolNotAvailable("smbclient")
	}

	args := []string{"-L", target}
	if creds != nil && creds.Username != "" {
		userSpec := creds.Username + "%" + creds.Password
		if creds.Domain != "" {
			userSpec = creds.Domain + "\\" + userSpec
		}
		args = append(args, "-U", userSpec)
	} else {
		args = append(args, "-N", "--no-pass")
	}

	result := trtypes.Run(info.BinaryPath, args, trtypes.RunOptions{Timeout: timeout})
	trtypes.DefaultRegistry.RecordRun("smbclient", result.Error == nil)

	var out []SMBResult
	for _, line := range parseLines(result.Stdout) {
		if len(line) == 0 || (line[0] != '\t' && line[0] != ' ') {
			continue
		}
		fields := strings.Fields(line)
		if len(fields) < 2 {
			continue
		}
		out = append(out, SMBResult{
			Host:    target,
			Share:   fields[0],
			Type:    fields[1],
			Comment: strings.Join(fields[2:], " "),
			Source:  "smbclient",
		})
	}
	return out, nil
}

// RunEnum4linuxNgWithCreds runs enum4linux-ng with optional credentials.
func RunEnum4linuxNgWithCreds(target string, creds *trtypes.ToolCredentials, timeout time.Duration) ([]SMBResult, error) {
	info, ok := trtypes.DefaultRegistry.Get("enum4linux-ng")
	if !ok || info.Status != trtypes.StatusInstalled || !info.Enabled {
		return nil, toolNotAvailable("enum4linux-ng")
	}

	args := []string{"-A"}
	if creds != nil && creds.Username != "" {
		args = append(args, "-u", creds.Username, "-p", creds.Password)
		if creds.Domain != "" {
			args = append(args, "-w", creds.Domain)
		}
	}
	args = append(args, "-oJ", "/dev/stdout", target)

	result := trtypes.Run(info.BinaryPath, args, trtypes.RunOptions{Timeout: timeout})
	trtypes.DefaultRegistry.RecordRun("enum4linux-ng", result.Error == nil)

	var out []SMBResult
	clean := extractJSON(result.Stdout)
	if clean == "" {
		return out, nil
	}
	var resp struct {
		Shares map[string]struct {
			Type    string `json:"type"`
			Comment string `json:"comment"`
		} `json:"shares"`
	}
	if err := parseJSONObj(clean, &resp); err != nil {
		return out, nil
	}
	for name, share := range resp.Shares {
		out = append(out, SMBResult{
			Host:    target,
			Share:   name,
			Type:    share.Type,
			Comment: share.Comment,
			Source:  "enum4linux-ng",
		})
	}
	return out, nil
}

// RunCrackMapExecWithCreds runs crackmapexec with optional credentials.
// Supports username/password and pass-the-hash (NTHash).
func RunCrackMapExecWithCreds(target string, creds *trtypes.ToolCredentials, timeout time.Duration) ([]SMBResult, error) {
	info, ok := trtypes.DefaultRegistry.Get("crackmapexec")
	if !ok || info.Status != trtypes.StatusInstalled || !info.Enabled {
		return nil, toolNotAvailable("crackmapexec")
	}

	args := []string{"smb", target, "--shares"}
	if creds != nil && creds.NTHash != "" {
		args = append(args, "-u", creds.Username, "-H", creds.NTHash)
		if creds.Domain != "" {
			args = append(args, "-d", creds.Domain)
		}
	} else if creds != nil && creds.Username != "" {
		args = append(args, "-u", creds.Username, "-p", creds.Password)
		if creds.Domain != "" {
			args = append(args, "-d", creds.Domain)
		}
	} else {
		args = append(args, "-u", "", "-p", "")
	}

	result := trtypes.Run(info.BinaryPath, args, trtypes.RunOptions{Timeout: timeout})
	trtypes.DefaultRegistry.RecordRun("crackmapexec", result.Error == nil)

	var out []SMBResult
	for _, line := range parseLines(result.Stdout) {
		if !strings.Contains(line, "SMB") {
			continue
		}
		fields := strings.Fields(line)
		for i, f := range fields {
			if (f == "READ" || f == "WRITE" || f == "NO") && i > 0 {
				out = append(out, SMBResult{
					Host:   target,
					Share:  fields[i-1],
					Type:   "Disk",
					Source: "crackmapexec",
				})
			}
		}
	}
	return out, nil
}
