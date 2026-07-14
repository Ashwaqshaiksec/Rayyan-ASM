package tools

import (
	"database/sql"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	_ "github.com/mattn/go-sqlite3"

	trtypes "github.com/ShadooowX/rayyan-asm/internal/modules/toolrunner/types"
)

// ScreenshotResult holds a captured screenshot for a web target.
type ScreenshotResult struct {
	URL        string `json:"url"`
	FilePath   string `json:"file_path"` // path on disk
	StatusCode int    `json:"status_code"`
	Title      string `json:"title"`
	Source     string `json:"source"`
}

// RunGowitness captures screenshots for all given URLs using gowitness.
// outDir is the directory where PNG files will be written.
func RunGowitness(targets []string, outDir string, timeout time.Duration) ([]ScreenshotResult, error) {
	info, ok := trtypes.DefaultRegistry.Get("gowitness")
	if !ok || info.Status != trtypes.StatusInstalled || !info.Enabled {
		return nil, toolNotAvailable("gowitness")
	}
	if len(targets) == 0 {
		return nil, nil
	}
	if outDir == "" {
		outDir = "/tmp/rayyan-screenshots"
	}
	if err := os.MkdirAll(outDir, 0o755); err != nil {
		return nil, fmt.Errorf("gowitness: cannot create output dir: %w", err)
	}

	// Write targets to a temp file
	tmpFile, err := os.CreateTemp("", "gowitness-targets-*.txt")
	if err != nil {
		return nil, fmt.Errorf("gowitness: cannot create temp file: %w", err)
	}
	defer os.Remove(tmpFile.Name())
	for _, t := range targets {
		fmt.Fprintln(tmpFile, t)
	}
	_ = tmpFile.Close()

	args := []string{
		"scan", "file",
		"-f", tmpFile.Name(),
		"--screenshot-path", outDir,
		"--write-db",
		"--db-path", filepath.Join(outDir, "gowitness.db"),
		"--threads", "4",
		"--timeout", fmt.Sprintf("%d", int(timeout.Seconds())-5),
	}
	result := trtypes.Run(info.BinaryPath, args, trtypes.RunOptions{Timeout: timeout})
	trtypes.DefaultRegistry.RecordRun("gowitness", result.Error == nil)

	dbPath := filepath.Join(outDir, "gowitness.db")

	// Primary source of truth: the sqlite DB written via --write-db. This is
	// stable across gowitness versions, unlike scraping stdout — newer
	// gowitness releases don't always print JSON lines to stdout for
	// `scan file`, which previously caused every result here to be dropped.
	out := readGowitnessDB(dbPath, outDir)

	// Secondary: legacy stdout JSON-lines parsing, kept for older gowitness
	// builds that don't support --write-db or use a different schema.
	if len(out) == 0 {
		for _, line := range parseLines(result.Stdout) {
			var obj struct {
				URL        string `json:"url"`
				Screenshot string `json:"screenshot"`
				StatusCode int    `json:"response_code"`
				Title      string `json:"title"`
			}
			if err := parseJSONLine(line, &obj); err != nil {
				continue
			}
			if obj.URL == "" {
				continue
			}
			fp := obj.Screenshot
			if fp != "" && !filepath.IsAbs(fp) {
				fp = filepath.Join(outDir, fp)
			}
			out = append(out, ScreenshotResult{
				URL:        obj.URL,
				FilePath:   fp,
				StatusCode: obj.StatusCode,
				Title:      obj.Title,
				Source:     "gowitness",
			})
		}
	}

	// Last resort: enumerate the output directory directly. Previously this
	// path always left URL empty, which meant every screenshot recovered
	// this way was silently dropped by the caller (it skips results with no
	// URL) — screenshots existed on disk but never got linked back to a
	// web_asset. Recover the URL by matching each PNG's sanitised filename
	// against the target list using gowitness's own naming convention.
	if len(out) == 0 {
		entries, _ := os.ReadDir(outDir)
		for _, e := range entries {
			if e.IsDir() || !strings.HasSuffix(e.Name(), ".png") {
				continue
			}
			out = append(out, ScreenshotResult{
				URL:      matchTargetToFilename(e.Name(), targets),
				FilePath: filepath.Join(outDir, e.Name()),
				Source:   "gowitness",
			})
		}
	}
	return out, nil
}

// readGowitnessDB opens the sqlite database gowitness writes via
// --write-db and returns one ScreenshotResult per row. It introspects the
// "results" table's columns instead of assuming exact names, since these
// have changed between gowitness releases (e.g. "screenshot" vs "filename",
// "response_code" vs "status_code").
func readGowitnessDB(dbPath, outDir string) []ScreenshotResult {
	if _, err := os.Stat(dbPath); err != nil {
		return nil
	}
	db, err := sql.Open("sqlite3", "file:"+dbPath+"?mode=ro")
	if err != nil {
		return nil
	}
	defer db.Close()

	cols, err := tableColumns(db, "results")
	if err != nil || len(cols) == 0 {
		return nil
	}

	urlCol := firstPresent(cols, "url", "final_url", "requested_url")
	fileCol := firstPresent(cols, "filename", "screenshot", "file_name", "screenshot_path")
	statusCol := firstPresent(cols, "response_code", "status_code", "code")
	titleCol := firstPresent(cols, "title")
	if urlCol == "" || fileCol == "" {
		return nil
	}

	selectCols := []string{urlCol, fileCol}
	if statusCol != "" {
		selectCols = append(selectCols, statusCol)
	}
	if titleCol != "" {
		selectCols = append(selectCols, titleCol)
	}
	query := fmt.Sprintf("SELECT %s FROM results", strings.Join(selectCols, ", "))
	rows, err := db.Query(query)
	if err != nil {
		return nil
	}
	defer rows.Close()

	var out []ScreenshotResult
	for rows.Next() {
		dest := make([]interface{}, len(selectCols))
		vals := make([]sql.NullString, len(selectCols))
		for i := range dest {
			dest[i] = &vals[i]
		}
		if err := rows.Scan(dest...); err != nil {
			continue
		}
		res := ScreenshotResult{Source: "gowitness"}
		res.URL = vals[0].String
		fp := vals[1].String
		if fp != "" && !filepath.IsAbs(fp) {
			fp = filepath.Join(outDir, fp)
		}
		res.FilePath = fp
		idx := 2
		if statusCol != "" {
			if n, err := strconv.Atoi(vals[idx].String); err == nil {
				res.StatusCode = n
			}
			idx++
		}
		if titleCol != "" {
			res.Title = vals[idx].String
		}
		if res.URL == "" || res.FilePath == "" {
			continue
		}
		out = append(out, res)
	}
	return out
}

func tableColumns(db *sql.DB, table string) ([]string, error) {
	rows, err := db.Query(fmt.Sprintf("PRAGMA table_info(%s)", table))
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var cols []string
	for rows.Next() {
		var cid int
		var name, ctype string
		var notnull, pk int
		var dflt sql.NullString
		if err := rows.Scan(&cid, &name, &ctype, &notnull, &dflt, &pk); err != nil {
			continue
		}
		cols = append(cols, name)
	}
	return cols, nil
}

func firstPresent(cols []string, candidates ...string) string {
	set := make(map[string]bool, len(cols))
	for _, c := range cols {
		set[strings.ToLower(c)] = true
	}
	for _, cand := range candidates {
		if set[strings.ToLower(cand)] {
			return cand
		}
	}
	return ""
}

// matchTargetToFilename recovers the original target URL for a screenshot
// PNG when only the filename is known, using the same sanitisation scheme
// the manual-capture handler uses (see ScreenshotHandler.Capture in
// internal/api/handlers/screenshots.go — kept in sync manually), so files
// from either code path can be matched back up.
func matchTargetToFilename(filename string, targets []string) string {
	stem := strings.TrimSuffix(filename, ".png")
	dashReplacer := strings.NewReplacer("://", "-", "/", "-", ":", "-", "?", "-", "&", "-", "=", "-")
	underscoreReplacer := strings.NewReplacer(
		"https://", "", "http://", "",
		"/", "_", ":", "_", ".", "_", "?", "_", "&", "_", "=", "_",
	)
	for _, t := range targets {
		if dashReplacer.Replace(t) == stem {
			return t
		}
		if underscoreReplacer.Replace(t)+".png" == filename {
			return t
		}
	}
	return ""
}

// RunAquatone captures screenshots using aquatone.
// outDir receives the aquatone_report.html and screenshots/ subdirectory.
func RunAquatone(targets []string, outDir string, timeout time.Duration) ([]ScreenshotResult, error) {
	info, ok := trtypes.DefaultRegistry.Get("aquatone")
	if !ok || info.Status != trtypes.StatusInstalled || !info.Enabled {
		return nil, toolNotAvailable("aquatone")
	}
	if len(targets) == 0 {
		return nil, nil
	}
	if outDir == "" {
		outDir = "/tmp/rayyan-aquatone"
	}
	if err := os.MkdirAll(outDir, 0o755); err != nil {
		return nil, fmt.Errorf("aquatone: cannot create output dir: %w", err)
	}

	// aquatone reads URLs from stdin
	args := []string{
		"-out", outDir,
		"-threads", "4",
		"-timeout", fmt.Sprintf("%d", int(timeout.Milliseconds())),
		"-screenshot-timeout", "30000",
		"-ports", "80,443,8080,8443",
	}
	stdin := strings.Join(targets, "\n")
	result := trtypes.RunWithStdin(info.BinaryPath, args, stdin, trtypes.RunOptions{Timeout: timeout})
	trtypes.DefaultRegistry.RecordRun("aquatone", result.Error == nil)

	// aquatone writes screenshots/<sanitised-url>.png
	var out []ScreenshotResult
	screenshotsDir := filepath.Join(outDir, "screenshots")
	entries, _ := os.ReadDir(screenshotsDir)
	for _, e := range entries {
		if e.IsDir() || !strings.HasSuffix(e.Name(), ".png") {
			continue
		}
		// Reverse-engineer URL from filename: "http__example.com__index.png" → "http://example.com/"
		name := strings.TrimSuffix(e.Name(), ".png")
		url := strings.Replace(name, "__", "://", 1)
		url = strings.ReplaceAll(url, "_", "/")
		out = append(out, ScreenshotResult{
			URL:      url,
			FilePath: filepath.Join(screenshotsDir, e.Name()),
			Source:   "aquatone",
		})
	}
	return out, nil
}
