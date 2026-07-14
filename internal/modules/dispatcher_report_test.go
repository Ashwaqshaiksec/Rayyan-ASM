package modules

import (
	"archive/zip"
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/ShadooowX/rayyan-asm/internal/database"
	"github.com/ShadooowX/rayyan-asm/internal/models"
	"github.com/google/uuid"
	"go.uber.org/zap"
)

// newTestDispatcher returns a Dispatcher backed by an in-memory SQLite DB
// with the models needed for report tests already migrated.
func newTestDispatcher(t *testing.T) (*Dispatcher, func()) {
	t.Helper()
	db, err := database.OpenSQLiteMemory()
	if err != nil {
		t.Fatalf("OpenSQLiteMemory: %v", err)
	}
	if err := db.AutoMigrate(
		&models.Organization{},
		&models.User{},
		&models.Domain{},
		&models.Subdomain{},
		&models.Host{},
		&models.Service{},
		&models.Certificate{},
		&models.Alert{},
		&models.Report{},
		&models.Finding{},
		&models.CloudAsset{},
		&models.AttackPath{},
		&models.ScanJob{},
		&models.AssetChangeEvent{},
	); err != nil {
		t.Fatalf("AutoMigrate: %v", err)
	}

	log := zap.NewNop().Sugar()
	d := &Dispatcher{db: db, log: log}
	return d, func() {
		sqlDB, _ := db.DB()
		_ = sqlDB.Close()
	}
}

// seedOrg creates an org row and returns its ID.
func seedOrg(t *testing.T, d *Dispatcher) uuid.UUID {
	t.Helper()
	org := models.Organization{Name: "test-org", Slug: "test-org", Plan: "pro"}
	org.ID = uuid.New()
	if err := d.db.Create(&org).Error; err != nil {
		t.Fatalf("seed org: %v", err)
	}
	return org.ID
}

// --- convertReportContent ---

func TestConvertReportContent_JSON(t *testing.T) {
	d := &Dispatcher{log: zap.NewNop().Sugar()}
	input := []byte(`{"report_type":"executive","total":42}`)

	got, err := d.convertReportContent(input, "json")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	var m map[string]any
	if err := json.Unmarshal(got, &m); err != nil {
		t.Fatalf("output not valid JSON: %v", err)
	}
	if m["report_type"] != "executive" {
		t.Errorf("expected report_type=executive, got %v", m["report_type"])
	}
}

func TestConvertReportContent_XLSX_ProducesValidWorkbook(t *testing.T) {
	d := &Dispatcher{log: zap.NewNop().Sugar()}
	input := []byte(`{"total_hosts":5,"report_type":"asset_inventory"}`)

	got, err := d.convertReportContent(input, "xlsx")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	// xlsx is a zip/OOXML package, not JSON — verify it unzips and that
	// [Content_Types].xml is the first entry per the OPC spec.
	zr, err := zip.NewReader(bytes.NewReader(got), int64(len(got)))
	if err != nil {
		t.Fatalf("xlsx output is not a valid zip: %v", err)
	}
	if len(zr.File) == 0 {
		t.Fatal("xlsx zip has no entries")
	}
	if zr.File[0].Name != "[Content_Types].xml" {
		t.Errorf("expected [Content_Types].xml first, got %q", zr.File[0].Name)
	}

	names := make(map[string]bool, len(zr.File))
	for _, f := range zr.File {
		names[f.Name] = true
	}
	for _, want := range []string{"_rels/.rels", "xl/workbook.xml", "xl/_rels/workbook.xml.rels", "xl/worksheets/sheet1.xml"} {
		if !names[want] {
			t.Errorf("expected xlsx entry %q not found", want)
		}
	}

	sheet, err := zr.Open("xl/worksheets/sheet1.xml")
	if err != nil {
		t.Fatalf("opening sheet1.xml: %v", err)
	}
	defer sheet.Close()
	sheetBytes, err := io.ReadAll(sheet)
	if err != nil {
		t.Fatalf("reading sheet1.xml: %v", err)
	}
	s := string(sheetBytes)
	if !strings.Contains(s, "report_type") || !strings.Contains(s, "asset_inventory") {
		t.Errorf("expected report fields in sheet1.xml, got: %s", s)
	}
}

func TestConvertReportContent_XLSX_SupportsMoreThan26Columns(t *testing.T) {
	d := &Dispatcher{log: zap.NewNop().Sugar()}
	payload := make(map[string]any, 30)
	for i := 0; i < 30; i++ {
		payload[fmt.Sprintf("field_%02d", i)] = i
	}
	input, err := json.Marshal(payload)
	if err != nil {
		t.Fatalf("marshal payload: %v", err)
	}

	got, err := d.convertReportContent(input, "xlsx")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	zr, err := zip.NewReader(bytes.NewReader(got), int64(len(got)))
	if err != nil {
		t.Fatalf("xlsx output is not a valid zip: %v", err)
	}
	sheet, err := zr.Open("xl/worksheets/sheet1.xml")
	if err != nil {
		t.Fatalf("opening sheet1.xml: %v", err)
	}
	defer sheet.Close()
	sheetBytes, err := io.ReadAll(sheet)
	if err != nil {
		t.Fatalf("reading sheet1.xml: %v", err)
	}
	s := string(sheetBytes)
	// The 27th column (index 26) must be "AA", not the overflowed '['.
	if strings.Contains(s, `r="[1"`) || strings.Contains(s, `r="\1"`) {
		t.Errorf("xlsx column letters overflowed past Z: %s", s)
	}
	if !strings.Contains(s, `r="AA1"`) {
		t.Errorf("expected column AA for the 27th field, got: %s", s)
	}
}

func TestConvertReportContent_TrulyUnknownFormat_FallsBackToJSON(t *testing.T) {
	d := &Dispatcher{log: zap.NewNop().Sugar()}
	input := []byte(`{"x":1}`)
	got, err := d.convertReportContent(input, "some_made_up_format")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !json.Valid(got) {
		t.Errorf("fallback output is not valid JSON")
	}
}

func TestExcelColumnName(t *testing.T) {
	cases := map[int]string{
		0:   "A",
		1:   "B",
		25:  "Z",
		26:  "AA",
		27:  "AB",
		51:  "AZ",
		52:  "BA",
		701: "ZZ",
		702: "AAA",
	}
	for idx, want := range cases {
		if got := excelColumnName(idx); got != want {
			t.Errorf("excelColumnName(%d) = %q, want %q", idx, got, want)
		}
	}
}

func TestFlattenScalarFields_DeterministicAcrossCalls(t *testing.T) {
	payload := map[string]any{
		"zeta":  1,
		"alpha": 2,
		"mike":  3,
	}
	h1, v1 := flattenScalarFields(payload)
	h2, v2 := flattenScalarFields(payload)
	if !reflect.DeepEqual(h1, h2) || !reflect.DeepEqual(v1, v2) {
		t.Fatalf("flattenScalarFields not deterministic: (%v,%v) vs (%v,%v)", h1, v1, h2, v2)
	}
	for i, h := range h1 {
		if want := payload[h]; fmt.Sprintf("%v", want) != v1[i] {
			t.Errorf("header %q misaligned with value %q", h, v1[i])
		}
	}
}

func TestConvertReportContent_HTML(t *testing.T) {
	d := &Dispatcher{log: zap.NewNop().Sugar()}
	input := []byte(`{"report_type":"exposure"}`)

	got, err := d.convertReportContent(input, "html")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	s := string(got)
	if !strings.Contains(s, "<!DOCTYPE html>") {
		t.Errorf("expected HTML doctype, got: %s", s[:min(200, len(s))])
	}
	if !strings.Contains(s, "exposure") {
		t.Errorf("expected report_type in HTML body")
	}
}

func TestConvertReportContent_CSV(t *testing.T) {
	d := &Dispatcher{log: zap.NewNop().Sugar()}
	// CSV renderer writes scalar keys as header row + value row.
	input := []byte(`{"total_hosts":5,"report_type":"asset_inventory"}`)

	got, err := d.convertReportContent(input, "csv")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	s := string(got)
	if !strings.Contains(s, "total_hosts") {
		t.Errorf("expected total_hosts in CSV header, got: %s", s)
	}
	if !strings.Contains(s, "5") {
		t.Errorf("expected value 5 in CSV row, got: %s", s)
	}
}

func TestConvertReportContent_PDF_FallsBackToHTML(t *testing.T) {
	// wkhtmltopdf will almost certainly not be present in the test environment.
	// The function must not error — it must degrade gracefully to HTML.
	t.Setenv("RAYYAN_SKIP_WKHTMLTOPDF", "1")
	d := &Dispatcher{log: zap.NewNop().Sugar()}
	input := []byte(`{"report_type":"executive"}`)

	got, err := d.convertReportContent(input, "pdf")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !strings.Contains(string(got), "<!DOCTYPE html>") {
		t.Errorf("expected HTML fallback when wkhtmltopdf absent")
	}
}

// --- buildReport ---

func TestBuildReport_AssetInventory(t *testing.T) {
	d, cleanup := newTestDispatcher(t)
	defer cleanup()
	orgID := seedOrg(t, d)

	// Seed two hosts.
	for i, ip := range []string{"10.0.0.1", "10.0.0.2"} {
		h := models.Host{OrgID: orgID, IP: ip, Status: "up"}
		h.ID = uuid.New()
		_ = i
		d.db.Create(&h)
	}
	// Seed one domain.
	dom := models.Domain{OrgID: orgID, Name: "example.com"}
	dom.ID = uuid.New()
	d.db.Create(&dom)

	report := &models.Report{OrgID: orgID, Type: "asset_inventory", Format: "json"}
	report.ID = uuid.New()

	got, err := d.buildReport(context.Background(), report)
	if err != nil {
		t.Fatalf("buildReport: %v", err)
	}
	var m map[string]any
	if err := json.Unmarshal(got, &m); err != nil {
		t.Fatalf("invalid JSON: %v", err)
	}
	if m["report_type"] != "asset_inventory" {
		t.Errorf("wrong report_type: %v", m["report_type"])
	}
	if int(m["total_hosts"].(float64)) != 2 {
		t.Errorf("expected total_hosts=2, got %v", m["total_hosts"])
	}
	if int(m["total_domains"].(float64)) != 1 {
		t.Errorf("expected total_domains=1, got %v", m["total_domains"])
	}
}

func TestBuildReport_Exposure(t *testing.T) {
	d, cleanup := newTestDispatcher(t)
	defer cleanup()
	orgID := seedOrg(t, d)

	// Seed an open service.
	svc := models.Service{OrgID: orgID, Port: 22, Protocol: "tcp", State: "open", HostRef: "10.0.0.1"}
	svc.ID = uuid.New()
	d.db.Create(&svc)

	// Seed an expiring cert (within 30 days).
	expires := time.Now().Add(10 * 24 * time.Hour)
	cert := models.Certificate{OrgID: orgID, Subject: "expiring.example.com", NotAfter: expires}
	cert.ID = uuid.New()
	d.db.Create(&cert)

	report := &models.Report{OrgID: orgID, Type: "exposure", Format: "json"}
	report.ID = uuid.New()

	got, err := d.buildReport(context.Background(), report)
	if err != nil {
		t.Fatalf("buildReport: %v", err)
	}
	var m map[string]any
	if err := json.Unmarshal(got, &m); err != nil {
		t.Fatalf("invalid JSON: %v", err)
	}
	if int(m["open_service_count"].(float64)) != 1 {
		t.Errorf("expected open_service_count=1, got %v", m["open_service_count"])
	}
	if int(m["expiring_cert_count"].(float64)) != 1 {
		t.Errorf("expected expiring_cert_count=1, got %v", m["expiring_cert_count"])
	}
}

func TestBuildReport_ServiceInventory(t *testing.T) {
	d, cleanup := newTestDispatcher(t)
	defer cleanup()
	orgID := seedOrg(t, d)

	for _, port := range []int{80, 443, 8080} {
		svc := models.Service{OrgID: orgID, Port: port, Protocol: "tcp", State: "open"}
		svc.ID = uuid.New()
		d.db.Create(&svc)
	}

	report := &models.Report{OrgID: orgID, Type: "service_inventory", Format: "json"}
	report.ID = uuid.New()

	got, err := d.buildReport(context.Background(), report)
	if err != nil {
		t.Fatalf("buildReport: %v", err)
	}
	var m map[string]any
	if err := json.Unmarshal(got, &m); err != nil {
		t.Fatalf("invalid JSON: %v", err)
	}
	if int(m["total_services"].(float64)) != 3 {
		t.Errorf("expected total_services=3, got %v", m["total_services"])
	}
}

func TestBuildReport_Executive(t *testing.T) {
	d, cleanup := newTestDispatcher(t)
	defer cleanup()
	orgID := seedOrg(t, d)

	// Seed enough to exercise every section of the new payload: a domain
	// (for TotalDomains), and an open critical finding with a CVSS score
	// (for the severity breakdown and top-findings table).
	dom := models.Domain{OrgID: orgID, Name: "example.com"}
	dom.ID = uuid.New()
	d.db.Create(&dom)

	f := models.Finding{OrgID: orgID, Title: "Exposed admin panel", Severity: "critical", Status: "open", CVSS: 9.8, URL: "https://example.com/admin"}
	f.ID = uuid.New()
	d.db.Create(&f)

	report := &models.Report{OrgID: orgID, Type: "executive", Format: "json"}
	report.ID = uuid.New()

	got, err := d.buildReport(context.Background(), report)
	if err != nil {
		t.Fatalf("buildReport: %v", err)
	}
	var m map[string]any
	if err := json.Unmarshal(got, &m); err != nil {
		t.Fatalf("invalid JSON: %v", err)
	}
	if m["report_type"] != "executive" {
		t.Errorf("wrong report_type: %v", m["report_type"])
	}
	// Previously the executive report was just 4 raw counts. It must now
	// carry a narrative summary, a risk score/tier, the full KPI set, and
	// the top-findings list — otherwise this is the same thin report with
	// a different name.
	for _, field := range []string{"summary", "risk_score", "risk_tier", "kpis", "top_findings"} {
		if _, ok := m[field]; !ok {
			t.Errorf("expected field %q in executive report payload, got keys: %v", field, m)
		}
	}
	summary, _ := m["summary"].(string)
	if summary == "" {
		t.Error("expected non-empty narrative summary")
	}
	topFindings, _ := m["top_findings"].([]any)
	if len(topFindings) != 1 {
		t.Errorf("expected 1 top finding, got %d", len(topFindings))
	}
}

func TestBuildReport_Executive_HTML_RendersFormattedReport(t *testing.T) {
	d, cleanup := newTestDispatcher(t)
	defer cleanup()
	orgID := seedOrg(t, d)

	f := models.Finding{OrgID: orgID, Title: "Outdated TLS version", Severity: "high", Status: "open", CVSS: 7.4}
	f.ID = uuid.New()
	d.db.Create(&f)

	report := &models.Report{OrgID: orgID, Type: "executive", Format: "html"}
	report.ID = uuid.New()

	jsonContent, err := d.buildReport(context.Background(), report)
	if err != nil {
		t.Fatalf("buildReport: %v", err)
	}
	htmlContent, err := d.convertReportContent(jsonContent, "html")
	if err != nil {
		t.Fatalf("convertReportContent: %v", err)
	}
	s := string(htmlContent)

	// The old renderer dumped raw JSON into a <pre> tag for every report
	// type, including executive. The new one must not do that, and must
	// actually surface the finding and a risk score badge.
	if strings.Contains(s, "<pre>") {
		t.Error("executive report HTML still uses the raw JSON <pre> dump")
	}
	if !strings.Contains(s, "Outdated TLS version") {
		t.Error("expected the seeded finding's title in the rendered HTML")
	}
	if !strings.Contains(s, "score-badge") {
		t.Error("expected a risk score badge in the rendered HTML")
	}
	if !strings.Contains(s, "<!DOCTYPE html>") {
		t.Error("expected a full HTML document")
	}
}

func TestBuildReport_UnknownType_ReturnsError(t *testing.T) {
	d, cleanup := newTestDispatcher(t)
	defer cleanup()
	orgID := seedOrg(t, d)

	report := &models.Report{OrgID: orgID, Type: "nonexistent_type", Format: "json"}
	report.ID = uuid.New()

	_, err := d.buildReport(context.Background(), report)
	if err == nil {
		t.Error("expected error for unknown report type, got nil")
	}
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}
