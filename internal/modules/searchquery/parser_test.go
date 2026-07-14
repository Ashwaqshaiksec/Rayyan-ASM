package searchquery

import (
	"reflect"
	"testing"
)

func TestParse_PlainFreeTextOnly(t *testing.T) {
	p := Parse("admin panel")
	if p.FreeText != "admin panel" {
		t.Errorf("FreeText = %q, want %q", p.FreeText, "admin panel")
	}
	if len(p.Filters) != 0 {
		t.Errorf("expected no filters, got %v", p.Filters)
	}
}

func TestParse_SingleField(t *testing.T) {
	p := Parse("port:443")
	if p.Filters["port"] != "443" {
		t.Errorf("Filters[port] = %q, want 443", p.Filters["port"])
	}
	if p.FreeText != "" {
		t.Errorf("expected empty FreeText, got %q", p.FreeText)
	}
}

func TestParse_MultipleFieldsCombinedWithFreeText(t *testing.T) {
	p := Parse("port:443 severity:critical admin")
	want := map[string]string{"port": "443", "severity": "critical"}
	if !reflect.DeepEqual(p.Filters, want) {
		t.Errorf("Filters = %v, want %v", p.Filters, want)
	}
	if p.FreeText != "admin" {
		t.Errorf("FreeText = %q, want %q", p.FreeText, "admin")
	}
}

func TestParse_ANDConnectiveIsIgnoredButHarmless(t *testing.T) {
	p := Parse("port:443 AND severity:critical")
	want := map[string]string{"port": "443", "severity": "critical"}
	if !reflect.DeepEqual(p.Filters, want) {
		t.Errorf("Filters = %v, want %v", p.Filters, want)
	}
	if p.FreeText != "" {
		t.Errorf("expected empty FreeText, got %q", p.FreeText)
	}
}

func TestParse_QuotedValue(t *testing.T) {
	p := Parse(`service:"http proxy"`)
	if p.Filters["service"] != "http proxy" {
		t.Errorf("Filters[service] = %q, want %q", p.Filters["service"], "http proxy")
	}
}

func TestParse_TypeFilterIsSeparatedFromFilters(t *testing.T) {
	p := Parse("type:findings severity:high")
	if _, ok := p.Filters["type"]; ok {
		t.Error("type: should not appear in Filters")
	}
	if !reflect.DeepEqual(p.Types, []string{"findings"}) {
		t.Errorf("Types = %v, want [findings]", p.Types)
	}
	if p.Filters["severity"] != "high" {
		t.Errorf("Filters[severity] = %q, want high", p.Filters["severity"])
	}
}

func TestParse_MultipleTypesCommaSeparated(t *testing.T) {
	p := Parse("type:hosts,services")
	if !reflect.DeepEqual(p.Types, []string{"hosts", "services"}) {
		t.Errorf("Types = %v, want [hosts services]", p.Types)
	}
}

func TestParsed_Includes(t *testing.T) {
	all := Parse("admin")
	if !all.Includes("hosts") || !all.Includes("findings") {
		t.Error("with no type: filter, every entity type should be included")
	}

	scoped := Parse("type:hosts admin")
	if !scoped.Includes("hosts") {
		t.Error("expected hosts to be included")
	}
	if scoped.Includes("findings") {
		t.Error("expected findings to be excluded when type:hosts is set")
	}
}

func TestParse_FieldNamesAreCaseInsensitive(t *testing.T) {
	p := Parse("PORT:443 Severity:Critical")
	if p.Filters["port"] != "443" {
		t.Errorf("expected uppercase field name PORT to be recognized, got filters %v", p.Filters)
	}
	if p.Filters["severity"] != "Critical" {
		t.Errorf("expected value case to be preserved, got %q", p.Filters["severity"])
	}
}

func TestParse_ASNAndCloudAccountFields(t *testing.T) {
	p := Parse("asn:AS15169 cloud_account:111122223333")
	want := map[string]string{"asn": "AS15169", "cloud_account": "111122223333"}
	if !reflect.DeepEqual(p.Filters, want) {
		t.Errorf("Filters = %v, want %v", p.Filters, want)
	}
}

func TestParse_CloudAssetsType(t *testing.T) {
	p := Parse("type:cloud_assets prod")
	if !p.Includes("cloud_assets") {
		t.Error("expected cloud_assets to be included")
	}
	if p.Includes("hosts") {
		t.Error("expected hosts to be excluded when type:cloud_assets is set")
	}
}
