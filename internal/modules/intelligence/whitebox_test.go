package intelligence

import (
	"encoding/json"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// ─── severityFromVulns ───────────────────────────────────────────────────

func TestSeverityFromVulns_Empty(t *testing.T) {
	vulns := map[string]struct {
		CVSS    float64  `json:"cvss"`
		Summary string   `json:"summary"`
		Refs    []string `json:"references"`
	}{}
	assert.Equal(t, "info", severityFromVulns(vulns))
}

func TestSeverityFromVulns_Low(t *testing.T) {
	vulns := map[string]struct {
		CVSS    float64  `json:"cvss"`
		Summary string   `json:"summary"`
		Refs    []string `json:"references"`
	}{
		"CVE-2024-0001": {CVSS: 2.5},
	}
	assert.Equal(t, "low", severityFromVulns(vulns))
}

func TestSeverityFromVulns_Medium(t *testing.T) {
	vulns := map[string]struct {
		CVSS    float64  `json:"cvss"`
		Summary string   `json:"summary"`
		Refs    []string `json:"references"`
	}{
		"CVE-2024-0002": {CVSS: 5.0},
	}
	assert.Equal(t, "medium", severityFromVulns(vulns))
}

func TestSeverityFromVulns_High(t *testing.T) {
	vulns := map[string]struct {
		CVSS    float64  `json:"cvss"`
		Summary string   `json:"summary"`
		Refs    []string `json:"references"`
	}{
		"CVE-2024-0003": {CVSS: 7.5},
	}
	assert.Equal(t, "high", severityFromVulns(vulns))
}

func TestSeverityFromVulns_Critical(t *testing.T) {
	vulns := map[string]struct {
		CVSS    float64  `json:"cvss"`
		Summary string   `json:"summary"`
		Refs    []string `json:"references"`
	}{
		"CVE-2024-0004": {CVSS: 9.8},
	}
	assert.Equal(t, "critical", severityFromVulns(vulns))
}

func TestSeverityFromVulns_PicksMaxAcrossMultiple(t *testing.T) {
	vulns := map[string]struct {
		CVSS    float64  `json:"cvss"`
		Summary string   `json:"summary"`
		Refs    []string `json:"references"`
	}{
		"CVE-A": {CVSS: 3.0},
		"CVE-B": {CVSS: 7.2}, // high
		"CVE-C": {CVSS: 5.5},
	}
	assert.Equal(t, "high", severityFromVulns(vulns))
}

// ─── intervalFor ─────────────────────────────────────────────────────────

func TestIntervalFor_Hourly(t *testing.T) {
	assert.Equal(t, time.Hour, intervalFor("hourly"))
}

func TestIntervalFor_Daily(t *testing.T) {
	assert.Equal(t, 24*time.Hour, intervalFor("daily"))
}

func TestIntervalFor_Weekly(t *testing.T) {
	assert.Equal(t, 7*24*time.Hour, intervalFor("weekly"))
}

func TestIntervalFor_UnknownDefaultsToDaily(t *testing.T) {
	assert.Equal(t, 24*time.Hour, intervalFor("unknown_cadence"))
	assert.Equal(t, 24*time.Hour, intervalFor(""))
	assert.Equal(t, 24*time.Hour, intervalFor("monthly"))
}

// ─── RawJSON ─────────────────────────────────────────────────────────────

func TestRawJSON_MarshalJSON_NonEmpty(t *testing.T) {
	r := RawJSON(`{"key":"value"}`)
	got, err := r.MarshalJSON()
	require.NoError(t, err)
	assert.Equal(t, `{"key":"value"}`, string(got))
}

func TestRawJSON_MarshalJSON_Empty(t *testing.T) {
	var r RawJSON
	got, err := r.MarshalJSON()
	require.NoError(t, err)
	assert.Equal(t, "null", string(got))
}

func TestRawJSON_MarshalJSON_RoundTrip(t *testing.T) {
	type wrapper struct {
		Data RawJSON `json:"data"`
	}
	original := wrapper{Data: RawJSON(`{"x":1}`)}
	b, err := json.Marshal(original)
	require.NoError(t, err)
	// Must not double-encode: the JSON object is embedded directly.
	assert.JSONEq(t, `{"data":{"x":1}}`, string(b))
}

func TestRawJSON_Scan_Bytes(t *testing.T) {
	var r RawJSON
	require.NoError(t, r.Scan([]byte(`{"a":1}`)))
	assert.Equal(t, RawJSON(`{"a":1}`), r)
}

func TestRawJSON_Scan_String(t *testing.T) {
	var r RawJSON
	require.NoError(t, r.Scan(`{"b":2}`))
	assert.Equal(t, RawJSON(`{"b":2}`), r)
}

func TestRawJSON_Scan_Nil(t *testing.T) {
	r := RawJSON("non-nil")
	require.NoError(t, r.Scan(nil))
	assert.Nil(t, r)
}

func TestRawJSON_Scan_UnsupportedType(t *testing.T) {
	var r RawJSON
	err := r.Scan(12345)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "unsupported type")
}

func TestRawJSON_Value_NonEmpty(t *testing.T) {
	r := RawJSON(`{"x":1}`)
	v, err := r.Value()
	require.NoError(t, err)
	assert.Equal(t, `{"x":1}`, v)
}

func TestRawJSON_Value_Empty(t *testing.T) {
	var r RawJSON
	v, err := r.Value()
	require.NoError(t, err)
	assert.Nil(t, v)
}

// ─── TextToRawJSON ────────────────────────────────────────────────────────

func TestTextToRawJSON_WrapsInObject(t *testing.T) {
	r := TextToRawJSON("hello,world")
	var got map[string]string
	require.NoError(t, json.Unmarshal(r, &got))
	assert.Equal(t, "hello,world", got["raw"])
}

func TestTextToRawJSON_EmptyString(t *testing.T) {
	r := TextToRawJSON("")
	var got map[string]string
	require.NoError(t, json.Unmarshal(r, &got))
	assert.Equal(t, "", got["raw"])
}

func TestTextToRawJSON_IsValidJSON(t *testing.T) {
	r := TextToRawJSON("API count exceeded")
	assert.True(t, json.Valid(r), "TextToRawJSON must produce valid JSON")
}
