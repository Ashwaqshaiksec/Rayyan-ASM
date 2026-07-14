package discovery

import (
	"reflect"
	"testing"
)

func TestNormalizeDomain(t *testing.T) {
	cases := map[string]string{
		"Example.com":          "example.com",
		"https://Example.com/": "example.com",
		"http://example.com":   "example.com",
		"  example.com.  ":     "example.com",
		"":                     "",
	}
	for in, want := range cases {
		if got := normalizeDomain(in); got != want {
			t.Errorf("normalizeDomain(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestNormalizeDomains_FiltersEmpty(t *testing.T) {
	got := normalizeDomains([]string{"Example.com", "", "  ", "Sub.Example.com"})
	want := []string{"example.com", "sub.example.com"}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("normalizeDomains = %v, want %v", got, want)
	}
}

func TestRootOf(t *testing.T) {
	cases := map[string]string{
		"example.com":            "example.com",
		"api.example.com":        "example.com",
		"deep.api.example.com":   "example.com",
		"api.example.co.uk":      "example.co.uk",
		"deep.sub.example.co.uk": "example.co.uk",
		"localhost":              "localhost",

		// Multi-level public suffixes that the old "last two labels"
		// heuristic broke: these are *registries*, not registrable roots,
		// so the registrable root sits one label deeper than a naive
		// last-two-labels split would assume.
		"foo.github.io":                "foo.github.io",
		"deep.foo.github.io":           "foo.github.io",
		"bucket.s3.amazonaws.com":      "bucket.s3.amazonaws.com",
		"deep.bucket.s3.amazonaws.com": "bucket.s3.amazonaws.com",
		"myapp.herokuapp.com":          "myapp.herokuapp.com",
		"deep.myapp.herokuapp.com":     "myapp.herokuapp.com",
		"api.example.com.au":           "example.com.au",
		"deep.sub.example.com.au":      "example.com.au",
	}
	for in, want := range cases {
		if got := rootOf(in); got != want {
			t.Errorf("rootOf(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestDedupe(t *testing.T) {
	got := dedupe([]string{"a", "b", "a", "", "c", "b"})
	want := []string{"a", "b", "c"}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("dedupe = %v, want %v", got, want)
	}
}

func TestIPVersion(t *testing.T) {
	if ipVersion("1.2.3.4") != 4 {
		t.Errorf("expected IPv4 detection")
	}
	if ipVersion("2001:db8::1") != 6 {
		t.Errorf("expected IPv6 detection")
	}
}

func TestHostnamesFromCT(t *testing.T) {
	entries := []CTEntry{
		{NameValue: "api.example.com\nold.example.com"},
		{NameValue: "*.internal.example.com"},
		{NameValue: "api.example.com"}, // duplicate
		{NameValue: "unrelated.other.com"},
	}
	hosts, wildcards := hostnamesFromCT(entries, "example.com")

	wantHosts := []string{"api.example.com", "old.example.com"}
	if !reflect.DeepEqual(hosts, wantHosts) {
		t.Errorf("hostnamesFromCT hosts = %v, want %v", hosts, wantHosts)
	}
	wantWildcards := []string{"internal.example.com"}
	if !reflect.DeepEqual(wildcards, wantWildcards) {
		t.Errorf("hostnamesFromCT wildcards = %v, want %v", wildcards, wantWildcards)
	}
}

func TestHostnamesFromWaybackRows(t *testing.T) {
	rows := [][]string{
		{"original"}, // header row
		{"http://api.example.com/v1/health"},
		{"https://OLD.example.com/path?x=1"},
		{"api.example.com/v1/other"}, // no scheme
		{"http://api.example.com/v1/dup"},
		{"https://unrelated.other.com/"},
		{""},
	}
	got := hostnamesFromWaybackRows(rows, "example.com")
	want := []string{"api.example.com", "old.example.com"}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("hostnamesFromWaybackRows = %v, want %v", got, want)
	}
}

func TestContainsHost(t *testing.T) {
	list := []string{"a.example.com", "b.example.com"}
	if !containsHost(list, "a.example.com") {
		t.Error("expected containsHost to find existing entry")
	}
	if containsHost(list, "c.example.com") {
		t.Error("expected containsHost to reject missing entry")
	}
}

func TestSanitizeBanner(t *testing.T) {
	got := sanitizeBanner([]byte("SSH-2.0-OpenSSH_8.9\x00\x01trailing"))
	want := "SSH-2.0-OpenSSH_8.9trailing"
	if got != want {
		t.Errorf("sanitizeBanner = %q, want %q", got, want)
	}
}

func TestExtractTitle(t *testing.T) {
	html := `<html><head><TITLE>  Admin Login  </TITLE></head><body></body></html>`
	if got := extractTitle(html); got != "Admin Login" {
		t.Errorf("extractTitle = %q, want %q", got, "Admin Login")
	}
	if got := extractTitle("<html><body>no title here</body></html>"); got != "" {
		t.Errorf("extractTitle on missing title = %q, want empty", got)
	}
}

func TestWordlistForTier(t *testing.T) {
	small := wordlistForTier("")
	if len(small) != len(bruteforceWordlist) {
		t.Errorf("empty tier should default to small/curated list, got %d words want %d", len(small), len(bruteforceWordlist))
	}
	if got := wordlistForTier("SMALL"); len(got) != len(bruteforceWordlist) {
		t.Errorf("explicit small tier mismatch: got %d want %d", len(got), len(bruteforceWordlist))
	}
	if got := wordlistForTier("unknown-tier"); len(got) != len(bruteforceWordlist) {
		t.Errorf("unrecognized tier should fall back to small list, got %d words", len(got))
	}

	medium := wordlistForTier(WordlistTierMedium)
	if len(medium) < 4000 || len(medium) > 5000 {
		t.Errorf("medium tier word count out of expected ~5k range: got %d", len(medium))
	}
	// Loading twice should return the same memoized slice (sync.Once).
	if medium2 := wordlistForTier(WordlistTierMedium); len(medium2) != len(medium) {
		t.Errorf("medium tier should be memoized consistently, got %d then %d", len(medium), len(medium2))
	}

	large := wordlistForTier(WordlistTierLarge)
	if len(large) < 90000 || len(large) > 110000 {
		t.Errorf("large tier word count out of expected ~100k range: got %d", len(large))
	}
	if len(large) <= len(medium) {
		t.Errorf("large tier (%d) should be a superset/larger than medium tier (%d)", len(large), len(medium))
	}
}

func TestPermutationBaseWords(t *testing.T) {
	discovered := map[string]bool{
		"api.example.com":         true,
		"staging.api.example.com": true,
		"example.com":             true, // bare root, shouldn't add empty label
	}
	words := permutationBaseWords([]string{"dev", "web"}, discovered, "example.com")

	wantPresent := map[string]bool{"dev": true, "web": true, "api": true, "staging": true}
	got := map[string]bool{}
	for _, w := range words {
		got[w] = true
	}
	for w := range wantPresent {
		if !got[w] {
			t.Errorf("permutationBaseWords missing expected base word %q in %v", w, words)
		}
	}
}

func TestGeneratePermutations(t *testing.T) {
	out := generatePermutations([]string{"dev", "api", "staging"})
	wantSome := []string{"dev1", "dev-2", "api-v2", "staging01", "staging-01"}
	set := map[string]bool{}
	for _, w := range out {
		set[w] = true
	}
	for _, w := range wantSome {
		if !set[w] {
			t.Errorf("generatePermutations missing expected variant %q in %v", w, out)
		}
	}
	// No duplicates.
	if len(set) != len(out) {
		t.Errorf("generatePermutations produced duplicates: %d unique vs %d total", len(set), len(out))
	}
}
