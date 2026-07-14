package discovery

import (
	_ "embed"
	"strings"
	"sync"
)

// WordlistTier selects which DNS brute-force wordlist Options.WordlistTier
// uses for subdomain discovery. See SOURCE.md in wordlists/ for provenance
// of the embedded "medium" and "large" lists.
const (
	WordlistTierSmall  = "small"  // ~70 words, hand-curated, default
	WordlistTierMedium = "medium" // ~5k words, SecLists subset
	WordlistTierLarge  = "large"  // ~110k words, full SecLists list
)

//go:embed wordlists/medium.txt
var mediumWordlistRaw string

//go:embed wordlists/large.txt
var largeWordlistRaw string

var (
	mediumWordlistOnce sync.Once
	mediumWordlist     []string

	largeWordlistOnce sync.Once
	largeWordlist     []string
)

// parseWordlist splits an embedded newline-delimited wordlist file into a
// clean slice of lowercase, non-empty words, computed once per process
// regardless of how many discovery jobs run.
func parseWordlist(raw string) []string {
	lines := strings.Split(raw, "\n")
	out := make([]string, 0, len(lines))
	for _, line := range lines {
		w := strings.ToLower(strings.TrimSpace(line))
		if w == "" || strings.HasPrefix(w, "#") {
			continue
		}
		out = append(out, w)
	}
	return out
}

// wordlistForTier resolves Options.WordlistTier to the actual word slice to
// brute-force with, defaulting to the small/curated list for an unrecognized
// or empty tier so existing callers (and the default Options zero value)
// keep today's fast, low-noise behavior.
func wordlistForTier(tier string) []string {
	switch strings.ToLower(strings.TrimSpace(tier)) {
	case WordlistTierMedium:
		mediumWordlistOnce.Do(func() { mediumWordlist = parseWordlist(mediumWordlistRaw) })
		return mediumWordlist
	case WordlistTierLarge:
		largeWordlistOnce.Do(func() { largeWordlist = parseWordlist(largeWordlistRaw) })
		return largeWordlist
	default:
		return bruteforceWordlist
	}
}

// permutationSuffixes are the numeric/version-style suffixes combined with
// known environment/service words to find hosts that follow common naming
// conventions (dev-2, api-v2, staging01) but wouldn't appear verbatim in any
// flat wordlist.
var permutationSuffixes = []string{
	"1", "2", "3", "4", "5",
	"01", "02", "03",
	"v1", "v2", "v3",
}

// maxPermutationBaseWords caps how many base words feed the permutation
// generator per hop, so a hop with thousands of CT-discovered hostnames
// doesn't explode into an unbounded number of DNS lookups — the highest
// value comes from short, label-like words (the ones permutations actually
// make sense for), not long multi-part hostnames.
const maxPermutationBaseWords = 100

// permutationBaseWords collects candidate base words for permutation
// generation from two sources: the active wordlist tier's hits for this
// hop, and the first label of every hostname already discovered via CT logs
// or brute force this hop. Only short, single-label, alphabetic-ish words
// are kept — multi-label hostnames and pure numbers don't produce useful
// permutations.
func permutationBaseWords(wordlistHits []string, discovered map[string]bool, rootDomain string) []string {
	seen := make(map[string]bool)
	var words []string
	add := func(w string) {
		w = strings.ToLower(strings.TrimSpace(w))
		if w == "" || len(w) > 20 || strings.Contains(w, ".") || strings.Contains(w, "*") {
			return
		}
		if seen[w] {
			return
		}
		seen[w] = true
		words = append(words, w)
	}

	for _, w := range wordlistHits {
		add(w)
	}
	for fqdn := range discovered {
		label := strings.TrimSuffix(fqdn, "."+rootDomain)
		if label == fqdn || label == "" {
			continue
		}
		// The leftmost label is the most useful permutation seed under
		// common env-prefix.service.domain naming (e.g. "staging" out of
		// "staging.api.example.com"), so take it rather than the leaf.
		if idx := strings.Index(label, "."); idx >= 0 {
			label = label[:idx]
		}
		add(label)
	}

	if len(words) > maxPermutationBaseWords {
		words = words[:maxPermutationBaseWords]
	}
	return words
}

// generatePermutations expands a set of base words into
// environment/numeric/version variants (dev-2, api-v2, staging01, ...)
// rather than relying solely on static wordlist membership.
func generatePermutations(baseWords []string) []string {
	seen := make(map[string]bool)
	var out []string
	add := func(s string) {
		if s == "" || seen[s] {
			return
		}
		seen[s] = true
		out = append(out, s)
	}

	for _, w := range baseWords {
		for _, suf := range permutationSuffixes {
			add(w + suf)
			add(w + "-" + suf)
		}
	}
	return out
}
