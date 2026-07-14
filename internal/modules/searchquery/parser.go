// Package searchquery parses the field-qualified query syntax used by the
// global Search page — e.g. "port:443 severity:critical AND admin" — into
// structured filters plus whatever's left as free text.
//
// Previously the search box only ever did a single free-text LIKE across
// a fixed set of columns per entity ("admin" matched title/name/etc.
// everywhere). This gives commercial-ASM-style field scoping (port:443,
// severity:critical, cve:CVE-2023-...) that can be combined with AND, plus
// a type: filter to scope which entity groups are searched at all.
package searchquery

import (
	"regexp"
	"strings"
)

// KnownFields lists every "field:" prefix the parser recognizes, in the
// order they should be suggested by autocomplete.
var KnownFields = []string{
	"type", "port", "protocol", "service", "severity", "status", "category", "cve", "country", "os", "tag",
	"asn", "cloud_account",
}

// EntityTypes lists the valid values for type: — which result groups the
// backend should populate. An empty/absent type: means "all of them".
var EntityTypes = []string{"domains", "hosts", "subdomains", "services", "technologies", "findings", "cloud_assets"}

var fieldToken = regexp.MustCompile(`(?i)\b(` + strings.Join(KnownFields, "|") + `):("([^"]*)"|(\S+))`)

// Parsed is the result of parsing a query string.
type Parsed struct {
	// Filters maps a recognized field name to its value, lowercased for
	// case-insensitive matching except cve (kept as-typed since CVE IDs
	// are conventionally uppercase but shouldn't be forced either way).
	Filters map[string]string
	// Types is the set of entity groups to search, derived from type:
	// filter(s). Nil/empty means "search everything" (no restriction).
	Types []string
	// FreeText is whatever's left after every field:value token is
	// stripped out, trimmed of extra whitespace. Applied the same way the
	// original plain-text search did: a LIKE substring match across each
	// entity's default fields.
	FreeText string
}

// Parse splits q into field:value filters and remaining free text.
// "AND"/"and" between tokens is accepted but ignored — every filter is
// already ANDed together, matching how Shodan/Censys-style bars read even
// though the connector is implicit rather than meaningful.
func Parse(q string) Parsed {
	filters := map[string]string{}
	var types []string

	rest := fieldToken.ReplaceAllStringFunc(q, func(match string) string {
		sub := fieldToken.FindStringSubmatch(match)
		field := strings.ToLower(sub[1])
		value := sub[3]
		if value == "" {
			value = sub[4]
		}
		if field == "type" {
			for _, t := range strings.Split(value, ",") {
				t = strings.ToLower(strings.TrimSpace(t))
				if t != "" {
					types = append(types, t)
				}
			}
		} else {
			filters[field] = value
		}
		return " "
	})

	// Strip standalone "AND"/"OR" connective words left over once their
	// field:value neighbors are removed, then collapse whitespace.
	words := strings.Fields(rest)
	kept := words[:0]
	for _, w := range words {
		up := strings.ToUpper(w)
		if up == "AND" || up == "OR" {
			continue
		}
		kept = append(kept, w)
	}

	return Parsed{
		Filters:  filters,
		Types:    types,
		FreeText: strings.Join(kept, " "),
	}
}

// Includes reports whether entity type t should be searched, given the
// parsed type: restriction (or lack thereof).
func (p Parsed) Includes(t string) bool {
	if len(p.Types) == 0 {
		return true
	}
	for _, want := range p.Types {
		if want == t {
			return true
		}
	}
	return false
}
