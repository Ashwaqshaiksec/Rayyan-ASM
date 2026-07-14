// Package whois performs RDAP-based domain WHOIS lookups. Extracted from
// internal/api/handlers/admin_ops.go so internal/modules (the scan
// dispatcher) can use the exact same lookup that the manual
// AdminOpsHandler.SnapWHOIS endpoint uses, instead of duplicating ~130
// lines of RDAP-parsing logic. handlers already imports modules, so
// modules importing handlers back would be a circular import — this
// neutral package is importable from both.
package whois

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"
)

// bootstrapURL returns the RDAP server base URL for a domain's TLD. Common
// TLDs are hardcoded to skip a bootstrap round-trip; unknown TLDs fall back
// to the IANA bootstrap registry.
func bootstrapURL(domain string) string {
	parts := strings.Split(strings.ToLower(domain), ".")
	if len(parts) < 2 {
		return "https://rdap.verisign.com/com/v1"
	}
	tld := parts[len(parts)-1]
	known := map[string]string{
		"com":  "https://rdap.verisign.com/com/v1",
		"net":  "https://rdap.verisign.com/net/v1",
		"org":  "https://rdap.publicinterestregistry.org/rdap",
		"io":   "https://rdap.nic.io",
		"co":   "https://rdap.nic.co",
		"uk":   "https://rdap.nominet.uk",
		"de":   "https://rdap.denic.de",
		"fr":   "https://rdap.nic.fr",
		"nl":   "https://rdap.sidn.nl",
		"au":   "https://rdap.auda.org.au",
		"ca":   "https://rdap.cira.ca",
		"jp":   "https://rdap.jprs.jp",
		"br":   "https://rdap.registro.br",
		"in":   "https://rdap.registry.in",
		"eu":   "https://rdap.eu",
		"info": "https://rdap.afilias.info/rdap/info",
		"biz":  "https://rdap.nic.biz",
		"app":  "https://rdap.nic.google",
		"dev":  "https://rdap.nic.google",
		"xyz":  "https://rdap.nic.xyz",
		"ai":   "https://rdap.nic.ai",
		"me":   "https://rdap.nic.me",
	}
	if base, ok := known[tld]; ok {
		return base
	}

	// Fall back to IANA bootstrap registry for unknown TLDs
	client := &http.Client{Timeout: 5 * time.Second}
	resp, err := client.Get("https://data.iana.org/rdap/dns.json")
	if err != nil {
		return "https://rdap.verisign.com/com/v1"
	}
	defer func() { _ = resp.Body.Close() }()
	var bootstrap struct {
		Services [][][]string `json:"services"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&bootstrap); err != nil {
		return "https://rdap.verisign.com/com/v1"
	}
	for _, svc := range bootstrap.Services {
		if len(svc) < 2 {
			continue
		}
		for _, t := range svc[0] {
			if strings.EqualFold(t, tld) && len(svc[1]) > 0 {
				return strings.TrimRight(svc[1][0], "/")
			}
		}
	}
	return "https://rdap.verisign.com/com/v1"
}

// FetchData performs an RDAP lookup for domain and returns a flat map of
// fields: raw, tld, nameservers, registration_date, expiry_date,
// updated_date, registrar, registrar_iana_id. Any of these may be absent if
// the RDAP response didn't include them or the lookup failed (in which
// case only "raw" is set, describing the failure).
func FetchData(domain string) map[string]string {
	return fetchData(bootstrapURL(domain), domain)
}

// fetchData is FetchData's implementation, parameterized on the RDAP base
// URL so tests can point it at an httptest.Server instead of a real RDAP
// host, without needing a mutable package-level var.
func fetchData(base, domain string) map[string]string {
	result := map[string]string{}
	url := fmt.Sprintf("%s/domain/%s", base, domain)

	client := &http.Client{Timeout: 10 * time.Second}
	resp, err := client.Get(url)
	if err != nil {
		result["raw"] = "RDAP lookup failed: " + err.Error()
		return result
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode == 404 {
		result["raw"] = "domain not found in RDAP"
		return result
	}

	var rdap struct {
		LDHName     string `json:"ldhName"`
		Nameservers []struct {
			LDHName string `json:"ldhName"`
		} `json:"nameservers"`
		Events []struct {
			EventAction string `json:"eventAction"`
			EventDate   string `json:"eventDate"`
		} `json:"events"`
		Entities []struct {
			Roles     []string        `json:"roles"`
			VCard     [][]interface{} `json:"vcardArray"`
			PublicIDs []struct {
				Type       string `json:"type"`
				Identifier string `json:"identifier"`
			} `json:"publicIds"`
		} `json:"entities"`
	}
	body, _ := io.ReadAll(resp.Body)
	_ = json.Unmarshal(body, &rdap)
	result["raw"] = string(body)
	result["tld"] = func() string {
		p := strings.Split(domain, ".")
		if len(p) > 0 {
			return p[len(p)-1]
		}
		return ""
	}()

	var nsList []string
	for _, ns := range rdap.Nameservers {
		nsList = append(nsList, ns.LDHName)
	}
	if len(nsList) > 0 {
		result["nameservers"] = strings.Join(nsList, ",")
	}

	for _, ev := range rdap.Events {
		switch ev.EventAction {
		case "registration":
			result["registration_date"] = ev.EventDate
		case "expiration":
			result["expiry_date"] = ev.EventDate
		case "last changed":
			result["updated_date"] = ev.EventDate
		}
	}
	for _, ent := range rdap.Entities {
		for _, role := range ent.Roles {
			if role == "registrar" {
				// vcardArray's real shape is ["vcard", [prop1, prop2, ...]]
				// — VCard[0] is the literal string "vcard" (which fails to
				// unmarshal into []interface{} above, leaving VCard[0] as
				// an empty slice — harmless, we never read index 0) and
				// VCard[1] is the actual array of properties. Each
				// property is itself typically [name, params, type,
				// value, ...], e.g. ["fn", {}, "text", "Example Registrar"].
				if len(ent.VCard) > 1 {
					for _, propRaw := range ent.VCard[1] {
						prop, ok := propRaw.([]interface{})
						if !ok || len(prop) < 4 {
							continue
						}
						if name, ok := prop[0].(string); ok && name == "fn" {
							if val, ok := prop[3].(string); ok {
								result["registrar"] = val
							}
						}
					}
				}
				for _, pid := range ent.PublicIDs {
					if pid.Type == "IANA Registrar ID" {
						result["registrar_iana_id"] = pid.Identifier
					}
				}
			}
		}
	}
	return result
}
