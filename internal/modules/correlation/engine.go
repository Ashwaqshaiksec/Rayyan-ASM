package correlation

import (
	"net"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/ShadooowX/rayyan-asm/internal/models"
	"github.com/google/uuid"
	"go.uber.org/zap"
	"gorm.io/gorm"
)

type Engine struct {
	db  *gorm.DB
	log *zap.SugaredLogger
}

func New(db *gorm.DB, log *zap.SugaredLogger) *Engine {
	return &Engine{db: db, log: log}
}

// Node — one vertex in the correlation graph.
type Node struct {
	Type  string    `json:"type"`
	ID    uuid.UUID `json:"id"`
	Label string    `json:"label"`
}

// Edge — one relationship between two nodes.
type Edge struct {
	From         Node    `json:"from"`
	To           Node    `json:"to"`
	RelationType string  `json:"relation_type"`
	Confidence   float64 `json:"confidence"`
	Evidence     string  `json:"evidence,omitempty"`
}

// Graph is a node/edge subgraph returned by queries.
type Graph struct {
	Nodes []Node `json:"nodes"`
	Edges []Edge `json:"edges"`
}

// Related describes one neighbor of a queried asset.
type Related struct {
	Asset        Node    `json:"asset"`
	RelationType string  `json:"relation_type"`
	Direction    string  `json:"direction"` // parent, child, peer
	Confidence   float64 `json:"confidence"`
}

// PathHop is one node in an exposure-path chain, with the relation that
// connects it to the previous hop (empty for the first node).
type PathHop struct {
	Node         Node   `json:"node"`
	RelationType string `json:"relation_type,omitempty"`
}

// Summary is returned from a recompute run.
type Summary struct {
	OrgID      uuid.UUID `json:"org_id"`
	EdgesBuilt int       `json:"edges_built"`
	DurationMS int64     `json:"duration_ms"`
}

type nodeKey struct {
	Type string
	ID   uuid.UUID
}

// namespace for deterministic synthetic node IDs (ASN, registrant hubs —
// neither has its own row to anchor an ID to).
var nodeNamespace = uuid.MustParse("6f6e9b9e-0a35-4e6c-9d36-9a9a6c9f9b50")

func syntheticID(kind, key string) uuid.UUID {
	return uuid.NewSHA1(nodeNamespace, []byte(kind+":"+strings.ToLower(key)))
}

// RecomputeOrg rebuilds the full correlation graph for one org: existing
// edges are dropped and replaced with a freshly computed set.
func (e *Engine) RecomputeOrg(orgID uuid.UUID) (Summary, error) {
	start := time.Now()
	now := time.Now()

	var domains []models.Domain
	if err := e.db.Where("org_id = ?", orgID).Find(&domains).Error; err != nil {
		return Summary{}, err
	}
	var subdomains []models.Subdomain
	if err := e.db.Where("org_id = ?", orgID).Find(&subdomains).Error; err != nil {
		return Summary{}, err
	}
	var hosts []models.Host
	if err := e.db.Where("org_id = ?", orgID).Find(&hosts).Error; err != nil {
		return Summary{}, err
	}
	var services []models.Service
	if err := e.db.Where("org_id = ?", orgID).Find(&services).Error; err != nil {
		return Summary{}, err
	}
	var certs []models.Certificate
	if err := e.db.Where("org_id = ?", orgID).Find(&certs).Error; err != nil {
		return Summary{}, err
	}
	var technologies []models.Technology
	if err := e.db.Where("org_id = ?", orgID).Find(&technologies).Error; err != nil {
		return Summary{}, err
	}
	var findings []models.Finding
	if err := e.db.Where("org_id = ?", orgID).Find(&findings).Error; err != nil {
		return Summary{}, err
	}
	var asnRanges []models.ASNRange
	if err := e.db.Where("org_id = ?", orgID).Find(&asnRanges).Error; err != nil {
		return Summary{}, err
	}
	var whois []models.WHOISHistory
	if err := e.db.Where("org_id = ?", orgID).Order("snapped_at asc").Find(&whois).Error; err != nil {
		return Summary{}, err
	}

	hostByID := make(map[uuid.UUID]models.Host, len(hosts))
	hostByIP := make(map[string]models.Host, len(hosts))
	for _, h := range hosts {
		hostByID[h.ID] = h
		hostByIP[h.IP] = h
	}
	domainByID := make(map[uuid.UUID]models.Domain, len(domains))
	for _, d := range domains {
		domainByID[d.ID] = d
	}
	subByFQDN := make(map[string]models.Subdomain, len(subdomains))
	for _, sd := range subdomains {
		subByFQDN[strings.ToLower(sd.FQDN)] = sd
	}
	subByID := make(map[uuid.UUID]models.Subdomain, len(subdomains))
	for _, sd := range subdomains {
		subByID[sd.ID] = sd
	}

	type edgeKey struct {
		from, to uuid.UUID
		rel      string
	}
	seen := make(map[edgeKey]bool)
	var edges []models.AssetRelationship

	add := func(fromType string, fromID uuid.UUID, fromLabel, toType string, toID uuid.UUID, toLabel, relation string, confidence float64, evidence string) {
		k := edgeKey{fromID, toID, relation}
		if seen[k] {
			return
		}
		seen[k] = true
		edges = append(edges, models.AssetRelationship{
			ID: uuid.New(), CreatedAt: now, OrgID: orgID,
			FromType: fromType, FromID: fromID, FromLabel: fromLabel,
			ToType: toType, ToID: toID, ToLabel: toLabel,
			RelationType: relation, Confidence: confidence, Evidence: evidence,
			ComputedAt: now,
		})
	}

	for _, sd := range subdomains {
		if d, ok := domainByID[sd.DomainID]; ok {
			add("domain", d.ID, d.Name, "subdomain", sd.ID, sd.FQDN, "parent_child", 1, "")
		}
	}

	for _, sd := range subdomains {
		for _, ip := range sd.IPs {
			if h, ok := hostByIP[ip]; ok {
				add("subdomain", sd.ID, sd.FQDN, "host", h.ID, h.IP, "resolves_to", 1, "")
			}
		}
	}

	for _, s := range services {
		label := serviceLabel(s)
		if s.HostID != uuid.Nil {
			if h, ok := hostByID[s.HostID]; ok {
				add("host", h.ID, h.IP, "service", s.ID, label, "parent_child", 1, "")
				continue
			}
		}
		if s.HostRef == "" {
			continue
		}
		if sd, ok := subByFQDN[strings.ToLower(s.HostRef)]; ok {
			add("subdomain", sd.ID, sd.FQDN, "service", s.ID, label, "parent_child", 1, "")
		} else if h, ok := hostByIP[s.HostRef]; ok {
			add("host", h.ID, h.IP, "service", s.ID, label, "parent_child", 1, "")
		}
	}

	for _, c := range certs {
		if c.ServiceID == nil {
			continue
		}
		for _, s := range services {
			if s.ID == *c.ServiceID {
				add("service", s.ID, serviceLabel(s), "certificate", c.ID, c.Subject, "parent_child", 1, "")
				break
			}
		}
	}

	serviceByID := make(map[uuid.UUID]models.Service, len(services))
	for _, s := range services {
		serviceByID[s.ID] = s
	}
	for _, t := range technologies {
		if t.ServiceID == nil {
			continue
		}
		if s, ok := serviceByID[*t.ServiceID]; ok {
			techLabel := t.Name
			if t.Version != "" {
				techLabel = t.Name + " " + t.Version
			}
			add("service", s.ID, serviceLabel(s), "technology", t.ID, techLabel, "runs", 1, "")
		}
	}

	for _, f := range findings {
		if f.HostID != nil {
			if h, ok := hostByID[*f.HostID]; ok {
				add("finding", f.ID, f.Title, "host", h.ID, h.IP, "related_to", 1, "")
			}
		}
		if f.SubdomainID != nil {
			if sd, ok := subByID[*f.SubdomainID]; ok {
				add("finding", f.ID, f.Title, "subdomain", sd.ID, sd.FQDN, "related_to", 1, "")
			}
		}
	}

	for _, h := range hosts {
		if h.ASN == "" {
			continue
		}
		asnNode := syntheticID("asn", h.ASN)
		label := h.ASN
		if h.ASNOrg != "" {
			label = h.ASN + " (" + h.ASNOrg + ")"
		}
		add("asn", asnNode, label, "host", h.ID, h.IP, "parent_child", 1, "")
	}

	for _, r := range asnRanges {
		if r.CIDR == "" {
			continue
		}
		_, ipnet, err := net.ParseCIDR(r.CIDR)
		if err != nil {
			continue
		}
		for _, h := range hosts {
			ip := net.ParseIP(h.IP)
			if ip != nil && ipnet.Contains(ip) {
				add("asn_range", r.ID, r.ASN+" "+r.CIDR, "host", h.ID, h.IP, "parent_child", 1, "host IP falls within expanded ASN range "+r.CIDR)
			}
		}
	}

	hostsByASN := make(map[string][]models.Host)
	for _, h := range hosts {
		if h.ASN != "" {
			hostsByASN[h.ASN] = append(hostsByASN[h.ASN], h)
		}
	}
	for asn, hs := range hostsByASN {
		if len(hs) < 2 {
			continue
		}
		asnNode := syntheticID("asn", asn)
		for _, h := range hs {
			add("asn", asnNode, asn, "host", h.ID, h.IP, "shared_asn", 0.6, "multiple hosts share ASN "+asn)
		}
	}

	for _, c := range certs {
		if len(c.SubjectAltNames) == 0 {
			continue
		}
		var matched []models.Subdomain
		for _, san := range c.SubjectAltNames {
			for _, sd := range subdomains {
				if wildcardMatch(san, sd.FQDN) {
					matched = append(matched, sd)
				}
			}
		}
		if len(matched) < 2 {
			continue
		}
		for _, sd := range matched {
			add("certificate", c.ID, c.Subject, "subdomain", sd.ID, sd.FQDN, "cert_san_match", 0.7, "subdomain covered by certificate SAN")
		}
	}

	latestRegistrant := make(map[string]string)
	for _, w := range whois {
		if w.Registrant != "" {
			latestRegistrant[strings.ToLower(w.Domain)] = w.Registrant
		}
	}
	domainsByRegistrant := make(map[string][]models.Domain)
	for _, d := range domains {
		if reg, ok := latestRegistrant[strings.ToLower(d.Name)]; ok {
			domainsByRegistrant[reg] = append(domainsByRegistrant[reg], d)
		}
	}
	for reg, ds := range domainsByRegistrant {
		if len(ds) < 2 {
			continue
		}
		regNode := syntheticID("registrant", reg)
		for _, d := range ds {
			add("registrant", regNode, reg, "domain", d.ID, d.Name, "shared_registrant", 0.6, "domains share WHOIS registrant "+reg)
		}
	}

	if err := e.db.Where("org_id = ?", orgID).Delete(&models.AssetRelationship{}).Error; err != nil {
		return Summary{}, err
	}
	if len(edges) > 0 {
		if err := e.db.CreateInBatches(&edges, 200).Error; err != nil {
			return Summary{}, err
		}
	}

	return Summary{OrgID: orgID, EdgesBuilt: len(edges), DurationMS: time.Since(start).Milliseconds()}, nil
}

// Graph returns a subgraph centered on a focus asset out to depth hops, or
// the org's whole stored graph when no focus asset is given.
func (e *Engine) Graph(orgID uuid.UUID, focusType string, focusID uuid.UUID, depth int) (Graph, error) {
	var rows []models.AssetRelationship
	if err := e.db.Where("org_id = ?", orgID).Find(&rows).Error; err != nil {
		return Graph{}, err
	}
	if focusType == "" || focusID == uuid.Nil {
		return graphFromRows(rows), nil
	}
	if depth <= 0 {
		depth = 2
	}

	adj := buildAdjacency(rows)
	start := nodeKey{focusType, focusID}
	visited := map[nodeKey]bool{start: true}
	frontier := []nodeKey{start}
	keepEdge := make(map[int]bool)

	for d := 0; d < depth && len(frontier) > 0; d++ {
		var next []nodeKey
		for _, nk := range frontier {
			for _, h := range adj[nk] {
				keepEdge[h.edgeIdx] = true
				if !visited[h.to] {
					visited[h.to] = true
					next = append(next, h.to)
				}
			}
		}
		frontier = next
	}

	sub := make([]models.AssetRelationship, 0, len(keepEdge))
	for i, r := range rows {
		if keepEdge[i] {
			sub = append(sub, r)
		}
	}
	return graphFromRows(sub), nil
}

// Related returns the immediate neighbors of one asset.
func (e *Engine) Related(orgID uuid.UUID, assetType string, assetID uuid.UUID) ([]Related, error) {
	var rows []models.AssetRelationship
	if err := e.db.Where(
		"org_id = ? AND ((from_type = ? AND from_id = ?) OR (to_type = ? AND to_id = ?))",
		orgID, assetType, assetID, assetType, assetID,
	).Find(&rows).Error; err != nil {
		return nil, err
	}

	out := make([]Related, 0, len(rows))
	for _, r := range rows {
		isStructural := r.RelationType == "parent_child" || r.RelationType == "resolves_to"
		if r.FromType == assetType && r.FromID == assetID {
			direction := "child"
			if !isStructural {
				direction = "peer"
			}
			out = append(out, Related{Asset: Node{Type: r.ToType, ID: r.ToID, Label: r.ToLabel}, RelationType: r.RelationType, Direction: direction, Confidence: r.Confidence})
		} else {
			direction := "parent"
			if !isStructural {
				direction = "peer"
			}
			out = append(out, Related{Asset: Node{Type: r.FromType, ID: r.FromID, Label: r.FromLabel}, RelationType: r.RelationType, Direction: direction, Confidence: r.Confidence})
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Asset.Label < out[j].Asset.Label })
	return out, nil
}

// ExposurePath finds the shortest chain of relationships connecting two
// assets, treating edges as undirected, via breadth-first search. Returns
// nil with no error if no path exists.
func (e *Engine) ExposurePath(orgID uuid.UUID, fromType string, fromID uuid.UUID, toType string, toID uuid.UUID) ([]PathHop, error) {
	var rows []models.AssetRelationship
	if err := e.db.Where("org_id = ?", orgID).Find(&rows).Error; err != nil {
		return nil, err
	}

	nodeLabels := make(map[nodeKey]string, len(rows)*2)
	for _, r := range rows {
		nodeLabels[nodeKey{r.FromType, r.FromID}] = r.FromLabel
		nodeLabels[nodeKey{r.ToType, r.ToID}] = r.ToLabel
	}
	toNode := func(nk nodeKey) Node { return Node{Type: nk.Type, ID: nk.ID, Label: nodeLabels[nk]} }

	start := nodeKey{fromType, fromID}
	goal := nodeKey{toType, toID}
	if start == goal {
		return []PathHop{{Node: toNode(start)}}, nil
	}

	adj := buildAdjacency(rows)
	type queued struct {
		node nodeKey
		path []PathHop
	}
	visited := map[nodeKey]bool{start: true}
	queue := []queued{{node: start, path: []PathHop{{Node: toNode(start)}}}}

	for len(queue) > 0 {
		cur := queue[0]
		queue = queue[1:]
		for _, h := range adj[cur.node] {
			if visited[h.to] {
				continue
			}
			path := append(append([]PathHop{}, cur.path...), PathHop{Node: toNode(h.to), RelationType: rows[h.edgeIdx].RelationType})
			if h.to == goal {
				return path, nil
			}
			visited[h.to] = true
			queue = append(queue, queued{node: h.to, path: path})
		}
	}
	return nil, nil
}

type hop struct {
	to      nodeKey
	edgeIdx int
}

func buildAdjacency(rows []models.AssetRelationship) map[nodeKey][]hop {
	adj := make(map[nodeKey][]hop, len(rows)*2)
	for i, r := range rows {
		from := nodeKey{r.FromType, r.FromID}
		to := nodeKey{r.ToType, r.ToID}
		adj[from] = append(adj[from], hop{to: to, edgeIdx: i})
		adj[to] = append(adj[to], hop{to: from, edgeIdx: i})
	}
	return adj
}

func graphFromRows(rows []models.AssetRelationship) Graph {
	nodesSeen := make(map[nodeKey]Node, len(rows)*2)
	for _, r := range rows {
		nodesSeen[nodeKey{r.FromType, r.FromID}] = Node{Type: r.FromType, ID: r.FromID, Label: r.FromLabel}
		nodesSeen[nodeKey{r.ToType, r.ToID}] = Node{Type: r.ToType, ID: r.ToID, Label: r.ToLabel}
	}
	nodes := make([]Node, 0, len(nodesSeen))
	for _, n := range nodesSeen {
		nodes = append(nodes, n)
	}
	sort.Slice(nodes, func(i, j int) bool {
		if nodes[i].Type != nodes[j].Type {
			return nodes[i].Type < nodes[j].Type
		}
		return nodes[i].Label < nodes[j].Label
	})

	edges := make([]Edge, 0, len(rows))
	for _, r := range rows {
		edges = append(edges, Edge{
			From:         Node{Type: r.FromType, ID: r.FromID, Label: r.FromLabel},
			To:           Node{Type: r.ToType, ID: r.ToID, Label: r.ToLabel},
			RelationType: r.RelationType,
			Confidence:   r.Confidence,
			Evidence:     r.Evidence,
		})
	}
	return Graph{Nodes: nodes, Edges: edges}
}

func serviceLabel(s models.Service) string {
	proto := s.Protocol
	if proto == "" {
		proto = "tcp"
	}
	return strconv.Itoa(s.Port) + "/" + proto
}

// wildcardMatch reports whether a certificate SAN entry covers host, with
// single-level wildcard support ("*.example.com" matches "foo.example.com"
// but not "example.com" or "a.foo.example.com").
func wildcardMatch(san, host string) bool {
	san = strings.ToLower(strings.TrimSpace(san))
	host = strings.ToLower(strings.TrimSpace(host))
	if san == host {
		return true
	}
	if !strings.HasPrefix(san, "*.") {
		return false
	}
	suffix := san[1:]
	if !strings.HasSuffix(host, suffix) {
		return false
	}
	return strings.Count(host, ".") == strings.Count(san, ".")
}
