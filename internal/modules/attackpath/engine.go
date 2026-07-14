package attackpath

import (
	"container/heap"
	"math"
	"net"
	"sort"
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

// Summary — result of a recompute run.
type Summary struct {
	OrgID      uuid.UUID `json:"org_id"`
	PathsFound int       `json:"paths_found"`
	DurationMS int64     `json:"duration_ms"`
}

type nodeKey struct {
	Type string
	ID   uuid.UUID
}

type nodeInfo struct {
	label           string
	riskScore       float64
	internetExposed bool
	sensitiveAsset  bool
}

// Hop — one step in a ranked attack path.
type Hop struct {
	Type         string    `json:"type"`
	ID           uuid.UUID `json:"id"`
	Label        string    `json:"label"`
	RelationType string    `json:"relation_type,omitempty"`
	RiskScore    float64   `json:"risk_score"`
}

var severityRank = map[string]int{
	"critical": 4, "high": 3, "medium": 2, "low": 1, "info": 0,
}

// RecomputeOrg drops and rebuilds attack_paths for one org.
// Entry nodes: hosts/subdomains with internet_exposed=true in risk_factors,
// or a public IP when risk scoring hasn't run yet.
// Target nodes: assets with sensitive_asset=true or risk_tier critical/high.
// Path selection: max-min Dijkstra — picks the path that maximises the
// minimum per-hop risk score, so the weakest link is as strong as possible.
func (e *Engine) RecomputeOrg(orgID uuid.UUID) (Summary, error) {
	start := time.Now()

	rows, nodes, err := e.loadGraph(orgID)
	if err != nil {
		return Summary{}, err
	}

	adj := buildAdjacency(rows)

	svcByHost, svcBySub, err := e.loadServiceIndex(orgID)
	if err != nil {
		return Summary{}, err
	}
	findByHost, findBySub, err := e.loadFindingIndex(orgID)
	if err != nil {
		return Summary{}, err
	}

	var entries, targets []nodeKey
	for nk, info := range nodes {
		if nk.Type != "subdomain" && nk.Type != "host" {
			continue
		}
		if info.internetExposed || (nk.Type == "host" && isPublicIP(info.label)) {
			entries = append(entries, nk)
		}
		if info.sensitiveAsset {
			targets = append(targets, nk)
		}
	}

	now := time.Now()
	var paths []models.AttackPath

	for _, entry := range entries {
		for _, target := range targets {
			if entry == target {
				continue
			}
			hops := maxMinRiskPath(adj, rows, nodes, entry, target)
			if len(hops) == 0 {
				continue
			}

			weakest := hops[0]
			for _, h := range hops {
				if h.RiskScore < weakest.RiskScore {
					weakest = h
				}
			}

			chokeSvcID, findSev := bestFinding(hops, svcByHost, svcBySub, findByHost, findBySub)

			hopRows := make([]map[string]interface{}, 0, len(hops))
			for _, h := range hops {
				hopRows = append(hopRows, map[string]interface{}{
					"type":          h.Type,
					"id":            h.ID.String(),
					"label":         h.Label,
					"relation_type": h.RelationType,
					"risk_score":    h.RiskScore,
				})
			}

			ap := models.AttackPath{
				ID:           uuid.New(),
				CreatedAt:    now,
				OrgID:        orgID,
				EntryType:    entry.Type,
				EntryID:      entry.ID,
				EntryLabel:   nodes[entry].label,
				TargetType:   target.Type,
				TargetID:     target.ID,
				TargetLabel:  nodes[target].label,
				WeakestScore: weakest.RiskScore,
				WeakestType:  weakest.Type,
				WeakestID:    weakest.ID,
				WeakestLabel: weakest.Label,
				HopCount:     len(hops),
				Hops:         models.JSONB{"hops": hopRows},
				FindingSev:   findSev,
				ComputedAt:   now,
			}
			if chokeSvcID != uuid.Nil {
				ap.ChokepointSvc = &chokeSvcID
			}
			paths = append(paths, ap)
		}
	}

	sort.Slice(paths, func(i, j int) bool {
		return paths[i].WeakestScore > paths[j].WeakestScore
	})

	if err := e.db.Where("org_id = ?", orgID).Delete(&models.AttackPath{}).Error; err != nil {
		return Summary{}, err
	}
	if len(paths) > 0 {
		if err := e.db.CreateInBatches(&paths, 200).Error; err != nil {
			return Summary{}, err
		}
	}

	return Summary{
		OrgID:      orgID,
		PathsFound: len(paths),
		DurationMS: time.Since(start).Milliseconds(),
	}, nil
}

// List GET /attack-paths — ranked by weakest_score desc.
func (e *Engine) List(orgID uuid.UUID, limit int) ([]models.AttackPath, error) {
	q := e.db.Where("org_id = ?", orgID).Order("weakest_score desc")
	if limit > 0 {
		q = q.Limit(limit)
	}
	var out []models.AttackPath
	return out, q.Find(&out).Error
}

func (e *Engine) loadGraph(orgID uuid.UUID) ([]models.AssetRelationship, map[nodeKey]nodeInfo, error) {
	var rows []models.AssetRelationship
	if err := e.db.Where("org_id = ?", orgID).Find(&rows).Error; err != nil {
		return nil, nil, err
	}

	nodes := make(map[nodeKey]nodeInfo, len(rows)*2)
	for _, r := range rows {
		nodes[nodeKey{r.FromType, r.FromID}] = nodeInfo{label: r.FromLabel}
		nodes[nodeKey{r.ToType, r.ToID}] = nodeInfo{label: r.ToLabel}
	}

	if err := e.attachAssetInfo(orgID, nodes); err != nil {
		return nil, nil, err
	}
	return rows, nodes, nil
}

func (e *Engine) attachAssetInfo(orgID uuid.UUID, nodes map[nodeKey]nodeInfo) error {
	var hosts []models.Host
	if err := e.db.Where("org_id = ?", orgID).Find(&hosts).Error; err != nil {
		return err
	}
	for _, h := range hosts {
		k := nodeKey{"host", h.ID}
		if _, ok := nodes[k]; !ok {
			continue
		}
		nodes[k] = nodeInfo{
			label:           h.IP,
			riskScore:       h.RiskScore,
			internetExposed: boolFactor(h.RiskFactors, "internet_exposed"),
			sensitiveAsset:  boolFactor(h.RiskFactors, "sensitive_asset") || h.RiskTier == "critical" || h.RiskTier == "high",
		}
	}

	var subs []models.Subdomain
	if err := e.db.Where("org_id = ?", orgID).Find(&subs).Error; err != nil {
		return err
	}
	for _, sd := range subs {
		k := nodeKey{"subdomain", sd.ID}
		if _, ok := nodes[k]; !ok {
			continue
		}
		nodes[k] = nodeInfo{
			label:           sd.FQDN,
			riskScore:       sd.RiskScore,
			internetExposed: boolFactor(sd.RiskFactors, "internet_exposed"),
			sensitiveAsset:  boolFactor(sd.RiskFactors, "sensitive_asset") || sd.RiskTier == "critical" || sd.RiskTier == "high",
		}
	}

	var domains []models.Domain
	if err := e.db.Where("org_id = ?", orgID).Find(&domains).Error; err != nil {
		return err
	}
	for _, d := range domains {
		k := nodeKey{"domain", d.ID}
		if _, ok := nodes[k]; !ok {
			continue
		}
		nodes[k] = nodeInfo{
			label:          d.Name,
			riskScore:      d.RiskScore,
			sensitiveAsset: boolFactor(d.RiskFactors, "sensitive_asset") || d.RiskTier == "critical" || d.RiskTier == "high",
		}
	}

	return nil
}

func (e *Engine) loadServiceIndex(orgID uuid.UUID) (map[uuid.UUID][]models.Service, map[uuid.UUID][]models.Service, error) {
	var svcs []models.Service
	if err := e.db.Where("org_id = ?", orgID).Find(&svcs).Error; err != nil {
		return nil, nil, err
	}
	byHost := make(map[uuid.UUID][]models.Service)
	bySub := make(map[uuid.UUID][]models.Service)
	for _, s := range svcs {
		if s.HostID != uuid.Nil {
			byHost[s.HostID] = append(byHost[s.HostID], s)
		}
	}
	return byHost, bySub, nil
}

func (e *Engine) loadFindingIndex(orgID uuid.UUID) (map[uuid.UUID][]models.Finding, map[uuid.UUID][]models.Finding, error) {
	var findings []models.Finding
	if err := e.db.Where("org_id = ? AND status = 'open'", orgID).Find(&findings).Error; err != nil {
		return nil, nil, err
	}
	byHost := make(map[uuid.UUID][]models.Finding)
	bySub := make(map[uuid.UUID][]models.Finding)
	for _, f := range findings {
		if f.HostID != nil {
			byHost[*f.HostID] = append(byHost[*f.HostID], f)
		}
		if f.SubdomainID != nil {
			bySub[*f.SubdomainID] = append(bySub[*f.SubdomainID], f)
		}
	}
	return byHost, bySub, nil
}

type pathState struct {
	node     nodeKey
	minScore float64
	path     []Hop
}

type maxHeap []*pathState

func (h maxHeap) Len() int            { return len(h) }
func (h maxHeap) Less(i, j int) bool  { return h[i].minScore > h[j].minScore }
func (h maxHeap) Swap(i, j int)       { h[i], h[j] = h[j], h[i] }
func (h *maxHeap) Push(x interface{}) { *h = append(*h, x.(*pathState)) }
func (h *maxHeap) Pop() interface{} {
	old := *h
	n := len(old)
	x := old[n-1]
	old[n-1] = nil
	*h = old[:n-1]
	return x
}

func maxMinRiskPath(
	adj map[nodeKey][]int,
	rows []models.AssetRelationship,
	nodes map[nodeKey]nodeInfo,
	start, goal nodeKey,
) []Hop {
	best := make(map[nodeKey]float64, len(nodes))
	for k := range nodes {
		best[k] = -1
	}
	best[start] = nodes[start].riskScore

	pq := &maxHeap{}
	heap.Push(pq, &pathState{
		node:     start,
		minScore: nodes[start].riskScore,
		path: []Hop{{
			Type:      start.Type,
			ID:        start.ID,
			Label:     nodes[start].label,
			RiskScore: nodes[start].riskScore,
		}},
	})

	for pq.Len() > 0 {
		cur := heap.Pop(pq).(*pathState)

		if cur.node == goal {
			return cur.path
		}
		if cur.minScore < best[cur.node] {
			continue
		}

		for _, edgeIdx := range adj[cur.node] {
			r := rows[edgeIdx]
			from := nodeKey{r.FromType, r.FromID}
			to := nodeKey{r.ToType, r.ToID}
			var neighbor nodeKey
			if from == cur.node {
				neighbor = to
			} else {
				neighbor = from
			}

			neighborScore := nodes[neighbor].riskScore
			newMin := math.Min(cur.minScore, neighborScore)
			if newMin <= best[neighbor] {
				continue
			}
			best[neighbor] = newMin

			newPath := make([]Hop, len(cur.path)+1)
			copy(newPath, cur.path)
			newPath[len(cur.path)] = Hop{
				Type:         neighbor.Type,
				ID:           neighbor.ID,
				Label:        nodes[neighbor].label,
				RelationType: r.RelationType,
				RiskScore:    neighborScore,
			}
			heap.Push(pq, &pathState{
				node:     neighbor,
				minScore: newMin,
				path:     newPath,
			})
		}
	}
	return nil
}

func bestFinding(
	hops []Hop,
	svcByHost map[uuid.UUID][]models.Service,
	svcBySub map[uuid.UUID][]models.Service,
	findByHost map[uuid.UUID][]models.Finding,
	findBySub map[uuid.UUID][]models.Finding,
) (uuid.UUID, string) {
	worstRank := -1
	worstSev := ""
	chokeSvcID := uuid.Nil

	for _, h := range hops {
		var findings []models.Finding
		var svcs []models.Service
		switch h.Type {
		case "host":
			findings = findByHost[h.ID]
			svcs = svcByHost[h.ID]
		case "subdomain":
			findings = findBySub[h.ID]
			svcs = svcBySub[h.ID]
		}
		for _, f := range findings {
			if rank := severityRank[f.Severity]; rank > worstRank {
				worstRank = rank
				worstSev = f.Severity
				if len(svcs) > 0 {
					chokeSvcID = svcs[0].ID
				}
			}
		}
	}
	return chokeSvcID, worstSev
}

func buildAdjacency(rows []models.AssetRelationship) map[nodeKey][]int {
	adj := make(map[nodeKey][]int, len(rows)*2)
	for i, r := range rows {
		from := nodeKey{r.FromType, r.FromID}
		to := nodeKey{r.ToType, r.ToID}
		adj[from] = append(adj[from], i)
		adj[to] = append(adj[to], i)
	}
	return adj
}

func boolFactor(factors models.JSONB, key string) bool {
	if factors == nil {
		return false
	}
	v, ok := factors[key]
	if !ok {
		return false
	}
	b, ok := v.(bool)
	return ok && b
}

func isPublicIP(ipStr string) bool {
	ip := net.ParseIP(strings.TrimSpace(ipStr))
	if ip == nil {
		return false
	}
	for _, block := range privateBlocks {
		if block.Contains(ip) {
			return false
		}
	}
	return !ip.IsLoopback() && !ip.IsLinkLocalUnicast() && !ip.IsLinkLocalMulticast()
}

var privateBlocks = func() []*net.IPNet {
	var blocks []*net.IPNet
	for _, cidr := range []string{"10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16", "fc00::/7", "::1/128"} {
		_, block, _ := net.ParseCIDR(cidr)
		blocks = append(blocks, block)
	}
	return blocks
}()
