package correlation

import (
	"sort"

	"github.com/ShadooowX/rayyan-asm/internal/models"
	"github.com/google/uuid"
)

// AssetStat is per-asset graph metrics: how connected and how risky it is.
type AssetStat struct {
	Asset           Node    `json:"asset"`
	Degree          int     `json:"degree"`           // total edges touching the asset
	ConnectedAssets int     `json:"connected_assets"` // distinct neighbor count
	RelationCount   int     `json:"relation_count"`   // distinct relation_type count
	RiskScore       float64 `json:"risk_score,omitempty"`
	Critical        bool    `json:"critical"`
	Orphan          bool    `json:"orphan"`
}

// GraphStats summarizes the whole org graph.
type GraphStats struct {
	TotalNodes     int         `json:"total_nodes"`
	TotalEdges     int         `json:"total_edges"`
	CriticalAssets []AssetStat `json:"critical_assets"`
	OrphanAssets   []AssetStat `json:"orphan_assets"`
}

// criticalDegreeThreshold — an asset with this many or more connections is
// considered a hub and, combined with risk score, a candidate "critical asset".
const criticalDegreeThreshold = 5

// riskScoreByAsset pulls known risk scores (domain/subdomain/host carry one)
// so the analyzer can flag high-degree + high-risk assets as critical.
func (e *Engine) riskScoreByAsset(orgID uuid.UUID) (map[nodeKey]float64, error) {
	out := make(map[nodeKey]float64)

	var domains []models.Domain
	if err := e.db.Where("org_id = ?", orgID).Find(&domains).Error; err != nil {
		return nil, err
	}
	for _, d := range domains {
		out[nodeKey{"domain", d.ID}] = d.RiskScore
	}

	var subdomains []models.Subdomain
	if err := e.db.Where("org_id = ?", orgID).Find(&subdomains).Error; err != nil {
		return nil, err
	}
	for _, sd := range subdomains {
		out[nodeKey{"subdomain", sd.ID}] = sd.RiskScore
	}

	var hosts []models.Host
	if err := e.db.Where("org_id = ?", orgID).Find(&hosts).Error; err != nil {
		return nil, err
	}
	for _, h := range hosts {
		out[nodeKey{"host", h.ID}] = h.RiskScore
	}

	return out, nil
}

// AssetStats computes degree, connected-asset-count, relation-type-count,
// and risk for every node currently in the org's relationship graph.
func (e *Engine) AssetStats(orgID uuid.UUID) ([]AssetStat, error) {
	var rows []models.AssetRelationship
	if err := e.db.Where("org_id = ?", orgID).Find(&rows).Error; err != nil {
		return nil, err
	}
	risk, err := e.riskScoreByAsset(orgID)
	if err != nil {
		return nil, err
	}

	type agg struct {
		node      Node
		neighbors map[nodeKey]bool
		relTypes  map[string]bool
		degree    int
	}
	stats := make(map[nodeKey]*agg)

	touch := func(self nodeKey, selfNode Node, other nodeKey, rel string) {
		a, ok := stats[self]
		if !ok {
			a = &agg{node: selfNode, neighbors: map[nodeKey]bool{}, relTypes: map[string]bool{}}
			stats[self] = a
		}
		a.degree++
		a.neighbors[other] = true
		a.relTypes[rel] = true
	}

	for _, r := range rows {
		fk := nodeKey{r.FromType, r.FromID}
		tk := nodeKey{r.ToType, r.ToID}
		touch(fk, Node{Type: r.FromType, ID: r.FromID, Label: r.FromLabel}, tk, r.RelationType)
		touch(tk, Node{Type: r.ToType, ID: r.ToID, Label: r.ToLabel}, fk, r.RelationType)
	}

	out := make([]AssetStat, 0, len(stats))
	for k, a := range stats {
		rs := risk[k]
		critical := a.degree >= criticalDegreeThreshold && rs >= 50
		out = append(out, AssetStat{
			Asset:           a.node,
			Degree:          a.degree,
			ConnectedAssets: len(a.neighbors),
			RelationCount:   len(a.relTypes),
			RiskScore:       rs,
			Critical:        critical,
		})
	}

	sort.Slice(out, func(i, j int) bool { return out[i].Degree > out[j].Degree })
	return out, nil
}

// OrphanAssets returns assets that exist in the inventory but have zero
// edges in the relationship graph (i.e. fully isolated / unmapped).
func (e *Engine) OrphanAssets(orgID uuid.UUID) ([]AssetStat, error) {
	var rows []models.AssetRelationship
	if err := e.db.Where("org_id = ?", orgID).Find(&rows).Error; err != nil {
		return nil, err
	}
	connected := make(map[nodeKey]bool, len(rows)*2)
	for _, r := range rows {
		connected[nodeKey{r.FromType, r.FromID}] = true
		connected[nodeKey{r.ToType, r.ToID}] = true
	}

	var out []AssetStat

	var domains []models.Domain
	if err := e.db.Where("org_id = ?", orgID).Find(&domains).Error; err != nil {
		return nil, err
	}
	for _, d := range domains {
		if !connected[nodeKey{"domain", d.ID}] {
			out = append(out, AssetStat{Asset: Node{Type: "domain", ID: d.ID, Label: d.Name}, RiskScore: d.RiskScore, Orphan: true})
		}
	}

	var subdomains []models.Subdomain
	if err := e.db.Where("org_id = ?", orgID).Find(&subdomains).Error; err != nil {
		return nil, err
	}
	for _, sd := range subdomains {
		if !connected[nodeKey{"subdomain", sd.ID}] {
			out = append(out, AssetStat{Asset: Node{Type: "subdomain", ID: sd.ID, Label: sd.FQDN}, RiskScore: sd.RiskScore, Orphan: true})
		}
	}

	var hosts []models.Host
	if err := e.db.Where("org_id = ?", orgID).Find(&hosts).Error; err != nil {
		return nil, err
	}
	for _, h := range hosts {
		if !connected[nodeKey{"host", h.ID}] {
			out = append(out, AssetStat{Asset: Node{Type: "host", ID: h.ID, Label: h.IP}, RiskScore: h.RiskScore, Orphan: true})
		}
	}

	sort.Slice(out, func(i, j int) bool { return out[i].Asset.Label < out[j].Asset.Label })
	return out, nil
}

// CriticalAssets returns high-degree, high-risk hub assets — nodes whose
// compromise or exposure would cascade across many connected assets.
func (e *Engine) CriticalAssets(orgID uuid.UUID) ([]AssetStat, error) {
	all, err := e.AssetStats(orgID)
	if err != nil {
		return nil, err
	}
	var out []AssetStat
	for _, s := range all {
		if s.Critical {
			out = append(out, s)
		}
	}
	return out, nil
}

// Stats returns an org-wide summary: node/edge counts plus critical and
// orphan asset lists, for the executive-facing graph view.
func (e *Engine) Stats(orgID uuid.UUID) (GraphStats, error) {
	all, err := e.AssetStats(orgID)
	if err != nil {
		return GraphStats{}, err
	}
	orphans, err := e.OrphanAssets(orgID)
	if err != nil {
		return GraphStats{}, err
	}
	var edgeCount int64
	if err := e.db.Model(&models.AssetRelationship{}).Where("org_id = ?", orgID).Count(&edgeCount).Error; err != nil {
		return GraphStats{}, err
	}

	var critical []AssetStat
	for _, s := range all {
		if s.Critical {
			critical = append(critical, s)
		}
	}

	return GraphStats{
		TotalNodes:     len(all) + len(orphans),
		TotalEdges:     int(edgeCount),
		CriticalAssets: critical,
		OrphanAssets:   orphans,
	}, nil
}
