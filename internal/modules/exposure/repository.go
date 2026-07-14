package exposure

import (
	"strings"

	"github.com/ShadooowX/rayyan-asm/internal/models"
	"github.com/google/uuid"
	"gorm.io/gorm"
)

// graphContext holds everything pulled from the DB once per org and reused
// across every asset scored, so a recompute does O(1) queries per table
// instead of O(n) per asset.
type graphContext struct {
	hosts      []models.Host
	subdomains []models.Subdomain
	domains    []models.Domain

	findingsByHost map[uuid.UUID][]models.Finding
	findingsBySub  map[uuid.UUID][]models.Finding

	// keyed by (type,id) — counts attack paths the asset appears in
	// anywhere (entry, target, or weakest link)
	attackPathCount map[nodeKey]int

	// asset_relationships adjacency
	relCount  map[nodeKey]int
	neighbors map[nodeKey][]nodeKey
	sensitive map[nodeKey]bool

	techNamesByHost map[uuid.UUID][]string
	techNamesBySub  map[uuid.UUID][]string

	cloudIPs map[string]bool
}

type nodeKey struct {
	Type string
	ID   uuid.UUID
}

func (e *Engine) loadContext(orgID uuid.UUID) (*graphContext, error) {
	ctx := &graphContext{
		findingsByHost:  map[uuid.UUID][]models.Finding{},
		findingsBySub:   map[uuid.UUID][]models.Finding{},
		attackPathCount: map[nodeKey]int{},
		relCount:        map[nodeKey]int{},
		neighbors:       map[nodeKey][]nodeKey{},
		sensitive:       map[nodeKey]bool{},
		techNamesByHost: map[uuid.UUID][]string{},
		techNamesBySub:  map[uuid.UUID][]string{},
		cloudIPs:        map[string]bool{},
	}

	if err := e.db.Where("org_id = ?", orgID).Find(&ctx.hosts).Error; err != nil {
		return nil, err
	}
	if err := e.db.Where("org_id = ?", orgID).Find(&ctx.subdomains).Error; err != nil {
		return nil, err
	}
	if err := e.db.Where("org_id = ?", orgID).Find(&ctx.domains).Error; err != nil {
		return nil, err
	}

	var findings []models.Finding
	if err := e.db.Where("org_id = ? AND status = 'open'", orgID).Find(&findings).Error; err != nil {
		return nil, err
	}
	for _, f := range findings {
		if f.HostID != nil {
			ctx.findingsByHost[*f.HostID] = append(ctx.findingsByHost[*f.HostID], f)
		}
		if f.SubdomainID != nil {
			ctx.findingsBySub[*f.SubdomainID] = append(ctx.findingsBySub[*f.SubdomainID], f)
		}
	}

	for _, h := range ctx.hosts {
		k := nodeKey{"host", h.ID}
		ctx.sensitive[k] = boolFactor(h.RiskFactors, "sensitive_asset") || h.RiskTier == "critical"
	}
	for _, sd := range ctx.subdomains {
		k := nodeKey{"subdomain", sd.ID}
		ctx.sensitive[k] = boolFactor(sd.RiskFactors, "sensitive_asset") || sd.RiskTier == "critical"
	}
	for _, d := range ctx.domains {
		k := nodeKey{"domain", d.ID}
		ctx.sensitive[k] = boolFactor(d.RiskFactors, "sensitive_asset") || d.RiskTier == "critical"
	}

	var paths []models.AttackPath
	if err := e.db.Where("org_id = ?", orgID).Find(&paths).Error; err != nil {
		return nil, err
	}
	for _, p := range paths {
		seen := map[nodeKey]bool{}
		add := func(t string, id uuid.UUID) {
			if id == uuid.Nil {
				return
			}
			k := nodeKey{t, id}
			if seen[k] {
				return
			}
			seen[k] = true
			ctx.attackPathCount[k]++
		}
		add(p.EntryType, p.EntryID)
		add(p.TargetType, p.TargetID)
		add(p.WeakestType, p.WeakestID)
	}

	var rels []models.AssetRelationship
	if err := e.db.Where("org_id = ?", orgID).Find(&rels).Error; err != nil {
		return nil, err
	}
	for _, r := range rels {
		from := nodeKey{r.FromType, r.FromID}
		to := nodeKey{r.ToType, r.ToID}
		ctx.relCount[from]++
		ctx.relCount[to]++
		ctx.neighbors[from] = append(ctx.neighbors[from], to)
		ctx.neighbors[to] = append(ctx.neighbors[to], from)
	}

	var services []models.Service
	if err := e.db.Where("org_id = ?", orgID).Find(&services).Error; err != nil {
		return nil, err
	}
	svcIDs := make([]uuid.UUID, 0, len(services))
	svcByID := make(map[uuid.UUID]models.Service, len(services))
	for _, s := range services {
		svcIDs = append(svcIDs, s.ID)
		svcByID[s.ID] = s
	}

	var techs []models.Technology
	if len(svcIDs) > 0 {
		if err := e.db.Where("org_id = ? AND service_id IN ?", orgID, svcIDs).Find(&techs).Error; err != nil {
			return nil, err
		}
	}
	subByFQDN := make(map[string]uuid.UUID, len(ctx.subdomains))
	for _, sd := range ctx.subdomains {
		subByFQDN[strings.ToLower(sd.FQDN)] = sd.ID
	}
	for _, t := range techs {
		if t.ServiceID == nil {
			continue
		}
		svc, ok := svcByID[*t.ServiceID]
		if !ok {
			continue
		}
		if svc.HostID != uuid.Nil {
			ctx.techNamesByHost[svc.HostID] = append(ctx.techNamesByHost[svc.HostID], t.Name)
		}
		if svc.HostRef != "" {
			if sid, ok := subByFQDN[strings.ToLower(svc.HostRef)]; ok {
				ctx.techNamesBySub[sid] = append(ctx.techNamesBySub[sid], t.Name)
			}
		}
	}

	var cloudAssets []models.CloudAsset
	if err := e.db.Where("org_id = ?", orgID).Find(&cloudAssets).Error; err != nil {
		return nil, err
	}
	for _, ca := range cloudAssets {
		for _, ip := range ca.IPs {
			ctx.cloudIPs[ip] = true
		}
	}

	return ctx, nil
}

// connectedToCritical checks if any 1-hop neighbor of k is itself
// sensitive/critical — an otherwise unremarkable asset's exposure should
// rise if it sits next to something that matters.
func (c *graphContext) connectedToCritical(k nodeKey) bool {
	for _, n := range c.neighbors[k] {
		if c.sensitive[n] {
			return true
		}
	}
	return false
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

func numFactor(factors models.JSONB, key string) int {
	if factors == nil {
		return 0
	}
	v, ok := factors[key]
	if !ok {
		return 0
	}
	switch n := v.(type) {
	case float64:
		return int(n)
	case int:
		return n
	default:
		return 0
	}
}

// listOrgs mirrors the pattern used by riskscore.RecomputeAll.
func listOrgs(db *gorm.DB) ([]models.Organization, error) {
	var orgs []models.Organization
	err := db.Find(&orgs).Error
	return orgs, err
}
