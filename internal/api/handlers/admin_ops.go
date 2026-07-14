package handlers

import (
	"archive/zip"
	"bytes"
	"encoding/csv"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/ShadooowX/rayyan-asm/internal/api/middleware"
	"github.com/ShadooowX/rayyan-asm/internal/models"
	"github.com/ShadooowX/rayyan-asm/internal/whois"
	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
	"go.uber.org/zap"
	"gorm.io/gorm"
)

type AdminOpsHandler struct {
	db  *gorm.DB
	log *zap.SugaredLogger
}

func NewAdminOpsHandler(db *gorm.DB, log *zap.SugaredLogger) *AdminOpsHandler {
	return &AdminOpsHandler{db: db, log: log}
}

// ListASNRanges GET /asn-ranges?asn=AS1234&page=1&per_page=50
func (h *AdminOpsHandler) ListASNRanges(c *gin.Context) {
	user := middleware.GetUser(c)
	if user == nil {
		c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{"error": "unauthorized"})
		return
	}
	asn := c.Query("asn")
	page, _ := strconv.Atoi(c.DefaultQuery("page", "1"))
	perPage, _ := strconv.Atoi(c.DefaultQuery("per_page", "50"))
	if page < 1 {
		page = 1
	}
	if perPage < 1 || perPage > 500 {
		perPage = 50
	}
	offset := (page - 1) * perPage

	q := h.db.Model(&models.ASNRange{}).Where("org_id = ?", user.OrgID)
	if asn != "" {
		q = q.Where("asn = ?", asn)
	}
	var total int64
	if err := q.Count(&total).Error; err != nil {
		c.JSON(500, gin.H{"error": err.Error()})
		return
	}
	var ranges []models.ASNRange
	if err := q.Order("asn, cidr").Offset(offset).Limit(perPage).Find(&ranges).Error; err != nil {
		c.JSON(500, gin.H{"error": err.Error()})
		return
	}
	c.JSON(200, gin.H{
		"data":     ranges,
		"total":    total,
		"page":     page,
		"per_page": perPage,
		"pages":    (int(total) + perPage - 1) / perPage,
	})
}

// ExpandASN POST /asn-ranges/expand — query BGP data for an ASN and store CIDRs
func (h *AdminOpsHandler) ExpandASN(c *gin.Context) {
	user := middleware.GetUser(c)
	if user == nil {
		c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{"error": "unauthorized"})
		return
	}
	var req struct {
		ASN string `json:"asn" binding:"required"`
	}
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(400, gin.H{"error": err.Error()})
		return
	}

	// Normalize ASN
	asn := strings.ToUpper(strings.TrimSpace(req.ASN))
	if !strings.HasPrefix(asn, "AS") {
		asn = "AS" + asn
	}
	asnNum := strings.TrimPrefix(asn, "AS")

	var (
		cidrs        []string
		asnOrg       string
		country      string
		usedFallback bool
		primaryErr   error
	)

	// RIPEstat's announced-prefixes API is purpose-built for exactly this
	// query (per-ASN, small payload, no auth/User-Agent requirements) and
	// aggregates global BGP data across all RIR regions, so it's used as
	// the primary source.
	cidrs, asnOrg, primaryErr = ripestatASNLookup(asnNum)
	if primaryErr == nil {
		country = ripestatASNCountry(asnNum)
	}

	// Fall back to bgp.tools' full table dump if RIPEstat was unreachable
	// or returned nothing. bgp.tools has no server-side per-ASN filter, so
	// the whole table has to be downloaded and filtered client-side, and
	// their API policy requires an identifying User-Agent or requests may
	// be blocked outright — both are handled below.
	if primaryErr != nil || len(cidrs) == 0 {
		fbCidrs, fbErr := bgpToolsASNLookup(asnNum)
		if fbErr != nil {
			if len(cidrs) == 0 {
				detail := fbErr.Error()
				if primaryErr != nil {
					detail = "ripestat: " + primaryErr.Error() + "; bgp.tools: " + detail
				}
				c.JSON(502, gin.H{"error": "could not retrieve announced prefixes for ASN", "details": detail})
				return
			}
			// RIPEstat already gave us something; bgp.tools failing on top
			// of that isn't fatal.
		} else {
			cidrs = fbCidrs
			usedFallback = true
		}
	}

	h.storeASNRanges(user.OrgID, asn, asnOrg, cidrs)
	c.JSON(200, gin.H{
		"asn": asn, "asn_org": asnOrg, "country": country,
		"cidrs": cidrs, "count": len(cidrs), "used_fallback": usedFallback,
	})
}

// bgpToolsASNLookup downloads bgp.tools' full global routing table dump and
// returns only the CIDRs originated by the given ASN. bgp.tools does not
// support a server-side per-ASN filter (there is no "origin" query param on
// table.jsonl — the whole table is always returned), so filtering has to
// happen client-side against the numeric "ASN" field of each entry.
//
// Per bgp.tools' API policy, requests must carry an identifying User-Agent;
// requests with a default/generic one (e.g. Go's own "Go-http-client/1.1")
// may be silently blocked.
func bgpToolsASNLookup(asnNum string) ([]string, error) {
	target, err := strconv.ParseInt(asnNum, 10, 64)
	if err != nil {
		return nil, fmt.Errorf("invalid ASN number %q: %w", asnNum, err)
	}

	client := &http.Client{Timeout: 60 * time.Second}
	req, err := http.NewRequest(http.MethodGet, "https://bgp.tools/table.jsonl", nil)
	if err != nil {
		return nil, fmt.Errorf("building bgp.tools request failed: %w", err)
	}
	req.Header.Set("User-Agent", "rayyan-asm bgp.tools client - github.com/ShadooowX/rayyan-asm")

	resp, err := client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("bgp.tools request failed: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("bgp.tools returned HTTP %d", resp.StatusCode)
	}

	type bgpEntry struct {
		CIDR string `json:"CIDR"`
		ASN  int64  `json:"ASN"`
	}

	var cidrs []string
	decoder := json.NewDecoder(resp.Body)
	for {
		var entry bgpEntry
		if err := decoder.Decode(&entry); err == io.EOF {
			break
		} else if err != nil {
			break
		}
		if entry.CIDR != "" && entry.ASN == target {
			cidrs = append(cidrs, entry.CIDR)
		}
	}

	if len(cidrs) == 0 {
		return nil, fmt.Errorf("no announced prefixes found for AS%s in bgp.tools table", asnNum)
	}
	return cidrs, nil
}

// ripestatASNCountry does a best-effort lookup of the primary country code
// associated with an ASN's announced address space via RIPEstat's geoloc
// dataset. Not fatal if it fails or comes back empty — country is a
// supplementary display field, not something CIDR discovery depends on.
func ripestatASNCountry(asnNum string) string {
	client := &http.Client{Timeout: 15 * time.Second}
	url := fmt.Sprintf("https://stat.ripe.net/data/geoloc/data.json?resource=AS%s", asnNum)
	resp, err := client.Get(url)
	if err != nil {
		return ""
	}
	defer func() { _ = resp.Body.Close() }()

	var result struct {
		Data struct {
			Locations []struct {
				Country string `json:"country"`
			} `json:"locations"`
		} `json:"data"`
	}
	if json.NewDecoder(resp.Body).Decode(&result) != nil {
		return ""
	}
	if len(result.Data.Locations) > 0 {
		return result.Data.Locations[0].Country
	}
	return ""
}

func (h *AdminOpsHandler) storeASNRanges(orgID uuid.UUID, asn, asnOrg string, cidrs []string) {
	for _, cidr := range cidrs {
		r := models.ASNRange{
			OrgID:  orgID,
			ASN:    asn,
			ASNOrg: asnOrg,
			CIDR:   cidr,
		}
		r.ID = uuid.New()
		r.CreatedAt = time.Now()
		if err := h.db.Where("org_id = ? AND asn = ? AND cidr = ?", orgID, asn, cidr).
			FirstOrCreate(&r).Error; err != nil {
			h.log.Warnw("failed to persist ASN range", "org_id", orgID, "asn", asn, "cidr", cidr, "error", err)
		}
	}
}

// ripestatASNLookup queries RIPEstat's free, keyless data API for the set of
// prefixes currently announced by an ASN. This works for ASNs in any RIR
// region (not just RIPE's), since RIPEstat aggregates global BGP data, and
// is used as the fallback when bgp.tools is unreachable or returns nothing.
// RDAP's autnum endpoint is intentionally not used here: it returns
// registration metadata (org name, handle) but never announced prefixes,
// so it can't actually serve as a CIDR source.
func ripestatASNLookup(asnNum string) ([]string, string, error) {
	client := &http.Client{Timeout: 15 * time.Second}

	prefixesURL := fmt.Sprintf("https://stat.ripe.net/data/announced-prefixes/data.json?resource=AS%s", asnNum)
	resp, err := client.Get(prefixesURL)
	if err != nil {
		return nil, "", fmt.Errorf("ripestat request failed: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()

	var result struct {
		Status string `json:"status"`
		Data   struct {
			Prefixes []struct {
				Prefix string `json:"prefix"`
			} `json:"prefixes"`
		} `json:"data"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return nil, "", fmt.Errorf("ripestat response decode failed: %w", err)
	}
	if result.Status != "ok" {
		return nil, "", fmt.Errorf("ripestat returned status %q for AS%s", result.Status, asnNum)
	}

	var cidrs []string
	for _, p := range result.Data.Prefixes {
		if p.Prefix != "" {
			cidrs = append(cidrs, p.Prefix)
		}
	}
	if len(cidrs) == 0 {
		return nil, "", fmt.Errorf("no announced prefixes found for AS%s", asnNum)
	}

	// Best-effort org name lookup; not fatal if it fails.
	asnOrg := ""
	overviewURL := fmt.Sprintf("https://stat.ripe.net/data/as-overview/data.json?resource=AS%s", asnNum)
	if oResp, oErr := client.Get(overviewURL); oErr == nil {
		defer func() { _ = oResp.Body.Close() }()
		var overview struct {
			Data struct {
				Holder string `json:"holder"`
			} `json:"data"`
		}
		if json.NewDecoder(oResp.Body).Decode(&overview) == nil {
			asnOrg = overview.Data.Holder
		}
	}

	return cidrs, asnOrg, nil
}

// DeleteASNRanges DELETE /asn-ranges — clear all for an ASN
func (h *AdminOpsHandler) DeleteASNRanges(c *gin.Context) {
	user := middleware.GetUser(c)
	if user == nil {
		c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{"error": "unauthorized"})
		return
	}
	asn := c.Query("asn")
	if asn == "" {
		c.JSON(400, gin.H{"error": "asn query param required"})
		return
	}
	if err := h.db.Where("org_id = ? AND asn = ?", user.OrgID, asn).Delete(&models.ASNRange{}).Error; err != nil {
		h.log.Warnw("failed to delete ASN range", "error", err)
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to remove ASN range"})
		return
	}
	c.JSON(200, gin.H{"deleted": true})
}

// GetWHOISHistory GET /whois-history — paginated history for a domain
func (h *AdminOpsHandler) GetWHOISHistory(c *gin.Context) {
	user := middleware.GetUser(c)
	if user == nil {
		c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{"error": "unauthorized"})
		return
	}
	domain := c.Query("domain")
	if domain == "" {
		c.JSON(400, gin.H{"error": "domain required"})
		return
	}
	limitStr := c.DefaultQuery("limit", "20")
	limit, _ := strconv.Atoi(limitStr)
	if limit <= 0 || limit > 100 {
		limit = 20
	}

	var records []models.WHOISHistory
	if err := h.db.Where("org_id = ? AND domain = ?", user.OrgID, domain).
		Order("snapped_at DESC").Limit(limit).
		Find(&records).Error; err != nil {
		c.JSON(500, gin.H{"error": err.Error()})
		return
	}
	c.JSON(200, gin.H{"data": records, "total": len(records)})
}

// SnapWHOIS POST /whois-history/snap — live WHOIS lookup + store snapshot
func (h *AdminOpsHandler) SnapWHOIS(c *gin.Context) {
	user := middleware.GetUser(c)
	if user == nil {
		c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{"error": "unauthorized"})
		return
	}
	var req struct {
		Domain string `json:"domain" binding:"required"`
	}
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(400, gin.H{"error": err.Error()})
		return
	}

	whoisData := whois.FetchData(req.Domain)

	record := models.WHOISHistory{
		ID:         uuid.New(),
		OrgID:      user.OrgID,
		Domain:     req.Domain,
		Registrar:  whoisData["registrar"],
		Registrant: whoisData["registrant"],
		Raw:        whoisData["raw"],
		SnappedAt:  time.Now(),
	}
	record.CreatedAt = time.Now()

	if exp, ok := whoisData["expiry_date"]; ok && exp != "" {
		if t, err := time.Parse(time.RFC3339, exp); err == nil {
			record.ExpiryDate = &t
		}
	}
	if reg, ok := whoisData["registration_date"]; ok && reg != "" {
		if t, err := time.Parse(time.RFC3339, reg); err == nil {
			record.RegistrationDate = &t
		}
	}

	if err := h.db.Create(&record).Error; err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to save WHOIS record"})
		return
	}
	c.JSON(201, record)
}

// SetFindingSLA PUT /findings/:id/sla
func (h *AdminOpsHandler) SetFindingSLA(c *gin.Context) {
	user := middleware.GetUser(c)
	if user == nil {
		c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{"error": "unauthorized"})
		return
	}
	id := c.Param("id")
	var req struct {
		DueAt string `json:"due_at" binding:"required"` // RFC3339
	}
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(400, gin.H{"error": err.Error()})
		return
	}
	dueAt, err := time.Parse(time.RFC3339, req.DueAt)
	if err != nil {
		c.JSON(400, gin.H{"error": "invalid due_at format, use RFC3339"})
		return
	}
	var finding models.Finding
	if err := h.db.Where("id = ? AND org_id = ?", id, user.OrgID).First(&finding).Error; err != nil {
		c.JSON(404, gin.H{"error": "finding not found"})
		return
	}
	finding.SLADueAt = &dueAt
	if err := h.db.Save(&finding).Error; err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to update finding"})
		return
	}
	c.JSON(200, finding)
}

// AcceptRisk PUT /findings/:id/risk-accept
func (h *AdminOpsHandler) AcceptRisk(c *gin.Context) {
	user := middleware.GetUser(c)
	if user == nil {
		c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{"error": "unauthorized"})
		return
	}
	id := c.Param("id")

	var req struct {
		Reason string `json:"reason" binding:"required"`
	}
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(400, gin.H{"error": err.Error()})
		return
	}
	var finding models.Finding
	if err := h.db.Where("id = ? AND org_id = ?", id, user.OrgID).First(&finding).Error; err != nil {
		c.JSON(404, gin.H{"error": "finding not found"})
		return
	}

	now := time.Now()
	userID := user.ID
	finding.RiskAccepted = true
	finding.RiskAcceptedBy = &userID
	finding.RiskAcceptedAt = &now
	finding.RiskAcceptReason = req.Reason
	finding.Status = "risk_accepted"
	if err := h.db.Save(&finding).Error; err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to update finding"})
		return
	}
	c.JSON(200, finding)
}

// RevokeRiskAcceptance DELETE /findings/:id/risk-accept
func (h *AdminOpsHandler) RevokeRiskAcceptance(c *gin.Context) {
	user := middleware.GetUser(c)
	if user == nil {
		c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{"error": "unauthorized"})
		return
	}
	id := c.Param("id")
	var finding models.Finding
	if err := h.db.Where("id = ? AND org_id = ?", id, user.OrgID).First(&finding).Error; err != nil {
		c.JSON(404, gin.H{"error": "finding not found"})
		return
	}
	finding.RiskAccepted = false
	finding.RiskAcceptedBy = nil
	finding.RiskAcceptedAt = nil
	finding.RiskAcceptReason = ""
	finding.Status = "open"
	if err := h.db.Save(&finding).Error; err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to update finding"})
		return
	}
	c.JSON(200, finding)
}

// SLAReport GET /findings/sla-report — findings with SLA status breakdown
func (h *AdminOpsHandler) SLAReport(c *gin.Context) {
	user := middleware.GetUser(c)
	if user == nil {
		c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{"error": "unauthorized"})
		return
	}
	now := time.Now()

	type Row struct {
		ID       uuid.UUID  `json:"id"`
		Title    string     `json:"title"`
		Severity string     `json:"severity"`
		Status   string     `json:"status"`
		SLADueAt *time.Time `json:"sla_due_at"`
		Breached bool       `json:"sla_breached"`
		DaysLeft int        `json:"days_left"`
	}

	var findings []models.Finding
	if err := h.db.Where("org_id = ? AND sla_due_at IS NOT NULL AND status NOT IN ('fixed','false_positive')", user.OrgID).
		Order("sla_due_at ASC").Find(&findings).Error; err != nil {
		h.log.Warnw("SLA findings query failed", "error", err)
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to fetch SLA findings"})
		return
	}

	var rows []Row
	overdue, ontrack := 0, 0
	for i := range findings {
		f := &findings[i]
		daysLeft := 0
		breached := false
		if f.SLADueAt != nil {
			daysLeft = int(f.SLADueAt.Sub(now).Hours() / 24)
			breached = f.SLADueAt.Before(now)
		}
		if breached {
			overdue++
			if !f.SLABreached {
				if err := h.db.Model(f).Updates(map[string]interface{}{
					"sla_breached": true, "sla_breach_at": now,
				}).Error; err != nil {
					h.log.Warnw("admin_ops: failed to persist SLA breach flag", "finding_id", f.ID, "error", err)
				}
				// Create an alert and dispatch notifications on first breach.
				alert := models.Alert{
					Base:     models.Base{ID: uuid.New(), CreatedAt: now, UpdatedAt: now},
					OrgID:    user.OrgID,
					Type:     "sla_breach",
					Severity: f.Severity,
					Title:    "SLA Breached: " + f.Title,
					Message: fmt.Sprintf(
						"Finding %q (severity: %s) exceeded its SLA deadline of %s.",
						f.Title, f.Severity, f.SLADueAt.Format("2006-01-02"),
					),
					Status: "open",
				}
				if err := h.db.Create(&alert).Error; err == nil {
					go DispatchAlertNotifications(h.db, h.log, &alert)
				} else {
					h.log.Warnw("failed to create SLA breach alert", "finding_id", f.ID, "error", err)
				}
			}
		} else {
			ontrack++
		}
		rows = append(rows, Row{
			ID:       f.ID,
			Title:    f.Title,
			Severity: f.Severity,
			Status:   f.Status,
			SLADueAt: f.SLADueAt,
			Breached: breached,
			DaysLeft: daysLeft,
		})
	}
	c.JSON(200, gin.H{
		"data":    rows,
		"total":   len(rows),
		"overdue": overdue,
		"ontrack": ontrack,
	})
}

// SetDomainCadence PUT /domains/:id/cadence
func (h *AdminOpsHandler) SetDomainCadence(c *gin.Context) {
	user := middleware.GetUser(c)
	if user == nil {
		c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{"error": "unauthorized"})
		return
	}
	id := c.Param("id")

	var req struct {
		ScanCron  string `json:"scan_cron"`  // e.g. "0 2 * * *"  — empty to disable
		ScanDepth string `json:"scan_depth"` // full, quick, passive
	}
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(400, gin.H{"error": err.Error()})
		return
	}

	var domain models.Domain
	if err := h.db.Where("id = ? AND org_id = ?", id, user.OrgID).First(&domain).Error; err != nil {
		c.JSON(404, gin.H{"error": "domain not found"})
		return
	}

	updates := map[string]interface{}{
		"scan_cron": req.ScanCron,
	}
	if req.ScanDepth != "" {
		updates["scan_depth"] = req.ScanDepth
	}
	if err := h.db.Model(&domain).Updates(updates).Error; err != nil {
		h.log.Warnw("failed to update domain", "error", err)
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to update domain"})
		return
	}
	if err := h.db.Where("id = ? AND org_id = ?", id, user.OrgID).First(&domain).Error; err != nil {
		h.log.Warnw("domain reload after update failed", "error", err)
	}
	c.JSON(200, domain)
}

// ListWebhookDeliveries GET /webhook-deliveries?channel=slack&success=true&page=1&per_page=50
func (h *AdminOpsHandler) ListWebhookDeliveries(c *gin.Context) {
	user := middleware.GetUser(c)
	if user == nil {
		c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{"error": "unauthorized"})
		return
	}
	page, _ := strconv.Atoi(c.DefaultQuery("page", "1"))
	perPage, _ := strconv.Atoi(c.DefaultQuery("per_page", "50"))
	if page < 1 {
		page = 1
	}
	if perPage < 1 || perPage > 200 {
		perPage = 50
	}
	offset := (page - 1) * perPage

	q := h.db.Model(&models.WebhookDelivery{}).Where("org_id = ?", user.OrgID)
	if ch := c.Query("channel"); ch != "" {
		q = q.Where("channel = ?", ch)
	}
	if s := c.Query("success"); s == "true" {
		q = q.Where("success = true")
	} else if s == "false" {
		q = q.Where("success = false")
	}

	var total int64
	q.Count(&total)

	var deliveries []models.WebhookDelivery
	if err := q.Order("sent_at DESC").Offset(offset).Limit(perPage).Find(&deliveries).Error; err != nil {
		h.log.Warnw("webhook deliveries list failed", "error", err)
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to fetch webhook deliveries"})
		return
	}
	c.JSON(200, gin.H{
		"data":     deliveries,
		"total":    total,
		"page":     page,
		"per_page": perPage,
		"pages":    (int(total) + perPage - 1) / perPage,
	})
}

// RetryWebhook POST /webhook-deliveries/:id/retry
func (h *AdminOpsHandler) RetryWebhook(c *gin.Context) {
	user := middleware.GetUser(c)
	if user == nil {
		c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{"error": "unauthorized"})
		return
	}
	id := c.Param("id")

	var delivery models.WebhookDelivery
	if err := h.db.Where("id = ? AND org_id = ?", id, user.OrgID).First(&delivery).Error; err != nil {
		c.JSON(404, gin.H{"error": "delivery not found"})
		return
	}
	if delivery.Success {
		c.JSON(400, gin.H{"error": "delivery already succeeded"})
		return
	}

	if delivery.AlertID != nil {
		var alert models.Alert
		if err := h.db.First(&alert, "id = ?", delivery.AlertID).Error; err == nil {
			go DispatchAlertNotifications(h.db, h.log, &alert)
		}
	}
	c.JSON(200, gin.H{"retried": true})
}

// BulkDeleteFindings DELETE /findings/bulk
func (h *AdminOpsHandler) BulkDeleteFindings(c *gin.Context) {
	user := middleware.GetUser(c)
	if user == nil {
		c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{"error": "unauthorized"})
		return
	}
	var req struct {
		IDs []string `json:"ids" binding:"required"`
	}
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(400, gin.H{"error": err.Error()})
		return
	}
	result := h.db.Where("id IN ? AND org_id = ?", req.IDs, user.OrgID).Delete(&models.Finding{})
	c.JSON(200, gin.H{"deleted": result.RowsAffected})
}

// BulkDeleteHosts DELETE /hosts/bulk
func (h *AdminOpsHandler) BulkDeleteHosts(c *gin.Context) {
	user := middleware.GetUser(c)
	if user == nil {
		c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{"error": "unauthorized"})
		return
	}
	var req struct {
		IDs []string `json:"ids" binding:"required"`
	}
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(400, gin.H{"error": err.Error()})
		return
	}
	result := h.db.Where("id IN ? AND org_id = ?", req.IDs, user.OrgID).Delete(&models.Host{})
	c.JSON(200, gin.H{"deleted": result.RowsAffected})
}

// BulkDeleteSubdomains DELETE /subdomains/bulk
func (h *AdminOpsHandler) BulkDeleteSubdomains(c *gin.Context) {
	user := middleware.GetUser(c)
	if user == nil {
		c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{"error": "unauthorized"})
		return
	}
	var req struct {
		IDs []string `json:"ids" binding:"required"`
	}
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(400, gin.H{"error": err.Error()})
		return
	}
	result := h.db.Where("id IN ? AND org_id = ?", req.IDs, user.OrgID).Delete(&models.Subdomain{})
	c.JSON(200, gin.H{"deleted": result.RowsAffected})
}

// BulkIgnoreFindings PUT /findings/bulk-ignore — set status to false_positive
func (h *AdminOpsHandler) BulkIgnoreFindings(c *gin.Context) {
	user := middleware.GetUser(c)
	if user == nil {
		c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{"error": "unauthorized"})
		return
	}
	var req struct {
		IDs []string `json:"ids" binding:"required"`
	}
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(400, gin.H{"error": err.Error()})
		return
	}
	result := h.db.Model(&models.Finding{}).
		Where("id IN ? AND org_id = ?", req.IDs, user.OrgID).
		Update("status", "false_positive")
	c.JSON(200, gin.H{"updated": result.RowsAffected})
}

// ExportHosts GET /hosts/export?format=csv|json&page=1&per_page=1000&status=active&country=US
func (h *AdminOpsHandler) ExportHosts(c *gin.Context) {
	user := middleware.GetUser(c)
	if user == nil {
		c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{"error": "unauthorized"})
		return
	}
	format := c.DefaultQuery("format", "csv")
	page, _ := strconv.Atoi(c.DefaultQuery("page", "1"))
	perPage, _ := strconv.Atoi(c.DefaultQuery("per_page", "1000"))
	if page < 1 {
		page = 1
	}
	if perPage < 1 || perPage > 5000 {
		perPage = 1000
	}
	offset := (page - 1) * perPage

	q := h.db.Where("org_id = ?", user.OrgID)
	if status := c.Query("status"); status != "" {
		q = q.Where("status = ?", status)
	}
	if country := c.Query("country"); country != "" {
		q = q.Where("country = ?", country)
	}
	if asn := c.Query("asn"); asn != "" {
		q = q.Where("asn = ?", asn)
	}

	var total int64
	q.Model(&models.Host{}).Count(&total)

	var hosts []models.Host
	if err := q.Preload("Services").Order("ip").Offset(offset).Limit(perPage).Find(&hosts).Error; err != nil {
		h.log.Warnw("hosts export query failed", "error", err)
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to export hosts"})
		return
	}

	if format == "json" {
		c.Header("Content-Disposition", "attachment; filename=hosts.json")
		c.JSON(200, gin.H{
			"data":     hosts,
			"total":    total,
			"page":     page,
			"per_page": perPage,
			"pages":    (int(total) + perPage - 1) / perPage,
		})
		return
	}

	c.Header("Content-Disposition", "attachment; filename=hosts.csv")
	c.Header("Content-Type", "text/csv")
	w := csv.NewWriter(c.Writer)
	_ = w.Write([]string{"ip", "hostname", "asn", "asn_org", "country", "os", "status", "first_seen", "last_seen", "tags"})
	for _, hh := range hosts {
		_ = w.Write([]string{
			hh.IP, hh.Hostname, hh.ASN, hh.ASNOrg, hh.Country,
			hh.OS, hh.Status,
			hh.FirstSeenAt.Format(time.RFC3339),
			hh.LastSeenAt.Format(time.RFC3339),
			strings.Join(hh.Tags, ";"),
		})
	}
	w.Flush()
	if err := w.Error(); err != nil {
		h.log.Warnw("hosts CSV export write error", "error", err)
	}
}

// ExportSubdomains GET /subdomains/export?format=csv|json
func (h *AdminOpsHandler) ExportSubdomains(c *gin.Context) {
	user := middleware.GetUser(c)
	if user == nil {
		c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{"error": "unauthorized"})
		return
	}
	format := c.DefaultQuery("format", "csv")

	var subs []models.Subdomain
	if err := h.db.Where("org_id = ?", user.OrgID).Find(&subs).Error; err != nil {
		h.log.Warnw("subdomains export query failed", "error", err)
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to export subdomains"})
		return
	}

	if format == "json" {
		c.Header("Content-Disposition", "attachment; filename=subdomains.json")
		c.JSON(200, subs)
		return
	}

	c.Header("Content-Disposition", "attachment; filename=subdomains.csv")
	c.Header("Content-Type", "text/csv")
	w := csv.NewWriter(c.Writer)
	_ = w.Write([]string{"fqdn", "ips", "status", "source", "dead", "first_seen", "last_seen", "tags"})
	for _, s := range subs {
		_ = w.Write([]string{
			s.FQDN,
			strings.Join(s.IPs, ";"),
			s.Status,
			s.Source,
			strconv.FormatBool(s.Dead),
			s.FirstSeenAt.Format(time.RFC3339),
			s.LastSeenAt.Format(time.RFC3339),
			strings.Join(s.Tags, ";"),
		})
	}
	w.Flush()
	if err := w.Error(); err != nil {
		h.log.Warnw("subdomains CSV export write error", "error", err)
	}
}

// ServiceDiff GET /services/diff?host_id=X — compare current services to last scan
func (h *AdminOpsHandler) ServiceDiff(c *gin.Context) {
	user := middleware.GetUser(c)
	if user == nil {
		c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{"error": "unauthorized"})
		return
	}
	hostID := c.Query("host_id")
	hostRef := c.Query("host_ref")

	type DiffRow struct {
		Port         int    `json:"port"`
		Protocol     string `json:"protocol"`
		Service      string `json:"service"`
		ChangeType   string `json:"change_type"` // appeared, disappeared, changed
		CurrentState string `json:"current_state,omitempty"`
		PrevState    string `json:"prev_state,omitempty"`
	}

	// Validate inputs: at least one must be supplied; host_id must be a valid UUID.
	if hostID == "" && hostRef == "" {
		c.JSON(400, gin.H{"error": "host_id or host_ref required"})
		return
	}
	if hostID != "" {
		if _, err := uuid.Parse(hostID); err != nil {
			c.JSON(400, gin.H{"error": "host_id must be a valid UUID"})
			return
		}
	}
	if hostRef != "" && strings.TrimSpace(hostRef) == "" {
		c.JSON(400, gin.H{"error": "host_ref must not be blank"})
		return
	}

	// When only host_ref is given, resolve it to a host_id so that the
	// *current* services query (host_id FK) can use the canonical lookup
	// path. service_history is queried by host_id OR host_ref together
	// below (regardless of which one resolution succeeded), since history
	// rows recorded before a host's ID was known may carry only host_ref.
	if hostID == "" && hostRef != "" {
		var resolvedHost models.Host
		if err := h.db.Select("id").
			Where("org_id = ? AND (ip = ? OR hostname = ?)", user.OrgID, hostRef, hostRef).
			First(&resolvedHost).Error; err == nil {
			hostID = resolvedHost.ID.String()
		}
		// If no UUID was resolved we still fall back to host_ref string match below.
	}

	var current []models.Service
	q := h.db.Where("org_id = ?", user.OrgID)
	if hostID != "" {
		q = q.Where("host_id = ?", hostID)
	} else {
		q = q.Where("host_ref = ?", hostRef)
	}
	if err := q.Find(&current).Error; err != nil {
		h.log.Warnw("service history current query failed", "error", err)
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to fetch current services"})
		return
	}

	var history []models.ServiceHistory
	hq := h.db.Where("org_id = ?", user.OrgID)
	switch {
	case hostID != "" && hostRef != "":
		hq = hq.Where("host_id = ? OR host_ref = ?", hostID, hostRef)
	case hostID != "":
		hq = hq.Where("host_id = ?", hostID)
	default:
		hq = hq.Where("host_ref = ?", hostRef)
	}
	if err := hq.Order("created_at DESC").Limit(100).Find(&history).Error; err != nil {
		h.log.Warnw("service history query failed", "error", err)
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to fetch service history"})
		return
	}

	currentMap := map[string]models.Service{}
	for _, s := range current {
		key := fmt.Sprintf("%d/%s", s.Port, s.Protocol)
		currentMap[key] = s
	}

	historyMap := map[string]models.ServiceHistory{}
	for _, s := range history {
		key := fmt.Sprintf("%d/%s", s.Port, s.Protocol)
		if _, exists := historyMap[key]; !exists {
			historyMap[key] = s
		}
	}

	var diffs []DiffRow

	for key, cur := range currentMap {
		if prev, ok := historyMap[key]; !ok {
			diffs = append(diffs, DiffRow{
				Port: cur.Port, Protocol: cur.Protocol, Service: cur.Service,
				ChangeType: "appeared", CurrentState: cur.State,
			})
		} else if prev.State != cur.State || prev.Version != cur.Version {
			diffs = append(diffs, DiffRow{
				Port: cur.Port, Protocol: cur.Protocol, Service: cur.Service,
				ChangeType: "changed", CurrentState: cur.State, PrevState: prev.State,
			})
		}
	}

	for key, prev := range historyMap {
		if _, ok := currentMap[key]; !ok {
			diffs = append(diffs, DiffRow{
				Port: prev.Port, Protocol: prev.Protocol, Service: prev.Service,
				ChangeType: "disappeared", PrevState: prev.State,
			})
		}
	}

	c.JSON(200, gin.H{"data": diffs, "total": len(diffs)})
}

type OrgBackup struct {
	ExportedAt time.Time          `json:"exported_at"`
	OrgID      string             `json:"org_id"`
	Domains    []models.Domain    `json:"domains"`
	Hosts      []models.Host      `json:"hosts"`
	Subdomains []models.Subdomain `json:"subdomains"`
	Findings   []models.Finding   `json:"findings"`
	DNSRecords []models.DNSRecord `json:"dns_records"`
	Projects   []models.Project   `json:"projects"`
	Notes      []models.Note      `json:"notes"`
	Todos      []models.Todo      `json:"todos"`
}

// BackupOrg GET /org/backup — export all org data as JSON zip
func (h *AdminOpsHandler) BackupOrg(c *gin.Context) {
	user := middleware.GetUser(c)
	if user == nil {
		c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{"error": "unauthorized"})
		return
	}

	backup := OrgBackup{
		ExportedAt: time.Now(),
		OrgID:      user.OrgID.String(),
	}
	backupTargets := []struct {
		label string
		dest  interface{}
	}{
		{"domains", &backup.Domains},
		{"hosts", &backup.Hosts},
		{"subdomains", &backup.Subdomains},
		{"findings", &backup.Findings},
		{"dns_records", &backup.DNSRecords},
		{"projects", &backup.Projects},
		{"notes", &backup.Notes},
		{"todos", &backup.Todos},
	}
	for _, bt := range backupTargets {
		if err := h.db.Where("org_id = ?", user.OrgID).Find(bt.dest).Error; err != nil {
			h.log.Warnw("backup query failed", "collection", bt.label, "error", err)
			c.JSON(http.StatusInternalServerError, gin.H{"error": "backup failed at " + bt.label})
			return
		}
	}

	jsonData, err := json.MarshalIndent(backup, "", "  ")
	if err != nil {
		c.JSON(500, gin.H{"error": err.Error()})
		return
	}

	var buf bytes.Buffer
	zw := zip.NewWriter(&buf)
	fw, err := zw.Create(fmt.Sprintf("rayyan-asm-backup-%s.json", time.Now().Format("2006-01-02")))
	if err != nil {
		c.JSON(500, gin.H{"error": err.Error()})
		return
	}
	if _, err := fw.Write(jsonData); err != nil {
		c.JSON(500, gin.H{"error": err.Error()})
		return
	}
	_ = zw.Close()

	c.Header("Content-Disposition", fmt.Sprintf("attachment; filename=rayyan-backup-%s.zip", time.Now().Format("2006-01-02")))
	c.Header("Content-Type", "application/zip")
	c.Data(200, "application/zip", buf.Bytes())
}

// RestoreOrg POST /org/restore — import backup JSON (upsert, non-destructive)
func (h *AdminOpsHandler) RestoreOrg(c *gin.Context) {
	user := middleware.GetUser(c)
	if user == nil {
		c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{"error": "unauthorized"})
		return
	}
	orgID := user.OrgID

	var backup OrgBackup
	if err := c.ShouldBindJSON(&backup); err != nil {
		c.JSON(400, gin.H{"error": "invalid backup JSON: " + err.Error()})
		return
	}

	stats := map[string]int{}

	if err := h.db.Transaction(func(tx *gorm.DB) error {
		for i := range backup.Domains {
			backup.Domains[i].OrgID = orgID
			// Business-key match (org_id + name). The backup's original ID
			// is irrelevant here (it belonged to whatever org/run produced
			// the backup) and would collide with the live primary key
			// sequence if reused verbatim, so clear it and let GORM mint a
			// fresh UUID whenever no existing row matches.
			backup.Domains[i].ID = uuid.Nil
			if err := tx.Where("org_id = ? AND name = ?", orgID, backup.Domains[i].Name).
				FirstOrCreate(&backup.Domains[i]).Error; err == nil {
				stats["domains"]++
			} else {
				h.log.Warnw("restore: domain upsert failed", "name", backup.Domains[i].Name, "error", err)
			}
		}
		for i := range backup.Hosts {
			backup.Hosts[i].OrgID = orgID
			backup.Hosts[i].ID = uuid.Nil
			if err := tx.Where("org_id = ? AND ip = ?", orgID, backup.Hosts[i].IP).
				FirstOrCreate(&backup.Hosts[i]).Error; err == nil {
				stats["hosts"]++
			} else {
				h.log.Warnw("restore: host upsert failed", "ip", backup.Hosts[i].IP, "error", err)
			}
		}
		for i := range backup.Subdomains {
			backup.Subdomains[i].OrgID = orgID
			backup.Subdomains[i].ID = uuid.Nil
			if err := tx.Where("org_id = ? AND fqdn = ?", orgID, backup.Subdomains[i].FQDN).
				FirstOrCreate(&backup.Subdomains[i]).Error; err == nil {
				stats["subdomains"]++
			} else {
				h.log.Warnw("restore: subdomain upsert failed", "fqdn", backup.Subdomains[i].FQDN, "error", err)
			}
		}
		for i := range backup.Projects {
			backup.Projects[i].OrgID = orgID
			backup.Projects[i].ID = uuid.Nil
			if err := tx.Where("org_id = ? AND slug = ?", orgID, backup.Projects[i].Slug).
				FirstOrCreate(&backup.Projects[i]).Error; err == nil {
				stats["projects"]++
			} else {
				h.log.Warnw("restore: project upsert failed", "slug", backup.Projects[i].Slug, "error", err)
			}
		}
		for i := range backup.Notes {
			backup.Notes[i].OrgID = orgID
			backup.Notes[i].ID = uuid.Nil
			if err := tx.Where("org_id = ? AND title = ? AND target = ?", orgID,
				backup.Notes[i].Title, backup.Notes[i].Target).
				FirstOrCreate(&backup.Notes[i]).Error; err == nil {
				stats["notes"]++
			} else {
				h.log.Warnw("restore: note upsert failed", "title", backup.Notes[i].Title, "error", err)
			}
		}
		for i := range backup.Todos {
			backup.Todos[i].OrgID = orgID
			// Todos have no other natural business key, so we'd like to
			// preserve the original ID for same-org idempotency. But that ID
			// is a global primary key: if it's already taken by a row in a
			// DIFFERENT org (e.g. restoring this backup into a new org while
			// the source org still exists), inserting with that same ID
			// would collide. Check ownership first and only keep the ID when
			// it's either free or already belongs to this org; otherwise
			// mint a fresh one so the row still restores instead of failing.
			origID := backup.Todos[i].ID
			var existing models.Todo
			lookupErr := tx.Select("id", "org_id").Where("id = ?", origID).First(&existing).Error
			ownedByAnotherOrg := lookupErr == nil && existing.OrgID != orgID
			if ownedByAnotherOrg {
				backup.Todos[i].ID = uuid.Nil
			}
			var matchErr error
			if backup.Todos[i].ID == uuid.Nil {
				matchErr = tx.Create(&backup.Todos[i]).Error
			} else {
				matchErr = tx.Where("org_id = ? AND id = ?", orgID, origID).
					FirstOrCreate(&backup.Todos[i]).Error
			}
			if matchErr == nil {
				stats["todos"]++
			} else {
				h.log.Warnw("restore: todo upsert failed", "id", origID, "error", matchErr)
			}
		}
		for i := range backup.DNSRecords {
			backup.DNSRecords[i].OrgID = orgID
			backup.DNSRecords[i].ID = uuid.Nil
			if err := tx.Where("org_id = ? AND domain_id = ? AND name = ? AND type = ? AND value = ?",
				orgID, backup.DNSRecords[i].DomainID, backup.DNSRecords[i].Name,
				backup.DNSRecords[i].Type, backup.DNSRecords[i].Value).
				FirstOrCreate(&backup.DNSRecords[i]).Error; err == nil {
				stats["dns_records"]++
			} else {
				h.log.Warnw("restore: dns record upsert failed", "name", backup.DNSRecords[i].Name, "error", err)
			}
		}
		for i := range backup.Findings {
			backup.Findings[i].OrgID = orgID
			// Findings have no other natural business key, so we'd like to
			// preserve the original ID for same-org idempotency — but that
			// ID is a global primary key, so check who (if anyone) already
			// owns it before reusing it across orgs.
			origID := backup.Findings[i].ID
			var existing models.Finding
			lookupErr := tx.Select("id", "org_id").Where("id = ?", origID).First(&existing).Error
			ownedByAnotherOrg := lookupErr == nil && existing.OrgID != orgID
			if ownedByAnotherOrg {
				backup.Findings[i].ID = uuid.Nil
			}
			var matchErr error
			if backup.Findings[i].ID == uuid.Nil {
				matchErr = tx.Create(&backup.Findings[i]).Error
			} else {
				matchErr = tx.Where("org_id = ? AND id = ?", orgID, origID).
					FirstOrCreate(&backup.Findings[i]).Error
			}
			if matchErr == nil {
				stats["findings"]++
			} else {
				h.log.Warnw("restore: finding upsert failed", "id", origID, "error", matchErr)
			}
		}
		return nil
	}); err != nil {
		c.JSON(500, gin.H{"error": "restore transaction failed: " + err.Error()})
		return
	}

	c.JSON(200, gin.H{"restored": stats})
}

// activeScanCount returns the number of currently pending/running scan jobs
// and discovery jobs for an org. Backed by the database (not an in-memory
// map), so it is correct across concurrent requests, multiple server
// instances, and survives restarts.
func activeScanCount(db *gorm.DB, orgID uuid.UUID) (int64, error) {
	var scanJobs, discoveryJobs int64
	if err := db.Model(&models.ScanJob{}).
		Where("org_id = ? AND status IN ('pending','running')", orgID).
		Count(&scanJobs).Error; err != nil {
		return 0, err
	}
	if err := db.Model(&models.DiscoveryJob{}).
		Where("org_id = ? AND status IN ('pending','running')", orgID).
		Count(&discoveryJobs).Error; err != nil {
		return 0, err
	}
	return scanJobs + discoveryJobs, nil
}

// EnforceScanThrottle checks whether an org is at its concurrent-scan limit
// and, if so, aborts the request with 429. Call this from any handler that
// creates a new scan/discovery job. Returns false (and has already written
// the response) when the org is over its limit.
func EnforceScanThrottle(c *gin.Context, db *gorm.DB, orgID uuid.UUID) bool {
	var org models.Organization
	if err := db.First(&org, "id = ?", orgID).Error; err != nil {
		c.AbortWithStatusJSON(http.StatusInternalServerError, gin.H{"error": "could not load organization"})
		return false
	}
	limit := org.MaxConcurrentScans
	if limit <= 0 {
		limit = defaultMaxConcurrentScans(org.Plan)
	}

	active, err := activeScanCount(db, orgID)
	if err != nil {
		c.AbortWithStatusJSON(http.StatusInternalServerError, gin.H{"error": "could not check scan limits"})
		return false
	}
	if active >= int64(limit) {
		c.AbortWithStatusJSON(http.StatusTooManyRequests, gin.H{
			"error":        "concurrent scan limit reached for this organization",
			"active_scans": active,
			"max_scans":    limit,
		})
		return false
	}
	return true
}

func defaultMaxConcurrentScans(plan string) int {
	switch plan {
	case "enterprise":
		return 20
	case "pro":
		return 8
	default: // free / unset
		return 2
	}
}

// GetOrgScanLimits GET /org/scan-limits
func (h *AdminOpsHandler) GetOrgScanLimits(c *gin.Context) {
	user := middleware.GetUser(c)
	if user == nil {
		c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{"error": "unauthorized"})
		return
	}
	var org models.Organization
	if err := h.db.First(&org, "id = ?", user.OrgID).Error; err != nil {
		c.JSON(404, gin.H{"error": "org not found"})
		return
	}
	active, err := activeScanCount(h.db, user.OrgID)
	if err != nil {
		c.JSON(500, gin.H{"error": "could not load active scan count"})
		return
	}
	limit := org.MaxConcurrentScans
	if limit <= 0 {
		limit = defaultMaxConcurrentScans(org.Plan)
	}
	c.JSON(200, gin.H{
		"org_id":               user.OrgID,
		"max_assets":           org.MaxAssets,
		"plan":                 org.Plan,
		"active_scans":         active,
		"max_concurrent_scans": limit,
		"throttled":            active >= int64(limit),
	})
}

// SetOrgPlan PUT /org/plan (admin only)
func (h *AdminOpsHandler) SetOrgPlan(c *gin.Context) {
	user := middleware.GetUser(c)
	if user == nil {
		c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{"error": "unauthorized"})
		return
	}
	var req struct {
		Plan               string `json:"plan"`
		MaxAssets          int    `json:"max_assets"`
		MaxConcurrentScans int    `json:"max_concurrent_scans"`
	}
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(400, gin.H{"error": err.Error()})
		return
	}
	updates := map[string]interface{}{}
	if req.Plan != "" {
		updates["plan"] = req.Plan
	}
	if req.MaxAssets > 0 {
		updates["max_assets"] = req.MaxAssets
	}
	if req.MaxConcurrentScans > 0 {
		updates["max_concurrent_scans"] = req.MaxConcurrentScans
	}
	if err := h.db.Model(&models.Organization{}).Where("id = ?", user.OrgID).Updates(updates).Error; err != nil {
		h.log.Warnw("failed to update org branding", "error", err)
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to update branding"})
		return
	}
	c.JSON(200, gin.H{"updated": true})
}

// ListScreenshots GET /screenshots/gallery — returns all screenshotted web assets for the org
func (h *AdminOpsHandler) ListScreenshots(c *gin.Context) {
	user := middleware.GetUser(c)
	if user == nil {
		c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{"error": "unauthorized"})
		return
	}
	limitStr := c.DefaultQuery("limit", "50")
	limit, _ := strconv.Atoi(limitStr)
	if limit <= 0 || limit > 200 {
		limit = 50
	}
	offsetStr := c.DefaultQuery("offset", "0")
	offset, _ := strconv.Atoi(offsetStr)

	var assets []models.WebAsset
	h.db.Where("org_id = ? AND screenshotted = true", user.OrgID).
		Order("scanned_at DESC").
		Limit(limit).Offset(offset).
		Find(&assets)

	var total int64
	h.db.Model(&models.WebAsset{}).
		Where("org_id = ? AND screenshotted = true", user.OrgID).
		Count(&total)

	c.JSON(200, gin.H{"data": assets, "total": total})
}

// UDPProbe POST /scan/udp-probe — lightweight UDP service probe on common ports
func (h *AdminOpsHandler) UDPProbe(c *gin.Context) {
	var req struct {
		Host  string `json:"host" binding:"required"`
		Ports []int  `json:"ports"`
	}
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(400, gin.H{"error": err.Error()})
		return
	}

	commonUDP := []int{53, 67, 68, 69, 123, 137, 138, 161, 162, 500, 514, 520, 1194, 1900, 4500, 5353}
	ports := req.Ports
	if len(ports) == 0 {
		ports = commonUDP
	}

	type UDPResult struct {
		Port    int    `json:"port"`
		Open    bool   `json:"open"`
		Service string `json:"service"`
	}

	udpServiceMap := map[int]string{
		53: "dns", 67: "dhcp", 68: "dhcp", 69: "tftp",
		123: "ntp", 137: "netbios-ns", 138: "netbios-dgm",
		161: "snmp", 162: "snmp-trap", 500: "isakmp",
		514: "syslog", 520: "rip", 1194: "openvpn",
		1900: "ssdp/upnp", 4500: "ipsec-nat-t", 5353: "mdns",
	}

	var results []UDPResult
	timeout := 2 * time.Second

	for _, port := range ports {
		addr := net.JoinHostPort(req.Host, fmt.Sprintf("%d", port))
		conn, err := net.DialTimeout("udp", addr, timeout)
		open := false
		if err == nil {
			_ = conn.SetDeadline(time.Now().Add(timeout))
			_, _ = conn.Write([]byte{0x00})
			buf := make([]byte, 64)
			_, readErr := conn.Read(buf)
			_ = conn.Close()
			open = readErr == nil
		}
		results = append(results, UDPResult{
			Port:    port,
			Open:    open,
			Service: udpServiceMap[port],
		})
	}

	c.JSON(200, gin.H{"host": req.Host, "results": results})
}

// GetTheme GET /auth/theme
func (h *AdminOpsHandler) GetTheme(c *gin.Context) {
	user := middleware.GetUser(c)
	if user == nil {
		c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{"error": "unauthorized"})
		return
	}
	theme := "slate"
	if user.Preferences != nil {
		if t, ok := user.Preferences["theme"].(string); ok {
			theme = t
		}
	}
	c.JSON(200, gin.H{"theme": theme})
}

// SetTheme PUT /auth/theme
func (h *AdminOpsHandler) SetTheme(c *gin.Context) {
	user := middleware.GetUser(c)
	if user == nil {
		c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{"error": "unauthorized"})
		return
	}
	var req struct {
		Theme string `json:"theme" binding:"required"` // dark, light, slate
	}
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(400, gin.H{"error": err.Error()})
		return
	}
	if req.Theme != "dark" && req.Theme != "light" && req.Theme != "slate" {
		c.JSON(400, gin.H{"error": "theme must be 'dark', 'light', or 'slate'"})
		return
	}
	if user.Preferences == nil {
		user.Preferences = models.JSONB{}
	}
	user.Preferences["theme"] = req.Theme
	if err := h.db.Model(user).Update("preferences", user.Preferences).Error; err != nil {
		h.log.Warnw("failed to update user preferences", "error", err)
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to update preferences"})
		return
	}
	c.JSON(200, gin.H{"theme": req.Theme})
}
