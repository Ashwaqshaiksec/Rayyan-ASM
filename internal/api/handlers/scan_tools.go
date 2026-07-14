package handlers

// No AI, no external API (TLS check uses pure Go net/tls; GeoIP uses ip-api.com).

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/ShadooowX/rayyan-asm/internal/api/middleware"
	"github.com/ShadooowX/rayyan-asm/internal/models"
	"github.com/ShadooowX/rayyan-asm/internal/modules/port"
	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
	"go.uber.org/zap"
	"gorm.io/gorm"
)

// Scan Diff
// GET /scans/:id/diff/:other_id

func (h *ScanHandler) Diff(c *gin.Context) {
	user := middleware.GetUser(c)
	if user == nil {
		c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{"error": "unauthorized"})
		return
	}

	idA := c.Param("id")
	idB := c.Param("other_id")

	var jobA, jobB models.ScanJob
	if err := h.db.Where("id = ? AND org_id = ?", idA, user.OrgID).First(&jobA).Error; err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "scan A not found"})
		return
	}
	if err := h.db.Where("id = ? AND org_id = ?", idB, user.OrgID).First(&jobB).Error; err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "scan B not found"})
		return
	}

	var findingsA, findingsB []models.Finding
	if err := h.db.Where("org_id = ? AND scan_job_id = ?", user.OrgID, idA).Find(&findingsA).Error; err != nil {
		h.log.Warnw("scan compare findings A failed", "error", err)
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to fetch scan A findings"})
		return
	}
	if err := h.db.Where("org_id = ? AND scan_job_id = ?", user.OrgID, idB).Find(&findingsB).Error; err != nil {
		h.log.Warnw("scan compare findings B failed", "error", err)
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to fetch scan B findings"})
		return
	}

	keyOf := func(f models.Finding) string {
		return strings.ToLower(f.Title + "|" + f.URL + "|" + f.Category)
	}

	setA := make(map[string]models.Finding, len(findingsA))
	for _, f := range findingsA {
		setA[keyOf(f)] = f
	}
	setB := make(map[string]models.Finding, len(findingsB))
	for _, f := range findingsB {
		setB[keyOf(f)] = f
	}

	var newFindings, removedFindings, persistentFindings []models.Finding
	for k, f := range setB {
		if _, exists := setA[k]; !exists {
			newFindings = append(newFindings, f)
		} else {
			persistentFindings = append(persistentFindings, f)
		}
	}
	for k, f := range setA {
		if _, exists := setB[k]; !exists {
			removedFindings = append(removedFindings, f)
		}
	}

	c.JSON(http.StatusOK, gin.H{
		"scan_a":     gin.H{"id": jobA.ID, "name": jobA.Name, "created_at": jobA.CreatedAt},
		"scan_b":     gin.H{"id": jobB.ID, "name": jobB.Name, "created_at": jobB.CreatedAt},
		"new":        newFindings,
		"removed":    removedFindings,
		"persistent": persistentFindings,
		"summary": gin.H{
			"new":        len(newFindings),
			"removed":    len(removedFindings),
			"persistent": len(persistentFindings),
		},
	})
}

// Attack Surface Risk Score
// GET /dashboard/risk-score

func (h *DashboardHandler) RiskScore(c *gin.Context) {
	user := middleware.GetUser(c)
	if user == nil {
		c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{"error": "unauthorized"})
		return
	}
	orgID := user.OrgID

	var critical, high, medium, low int64
	h.db.Model(&models.Finding{}).Where("org_id = ? AND severity='critical' AND status='open'", orgID).Count(&critical)
	h.db.Model(&models.Finding{}).Where("org_id = ? AND severity='high'     AND status='open'", orgID).Count(&high)
	h.db.Model(&models.Finding{}).Where("org_id = ? AND severity='medium'   AND status='open'", orgID).Count(&medium)
	h.db.Model(&models.Finding{}).Where("org_id = ? AND severity='low'      AND status='open'", orgID).Count(&low)

	var expiringCerts int64
	h.db.Model(&models.Certificate{}).Where(
		"org_id = ? AND not_after < ? AND is_expired = false",
		orgID, time.Now().Add(14*24*time.Hour),
	).Count(&expiringCerts)

	var totalServices int64
	h.db.Model(&models.Service{}).Where("org_id = ?", orgID).Count(&totalServices)

	score := float64(0)
	score += float64(critical) * 10.0
	score += float64(high) * 4.0
	score += float64(medium) * 1.5
	score += float64(low) * 0.5
	score += float64(expiringCerts) * 5.0
	if totalServices > 100 {
		score += float64(totalServices-100) * 0.1
	}
	if score > 100 {
		score = 100
	}

	tier := "low"
	switch {
	case score >= 75:
		tier = "critical"
	case score >= 50:
		tier = "high"
	case score >= 25:
		tier = "medium"
	}

	c.JSON(http.StatusOK, gin.H{
		"score": score,
		"tier":  tier,
		"breakdown": gin.H{
			"critical_findings": critical,
			"high_findings":     high,
			"medium_findings":   medium,
			"low_findings":      low,
			"expiring_certs":    expiringCerts,
			"total_services":    totalServices,
		},
	})
}

// Bulk Tag
// PUT /hosts/bulk-tag
// PUT /subdomains/bulk-tag

func (h *HostHandler) BulkTag(c *gin.Context) {
	user := middleware.GetUser(c)
	if user == nil {
		c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{"error": "unauthorized"})
		return
	}
	var req struct {
		IDs    []string `json:"ids"`
		Tags   []string `json:"tags"`
		Action string   `json:"action"` // "add" or "remove"
	}
	if err := c.ShouldBindJSON(&req); err != nil || len(req.IDs) == 0 || len(req.Tags) == 0 {
		c.JSON(http.StatusBadRequest, gin.H{"error": "ids and tags required"})
		return
	}
	if req.Action != "add" && req.Action != "remove" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "action must be 'add' or 'remove'"})
		return
	}

	var hosts []models.Host
	if err := h.db.Where("org_id = ? AND id IN ?", user.OrgID, req.IDs).Find(&hosts).Error; err != nil {
		h.log.Warnw("tag hosts query failed", "error", err)
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to fetch hosts"})
		return
	}

	for i := range hosts {
		existing := map[string]bool{}
		for _, t := range hosts[i].Tags {
			existing[t] = true
		}
		if req.Action == "add" {
			for _, t := range req.Tags {
				existing[t] = true
			}
		} else {
			for _, t := range req.Tags {
				delete(existing, t)
			}
		}
		newTags := make(models.StringArray, 0, len(existing))
		for t := range existing {
			newTags = append(newTags, t)
		}
		if err := h.db.Model(&hosts[i]).Update("tags", newTags).Error; err != nil {
			h.log.Warnw("host tag update failed", "id", hosts[i].ID, "error", err)
		}
	}
	c.JSON(http.StatusOK, gin.H{"updated": len(hosts)})
}

func (h *DomainHandler) BulkTagSubdomains(c *gin.Context) {
	user := middleware.GetUser(c)
	if user == nil {
		c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{"error": "unauthorized"})
		return
	}
	var req struct {
		IDs    []string `json:"ids"`
		Tags   []string `json:"tags"`
		Action string   `json:"action"`
	}
	if err := c.ShouldBindJSON(&req); err != nil || len(req.IDs) == 0 || len(req.Tags) == 0 {
		c.JSON(http.StatusBadRequest, gin.H{"error": "ids and tags required"})
		return
	}
	if req.Action != "add" && req.Action != "remove" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "action must be 'add' or 'remove'"})
		return
	}

	var subs []models.Subdomain
	if err := h.db.Where("org_id = ? AND id IN ?", user.OrgID, req.IDs).Find(&subs).Error; err != nil {
		h.log.Warnw("tag subs query failed", "error", err)
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to fetch subdomains"})
		return
	}

	for i := range subs {
		existing := map[string]bool{}
		for _, t := range subs[i].Tags {
			existing[t] = true
		}
		if req.Action == "add" {
			for _, t := range req.Tags {
				existing[t] = true
			}
		} else {
			for _, t := range req.Tags {
				delete(existing, t)
			}
		}
		newTags := make(models.StringArray, 0, len(existing))
		for t := range existing {
			newTags = append(newTags, t)
		}
		if err := h.db.Model(&subs[i]).Update("tags", newTags).Error; err != nil {
			h.log.Warnw("subdomain tag update failed", "id", subs[i].ID, "error", err)
		}
	}
	c.JSON(http.StatusOK, gin.H{"updated": len(subs)})
}

// Service History

type ServiceHistoryHandler struct {
	db  *gorm.DB
	log *zap.SugaredLogger
}

func NewServiceHistoryHandler(db *gorm.DB, log *zap.SugaredLogger) *ServiceHistoryHandler {
	return &ServiceHistoryHandler{db: db, log: log}
}

func (h *ServiceHistoryHandler) ForHost(c *gin.Context) {
	user := middleware.GetUser(c)
	if user == nil {
		c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{"error": "unauthorized"})
		return
	}
	var host models.Host
	if err := h.db.Where("id = ? AND org_id = ?", c.Param("id"), user.OrgID).First(&host).Error; err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "host not found"})
		return
	}

	q := h.db.Model(&models.ServiceHistory{}).
		Where("org_id = ? AND (host_id = ? OR host_ref = ?)", user.OrgID, host.ID, host.IP).
		Order("created_at desc")

	if port := c.Query("port"); port != "" {
		q = q.Where("port = ?", port)
	}
	if proto := c.Query("protocol"); proto != "" {
		q = q.Where("protocol = ?", proto)
	}

	var history []models.ServiceHistory
	if err := q.Limit(500).Find(&history).Error; err != nil {
		h.log.Warnw("tool history query failed", "error", err)
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to fetch tool history"})
		return
	}
	c.JSON(http.StatusOK, gin.H{"data": history, "total": len(history)})
}

// RecordServiceHistory is a convenience alias so existing call sites in this
// package continue to compile. The canonical implementation lives in
// internal/models so it can be called from the scan pipeline without an
// import cycle.
func RecordServiceHistory(db *gorm.DB, svc models.Service, scanJobID *uuid.UUID) {
	models.RecordServiceHistory(db, svc, scanJobID)
}

// TLS Check — pure Go
// GET /toolbox/tls-check?target=hostname[:port]

func (h *ToolboxHandler) TLSCheck(c *gin.Context) {
	if middleware.GetUser(c) == nil {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "unauthorized"})
		return
	}
	target := strings.TrimSpace(c.Query("target"))
	if target == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "target required"})
		return
	}
	target = strings.TrimPrefix(target, "https://")
	target = strings.TrimPrefix(target, "http://")
	target = strings.TrimSuffix(target, "/")

	host, port, err := net.SplitHostPort(target)
	if err != nil {
		host = target
		port = "443"
	}
	addr := net.JoinHostPort(host, port)

	type VersionResult struct {
		Supported bool   `json:"supported"`
		Cipher    string `json:"cipher,omitempty"`
		ErrorMsg  string `json:"error,omitempty"`
	}

	tlsVersions := []struct {
		name string
		ver  uint16
	}{
		{"TLSv1.0", tls.VersionTLS10},
		{"TLSv1.1", tls.VersionTLS11},
		{"TLSv1.2", tls.VersionTLS12},
		{"TLSv1.3", tls.VersionTLS13},
	}

	versionSupport := map[string]VersionResult{}
	for _, v := range tlsVersions {
		conf := &tls.Config{
			MinVersion:         v.ver,
			MaxVersion:         v.ver,
			InsecureSkipVerify: true, // #nosec G402 — intentional scanner
			ServerName:         host,
		}
		conn, dialErr := tls.DialWithDialer(&net.Dialer{Timeout: 4 * time.Second}, "tcp", addr, conf)
		if dialErr != nil {
			versionSupport[v.name] = VersionResult{Supported: false, ErrorMsg: dialErr.Error()}
			continue
		}
		cs := conn.ConnectionState()
		_ = conn.Close()
		versionSupport[v.name] = VersionResult{Supported: true, Cipher: tls.CipherSuiteName(cs.CipherSuite)}
	}

	// Full handshake for cert chain
	conf := &tls.Config{InsecureSkipVerify: true, ServerName: host} // #nosec G402
	fullConn, fullErr := tls.DialWithDialer(&net.Dialer{Timeout: 8 * time.Second}, "tcp", addr, conf)

	type CertInfo struct {
		Subject       string    `json:"subject"`
		Issuer        string    `json:"issuer"`
		SANs          []string  `json:"sans"`
		NotBefore     time.Time `json:"not_before"`
		NotAfter      time.Time `json:"not_after"`
		DaysRemaining int       `json:"days_remaining"`
		Expired       bool      `json:"expired"`
		SelfSigned    bool      `json:"self_signed"`
		SigAlgorithm  string    `json:"sig_algorithm"`
	}

	var certChain []CertInfo
	var negotiatedVersion, negotiatedCipher string

	if fullErr == nil {
		cs := fullConn.ConnectionState()
		negotiatedCipher = tls.CipherSuiteName(cs.CipherSuite)
		switch cs.Version {
		case tls.VersionTLS13:
			negotiatedVersion = "TLSv1.3"
		case tls.VersionTLS12:
			negotiatedVersion = "TLSv1.2"
		case tls.VersionTLS11:
			negotiatedVersion = "TLSv1.1"
		case tls.VersionTLS10:
			negotiatedVersion = "TLSv1.0"
		}
		for _, cert := range cs.PeerCertificates {
			daysLeft := int(time.Until(cert.NotAfter).Hours() / 24)
			certChain = append(certChain, CertInfo{
				Subject:       cert.Subject.CommonName,
				Issuer:        cert.Issuer.CommonName,
				SANs:          cert.DNSNames,
				NotBefore:     cert.NotBefore,
				NotAfter:      cert.NotAfter,
				DaysRemaining: daysLeft,
				Expired:       daysLeft < 0,
				SelfSigned:    cert.Issuer.CommonName == cert.Subject.CommonName,
				SigAlgorithm:  cert.SignatureAlgorithm.String(),
			})
		}
		_ = fullConn.Close()
	}

	var issues []string
	if r, ok := versionSupport["TLSv1.0"]; ok && r.Supported {
		issues = append(issues, "TLSv1.0 accepted (deprecated, RFC 8996)")
	}
	if r, ok := versionSupport["TLSv1.1"]; ok && r.Supported {
		issues = append(issues, "TLSv1.1 accepted (deprecated, RFC 8996)")
	}
	for _, ci := range certChain {
		if ci.Expired {
			issues = append(issues, fmt.Sprintf("Certificate expired: %s", ci.Subject))
		} else if ci.DaysRemaining < 14 {
			issues = append(issues, fmt.Sprintf("Certificate expiring in %d days: %s", ci.DaysRemaining, ci.Subject))
		}
		if ci.SelfSigned {
			issues = append(issues, fmt.Sprintf("Self-signed certificate: %s", ci.Subject))
		}
	}
	if strings.Contains(negotiatedCipher, "RC4") || strings.Contains(negotiatedCipher, "3DES") || strings.Contains(negotiatedCipher, "NULL") {
		issues = append(issues, "Weak cipher negotiated: "+negotiatedCipher)
	}
	if len(issues) == 0 {
		issues = []string{}
	}

	c.JSON(http.StatusOK, gin.H{
		"target":             fmt.Sprintf("%s:%s", host, port),
		"host":               host,
		"port":               port,
		"negotiated_version": negotiatedVersion,
		"negotiated_cipher":  negotiatedCipher,
		"version_support":    versionSupport,
		"certificate_chain":  certChain,
		"issues":             issues,
		"issues_count":       len(issues),
	})
}

// Port Scan — pure Go (internal/modules/port), no nmap/naabu/masscan binary
// required. Quick on-demand lookup for the Toolbox panel, distinct from the
// scheduled recon pipeline's own port-scanning (internal/modules/discovery),
// which this reuses the same worker-pool scanner package as.
// GET /toolbox/port-scan?target=host_or_ip[&ports=quick|top100|22,80,443][&banner=true]
func (h *ToolboxHandler) PortScan(c *gin.Context) {
	if middleware.GetUser(c) == nil {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "unauthorized"})
		return
	}
	target := strings.TrimSpace(c.Query("target"))
	if target == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "target required"})
		return
	}
	target = strings.TrimPrefix(target, "https://")
	target = strings.TrimPrefix(target, "http://")
	if slash := strings.Index(target, "/"); slash != -1 {
		target = target[:slash]
	}
	if host, _, err := net.SplitHostPort(target); err == nil {
		target = host
	}

	profile := strings.ToLower(strings.TrimSpace(c.DefaultQuery("ports", "quick")))
	var ports []int
	switch profile {
	case "", "quick":
		ports = port.CommonPorts
	case "top100":
		ports = port.CommonPorts
		if len(ports) > 100 {
			ports = ports[:100]
		}
	default:
		// Treat the value as an explicit comma-separated port list.
		for _, p := range strings.Split(profile, ",") {
			p = strings.TrimSpace(p)
			if p == "" {
				continue
			}
			n, err := strconv.Atoi(p)
			if err != nil || n < 1 || n > 65535 {
				c.JSON(http.StatusBadRequest, gin.H{"error": fmt.Sprintf("invalid port: %q", p)})
				return
			}
			ports = append(ports, n)
		}
		if len(ports) == 0 {
			c.JSON(http.StatusBadRequest, gin.H{"error": "ports must be 'quick', 'top100', or a comma-separated list"})
			return
		}
		if len(ports) > 1000 {
			c.JSON(http.StatusBadRequest, gin.H{"error": "at most 1000 explicit ports per request; use the full scan pipeline for larger ranges"})
			return
		}
	}

	bannerGrab := c.DefaultQuery("banner", "true") != "false"

	ctx, cancel := context.WithTimeout(c.Request.Context(), 45*time.Second)
	defer cancel()

	scanner := port.NewScanner(h.log)
	resultsCh, err := scanner.Scan(ctx, port.ScanOptions{
		Hosts:      []string{target},
		Ports:      ports,
		Timeout:    800 * time.Millisecond,
		Workers:    150,
		BannerGrab: bannerGrab,
	})
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "port scan failed to start: " + err.Error()})
		return
	}

	type openPortResult struct {
		Port    int    `json:"port"`
		Service string `json:"service"`
		Banner  string `json:"banner,omitempty"`
		Latency string `json:"latency"`
	}
	var open []openPortResult
	for r := range resultsCh {
		open = append(open, openPortResult{
			Port:    r.Port,
			Service: r.Service,
			Banner:  strings.TrimSpace(r.Banner),
			Latency: r.Latency.Round(time.Millisecond).String(),
		})
	}
	sort.Slice(open, func(i, j int) bool { return open[i].Port < open[j].Port })
	if open == nil {
		open = []openPortResult{}
	}

	c.JSON(http.StatusOK, gin.H{
		"target":       target,
		"profile":      profile,
		"ports_probed": len(ports),
		"open_ports":   open,
		"open_count":   len(open),
	})
}

// IP Geolocation — ip-api.com (free, no key required)
// GET /toolbox/geoip?ip=1.2.3.4

func (h *ToolboxHandler) GeoIP(c *gin.Context) {
	if middleware.GetUser(c) == nil {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "unauthorized"})
		return
	}
	ip := strings.TrimSpace(c.Query("ip"))
	if ip == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "ip required"})
		return
	}
	if net.ParseIP(ip) == nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid IP address"})
		return
	}

	fields := "status,message,country,countryCode,region,regionName,city,zip,lat,lon,timezone,isp,org,as,asname,reverse,mobile,proxy,hosting,query"
	url := fmt.Sprintf("http://ip-api.com/json/%s?fields=%s", ip, fields)

	client := &http.Client{Timeout: 8 * time.Second}
	resp, err := client.Get(url)
	if err != nil {
		c.JSON(http.StatusBadGateway, gin.H{"error": "geolocation lookup failed: " + err.Error()})
		return
	}
	defer func() { _ = resp.Body.Close() }()

	var result map[string]interface{}
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to parse response"})
		return
	}
	c.JSON(http.StatusOK, gin.H{"ip": ip, "data": result})
}
