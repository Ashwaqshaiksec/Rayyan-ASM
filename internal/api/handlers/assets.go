package handlers

import (
	"net/http"
	"strconv"
	"time"

	"github.com/ShadooowX/rayyan-asm/internal/api/middleware"
	"github.com/ShadooowX/rayyan-asm/internal/models"
	dnsmod "github.com/ShadooowX/rayyan-asm/internal/modules/dns"
	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
	"go.uber.org/zap"
	"gorm.io/gorm"
)

type DomainHandler struct {
	db  *gorm.DB
	log *zap.SugaredLogger
}

func NewDomainHandler(db *gorm.DB, log *zap.SugaredLogger) *DomainHandler {
	return &DomainHandler{db: db, log: log}
}

func (h *DomainHandler) List(c *gin.Context) {
	user := middleware.GetUser(c)
	if user == nil {
		c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{"error": "unauthorized"})
		return
	}
	var domains []models.Domain
	q := dbCtx(h.db, c).Where("org_id = ?", user.OrgID)

	if tags := c.Query("tags"); tags != "" {
		q = q.Where("? = ANY(tags)", tags)
	}
	if env := c.Query("environment"); env != "" {
		q = q.Where("environment = ?", env)
	}

	page, _ := strconv.Atoi(c.DefaultQuery("page", "1"))
	limit, _ := strconv.Atoi(c.DefaultQuery("limit", "50"))
	if page < 1 {
		page = 1
	}
	if limit < 1 || limit > MaxPageLimit {
		limit = 50
	}
	offset := (page - 1) * limit

	var total int64
	q.Model(&models.Domain{}).Count(&total)
	if err := q.Offset(offset).Limit(limit).Order("created_at desc").Find(&domains).Error; err != nil {
		h.log.Warnw("domains list failed", "error", err)
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to fetch domains"})
		return
	}

	c.JSON(http.StatusOK, gin.H{"data": domains, "total": total, "page": page, "limit": limit})
}

type createDomainRequest struct {
	Name         string   `json:"name" binding:"required"`
	Status       string   `json:"status"`
	Environment  string   `json:"environment"`
	Tags         []string `json:"tags"`
	Owner        string   `json:"owner"`
	BusinessUnit string   `json:"business_unit"`
	Notes        string   `json:"notes"`
}

func (h *DomainHandler) Create(c *gin.Context) {
	user := middleware.GetUser(c)
	if user == nil {
		c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{"error": "unauthorized"})
		return
	}
	var req createDomainRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	domain := models.Domain{
		Base:         models.Base{ID: uuid.New()},
		OrgID:        user.OrgID,
		Name:         req.Name,
		Status:       req.Status,
		Environment:  req.Environment,
		Tags:         models.StringArray(req.Tags),
		Owner:        req.Owner,
		BusinessUnit: req.BusinessUnit,
		Notes:        req.Notes,
	}
	if err := h.db.Create(&domain).Error; err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to create domain"})
		return
	}
	c.JSON(http.StatusCreated, domain)
}

func (h *DomainHandler) Get(c *gin.Context) {
	user := middleware.GetUser(c)
	if user == nil {
		c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{"error": "unauthorized"})
		return
	}
	var domain models.Domain
	if err := h.db.Where("id = ? AND org_id = ?", c.Param("id"), user.OrgID).First(&domain).Error; err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "domain not found"})
		return
	}
	c.JSON(http.StatusOK, domain)
}

type updateDomainRequest struct {
	Name         *string   `json:"name"`
	Status       *string   `json:"status"`
	Environment  *string   `json:"environment"`
	Tags         *[]string `json:"tags"`
	Owner        *string   `json:"owner"`
	BusinessUnit *string   `json:"business_unit"`
	Notes        *string   `json:"notes"`
	Monitored    *bool     `json:"monitored"`
}

func (h *DomainHandler) Update(c *gin.Context) {
	user := middleware.GetUser(c)
	if user == nil {
		c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{"error": "unauthorized"})
		return
	}
	var domain models.Domain
	if err := h.db.Where("id = ? AND org_id = ?", c.Param("id"), user.OrgID).First(&domain).Error; err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "domain not found"})
		return
	}
	var req updateDomainRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	if req.Name != nil {
		domain.Name = *req.Name
	}
	if req.Status != nil {
		domain.Status = *req.Status
	}
	if req.Environment != nil {
		domain.Environment = *req.Environment
	}
	if req.Tags != nil {
		domain.Tags = models.StringArray(*req.Tags)
	}
	if req.Owner != nil {
		domain.Owner = *req.Owner
	}
	if req.BusinessUnit != nil {
		domain.BusinessUnit = *req.BusinessUnit
	}
	if req.Notes != nil {
		domain.Notes = *req.Notes
	}
	if req.Monitored != nil {
		domain.Monitored = *req.Monitored
	}
	if err := h.db.Save(&domain).Error; err != nil {
		h.log.Warnw("failed to update domain", "error", err)
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to update domain"})
		return
	}
	c.JSON(http.StatusOK, domain)
}

func (h *DomainHandler) Delete(c *gin.Context) {
	user := middleware.GetUser(c)
	if user == nil {
		c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{"error": "unauthorized"})
		return
	}
	result := h.db.Where("id = ? AND org_id = ?", c.Param("id"), user.OrgID).Delete(&models.Domain{})
	if result.Error != nil {
		h.log.Warnw("failed to delete domain", "error", result.Error)
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to delete domain"})
		return
	}
	if result.RowsAffected == 0 {
		c.JSON(http.StatusNotFound, gin.H{"error": "domain not found"})
		return
	}
	c.JSON(http.StatusOK, gin.H{"message": "deleted"})
}

func (h *DomainHandler) Subdomains(c *gin.Context) {
	user := middleware.GetUser(c)
	if user == nil {
		c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{"error": "unauthorized"})
		return
	}
	var subs []models.Subdomain
	if err := h.db.Where("domain_id = ? AND org_id = ?", c.Param("id"), user.OrgID).Find(&subs).Error; err != nil {
		h.log.Warnw("domain subdomains query failed", "error", err)
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to fetch subdomains"})
		return
	}
	c.JSON(http.StatusOK, gin.H{"data": subs, "total": len(subs)})
}

func (h *DomainHandler) DNSRecords(c *gin.Context) {
	user := middleware.GetUser(c)
	if user == nil {
		c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{"error": "unauthorized"})
		return
	}
	var records []models.DNSRecord
	if err := h.db.Where("domain_id = ? AND org_id = ?", c.Param("id"), user.OrgID).Find(&records).Error; err != nil {
		h.log.Warnw("domain DNS records query failed", "error", err)
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to fetch DNS records"})
		return
	}
	c.JSON(http.StatusOK, gin.H{"data": records, "total": len(records)})
}

func (h *DomainHandler) ListSubdomains(c *gin.Context) {
	user := middleware.GetUser(c)
	if user == nil {
		c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{"error": "unauthorized"})
		return
	}
	var subs []models.Subdomain
	q := h.db.Where("org_id = ?", user.OrgID)

	page, _ := strconv.Atoi(c.DefaultQuery("page", "1"))
	limit, _ := strconv.Atoi(c.DefaultQuery("limit", "50"))
	if page < 1 {
		page = 1
	}
	if limit < 1 || limit > MaxPageLimit {
		limit = 50
	}
	offset := (page - 1) * limit

	var total int64
	q.Model(&models.Subdomain{}).Count(&total)
	if err := q.Offset(offset).Limit(limit).Order("created_at desc").Find(&subs).Error; err != nil {
		h.log.Warnw("subdomains list failed", "error", err)
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to fetch subdomains"})
		return
	}
	c.JSON(http.StatusOK, gin.H{"data": subs, "total": total, "page": page, "limit": limit})
}

func (h *DomainHandler) GetSubdomain(c *gin.Context) {
	user := middleware.GetUser(c)
	if user == nil {
		c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{"error": "unauthorized"})
		return
	}
	var sub models.Subdomain
	if err := h.db.Where("id = ? AND org_id = ?", c.Param("id"), user.OrgID).First(&sub).Error; err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "subdomain not found"})
		return
	}
	c.JSON(http.StatusOK, sub)
}

type HostHandler struct {
	db  *gorm.DB
	log *zap.SugaredLogger
}

func NewHostHandler(db *gorm.DB, log *zap.SugaredLogger) *HostHandler {
	return &HostHandler{db: db, log: log}
}

func (h *HostHandler) List(c *gin.Context) {
	user := middleware.GetUser(c)
	if user == nil {
		c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{"error": "unauthorized"})
		return
	}
	var hosts []models.Host

	q := dbCtx(h.db, c).Where("org_id = ?", user.OrgID)
	if provider := c.Query("provider"); provider != "" {
		q = q.Where("provider = ?", provider)
	}
	if status := c.Query("status"); status != "" {
		q = q.Where("status = ?", status)
	}
	if env := c.Query("environment"); env != "" {
		q = q.Where("environment = ?", env)
	}

	page, _ := strconv.Atoi(c.DefaultQuery("page", "1"))
	limit, _ := strconv.Atoi(c.DefaultQuery("limit", "50"))
	if page < 1 {
		page = 1
	}
	if limit < 1 || limit > MaxPageLimit {
		limit = 50
	}
	offset := (page - 1) * limit

	var total int64
	q.Model(&models.Host{}).Count(&total)
	if err := q.Offset(offset).Limit(limit).Order("last_seen_at desc").Find(&hosts).Error; err != nil {
		h.log.Warnw("hosts list failed", "error", err)
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to fetch hosts"})
		return
	}

	c.JSON(http.StatusOK, gin.H{"data": hosts, "total": total, "page": page, "limit": limit})
}

type createHostRequest struct {
	IP          string `json:"ip" binding:"required"`
	Hostname    string `json:"hostname"`
	Provider    string `json:"provider"`
	Status      string `json:"status"`
	Environment string `json:"environment"`
	ASN         string `json:"asn"`
	ASNOrg      string `json:"asn_org"`
	Country     string `json:"country"`
}

func (h *HostHandler) Create(c *gin.Context) {
	user := middleware.GetUser(c)
	if user == nil {
		c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{"error": "unauthorized"})
		return
	}
	var req createHostRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	host := models.Host{
		Base:        models.Base{ID: uuid.New()},
		OrgID:       user.OrgID,
		IP:          req.IP,
		Hostname:    req.Hostname,
		Provider:    req.Provider,
		Status:      req.Status,
		Environment: req.Environment,
		ASN:         req.ASN,
		ASNOrg:      req.ASNOrg,
		Country:     req.Country,
	}
	if err := h.db.Create(&host).Error; err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to create host"})
		return
	}
	c.JSON(http.StatusCreated, host)
}

func (h *HostHandler) Get(c *gin.Context) {
	user := middleware.GetUser(c)
	if user == nil {
		c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{"error": "unauthorized"})
		return
	}
	var host models.Host
	if err := h.db.Preload("Services.Technologies").Where("id = ? AND org_id = ?", c.Param("id"), user.OrgID).First(&host).Error; err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "host not found"})
		return
	}
	c.JSON(http.StatusOK, host)
}

type updateHostRequest struct {
	Hostname     *string   `json:"hostname"`
	Status       *string   `json:"status"`
	Environment  *string   `json:"environment"`
	Provider     *string   `json:"provider"`
	HostType     *string   `json:"host_type"`
	OS           *string   `json:"os"`
	OSVersion    *string   `json:"os_version"`
	Tags         *[]string `json:"tags"`
	Owner        *string   `json:"owner"`
	BusinessUnit *string   `json:"business_unit"`
	Notes        *string   `json:"notes"`
	Monitored    *bool     `json:"monitored"`
}

func (h *HostHandler) Update(c *gin.Context) {
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
	var req updateHostRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	if req.Hostname != nil {
		host.Hostname = *req.Hostname
	}
	if req.Status != nil {
		host.Status = *req.Status
	}
	if req.Environment != nil {
		host.Environment = *req.Environment
	}
	if req.Provider != nil {
		host.Provider = *req.Provider
	}
	if req.HostType != nil {
		host.HostType = *req.HostType
	}
	if req.OS != nil {
		host.OS = *req.OS
	}
	if req.OSVersion != nil {
		host.OSVersion = *req.OSVersion
	}
	if req.Tags != nil {
		host.Tags = models.StringArray(*req.Tags)
	}
	if req.Owner != nil {
		host.Owner = *req.Owner
	}
	if req.BusinessUnit != nil {
		host.BusinessUnit = *req.BusinessUnit
	}
	if req.Notes != nil {
		host.Notes = *req.Notes
	}
	if req.Monitored != nil {
		host.Monitored = *req.Monitored
	}
	if err := h.db.Save(&host).Error; err != nil {
		h.log.Warnw("failed to update host", "error", err)
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to update host"})
		return
	}
	c.JSON(http.StatusOK, host)
}

func (h *HostHandler) Delete(c *gin.Context) {
	user := middleware.GetUser(c)
	if user == nil {
		c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{"error": "unauthorized"})
		return
	}
	result := h.db.Where("id = ? AND org_id = ?", c.Param("id"), user.OrgID).Delete(&models.Host{})
	if result.Error != nil {
		h.log.Warnw("failed to delete host", "error", result.Error)
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to delete host"})
		return
	}
	if result.RowsAffected == 0 {
		c.JSON(http.StatusNotFound, gin.H{"error": "host not found"})
		return
	}
	c.JSON(http.StatusOK, gin.H{"message": "deleted"})
}

func (h *HostHandler) Services(c *gin.Context) {
	user := middleware.GetUser(c)
	if user == nil {
		c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{"error": "unauthorized"})
		return
	}
	var services []models.Service
	if err := h.db.Preload("Technologies").Where("host_id = ? AND org_id = ?", c.Param("id"), user.OrgID).Find(&services).Error; err != nil {
		h.log.Warnw("host services query failed", "error", err)
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to fetch services"})
		return
	}
	c.JSON(http.StatusOK, gin.H{"data": services, "total": len(services)})
}

type ServiceHandler struct {
	db  *gorm.DB
	log *zap.SugaredLogger
}

func NewServiceHandler(db *gorm.DB, log *zap.SugaredLogger) *ServiceHandler {
	return &ServiceHandler{db: db, log: log}
}

func (h *ServiceHandler) List(c *gin.Context) {
	user := middleware.GetUser(c)
	if user == nil {
		c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{"error": "unauthorized"})
		return
	}
	var services []models.Service

	q := dbCtx(h.db, c).Where("org_id = ?", user.OrgID)
	if proto := c.Query("protocol"); proto != "" {
		q = q.Where("protocol = ?", proto)
	}
	if port := c.Query("port"); port != "" {
		q = q.Where("port = ?", port)
	}
	if state := c.Query("state"); state != "" {
		q = q.Where("state = ?", state)
	}

	page, _ := strconv.Atoi(c.DefaultQuery("page", "1"))
	limit, _ := strconv.Atoi(c.DefaultQuery("limit", "100"))
	if page < 1 {
		page = 1
	}
	if limit < 1 || limit > MaxPageLimit {
		limit = 100
	}
	offset := (page - 1) * limit

	var total int64
	q.Model(&models.Service{}).Count(&total)
	if err := q.Offset(offset).Limit(limit).Order("port asc").Find(&services).Error; err != nil {
		h.log.Warnw("services list failed", "error", err)
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to fetch services"})
		return
	}

	c.JSON(http.StatusOK, gin.H{"data": services, "total": total, "page": page, "limit": limit})
}

func (h *ServiceHandler) Get(c *gin.Context) {
	user := middleware.GetUser(c)
	if user == nil {
		c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{"error": "unauthorized"})
		return
	}
	var svc models.Service
	if err := h.db.Where("id = ? AND org_id = ?", c.Param("id"), user.OrgID).First(&svc).Error; err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "service not found"})
		return
	}
	c.JSON(http.StatusOK, svc)
}

type CertificateHandler struct {
	db  *gorm.DB
	log *zap.SugaredLogger
}

func NewCertificateHandler(db *gorm.DB, log *zap.SugaredLogger) *CertificateHandler {
	return &CertificateHandler{db: db, log: log}
}

func (h *CertificateHandler) List(c *gin.Context) {
	user := middleware.GetUser(c)
	if user == nil {
		c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{"error": "unauthorized"})
		return
	}
	var certs []models.Certificate

	page, _ := strconv.Atoi(c.DefaultQuery("page", "1"))
	limit, _ := strconv.Atoi(c.DefaultQuery("limit", "50"))
	if page < 1 {
		page = 1
	}
	if limit < 1 || limit > MaxPageLimit {
		limit = 50
	}
	offset := (page - 1) * limit

	var total int64
	q := dbCtx(h.db, c).Where("org_id = ?", user.OrgID)
	q.Model(&models.Certificate{}).Count(&total)
	if err := q.Offset(offset).Limit(limit).Order("not_after asc").Find(&certs).Error; err != nil {
		h.log.Warnw("certificates list failed", "error", err)
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to fetch certificates"})
		return
	}

	c.JSON(http.StatusOK, gin.H{"data": certs, "total": total, "page": page, "limit": limit})
}

func (h *CertificateHandler) Get(c *gin.Context) {
	user := middleware.GetUser(c)
	if user == nil {
		c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{"error": "unauthorized"})
		return
	}
	var cert models.Certificate
	if err := h.db.Where("id = ? AND org_id = ?", c.Param("id"), user.OrgID).First(&cert).Error; err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "certificate not found"})
		return
	}
	c.JSON(http.StatusOK, cert)
}

func (h *CertificateHandler) Expiring(c *gin.Context) {
	user := middleware.GetUser(c)
	if user == nil {
		c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{"error": "unauthorized"})
		return
	}
	days, _ := strconv.Atoi(c.DefaultQuery("days", "30"))
	cutoff := time.Now().AddDate(0, 0, days)
	var certs []models.Certificate
	if err := dbCtx(h.db, c).Where("org_id = ? AND not_after < ?", user.OrgID, cutoff).
		Order("not_after asc").Find(&certs).Error; err != nil {
		h.log.Warnw("expiring certs query failed", "error", err)
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to fetch expiring certificates"})
		return
	}
	c.JSON(http.StatusOK, gin.H{"data": certs, "total": len(certs)})
}

type DNSHandler struct {
	db  *gorm.DB
	log *zap.SugaredLogger
}

func NewDNSHandler(db *gorm.DB, log *zap.SugaredLogger) *DNSHandler {
	return &DNSHandler{db: db, log: log}
}

func (h *DNSHandler) List(c *gin.Context) {
	user := middleware.GetUser(c)
	if user == nil {
		c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{"error": "unauthorized"})
		return
	}
	var records []models.DNSRecord

	q := dbCtx(h.db, c).Where("org_id = ?", user.OrgID)
	if t := c.Query("type"); t != "" {
		q = q.Where("type = ?", t)
	}

	page, _ := strconv.Atoi(c.DefaultQuery("page", "1"))
	limit, _ := strconv.Atoi(c.DefaultQuery("limit", "100"))
	if page < 1 {
		page = 1
	}
	if limit < 1 || limit > MaxPageLimit {
		limit = 100
	}
	offset := (page - 1) * limit

	var total int64
	q.Model(&models.DNSRecord{}).Count(&total)
	if err := q.Preload("Domain").Offset(offset).Limit(limit).Order("name asc").Find(&records).Error; err != nil {
		h.log.Warnw("DNS records list failed", "error", err)
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to fetch DNS records"})
		return
	}
	// Domain itself is json:"-" (avoids pulling the whole domain row into
	// every record), so surface just the name the UI needs directly.
	for i := range records {
		records[i].DomainName = records[i].Domain.Name
	}

	c.JSON(http.StatusOK, gin.H{"data": records, "total": total, "page": page, "limit": limit})
}

// EmailSecurity GET /domains/:id/email-security
// Runs SPF, DKIM, and DMARC checks for the domain and returns the results.
func (h *DNSHandler) EmailSecurity(c *gin.Context) {
	user := middleware.GetUser(c)
	if user == nil {
		c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{"error": "unauthorized"})
		return
	}

	domainID, err := uuid.Parse(c.Param("id"))
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid domain ID"})
		return
	}

	var domain models.Domain
	if err := dbCtx(h.db, c).Where("id = ? AND org_id = ?", domainID, user.OrgID).First(&domain).Error; err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "domain not found"})
		return
	}

	result := dnsmod.CheckEmailSecurity(c.Request.Context(), domain.Name, 10*time.Second)
	c.JSON(http.StatusOK, result)
}
