package models

import (
	"time"

	"github.com/google/uuid"
	"gorm.io/gorm"
)

type Base struct {
	ID        uuid.UUID      `gorm:"type:uuid;primary_key" json:"id"`
	CreatedAt time.Time      `json:"created_at"`
	UpdatedAt time.Time      `json:"updated_at"`
	DeletedAt gorm.DeletedAt `gorm:"index" json:"-"`
}

func (b *Base) BeforeCreate(tx *gorm.DB) error {
	if b.ID == uuid.Nil {
		b.ID = uuid.New()
	}
	return nil
}

// Organization — tenant/org boundary
type Organization struct {
	Base
	Name               string `gorm:"uniqueIndex;not null" json:"name"`
	Slug               string `gorm:"uniqueIndex;not null" json:"slug"`
	Description        string `json:"description"`
	LogoURL            string `json:"logo_url"`
	Plan               string `gorm:"default:'free'" json:"plan"`
	MaxAssets          int    `gorm:"default:1000" json:"max_assets"`
	MaxConcurrentScans int    `gorm:"default:0" json:"max_concurrent_scans"` // 0 = use plan default, see defaultMaxConcurrentScans
	Active             bool   `gorm:"default:true" json:"active"`
	Settings           JSONB  `gorm:"type:jsonb" json:"settings"`

	Users   []User   `gorm:"foreignKey:OrgID" json:"-"`
	Domains []Domain `gorm:"foreignKey:OrgID" json:"-"`
	Hosts   []Host   `gorm:"foreignKey:OrgID" json:"-"`
}

// User
type User struct {
	Base
	OrgID         uuid.UUID  `gorm:"type:uuid;index;not null" json:"org_id"`
	Email         string     `gorm:"uniqueIndex;not null" json:"email"`
	Username      string     `gorm:"uniqueIndex;not null" json:"username"`
	PasswordHash  string     `gorm:"not null" json:"-"`
	FirstName     string     `json:"first_name"`
	LastName      string     `json:"last_name"`
	Role          string     `gorm:"default:'viewer'" json:"role"`
	MFAEnabled    bool       `gorm:"default:false" json:"mfa_enabled"`
	MFASecret     string     `json:"-"`
	Active        bool       `gorm:"default:true" json:"active"`
	EmailVerified bool       `gorm:"default:false" json:"email_verified"`
	LastLoginAt   *time.Time `json:"last_login_at"`
	LoginAttempts int        `gorm:"default:0" json:"-"`
	LockedUntil   *time.Time `json:"-"`
	AvatarURL     string     `json:"avatar_url"`
	Preferences   JSONB      `gorm:"type:jsonb" json:"preferences"`

	Org     Organization `gorm:"foreignKey:OrgID" json:"-"`
	APIKeys []APIKey     `gorm:"foreignKey:UserID" json:"-"`
}

func (u User) FullName() string {
	return u.FirstName + " " + u.LastName
}

// API Key
type APIKey struct {
	Base
	OrgID      uuid.UUID   `gorm:"type:uuid;index;not null" json:"org_id"`
	UserID     uuid.UUID   `gorm:"type:uuid;index;not null" json:"user_id"`
	Name       string      `gorm:"not null" json:"name"`
	KeyHash    string      `gorm:"uniqueIndex;not null" json:"-"`
	KeyPrefix  string      `gorm:"not null" json:"key_prefix"`
	Scopes     StringArray `gorm:"type:text[]" json:"scopes"`
	ExpiresAt  *time.Time  `json:"expires_at"`
	LastUsedAt *time.Time  `json:"last_used_at"`
	Active     bool        `gorm:"default:true" json:"active"`

	User User `gorm:"foreignKey:UserID" json:"-"`
}

// Domain
type Domain struct {
	Base
	OrgID            uuid.UUID   `gorm:"type:uuid;index;not null" json:"org_id"`
	Name             string      `gorm:"not null" json:"name"`
	Registrar        string      `json:"registrar"`
	RegistrationDate *time.Time  `json:"registration_date"`
	ExpiryDate       *time.Time  `json:"expiry_date"`
	Nameservers      StringArray `gorm:"type:text[]" json:"nameservers"`
	Status           string      `gorm:"default:'active'" json:"status"`
	Tags             StringArray `gorm:"type:text[]" json:"tags"`
	Notes            string      `json:"notes"`
	Owner            string      `json:"owner"`
	BusinessUnit     string      `json:"business_unit"`
	Environment      string      `gorm:"default:'production'" json:"environment"`
	Monitored        bool        `gorm:"default:true" json:"monitored"`
	LastScannedAt    *time.Time  `json:"last_scanned_at"`
	ScanCron         string      `json:"scan_cron,omitempty"`              // e.g. "0 2 * * *"
	ScanDepth        string      `gorm:"default:'full'" json:"scan_depth"` // full, quick, passive

	RiskScore    float64    `gorm:"default:0" json:"risk_score"`
	RiskTier     string     `gorm:"default:'low'" json:"risk_tier"` // low, medium, high, critical
	RiskFactors  JSONB      `gorm:"type:jsonb" json:"risk_factors"`
	RiskScoredAt *time.Time `json:"risk_scored_at,omitempty"`

	// DiscoveryJobID traces which external discovery run first surfaced
	// this domain, nil if added manually or via a regular scan.
	DiscoveryJobID *uuid.UUID `gorm:"type:uuid;index" json:"discovery_job_id,omitempty"`

	Org        Organization `gorm:"foreignKey:OrgID" json:"-"`
	Subdomains []Subdomain  `gorm:"foreignKey:DomainID" json:"subdomains,omitempty"`
	DNSRecords []DNSRecord  `gorm:"foreignKey:DomainID" json:"dns_records,omitempty"`
}

// Subdomain
type Subdomain struct {
	Base
	OrgID               uuid.UUID   `gorm:"type:uuid;index;not null" json:"org_id"`
	DomainID            uuid.UUID   `gorm:"type:uuid;index;not null" json:"domain_id"`
	Name                string      `gorm:"not null" json:"name"`
	FQDN                string      `gorm:"uniqueIndex;not null" json:"fqdn"`
	IPs                 StringArray `gorm:"type:text[]" json:"ips"`
	Status              string      `gorm:"default:'active'" json:"status"`
	Source              string      `json:"source"` // dns_brute, ct_log, shodan, etc.
	Tags                StringArray `gorm:"type:text[]" json:"tags"`
	FirstSeenAt         time.Time   `json:"first_seen_at"`
	LastSeenAt          time.Time   `json:"last_seen_at"`
	LastScannedAt       *time.Time  `json:"last_scanned_at"`
	ConsecutiveFailures int         `gorm:"default:0" json:"consecutive_failures"`
	LastCheckedAt       *time.Time  `json:"last_checked_at,omitempty"`
	Dead                bool        `gorm:"default:false" json:"dead"`

	RiskScore    float64    `gorm:"default:0" json:"risk_score"`
	RiskTier     string     `gorm:"default:'low'" json:"risk_tier"` // low, medium, high, critical
	RiskFactors  JSONB      `gorm:"type:jsonb" json:"risk_factors"`
	RiskScoredAt *time.Time `json:"risk_scored_at,omitempty"`

	// DiscoveryJobID traces which external discovery run first surfaced
	// this subdomain, nil if added manually or via a regular scan.
	DiscoveryJobID *uuid.UUID `gorm:"type:uuid;index" json:"discovery_job_id,omitempty"`

	Domain   Domain    `gorm:"foreignKey:DomainID" json:"-"`
	Services []Service `gorm:"foreignKey:HostRef;references:FQDN" json:"services,omitempty"`
}

// Host (IP-centric asset)
type Host struct {
	Base
	OrgID         uuid.UUID   `gorm:"type:uuid;index;not null" json:"org_id"`
	IP            string      `gorm:"index;not null" json:"ip"`
	IPVersion     int         `gorm:"default:4" json:"ip_version"`
	Hostname      string      `json:"hostname"`
	ReverseDNS    string      `json:"reverse_dns"`
	ASN           string      `json:"asn"`
	ASNOrg        string      `json:"asn_org"`
	CIDR          string      `gorm:"column:cidr" json:"cidr"`
	Country       string      `json:"country"`
	City          string      `json:"city"`
	ISP           string      `json:"isp"`
	Provider      string      `json:"provider"` // AWS, Azure, GCP, etc.
	HostType      string      `json:"host_type"`
	Status        string      `gorm:"default:'active'" json:"status"`
	OS            string      `json:"os"`
	OSVersion     string      `json:"os_version"`
	Tags          StringArray `gorm:"type:text[]" json:"tags"`
	Notes         string      `json:"notes"`
	Owner         string      `json:"owner"`
	BusinessUnit  string      `json:"business_unit"`
	Environment   string      `gorm:"default:'production'" json:"environment"`
	Monitored     bool        `gorm:"default:true" json:"monitored"`
	FirstSeenAt   time.Time   `json:"first_seen_at"`
	LastSeenAt    time.Time   `json:"last_seen_at"`
	LastScannedAt *time.Time  `json:"last_scanned_at"`

	RiskScore    float64    `gorm:"default:0" json:"risk_score"`
	RiskTier     string     `gorm:"default:'low'" json:"risk_tier"` // low, medium, high, critical
	RiskFactors  JSONB      `gorm:"type:jsonb" json:"risk_factors"`
	RiskScoredAt *time.Time `json:"risk_scored_at,omitempty"`

	// DiscoveryJobID traces which external discovery run first surfaced
	// this host, nil if added manually or via a regular scan.
	DiscoveryJobID *uuid.UUID `gorm:"type:uuid;index" json:"discovery_job_id,omitempty"`

	Org      Organization `gorm:"foreignKey:OrgID" json:"-"`
	Services []Service    `gorm:"foreignKey:HostID" json:"services,omitempty"`
}

// Service (open port / running service)
type Service struct {
	Base
	OrgID         uuid.UUID  `gorm:"type:uuid;index;not null" json:"org_id"`
	HostID        uuid.UUID  `gorm:"type:uuid;index" json:"host_id"`
	HostRef       string     `gorm:"index" json:"host_ref"`
	Port          int        `gorm:"not null" json:"port"`
	Protocol      string     `gorm:"not null" json:"protocol"` // tcp, udp
	Service       string     `json:"service"`
	Product       string     `json:"product"`
	Version       string     `json:"version"`
	Banner        string     `json:"banner"`
	State         string     `gorm:"default:'open'" json:"state"`
	Tunnel        string     `json:"tunnel"` // ssl, tls
	CPE           string     `json:"cpe"`
	FirstSeenAt   time.Time  `json:"first_seen_at"`
	LastSeenAt    time.Time  `json:"last_seen_at"`
	ContentHash   string     `json:"content_hash,omitempty"`
	LastChangedAt *time.Time `json:"last_changed_at,omitempty"`

	// DiscoveryJobID traces which external discovery run first surfaced
	// this service, nil if added manually or via a regular scan.
	DiscoveryJobID *uuid.UUID `gorm:"type:uuid;index" json:"discovery_job_id,omitempty"`

	Host         Host          `gorm:"foreignKey:HostID" json:"-"`
	Technologies []Technology  `gorm:"foreignKey:ServiceID" json:"technologies,omitempty"`
	Certificates []Certificate `gorm:"foreignKey:ServiceID" json:"certificates,omitempty"`
	WebAssets    []WebAsset    `gorm:"foreignKey:ServiceID" json:"web_assets,omitempty"`
}

// Certificate
type Certificate struct {
	Base
	OrgID           uuid.UUID   `gorm:"type:uuid;index;not null" json:"org_id"`
	ServiceID       *uuid.UUID  `gorm:"type:uuid;index" json:"service_id"`
	Fingerprint     string      `gorm:"uniqueIndex;not null" json:"fingerprint"`
	Subject         string      `json:"subject"`
	Issuer          string      `json:"issuer"`
	SubjectAltNames StringArray `gorm:"type:text[]" json:"subject_alt_names"`
	SerialNumber    string      `json:"serial_number"`
	NotBefore       time.Time   `json:"not_before"`
	NotAfter        time.Time   `json:"not_after"`
	IsExpired       bool        `json:"is_expired"`
	IsWildcard      bool        `json:"is_wildcard"`
	IsSelfSigned    bool        `json:"is_self_signed"`
	SignatureAlg    string      `json:"signature_alg"`
	KeyAlg          string      `json:"key_alg"`
	KeyBits         int         `json:"key_bits"`
	Version         int         `json:"version"`

	// DiscoveryJobID traces which external discovery run first surfaced
	// this certificate, nil if added manually or via a regular scan.
	DiscoveryJobID *uuid.UUID `gorm:"type:uuid;index" json:"discovery_job_id,omitempty"`

	// Metadata stores supplemental findings from the discovery engine
	// that don't warrant a dedicated column yet — currently:
	//   "tls_valid"            bool   — passed OS/CA-pool chain validation
	//   "tls_validation_error" string — reason for failure if !tls_valid
	Metadata JSONB `gorm:"type:jsonb;default:'{}'" json:"metadata,omitempty"`

	Service *Service `gorm:"foreignKey:ServiceID" json:"-"`
}

// DNS Record
type DNSRecord struct {
	Base
	OrgID     uuid.UUID `gorm:"type:uuid;index;not null" json:"org_id"`
	DomainID  uuid.UUID `gorm:"type:uuid;index;not null" json:"domain_id"`
	Name      string    `gorm:"not null" json:"name"`
	Type      string    `gorm:"not null" json:"type"` // A, AAAA, MX, TXT, NS, SOA, PTR
	Value     string    `gorm:"not null" json:"value"`
	TTL       int       `json:"ttl"`
	Priority  int       `json:"priority"` // for MX records
	FirstSeen time.Time `json:"first_seen"`
	LastSeen  time.Time `json:"last_seen"`

	// Preloaded by DNSHandler.List so the frontend can show a readable
	// domain name instead of the raw domain_id UUID; DomainName is a
	// derived convenience field, not a DB column.
	Domain     Domain `gorm:"foreignKey:DomainID" json:"-"`
	DomainName string `gorm:"-" json:"domain_name,omitempty"`
}

// Technology
type Technology struct {
	Base
	OrgID      uuid.UUID  `gorm:"type:uuid;index;not null" json:"org_id"`
	ServiceID  *uuid.UUID `gorm:"type:uuid;index" json:"service_id"`
	Name       string     `gorm:"not null" json:"name"`
	Category   string     `json:"category"`
	Version    string     `json:"version"`
	Confidence int        `json:"confidence"`
	Source     string     `json:"source"`

	Service *Service `gorm:"foreignKey:ServiceID" json:"-"`
}

// Web Asset
type WebAsset struct {
	Base
	OrgID           uuid.UUID   `gorm:"type:uuid;index;not null" json:"org_id"`
	ServiceID       uuid.UUID   `gorm:"type:uuid;index;not null" json:"service_id"`
	URL             string      `gorm:"not null" json:"url"`
	Title           string      `json:"title"`
	StatusCode      int         `json:"status_code"`
	ContentLength   int64       `json:"content_length"`
	ContentType     string      `json:"content_type"`
	Server          string      `json:"server"`
	FinalURL        string      `json:"final_url"` // after redirects
	RedirectChain   StringArray `gorm:"type:text[]" json:"redirect_chain"`
	SecurityHeaders JSONB       `gorm:"type:jsonb" json:"security_headers"`
	HTTPMethods     StringArray `gorm:"type:text[]" json:"http_methods"`
	Screenshotted   bool        `json:"screenshotted"`
	ScreenshotPath  string      `json:"screenshot_path"`
	ScannedAt       time.Time   `json:"scanned_at"`

	Service Service `gorm:"foreignKey:ServiceID" json:"-"`
}

// Scan Job
type ScanJob struct {
	Base
	OrgID       uuid.UUID  `gorm:"type:uuid;index;not null" json:"org_id"`
	CreatedBy   uuid.UUID  `gorm:"type:uuid;index;not null" json:"created_by"`
	Name        string     `gorm:"not null" json:"name"`
	Type        string     `gorm:"not null" json:"type"`
	Workflow    string     `gorm:"default:''" json:"workflow"` // optional: external_asm, bug_bounty, etc.
	Status      string     `gorm:"default:'pending'" json:"status"`
	Priority    int        `gorm:"default:5" json:"priority"`
	Targets     JSONB      `gorm:"type:jsonb;not null" json:"targets"`
	Options     JSONB      `gorm:"type:jsonb" json:"options"`
	Progress    int        `gorm:"default:0" json:"progress"`
	TotalItems  int        `json:"total_items"`
	DoneItems   int        `json:"done_items"`
	Error       string     `json:"error"`
	StartedAt   *time.Time `json:"started_at"`
	CompletedAt *time.Time `json:"completed_at"`
	ScheduledAt *time.Time `json:"scheduled_at"`
	CronExpr    string     `json:"cron_expr"`

	Results []ScanResult `gorm:"foreignKey:JobID" json:"results,omitempty"`
}

// Scan Result
type ScanResult struct {
	Base
	OrgID  uuid.UUID `gorm:"type:uuid;index;not null" json:"org_id"`
	JobID  uuid.UUID `gorm:"type:uuid;index;not null" json:"job_id"`
	Target string    `gorm:"not null" json:"target"`
	Type   string    `gorm:"not null" json:"type"`
	Status string    `json:"status"`
	Data   JSONB     `gorm:"type:jsonb" json:"data"`
	Error  string    `json:"error"`

	Job ScanJob `gorm:"foreignKey:JobID" json:"-"`
}

// Alert
type Alert struct {
	Base
	OrgID      uuid.UUID  `gorm:"type:uuid;index;not null" json:"org_id"`
	Type       string     `gorm:"not null" json:"type"`     // new_asset, cert_expiry, new_service, dns_change
	Severity   string     `gorm:"not null" json:"severity"` // critical, high, medium, low, info
	Title      string     `gorm:"not null" json:"title"`
	Message    string     `json:"message"`
	AssetID    *uuid.UUID `gorm:"type:uuid;index" json:"asset_id"`
	AssetType  string     `json:"asset_type"`
	Data       JSONB      `gorm:"type:jsonb" json:"data"`
	Status     string     `gorm:"default:'open'" json:"status"` // open, acknowledged, resolved
	AckedBy    *uuid.UUID `gorm:"type:uuid" json:"acked_by"`
	AckedAt    *time.Time `json:"acked_at"`
	ResolvedAt *time.Time `json:"resolved_at"`
}

// Report
type Report struct {
	Base
	OrgID       uuid.UUID  `gorm:"type:uuid;index;not null" json:"org_id"`
	CreatedBy   uuid.UUID  `gorm:"type:uuid;index;not null" json:"created_by"`
	Name        string     `gorm:"not null" json:"name"`
	Type        string     `gorm:"not null" json:"type"`   // asset_inventory, service_inventory, exposure, executive
	Format      string     `gorm:"not null" json:"format"` // html, pdf, csv, json, xlsx
	Status      string     `gorm:"default:'pending'" json:"status"`
	FilePath    string     `json:"file_path"`
	FileSize    int64      `json:"file_size"`
	Options     JSONB      `gorm:"type:jsonb" json:"options"`
	GeneratedAt *time.Time `json:"generated_at"`
	ExpiresAt   *time.Time `json:"expires_at"`
}

// Audit Log
type AuditLog struct {
	Base
	OrgID      uuid.UUID `gorm:"type:uuid;index;not null" json:"org_id"`
	UserID     uuid.UUID `gorm:"type:uuid;index;not null" json:"user_id"`
	Action     string    `gorm:"not null" json:"action"`
	Resource   string    `gorm:"not null" json:"resource"`
	ResourceID string    `json:"resource_id"`
	Changes    JSONB     `gorm:"type:jsonb" json:"changes"`
	IP         string    `json:"ip"`
	UserAgent  string    `json:"user_agent"`
	RequestID  string    `json:"request_id"` // correlates with X-Request-ID header
	Success    bool      `json:"success"`
	Error      string    `json:"error"`

	User User `gorm:"foreignKey:UserID" json:"-"`
}

// Cloud Asset
type CloudAsset struct {
	Base
	OrgID        uuid.UUID   `gorm:"type:uuid;uniqueIndex:idx_cloud_asset_key;not null" json:"org_id"`
	Provider     string      `gorm:"not null;uniqueIndex:idx_cloud_asset_key" json:"provider"` // aws, azure, gcp, do, cloudflare
	AccountID    string      `json:"account_id"`
	Region       string      `json:"region"`
	ResourceID   string      `gorm:"not null;uniqueIndex:idx_cloud_asset_key" json:"resource_id"`
	ResourceType string      `gorm:"not null" json:"resource_type"` // ec2, s3, rds, etc.
	Name         string      `json:"name"`
	IPs          StringArray `gorm:"type:text[]" json:"ips"`
	Tags         JSONB       `gorm:"type:jsonb" json:"tags"`
	Metadata     JSONB       `gorm:"type:jsonb" json:"metadata"`
	Status       string      `json:"status"`
	LastSyncedAt *time.Time  `json:"last_synced_at"`
}

// TakeoverFinding stores a confirmed or candidate subdomain takeover result.
type TakeoverFinding struct {
	Base
	OrgID       uuid.UUID  `gorm:"type:uuid;index;not null" json:"org_id"`
	Subdomain   string     `gorm:"not null;index" json:"subdomain"`
	CNAME       string     `json:"cname"`
	Provider    string     `json:"provider"`
	Fingerprint string     `json:"fingerprint"`
	Vulnerable  bool       `gorm:"default:true" json:"vulnerable"`
	Confidence  string     `gorm:"default:'medium'" json:"confidence"` // high | medium | low
	Source      string     `json:"source"`                             // subjack | subzy | nuclei-takeover | dns-takeover-check
	ScanID      *uuid.UUID `gorm:"type:uuid;index" json:"scan_id,omitempty"`
	Remediated  bool       `gorm:"default:false" json:"remediated"`
}

// Finding — vulnerability / web test result
type Finding struct {
	Base
	OrgID       uuid.UUID  `gorm:"type:uuid;index;not null" json:"org_id"`
	ScanJobID   *uuid.UUID `gorm:"type:uuid;index" json:"scan_job_id,omitempty"`
	HostID      *uuid.UUID `gorm:"type:uuid;index" json:"host_id,omitempty"`
	SubdomainID *uuid.UUID `gorm:"type:uuid;index" json:"subdomain_id,omitempty"`

	Title       string  `gorm:"not null" json:"title"`
	Description string  `gorm:"type:text" json:"description"`
	Severity    string  `gorm:"default:'info'" json:"severity"` // critical, high, medium, low, info
	Category    string  `json:"category"`
	URL         string  `json:"url"`
	Evidence    string  `gorm:"type:text" json:"evidence"`
	Remediation string  `gorm:"type:text" json:"remediation"`
	CVSS        float64 `json:"cvss"`
	CVSSVector  string  `gorm:"default:''" json:"cvss_vector"`
	CVSSVersion string  `gorm:"default:'CVSS:3.1'" json:"cvss_version"`
	CVE         string  `json:"cve"`

	Status         string     `gorm:"default:'open'" json:"status"` // open, acknowledged, false_positive, fixed, risk_accepted
	AcknowledgedAt *time.Time `json:"acknowledged_at,omitempty"`
	FixedAt        *time.Time `json:"fixed_at,omitempty"`

	// SLA tracking
	SLADueAt    *time.Time `json:"sla_due_at,omitempty"`
	SLABreached bool       `gorm:"default:false" json:"sla_breached"`
	SLABreachAt *time.Time `json:"sla_breach_at,omitempty"`

	// Risk acceptance
	RiskAccepted     bool       `gorm:"default:false" json:"risk_accepted"`
	RiskAcceptedBy   *uuid.UUID `gorm:"type:uuid" json:"risk_accepted_by,omitempty"`
	RiskAcceptedAt   *time.Time `json:"risk_accepted_at,omitempty"`
	RiskAcceptReason string     `gorm:"type:text" json:"risk_accept_reason,omitempty"`

	// Frameworks lists the compliance/threat framework identifiers this finding
	// maps to (e.g. "OWASP:A01", "MITRE:T1190", "CWE-89", "PCI-DSS:6.3").
	// Stored as a text array so multiple frameworks can be tagged per finding.
	Frameworks StringArray `gorm:"type:text[]" json:"frameworks,omitempty"`

	Org Organization `gorm:"foreignKey:OrgID" json:"-"`
}

// ASNRange — CIDR blocks belonging to an ASN
type ASNRange struct {
	ID        uuid.UUID `gorm:"type:uuid;primary_key" json:"id"`
	CreatedAt time.Time `json:"created_at"`
	OrgID     uuid.UUID `gorm:"type:uuid;index;not null" json:"org_id"`
	ASN       string    `gorm:"index;not null" json:"asn"`
	ASNOrg    string    `json:"asn_org"`
	CIDR      string    `gorm:"column:cidr;not null" json:"cidr"`
	Country   string    `json:"country"`
	RIR       string    `json:"rir"` // ARIN, RIPE, APNIC, AFRINIC, LACNIC
}

func (ASNRange) TableName() string { return "asn_ranges" }

// WHOISHistory — snapshotted WHOIS data per domain
type WHOISHistory struct {
	ID               uuid.UUID   `gorm:"type:uuid;primary_key" json:"id"`
	CreatedAt        time.Time   `json:"created_at"`
	OrgID            uuid.UUID   `gorm:"type:uuid;index;not null" json:"org_id"`
	Domain           string      `gorm:"index;not null" json:"domain"`
	Registrar        string      `json:"registrar"`
	Registrant       string      `json:"registrant"`
	RegistrationDate *time.Time  `json:"registration_date,omitempty"`
	ExpiryDate       *time.Time  `json:"expiry_date,omitempty"`
	Nameservers      StringArray `gorm:"type:text[]" json:"nameservers"`
	Raw              string      `gorm:"type:text" json:"-"`
	SnappedAt        time.Time   `json:"snapped_at"`
}

func (WHOISHistory) TableName() string { return "whois_history" }

// WebhookDelivery — audit log of outbound webhook calls
type WebhookDelivery struct {
	ID            uuid.UUID  `gorm:"type:uuid;primary_key" json:"id"`
	CreatedAt     time.Time  `json:"created_at"`
	OrgID         uuid.UUID  `gorm:"type:uuid;index;not null" json:"org_id"`
	NotifConfigID *uuid.UUID `gorm:"type:uuid;index" json:"notif_config_id,omitempty"`
	AlertID       *uuid.UUID `gorm:"type:uuid;index" json:"alert_id,omitempty"`
	Channel       string     `json:"channel"`
	Endpoint      string     `json:"endpoint"`
	StatusCode    int        `json:"status_code"`
	Success       bool       `json:"success"`
	ErrorMessage  string     `json:"error_message,omitempty"`
	Attempt       int        `gorm:"default:1" json:"attempt"`
	SentAt        time.Time  `json:"sent_at"`
}

func (WebhookDelivery) TableName() string { return "webhook_deliveries" }

// ToolCredential stores encrypted authentication material for external tools
// (e.g. SMB/AD creds for smbclient, enum4linux-ng, crackmapexec).
// The Secret field holds an AES-256-GCM encrypted JSON blob of
// toolrunner/types.ToolCredentials, never logged or returned in API responses.
type ToolCredential struct {
	Base
	OrgID    uuid.UUID `gorm:"type:uuid;index;not null" json:"org_id"`
	ToolName string    `gorm:"index;not null" json:"tool_name"`
	Label    string    `json:"label"`

	// EncryptedSecret is the AES-256-GCM ciphertext (base64) of the
	// JSON-marshalled ToolCredentials struct. Never exposed via JSON.
	EncryptedSecret string `gorm:"type:text;not null" json:"-"`

	CreatedBy uuid.UUID `gorm:"type:uuid" json:"created_by"`

	Org Organization `gorm:"foreignKey:OrgID" json:"-"`
}

func (ToolCredential) TableName() string { return "tool_credentials" }

// Project — distinct workspace for bug bounty / client / personal recon
type Project struct {
	Base
	OrgID       uuid.UUID   `gorm:"type:uuid;index;not null" json:"org_id"`
	CreatedBy   uuid.UUID   `gorm:"type:uuid;index;not null" json:"created_by"`
	Name        string      `gorm:"not null" json:"name"`
	Slug        string      `gorm:"uniqueIndex;not null" json:"slug"`
	Description string      `json:"description"`
	Type        string      `gorm:"default:'general'" json:"type"` // bug_bounty, client, personal, general
	Scope       StringArray `gorm:"type:text[]" json:"scope"`      // in-scope domains/IPs
	OutOfScope  StringArray `gorm:"type:text[]" json:"out_of_scope"`
	Color       string      `gorm:"default:'#6366f1'" json:"color"`
	Active      bool        `gorm:"default:true" json:"active"`

	Org Organization `gorm:"foreignKey:OrgID" json:"-"`
}

// Note — free-form recon notes scoped to an org and optionally a target
type Note struct {
	Base
	OrgID     uuid.UUID   `gorm:"type:uuid;index;not null" json:"org_id"`
	ProjectID *uuid.UUID  `gorm:"type:uuid;index" json:"project_id,omitempty"`
	CreatedBy uuid.UUID   `gorm:"type:uuid;index;not null" json:"created_by"`
	Title     string      `gorm:"not null" json:"title"`
	Content   string      `gorm:"type:text;not null" json:"content"`
	Target    string      `json:"target"` // domain/IP this note relates to
	Tags      StringArray `gorm:"type:text[]" json:"tags"`
	Pinned    bool        `gorm:"default:false" json:"pinned"`

	Org Organization `gorm:"foreignKey:OrgID" json:"-"`
}

// Todo — actionable recon task
type Todo struct {
	Base
	OrgID      uuid.UUID  `gorm:"type:uuid;index;not null" json:"org_id"`
	ProjectID  *uuid.UUID `gorm:"type:uuid;index" json:"project_id,omitempty"`
	CreatedBy  uuid.UUID  `gorm:"type:uuid;index;not null" json:"created_by"`
	AssignedTo *uuid.UUID `gorm:"type:uuid;index" json:"assigned_to,omitempty"`
	Title      string     `gorm:"not null" json:"title"`
	Notes      string     `gorm:"type:text" json:"notes"`
	Status     string     `gorm:"default:'open'" json:"status"`     // open, in_progress, done
	Priority   string     `gorm:"default:'medium'" json:"priority"` // low, medium, high, critical
	Target     string     `json:"target"`
	DueAt      *time.Time `json:"due_at,omitempty"`
	DoneAt     *time.Time `json:"done_at,omitempty"`

	Org Organization `gorm:"foreignKey:OrgID" json:"-"`
}

// NotificationConfig — webhook/channel config per org
// SavedSearch lets a user store a field-qualified search query (see
// internal/modules/searchquery) under a name for one-click reuse — the
// search box previously had no way to persist or share a query beyond
// copy/pasting the URL by hand.
type SavedSearch struct {
	Base
	OrgID    uuid.UUID `gorm:"type:uuid;index;not null" json:"org_id"`
	UserID   uuid.UUID `gorm:"type:uuid;index;not null" json:"user_id"`
	Name     string    `gorm:"not null" json:"name"`
	Query    string    `gorm:"not null" json:"query"`
	UseCount int       `gorm:"default:0" json:"use_count"`
	LastUsed time.Time `json:"last_used_at"`
}

type NotificationConfig struct {
	Base
	OrgID     uuid.UUID `gorm:"type:uuid;index;not null" json:"org_id"`
	CreatedBy uuid.UUID `gorm:"type:uuid;index;not null" json:"created_by"`
	Channel   string    `gorm:"not null" json:"channel"` // slack, discord, telegram, teams, email, siem
	Name      string    `gorm:"not null" json:"name"`
	// WebhookURL is used by slack, discord, teams, and siem (all deliver
	// over an HTTP POST to a URL). Unused for telegram and email.
	WebhookURL string `gorm:"type:text" json:"webhook_url"`
	// SIEM/SOAR only. Most SIEM/SOAR HTTP collectors (Splunk HEC, generic
	// ingest endpoints, Tines/Torq webhooks) require an auth token unlike
	// Slack/Discord/Teams incoming webhooks, which authenticate via the
	// secrecy of the URL itself. AuthHeader lets the operator name the
	// header the collector expects (e.g. "Authorization" or
	// "X-Splunk-Token"); it defaults to "Authorization" if left blank.
	AuthHeader         string `json:"auth_header,omitempty"`
	AuthTokenEncrypted string `json:"-"`
	// Telegram only
	BotToken string `json:"-"`
	ChatID   string `json:"chat_id,omitempty"`
	// Email (SMTP) only. SMTPPasswordEncrypted holds an AES-256-GCM
	// ciphertext (base64) of the SMTP password/app-password, encrypted with
	// the same RAYYAN_AUTH_CREDENTIALKEY used for tool_credentials — see
	// internal/crypto. It is never exposed via JSON.
	SMTPHost              string      `json:"smtp_host,omitempty"`
	SMTPPort              int         `gorm:"default:587" json:"smtp_port,omitempty"`
	SMTPUsername          string      `json:"smtp_username,omitempty"`
	SMTPPasswordEncrypted string      `json:"-"`
	SMTPFrom              string      `json:"smtp_from,omitempty"`
	SMTPTo                StringArray `gorm:"type:text[]" json:"smtp_to,omitempty"`
	SMTPUseTLS            bool        `gorm:"default:true" json:"smtp_use_tls,omitempty"`
	// Filters
	AlertTypes  StringArray `gorm:"type:text[]" json:"alert_types"` // new_asset, cert_expiry, new_service, finding
	MinSeverity string      `gorm:"default:'info'" json:"min_severity"`
	Active      bool        `gorm:"default:true" json:"active"`

	Org Organization `gorm:"foreignKey:OrgID" json:"-"`
}

// HasSMTPSecret reports whether an encrypted SMTP password is stored,
// without ever decrypting or exposing it. Used by API responses that need
// to show "secret configured: yes/no" without leaking the secret itself.
func (n NotificationConfig) HasSMTPSecret() bool {
	return n.SMTPPasswordEncrypted != ""
}

func (NotificationConfig) TableName() string { return "notification_configs" }

// ServiceHistory — one row per state-change event on a port/protocol
type ServiceHistory struct {
	ID        uuid.UUID  `gorm:"type:uuid;primary_key" json:"id"`
	CreatedAt time.Time  `json:"created_at"`
	OrgID     uuid.UUID  `gorm:"type:uuid;index;not null" json:"org_id"`
	HostID    *uuid.UUID `gorm:"type:uuid;index" json:"host_id,omitempty"`
	HostRef   string     `gorm:"index;not null" json:"host_ref"`
	Port      int        `gorm:"not null" json:"port"`
	Protocol  string     `gorm:"default:'tcp'" json:"protocol"`
	Service   string     `json:"service"`
	Product   string     `json:"product"`
	Version   string     `json:"version"`
	State     string     `gorm:"default:'open'" json:"state"` // open, closed, filtered
	Banner    string     `json:"banner"`
	ScanJobID *uuid.UUID `gorm:"type:uuid" json:"scan_job_id,omitempty"`
}

func (ServiceHistory) TableName() string { return "service_history" }

// AssetRelationship — one edge in the asset correlation graph, rebuilt on demand
type AssetRelationship struct {
	ID           uuid.UUID `gorm:"type:uuid;primary_key" json:"id"`
	CreatedAt    time.Time `json:"created_at"`
	OrgID        uuid.UUID `gorm:"type:uuid;index;not null" json:"org_id"`
	FromType     string    `gorm:"index;not null" json:"from_type"`
	FromID       uuid.UUID `gorm:"type:uuid;index;not null" json:"from_id"`
	FromLabel    string    `json:"from_label"`
	ToType       string    `gorm:"index;not null" json:"to_type"`
	ToID         uuid.UUID `gorm:"type:uuid;index;not null" json:"to_id"`
	ToLabel      string    `json:"to_label"`
	RelationType string    `gorm:"index;not null" json:"relation_type"` // parent_child, resolves_to, cert_san_match, shared_asn, shared_registrant
	Confidence   float64   `gorm:"default:1" json:"confidence"`
	Evidence     string    `json:"evidence,omitempty"`
	ComputedAt   time.Time `gorm:"index;not null" json:"computed_at"`
}

func (AssetRelationship) TableName() string { return "asset_relationships" }

// AssetStateSnapshot — latest known field-state for one asset (any type),
// compared against on the next change-detection run, then overwritten.
type AssetStateSnapshot struct {
	ID        uuid.UUID `gorm:"type:uuid;primary_key" json:"id"`
	OrgID     uuid.UUID `gorm:"type:uuid;uniqueIndex:idx_asset_snapshot_key;not null" json:"org_id"`
	AssetType string    `gorm:"uniqueIndex:idx_asset_snapshot_key;not null" json:"asset_type"`
	AssetKey  string    `gorm:"uniqueIndex:idx_asset_snapshot_key;not null" json:"asset_key"`
	Label     string    `json:"label"`
	Fields    JSONB     `gorm:"type:jsonb" json:"fields"`
	UpdatedAt time.Time `json:"updated_at"`
}

func (AssetStateSnapshot) TableName() string { return "asset_state_snapshots" }

// AssetChangeEvent — one row per detected change (new, removed, changed)
// across any asset type; the append-only timeline change detection reads from.
type AssetChangeEvent struct {
	ID         uuid.UUID `gorm:"type:uuid;primary_key" json:"id"`
	CreatedAt  time.Time `json:"created_at"`
	OrgID      uuid.UUID `gorm:"type:uuid;index;not null" json:"org_id"`
	AssetType  string    `gorm:"index;not null" json:"asset_type"`
	AssetKey   string    `gorm:"index;not null" json:"asset_key"`
	AssetLabel string    `json:"asset_label"`
	ChangeType string    `gorm:"index;not null" json:"change_type"` // new, removed, changed
	Field      string    `json:"field,omitempty"`
	OldValue   string    `json:"old_value,omitempty"`
	NewValue   string    `json:"new_value,omitempty"`
	DetectedAt time.Time `gorm:"index;not null" json:"detected_at"`
}

func (AssetChangeEvent) TableName() string { return "asset_change_events" }

// AssetRiskHistory — one row per risk-scoring run per asset, for trend charts
type AssetRiskHistory struct {
	ID         uuid.UUID `gorm:"type:uuid;primary_key" json:"id"`
	CreatedAt  time.Time `json:"created_at"`
	OrgID      uuid.UUID `gorm:"type:uuid;index;not null" json:"org_id"`
	AssetType  string    `gorm:"index;not null" json:"asset_type"` // domain, subdomain, host
	AssetID    uuid.UUID `gorm:"type:uuid;index;not null" json:"asset_id"`
	AssetLabel string    `json:"asset_label"`
	Score      float64   `json:"score"`
	Tier       string    `json:"tier"`
	Factors    JSONB     `gorm:"type:jsonb" json:"factors"`
	ComputedAt time.Time `gorm:"index;not null" json:"computed_at"`
}

func (AssetRiskHistory) TableName() string { return "asset_risk_history" }

// AttackPath — one ranked exposure chain from an internet-facing entry
// asset to a sensitive internal target, weighted by the weakest link's
// risk score along the chain.
type AttackPath struct {
	ID            uuid.UUID  `gorm:"type:uuid;primary_key" json:"id"`
	CreatedAt     time.Time  `json:"created_at"`
	OrgID         uuid.UUID  `gorm:"type:uuid;index;not null" json:"org_id"`
	EntryType     string     `gorm:"index;not null" json:"entry_type"`
	EntryID       uuid.UUID  `gorm:"type:uuid;index;not null" json:"entry_id"`
	EntryLabel    string     `json:"entry_label"`
	TargetType    string     `gorm:"index;not null" json:"target_type"`
	TargetID      uuid.UUID  `gorm:"type:uuid;index;not null" json:"target_id"`
	TargetLabel   string     `json:"target_label"`
	WeakestScore  float64    `gorm:"index" json:"weakest_score"`
	WeakestType   string     `json:"weakest_type"`
	WeakestID     uuid.UUID  `gorm:"type:uuid" json:"weakest_id"`
	WeakestLabel  string     `json:"weakest_label"`
	HopCount      int        `json:"hop_count"`
	Hops          JSONB      `gorm:"type:jsonb" json:"hops"`
	ChokepointSvc *uuid.UUID `gorm:"type:uuid" json:"chokepoint_service_id,omitempty"`
	FindingSev    string     `json:"finding_severity,omitempty"`
	ComputedAt    time.Time  `gorm:"index;not null" json:"computed_at"`
}

func (AttackPath) TableName() string { return "attack_paths" }

// AssetExposureScore — one row per scored asset (host, subdomain, or
// domain), capturing the multi-factor exposure score for that asset.
// Rebuilt in full per org on each recompute, same lifecycle as
// asset_relationships/attack_paths. RiskScore here is a read-only copy
// of the riskscore engine's own score, never written back to.
type AssetExposureScore struct {
	ID               uuid.UUID `gorm:"type:uuid;primary_key" json:"id"`
	CreatedAt        time.Time `json:"created_at"`
	OrgID            uuid.UUID `gorm:"type:uuid;index;not null" json:"org_id"`
	AssetType        string    `gorm:"index;not null" json:"asset_type"` // host, subdomain, domain
	AssetID          uuid.UUID `gorm:"type:uuid;index;not null" json:"asset_id"`
	AssetLabel       string    `json:"asset_label"`
	RiskScore        float64   `json:"risk_score"`
	ExposureScore    float64   `gorm:"index" json:"exposure_score"`
	ExposureLevel    string    `gorm:"index;not null" json:"exposure_level"` // critical, high, medium, low, informational
	InternetExposed  bool      `json:"internet_exposed"`
	AttackPathCount  int       `json:"attack_path_count"`
	CriticalFindings int       `json:"critical_findings"`
	Criticality      string    `json:"criticality"` // crown_jewel, sensitive, standard
	Factors          JSONB     `gorm:"type:jsonb" json:"factors"`
	CalculatedAt     time.Time `gorm:"index;not null" json:"calculated_at"`
}

func (AssetExposureScore) TableName() string { return "asset_exposure_scores" }

// ExecutiveKPISnapshot — one row per org per day, capturing the executive
// dashboard's headline KPIs as computed at that point in time. Snapshots are
// produced by the executive engine (on-demand recompute or the nightly
// scheduler job) and are the backing data for historical trend charts
// (daily/weekly/monthly/quarterly) without needing to replay raw tables.
type ExecutiveKPISnapshot struct {
	ID    uuid.UUID `gorm:"type:uuid;primary_key" json:"id"`
	OrgID uuid.UUID `gorm:"type:uuid;uniqueIndex:idx_exec_kpi_org_date;not null" json:"org_id"`
	Date  time.Time `gorm:"type:date;uniqueIndex:idx_exec_kpi_org_date;index;not null" json:"date"`

	// Inventory
	TotalAssets    int `json:"total_assets"`
	TotalDomains   int `json:"total_domains"`
	TotalHosts     int `json:"total_hosts"`
	TotalServices  int `json:"total_services"`
	TotalCloud     int `json:"total_cloud_assets"`
	InternetFacing int `json:"internet_facing_assets"`

	// Asset growth (since previous snapshot)
	NewAssets      int `json:"new_assets"`
	RemovedAssets  int `json:"removed_assets"`
	ModifiedAssets int `json:"modified_assets"`

	// Risk / exposure
	AvgRiskScore      float64 `json:"avg_risk_score"`
	ExposureScore     float64 `json:"exposure_score"`
	CriticalFindings  int     `json:"critical_findings"`
	HighFindings      int     `json:"high_findings"`
	MediumFindings    int     `json:"medium_findings"`
	LowFindings       int     `json:"low_findings"`
	OpenFindings      int     `json:"open_findings"`
	RiskAcceptedCount int     `json:"risk_accepted_count"`

	// Attack paths
	AttackPathCount         int     `json:"attack_path_count"`
	CriticalAttackPathCount int     `json:"critical_attack_path_count"`
	AvgChokepointScore      float64 `json:"avg_chokepoint_score"`

	// SLA
	SLATotal      int     `json:"sla_total"`
	SLABreached   int     `json:"sla_breached"`
	SLACompliance float64 `json:"sla_compliance_pct"`

	// Business impact
	CriticalAssetsExposed int `json:"critical_assets_exposed"`

	ComputedAt time.Time `gorm:"not null" json:"computed_at"`
}

func (ExecutiveKPISnapshot) TableName() string { return "executive_kpi_snapshots" }

// PasswordResetToken stores a single-use, time-limited password reset token.
// The token itself is never stored; only its bcrypt hash is persisted.
type PasswordResetToken struct {
	Base
	UserID    uuid.UUID  `gorm:"type:uuid;index;not null" json:"-"`
	TokenHash string     `gorm:"not null" json:"-"`
	ExpiresAt time.Time  `gorm:"not null" json:"-"`
	UsedAt    *time.Time `json:"-"`
}

// EmailVerificationToken is a single-use, time-limited token sent to new
// registrants. Consuming it sets the user's email_verified flag to true.
type EmailVerificationToken struct {
	Base
	UserID    uuid.UUID  `gorm:"type:uuid;index;not null" json:"-"`
	TokenHash string     `gorm:"not null" json:"-"`
	ExpiresAt time.Time  `gorm:"not null" json:"-"`
	UsedAt    *time.Time `json:"-"`
}

// FailedJob is the dead-letter queue table for jobs that exhausted all retries.
type FailedJob struct {
	Base
	JobType  string     `gorm:"not null" json:"job_type"`
	Payload  JSONB      `gorm:"type:jsonb;not null" json:"payload"`
	Error    string     `gorm:"type:text;not null" json:"error"`
	Attempts int        `gorm:"not null;default:0" json:"attempts"`
	OrgID    *uuid.UUID `gorm:"type:uuid" json:"org_id,omitempty"`
}

// DiscoveryJob — one run of the external discovery pipeline against a set
// of seed domains. Tracks per-stage progress so the dashboard and
// WebSocket feed can show live status without polling raw asset tables.
type DiscoveryJob struct {
	Base
	OrgID       uuid.UUID   `gorm:"type:uuid;index;not null" json:"org_id"`
	CreatedBy   *uuid.UUID  `gorm:"type:uuid" json:"created_by,omitempty"`
	SeedDomains StringArray `gorm:"type:text[];not null" json:"seed_domains"`
	Status      string      `gorm:"default:'pending';index" json:"status"` // pending, running, completed, failed, cancelled
	Stage       string      `json:"stage"`                                 // subdomain, certificate, asn, dns, port, service, correlation, done
	Progress    int         `gorm:"default:0" json:"progress"`             // 0-100
	Cadence     string      `gorm:"default:'manual'" json:"cadence"`       // manual, daily, weekly, monthly
	Depth       int         `gorm:"default:2" json:"depth"`                // recursive discovery hop limit
	Options     JSONB       `gorm:"type:jsonb" json:"options"`

	AssetsFound     int `gorm:"default:0" json:"assets_found"`
	NewAssets       int `gorm:"default:0" json:"new_assets"`
	DomainsFound    int `gorm:"default:0" json:"domains_found"`
	SubdomainsFound int `gorm:"default:0" json:"subdomains_found"`
	IPsFound        int `gorm:"default:0" json:"ips_found"`
	CertsFound      int `gorm:"default:0" json:"certs_found"`
	ServicesFound   int `gorm:"default:0" json:"services_found"`

	StartedAt   *time.Time `json:"started_at,omitempty"`
	CompletedAt *time.Time `json:"completed_at,omitempty"`
	Error       string     `json:"error,omitempty"`

	Org Organization `gorm:"foreignKey:OrgID" json:"-"`
}

func (DiscoveryJob) TableName() string { return "discovery_jobs" }

// DiscoveryEvent — append-only feed of significant discovery occurrences
// (new asset found, recursive expansion triggered, risk indicator raised,
// job lifecycle transitions). Distinct from AssetChangeEvent: this is
// discovery-pipeline-scoped narrative, not a generic field-level diff.
type DiscoveryEvent struct {
	ID         uuid.UUID  `gorm:"type:uuid;primary_key" json:"id"`
	CreatedAt  time.Time  `json:"created_at"`
	OrgID      uuid.UUID  `gorm:"type:uuid;index;not null" json:"org_id"`
	JobID      *uuid.UUID `gorm:"type:uuid;index" json:"job_id,omitempty"`
	EventType  string     `gorm:"index;not null" json:"event_type"` // asset_discovered, stage_started, stage_completed, job_completed, job_failed, risk_flag
	AssetType  string     `json:"asset_type,omitempty"`             // domain, subdomain, ip, certificate, service
	AssetLabel string     `json:"asset_label,omitempty"`
	Source     string     `json:"source,omitempty"` // crtsh, dns_brute, asn_expand, reverse_dns, port_scan, ...
	Severity   string     `json:"severity,omitempty"`
	Message    string     `json:"message,omitempty"`
	DetectedAt time.Time  `gorm:"index;not null" json:"detected_at"`
}

func (DiscoveryEvent) TableName() string { return "discovery_events" }

// DiscoveryRiskFlag — a flagged risk indicator surfaced during discovery
// (exposed admin panel, VPN portal, expired cert, shadow IT asset, etc.),
// kept distinct from the generic Finding table since these are raised by
// the discovery pipeline itself from asset metadata rather than an active
// vulnerability scan.
type DiscoveryRiskFlag struct {
	Base
	OrgID      uuid.UUID  `gorm:"type:uuid;index;not null" json:"org_id"`
	AssetType  string     `gorm:"index;not null" json:"asset_type"` // subdomain, host, service, certificate
	AssetID    uuid.UUID  `gorm:"type:uuid;index;not null" json:"asset_id"`
	AssetLabel string     `json:"asset_label"`
	FlagType   string     `gorm:"index;not null" json:"flag_type"` // admin_panel, vpn_portal, login_page, expired_cert, unknown_asset, shadow_it
	Severity   string     `gorm:"default:'medium'" json:"severity"`
	Evidence   string     `json:"evidence,omitempty"`
	Status     string     `gorm:"default:'open';index" json:"status"` // open, acknowledged, resolved
	DetectedAt time.Time  `gorm:"index;not null" json:"detected_at"`
	ResolvedAt *time.Time `json:"resolved_at,omitempty"`
}

func (DiscoveryRiskFlag) TableName() string { return "discovery_risk_flags" }

// CloudProviderCredential stores AES-256-GCM encrypted credentials for a
// cloud provider (aws, azure, gcp). Used by the scheduler to run periodic
// cloud asset syncs without requiring a user to re-supply credentials on
// each request. The EncryptedCreds field holds the JSON-marshalled
// cloud.ProviderCreds struct, encrypted with the same RAYYAN_AUTH_CREDENTIALKEY
// used for ToolCredential.
type CloudProviderCredential struct {
	Base
	OrgID          uuid.UUID `gorm:"type:uuid;index;not null"  json:"org_id"`
	Provider       string    `gorm:"index;not null"             json:"provider"` // aws | azure | gcp
	Label          string    `json:"label"`
	EncryptedCreds string    `gorm:"type:text;not null"         json:"-"`
	// SyncEnabled controls whether the daily scheduler will use this credential.
	SyncEnabled bool       `gorm:"default:true"               json:"sync_enabled"`
	LastSyncAt  *time.Time `json:"last_sync_at,omitempty"`
	CreatedBy   uuid.UUID  `gorm:"type:uuid"                  json:"created_by"`
}

func (CloudProviderCredential) TableName() string { return "cloud_provider_credentials" }

// RecordServiceHistory snapshots a service state into service_history.
// Call this immediately after any service upsert in the scan pipeline so the
// history table stays current. Errors are swallowed intentionally — history
// loss is preferable to blocking the scan pipeline, and callers do not
// surface this error.
func RecordServiceHistory(db *gorm.DB, svc Service, scanJobID *uuid.UUID) {
	h := ServiceHistory{
		ID:        uuid.New(),
		OrgID:     svc.OrgID,
		HostID:    &svc.HostID,
		HostRef:   svc.HostRef,
		Port:      svc.Port,
		Protocol:  svc.Protocol,
		Service:   svc.Service,
		Product:   svc.Product,
		Version:   svc.Version,
		State:     svc.State,
		Banner:    svc.Banner,
		ScanJobID: scanJobID,
	}
	_ = db.Create(&h).Error
}
