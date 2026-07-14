export interface PaginatedResponse<T> {
  data: T[]
  total: number
  page: number
  limit: number
}

export interface ApiError {
  error: string
  details?: string
}

export interface User {
  id: string
  org_id: string
  email: string
  username: string
  first_name: string
  last_name: string
  role: 'admin' | 'analyst' | 'viewer'
  mfa_enabled: boolean
  active: boolean
  last_login_at: string | null
  avatar_url: string
  created_at: string
  updated_at: string
}

export interface LoginResponse {
  access_token: string
  refresh_token: string
  expires_in: number
  user: User
}

export interface Organization {
  id: string
  name: string
  slug: string
  description: string
  plan: string
  max_assets: number
  active: boolean
  created_at: string
}

export interface Domain {
  id: string
  org_id: string
  name: string
  registrar: string
  registration_date: string | null
  expiry_date: string | null
  nameservers: string[]
  status: string
  tags: string[]
  notes: string
  owner: string
  business_unit: string
  environment: string
  monitored: boolean
  last_scanned_at: string | null
  risk_score?: number
  risk_tier?: string
  risk_factors?: Record<string, unknown>
  risk_scored_at?: string | null
  created_at: string
  updated_at: string
}

export interface Subdomain {
  id: string
  org_id: string
  domain_id: string
  name: string
  fqdn: string
  ips: string[]
  status: string
  source: string
  tags: string[]
  first_seen_at: string
  last_seen_at: string
  created_at: string
  dead: boolean
  consecutive_failures: number
  last_checked_at?: string
  risk_score?: number
  risk_tier?: string
  risk_factors?: Record<string, unknown>
  risk_scored_at?: string | null
}

export interface Host {
  id: string
  org_id: string
  ip: string
  ip_version: number
  hostname: string
  reverse_dns: string
  asn: string
  asn_org: string
  cidr: string
  country: string
  city: string
  isp: string
  provider: string
  host_type: string
  status: string
  os: string
  os_version: string
  tags: string[]
  notes: string
  owner: string
  business_unit: string
  environment: string
  monitored: boolean
  first_seen_at: string
  last_seen_at: string
  last_scanned_at: string | null
  risk_score?: number
  risk_tier?: string
  risk_factors?: Record<string, unknown>
  risk_scored_at?: string | null
  created_at: string
}

export interface RiskAssetRow {
  id: string
  asset_type: 'host' | 'subdomain' | 'domain'
  label: string
  score: number
  tier: string
  factors: Record<string, unknown>
  scored_at: string | null
}

export interface RiskTrendPoint {
  date: string
  score: number
}

export interface RiskHeatmapCell {
  group: string
  critical: number
  high: number
  medium: number
  low: number
}

export type CorrelationAssetType =
  | 'domain' | 'subdomain' | 'host' | 'service' | 'certificate' | 'asn' | 'asn_range' | 'registrant'
  | 'technology' | 'finding'

export interface CorrelationNode {
  type: CorrelationAssetType
  id: string
  label: string
}

export interface CorrelationEdge {
  from: CorrelationNode
  to: CorrelationNode
  relation_type: string
  confidence: number
  evidence?: string
}

export interface RelatedAsset {
  asset: CorrelationNode
  relation_type: string
  direction: 'parent' | 'child' | 'peer'
  confidence: number
}

export interface ExposurePathHop {
  node: CorrelationNode
  relation_type?: string
}

export interface AssetStat {
  asset: CorrelationNode
  degree: number
  connected_assets: number
  relation_count: number
  risk_score?: number
  critical: boolean
  orphan: boolean
}

export type ChangeAssetType = 'domain' | 'subdomain' | 'host' | 'service' | 'certificate' | 'dns_record' | 'technology'
export type ChangeType = 'new' | 'removed' | 'changed'

export interface AssetChangeEvent {
  id: string
  asset_type: ChangeAssetType
  asset_key: string
  asset_label: string
  change_type: ChangeType
  field?: string
  old_value?: string
  new_value?: string
  detected_at: string
}

// External Attack Surface Discovery

export type DiscoveryJobStatus = 'pending' | 'running' | 'completed' | 'failed' | 'cancelled'
export type DiscoveryCadence = 'manual' | 'daily' | 'weekly' | 'monthly'

export interface DiscoveryJob {
  id: string
  org_id: string
  created_by?: string
  seed_domains: string[]
  status: DiscoveryJobStatus
  stage: string
  progress: number
  cadence: DiscoveryCadence
  depth: number
  assets_found: number
  new_assets: number
  domains_found: number
  subdomains_found: number
  ips_found: number
  certs_found: number
  services_found: number
  started_at?: string
  completed_at?: string
  error?: string
  created_at: string
  updated_at: string
}

export interface DiscoveryEvent {
  id: string
  org_id: string
  job_id?: string
  event_type: string
  asset_type: string
  asset_label: string
  source: string
  severity: string
  message: string
  detected_at: string
}

export type DiscoveryFlagType = 'admin_panel' | 'vpn_portal' | 'login_page' | 'expired_cert' | 'unknown_asset' | 'shadow_it'
export type DiscoveryFlagStatus = 'open' | 'acknowledged' | 'resolved'

export interface DiscoveryRiskFlag {
  id: string
  org_id: string
  asset_type: string
  asset_id: string
  asset_label: string
  flag_type: DiscoveryFlagType
  severity: string
  evidence: string
  status: DiscoveryFlagStatus
  detected_at: string
  resolved_at?: string
}

export interface DiscoveryDashboard {
  total_assets: number
  total_domains: number
  total_subdomains: number
  total_hosts: number
  total_certificates: number
  total_services: number
  open_risk_flags: number
  running_jobs: number
  last_job?: DiscoveryJob
}

export interface Service {
  id: string
  org_id: string
  host_id: string
  host_ref: string
  port: number
  protocol: string
  service: string
  product: string
  version: string
  banner: string
  state: string
  tunnel: string
  first_seen_at: string
  last_seen_at: string
}

export interface Certificate {
  id: string
  org_id: string
  service_id: string | null
  fingerprint: string
  subject: string
  issuer: string
  subject_alt_names: string[]
  serial_number: string
  not_before: string
  not_after: string
  is_expired: boolean
  is_wildcard: boolean
  is_self_signed: boolean
  signature_alg: string
  key_alg: string
  key_bits: number
  created_at: string
}

export interface DNSRecord {
  id: string
  org_id: string
  domain_id: string
  domain_name?: string
  name: string
  type: string
  value: string
  ttl: number
  priority: number
  first_seen: string
  last_seen: string
}

export interface Technology {
  id: string
  org_id: string
  service_id: string | null
  name: string
  category: string
  version: string
  confidence: number
  source: string
}

export interface ScanJob {
  id: string
  org_id: string
  created_by: string
  name: string
  type: 'network' | 'port' | 'dns' | 'web' | 'full'
  status: 'pending' | 'queued' | 'running' | 'completed' | 'failed' | 'cancelled'
  priority: number
  targets: Record<string, unknown>
  options: Record<string, unknown>
  progress: number
  total_items: number
  done_items: number
  error: string
  started_at: string | null
  completed_at: string | null
  scheduled_at: string | null
  cron_expr: string
  created_at: string
}

export type AlertSeverity = 'critical' | 'high' | 'medium' | 'low' | 'info'
export type AlertStatus = 'open' | 'acknowledged' | 'resolved'

export interface Alert {
  id: string
  org_id: string
  type: string
  severity: AlertSeverity
  title: string
  message: string
  asset_id: string | null
  asset_type: string
  status: AlertStatus
  acked_by: string | null
  acked_at: string | null
  resolved_at: string | null
  created_at: string
}

export interface Report {
  id: string
  org_id: string
  created_by: string
  name: string
  type: string
  format: string
  status: string
  file_path: string
  file_size: number
  generated_at: string | null
  created_at: string
}

export interface CloudAsset {
  id: string
  org_id: string
  provider: string
  account_id: string
  region: string
  resource_id: string
  resource_type: string
  name: string
  ips: string[]
  status: string
  last_synced_at: string | null
  created_at: string
}

export interface DashboardSummary {
  domains: number
  subdomains: number
  hosts: number
  services: number
  certificates: number
  technologies: number
  total_alerts: number
  open_alerts: number
  expiring_certs: number
  active_scans: number
  total_findings: number
  open_findings: number
  critical_findings: number
  high_findings: number
}

export interface AuditLog {
  id: string
  org_id: string
  user_id: string
  action: string
  resource: string
  resource_id: string
  ip: string
  user_agent: string
  success: boolean
  error: string
  created_at: string
}

export interface APIKey {
  id: string
  org_id: string
  user_id: string
  name: string
  key_prefix: string
  scopes: string[]
  expires_at: string | null
  last_used_at: string | null
  active: boolean
  created_at: string
}

export interface Finding {
  id: string
  org_id: string
  scan_job_id?: string
  title: string
  description: string
  severity: string
  status: string
  category: string
  url: string
  cve: string
  cvss: number
  cvss_vector: string
  cvss_version: string
  false_positive: boolean
  created_at: string
  updated_at: string
}

export interface ServiceHistory {
  id: string
  org_id: string
  host_id?: string
  host_ref: string
  port: number
  protocol: string
  service: string
  product: string
  version: string
  state: string
  banner: string
  scan_job_id?: string
  created_at: string
}

export interface AttackPathHop {
  type: string
  id: string
  label: string
  relation_type?: string
  risk_score: number
}

export interface AttackPath {
  id: string
  org_id: string
  entry_type: string
  entry_id: string
  entry_label: string
  target_type: string
  target_id: string
  target_label: string
  weakest_score: number
  weakest_type: string
  weakest_id: string
  weakest_label: string
  hop_count: number
  hops: { hops: AttackPathHop[] }
  chokepoint_service_id?: string
  finding_severity?: string
  computed_at: string
}

export interface ExecutiveSummary {
  total_assets: number
  total_domains: number
  total_subdomains: number
  total_hosts: number
  total_services: number
  total_cloud_assets: number
  internet_facing_assets: number
  avg_risk_score: number
  exposure_score: number
  critical_findings: number
  high_findings: number
  medium_findings: number
  low_findings: number
  open_findings: number
  risk_accepted_count: number
  attack_path_count: number
  critical_attack_path_count: number
  avg_chokepoint_score: number
  sla_total: number
  sla_breached: number
  sla_compliance_pct: number
  critical_assets_exposed: number
  open_alerts: number
  active_scans: number
  expiring_certs: number
  new_assets_7d: number
  removed_assets_7d: number
  changed_assets_7d: number
  computed_at: string
}

export interface ExecutiveKPISnapshot {
  id: string
  org_id: string
  date: string
  total_assets: number
  new_assets: number
  removed_assets: number
  modified_assets: number
  avg_risk_score: number
  exposure_score: number
  critical_findings: number
  high_findings: number
  open_findings: number
  attack_path_count: number
  critical_attack_path_count: number
  sla_compliance_pct: number
  critical_assets_exposed: number
}

export interface ExecutiveSLACompliance {
  by_severity: { severity: string; total: number; breached: number }[]
  total: number
  breached: number
  compliance_pct: number
}

export interface ExecutiveAttackPathOverview {
  total: number
  critical: number
  high: number
  medium: number
  low: number
  top_paths: AttackPath[]
}

export interface ExecutiveBusinessImpactAsset {
  host_id: string
  ip: string
  hostname: string
  business_unit: string
  owner: string
  risk_score: number
  risk_tier: string
  open_findings: number
  critical_findings: number
}

export interface ExecutiveBusinessImpact {
  critical_assets_exposed: number
  assets: ExecutiveBusinessImpactAsset[]
  by_business_unit: { business_unit: string; count: number }[]
}

export type ExposureLevel = 'critical' | 'high' | 'medium' | 'low' | 'informational'

export interface ExposureFactors {
  existing_risk_score: number
  internet_exposure: number
  attack_path_score: number
  findings_score: number
  criticality_score: number
  certificate_score: number
  technology_score: number
  cloud_score: number
  relationship_score: number
  business_impact_score: number
  internet_exposed: boolean
  attack_path_count: number
  critical_findings: number
  high_findings: number
  relationship_count: number
  connected_to_critical_asset: boolean
  cloud_exposed: boolean
  risky_technologies?: string[]
}

export interface ExposureAssetRow {
  id: string
  asset_type: 'host' | 'subdomain' | 'domain'
  asset_id: string
  label: string
  risk_score: number
  exposure_score: number
  exposure_level: ExposureLevel
  internet_exposed: boolean
  attack_path_count: number
  critical_findings: number
  criticality: string
  calculated_at: string
}

export interface ExposureAssetDetail extends ExposureAssetRow {
  factors: ExposureFactors
}

export interface ExposureServiceRow {
  service_id: string
  host_ref: string
  port: number
  protocol: string
  product: string
  exposure_score: number
}

export interface ExposureTechRow {
  name: string
  category: string
  asset_count: number
  avg_exposure_score: number
}

export interface ExposureMatrixCell {
  risk_tier: string
  exposure_level: ExposureLevel
  count: number
}

export interface ExposureDashboard {
  total_scored: number
  critical: number
  high: number
  medium: number
  low: number
  informational: number
  avg_exposure_score: number
  avg_risk_score: number
  public_facing_count: number
  top_exposed_assets: ExposureAssetRow[]
  critical_exposures: ExposureAssetRow[]
  public_facing_assets: ExposureAssetRow[]
  high_risk_services: ExposureServiceRow[]
  most_dangerous_technologies: ExposureTechRow[]
  attack_path_exposure: ExposureAssetRow[]
  risk_vs_exposure_matrix: ExposureMatrixCell[]
  calculated_at: string
}

export interface ExposureRecomputeSummary {
  org_id: string
  assets_scored: number
  critical: number
  high: number
  medium: number
  low: number
  informational: number
  duration_ms: number
}

export interface SavedSearch {
  id: string
  org_id: string
  user_id: string
  name: string
  query: string
  use_count: number
  last_used_at: string
}
