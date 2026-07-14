import axios, { type AxiosError } from 'axios'
import { useAuthStore } from '@/store/auth'
import toast from 'react-hot-toast'

const api = axios.create({
  baseURL: '/api/v1',
  headers: { 'Content-Type': 'application/json' },
  timeout: 30_000,
})

// Request interceptor — attach JWT
api.interceptors.request.use((config) => {
  const token = useAuthStore.getState().accessToken
  if (token) {
    config.headers.Authorization = `Bearer ${token}`
  }
  return config
})

// Response interceptor — handle 401
api.interceptors.response.use(
  (res) => res,
  async (err: AxiosError<{ error: string }>) => {
    const originalRequest = err.config as typeof err.config & { _retry?: boolean }

    if (err.response?.status === 401 && !originalRequest._retry) {
      originalRequest._retry = true
      const { refreshToken, logout, setAuth, user } = useAuthStore.getState()

      if (refreshToken && user) {
        try {
          const { data } = await axios.post('/api/v1/auth/refresh', { refresh_token: refreshToken })
          setAuth(user, data.access_token, refreshToken)
          originalRequest.headers!.Authorization = `Bearer ${data.access_token}`
          return api(originalRequest)
        } catch {
          logout()
          window.location.href = '/login'
        }
      } else {
        logout()
        window.location.href = '/login'
      }
    }

    const msg = err.response?.data?.error ?? 'An unexpected error occurred'
    if (err.response?.status !== 401) {
      toast.error(msg)
    }

    return Promise.reject(err)
  }
)

export default api


export const authApi = {
  login: (email: string, password: string) =>
    api.post('/auth/login', { email, password }),
  register: (data: Record<string, string>) =>
    api.post('/auth/register', data),
  refresh: (refreshToken: string) =>
    api.post('/auth/refresh', { refresh_token: refreshToken }),
  me: () => api.get('/auth/me'),
  logout: () => api.post('/auth/logout'),
  changePassword: (current: string, newPwd: string) =>
    api.post('/auth/change-password', { current_password: current, new_password: newPwd }),
  verifyEmail: (token: string) =>
    api.get('/auth/verify-email', { params: { token } }),
  resendVerification: (email: string) =>
    api.post('/auth/resend-verification', { email }),
  forgotPassword: (email: string) =>
    api.post('/auth/forgot-password', { email }),
  resetPassword: (token: string, password: string) =>
    api.post('/auth/reset-password', { token, new_password: password }),
}

export const dashboardApi = {
  summary: () => api.get('/dashboard'),
  trends: () => api.get('/dashboard/trends'),
  riskScore: () => api.get('/dashboard/risk-score'),
  topAssets: (params?: Record<string, unknown>) => api.get('/dashboard/top-assets', { params }),
}

export const riskApi = {
  assets: (params?: Record<string, unknown>) => api.get('/risk/assets', { params }),
  trends: (params?: Record<string, unknown>) => api.get('/risk/trends', { params }),
  heatmap: () => api.get('/risk/heatmap'),
  recompute: () => api.post('/risk/recompute'),
}

export const correlationApi = {
  graph: (params?: Record<string, unknown>) => api.get('/correlation/graph', { params }),
  related: (type: string, id: string) => api.get(`/correlation/related/${type}/${id}`),
  exposurePath: (params: Record<string, unknown>) => api.get('/correlation/exposure-path', { params }),
  rebuild: () => api.post('/correlation/rebuild'),
}

export const graphApi = {
  assetStats: () => api.get('/graph/asset-stats'),
  stats: () => api.get('/graph/stats'),
}

export const changeDetectApi = {
  timeline: (params?: Record<string, unknown>) => api.get('/changes/timeline', { params }),
  run: () => api.post('/changes/run'),
}

export const attackPathApi = {
  list: (params?: Record<string, unknown>) => api.get('/attack-paths', { params }),
  recompute: () => api.post('/attack-paths/recompute'),
}

export const discoveryApi = {
  start: (data: { seed_domains: string[]; depth?: number; scan_ports?: boolean; cadence?: string }) =>
    api.post('/discovery/start', data),
  jobs: (params?: Record<string, unknown>) => api.get('/discovery/jobs', { params }),
  job: (id: string) => api.get(`/discovery/jobs/${id}`),
  cancel: (id: string) => api.delete(`/discovery/jobs/${id}`),
  dashboard: () => api.get('/discovery/dashboard'),
  events: (params?: Record<string, unknown>) => api.get('/discovery/events', { params }),
  changes: () => api.get('/discovery/changes'),
  assets: (params?: Record<string, unknown>) => api.get('/discovery/assets', { params }),
  riskFlags: (params?: Record<string, unknown>) => api.get('/discovery/risk-flags', { params }),
  resolveRiskFlag: (id: string) => api.put(`/discovery/risk-flags/${id}/resolve`),
}

export const executiveApi = {
  summary: () => api.get('/executive/summary'),
  trends: (params?: Record<string, unknown>) => api.get('/executive/trends', { params }),
  slaCompliance: () => api.get('/executive/sla-compliance'),
  attackPathOverview: () => api.get('/executive/attack-path-overview'),
  businessImpact: () => api.get('/executive/business-impact'),
  recompute: () => api.post('/executive/recompute'),
}

export const exposureApi = {
  assets: (params?: Record<string, unknown>) => api.get('/exposure/assets', { params }),
  detail: (id: string) => api.get(`/exposure/${id}`),
  dashboard: () => api.get('/exposure/dashboard'),
  recompute: () => api.post('/exposure/recompute'),
}

export const domainApi = {
  list: (params?: Record<string, unknown>) => api.get('/domains', { params }),
  get: (id: string) => api.get(`/domains/${id}`),
  create: (data: Record<string, unknown>) => api.post('/domains', data),
  update: (id: string, data: Record<string, unknown>) => api.put(`/domains/${id}`, data),
  delete: (id: string) => api.delete(`/domains/${id}`),
  subdomains: (id: string) => api.get(`/domains/${id}/subdomains`),
  dnsRecords: (id: string) => api.get(`/domains/${id}/dns`),
}

export const subdomainApi = {
  list: (params?: Record<string, unknown>) => api.get('/subdomains', { params }),
  get: (id: string) => api.get(`/subdomains/${id}`),
  bulkTag: (ids: string[], tags: string[], action: 'add' | 'remove') =>
    api.put('/subdomains/bulk-tag', { ids, tags, action }),
}

export const hostApi = {
  list: (params?: Record<string, unknown>) => api.get('/hosts', { params }),
  get: (id: string) => api.get(`/hosts/${id}`),
  create: (data: Record<string, unknown>) => api.post('/hosts', data),
  update: (id: string, data: Record<string, unknown>) => api.put(`/hosts/${id}`, data),
  delete: (id: string) => api.delete(`/hosts/${id}`),
  services: (id: string) => api.get(`/hosts/${id}/services`),
  bulkTag: (ids: string[], tags: string[], action: 'add' | 'remove') =>
    api.put('/hosts/bulk-tag', { ids, tags, action }),
  portHistory: (id: string, params?: Record<string, unknown>) =>
    api.get(`/hosts/${id}/port-history`, { params }),
}

export const serviceApi = {
  list: (params?: Record<string, unknown>) => api.get('/services', { params }),
  get: (id: string) => api.get(`/services/${id}`),
}

export const certificateApi = {
  list: (params?: Record<string, unknown>) => api.get('/certificates', { params }),
  get: (id: string) => api.get(`/certificates/${id}`),
  expiring: (days?: number) => api.get('/certificates/expiring', { params: { days } }),
}

export const dnsApi = {
  list: (params?: Record<string, unknown>) => api.get('/dns', { params }),
}

export const scanApi = {
  list: (params?: Record<string, unknown>) => api.get('/scans', { params }),
  get: (id: string) => api.get(`/scans/${id}`),
  create: (data: Record<string, unknown>) => api.post('/scans', data),
  cancel: (id: string) => api.delete(`/scans/${id}`),
  results: (id: string) => api.get(`/scans/${id}/results`),
  rerun: (id: string) => api.post(`/scans/${id}/rerun`),
  diff: (idA: string, idB: string) => api.get(`/scans/${idA}/diff/${idB}`),
}

export const toolboxApi = {
  // NOTE: all three of these hit endpoints whose backend handlers read
  // `c.Query("target")` (see internal/api/handlers/toolbox.go) — they were
  // previously sent as `domain`/`url`, which the backend was never looking
  // for, so `target` always arrived empty and every request failed with
  // "target required" regardless of environment. Fixed to send `target`.
  whois: (domain: string) => api.get('/toolbox/whois', { params: { target: domain } }),
  cmsDetect: (url: string) => api.get('/toolbox/cms-detect', { params: { target: url } }),
  cveLookup: (cveId: string) => api.get(`/toolbox/cve/${cveId}`),
  relatedDomains: (domain: string) => api.get('/toolbox/related-domains', { params: { target: domain } }),
  insights: () => api.get('/toolbox/insights'),
  tlsCheck: (target: string) => api.get('/toolbox/tls-check', { params: { target } }),
  geoip: (ip: string) => api.get('/toolbox/geoip', { params: { ip } }),
  portScan: (target: string, ports = 'quick') => api.get('/toolbox/port-scan', { params: { target, ports } }),
}

export const alertApi = {
  list: (params?: Record<string, unknown>) => api.get('/alerts', { params }),
  get: (id: string) => api.get(`/alerts/${id}`),
  acknowledge: (id: string) => api.put(`/alerts/${id}/acknowledge`),
  resolve: (id: string) => api.put(`/alerts/${id}/resolve`),
}

export const reportApi = {
  list: () => api.get('/reports'),
  generate: (data: Record<string, unknown>) => api.post('/reports', data),
  get: (id: string) => api.get(`/reports/${id}`),
  download: (id: string) => api.get(`/reports/${id}/download`, { responseType: 'blob' }),
  delete: (id: string) => api.delete(`/reports/${id}`),
}

export const searchApi = {
  search: (q: string) => api.get('/search', { params: { q } }),
  suggestions: (q: string) => api.get('/search/suggestions', { params: { q } }),
}

export const savedSearchApi = {
  list: () => api.get('/saved-searches'),
  create: (name: string, query: string) => api.post('/saved-searches', { name, query }),
  delete: (id: string) => api.delete(`/saved-searches/${id}`),
  use: (id: string) => api.post(`/saved-searches/${id}/use`),
}

export const cloudApi = {
  list: (params?: Record<string, unknown>) => api.get('/cloud', { params }),
  sync: (creds?: Record<string, unknown>) => api.post('/cloud/sync', creds ?? {}),
  // POST /cloud/scan — trigger nuclei vulnerability scan against synced cloud asset IPs/endpoints
  scan: (params?: { provider?: string; asset_ids?: string[] }) => api.post('/cloud/scan', params ?? {}),
  // GET /cloud/scan/findings — list nuclei findings from cloud asset scans
  listFindings: (params?: Record<string, unknown>) => api.get('/cloud/scan/findings', { params }),
}

export const userApi = {
  list: () => api.get('/users'),
  get: (id: string) => api.get(`/users/${id}`),
  create: (data: Record<string, unknown>) => api.post('/users', data),
  update: (id: string, data: Record<string, unknown>) => api.put(`/users/${id}`, data),
  delete: (id: string) => api.delete(`/users/${id}`),
}

export const apiKeyApi = {
  list: () => api.get('/apikeys'),
  create: (data: Record<string, unknown>) => api.post('/apikeys', data),
  delete: (id: string) => api.delete(`/apikeys/${id}`),
}

export const auditApi = {
  list: (params?: Record<string, unknown>) => api.get('/audit', { params }),
}

export const techApi = {
  list: (params?: Record<string, unknown>) => api.get('/technologies', { params }),
  summary: () => api.get('/technologies/summary'),
}

export const findingApi = {
  list: (params?: Record<string, unknown>) => api.get('/findings', { params }),
  get: (id: string) => api.get(`/findings/${id}`),
  create: (data: Record<string, unknown>) => api.post('/findings', data),
  update: (id: string, data: Record<string, unknown>) => api.put(`/findings/${id}`, data),
  summary: () => api.get('/findings/summary'),
  acknowledge: (id: string) => api.put(`/findings/${id}/acknowledge`),
  falsePositive: (id: string) => api.put(`/findings/${id}/false-positive`),
  markFixed: (id: string) => api.put(`/findings/${id}/fix`),
  bulkUpdate: (ids: string[], status: string) => api.post('/findings/bulk', { ids, status }),
  delete: (id: string) => api.delete(`/findings/${id}`),
  exportUrl: () => '/api/v1/findings/export',
}


export const asnApi = {
  list: (asn?: string, extra?: Record<string, unknown>) => api.get('/asn-ranges', { params: { ...(asn ? { asn } : {}), ...extra } }),
  expand: (asn: string) => api.post('/asn-ranges/expand', { asn }),
  delete: (asn: string) => api.delete('/asn-ranges', { params: { asn } }),
}

export const whoisHistoryApi = {
  list: (domain: string, limit?: number) =>
    api.get('/whois-history', { params: { domain, limit } }),
  snap: (domain: string) => api.post('/whois-history/snap', { domain }),
}

export const findingSLAApi = {
  setSLA: (id: string, due_at: string) => api.put(`/findings/${id}/sla`, { due_at }),
  acceptRisk: (id: string, reason: string) => api.put(`/findings/${id}/risk-accept`, { reason }),
  revokeRisk: (id: string) => api.delete(`/findings/${id}/risk-accept`),
  slaReport: () => api.get('/findings/sla-report'),
  bulkDelete: (ids: string[]) => api.delete('/findings/bulk', { data: { ids } }),
  bulkIgnore: (ids: string[]) => api.put('/findings/bulk-ignore', { ids }),
}

export const domainCadenceApi = {
  set: (id: string, scan_cron: string, scan_depth: string) =>
    api.put(`/domains/${id}/cadence`, { scan_cron, scan_depth }),
}

export const webhookLogApi = {
  // Backend reads `per_page` (see AdminOpsHandler.ListWebhookDeliveries) — was
  // sending `limit`, which the handler ignores, so callers always got the
  // default 50 rows regardless of what they asked for.
  list: (limit?: number) => api.get('/webhook-deliveries', { params: { per_page: limit } }),
  retry: (id: string) => api.post(`/webhook-deliveries/${id}/retry`),
}

export const notificationApi = {
  list: () => api.get('/notifications'),
  create: (data: Record<string, unknown>) => api.post('/notifications', data),
  update: (id: string, data: Record<string, unknown>) => api.put(`/notifications/${id}`, data),
  delete: (id: string) => api.delete(`/notifications/${id}`),
  test: (id: string) => api.post(`/notifications/${id}/test`),
}

export const exportApi = {
  hosts: (format: 'csv' | 'json' = 'csv') =>
    `/api/v1/hosts/export?format=${format}`,
  subdomains: (format: 'csv' | 'json' = 'csv') =>
    `/api/v1/subdomains/export?format=${format}`,
  findings: () => '/api/v1/findings/export',
}

export const serviceDiffApi = {
  diff: (hostId?: string, hostRef?: string) =>
    api.get('/services/diff', { params: { host_id: hostId, host_ref: hostRef } }),
}

export const orgApi = {
  backup: () => api.get('/org/backup', { responseType: 'blob' }),
  restore: (data: unknown) => api.post('/org/restore', data),
  scanLimits: () => api.get('/org/scan-limits'),
  setPlan: (plan: string, maxAssets: number) =>
    api.put('/org/plan', { plan, max_assets: maxAssets }),
}

export const themeApi = {
  get: () => api.get('/auth/theme'),
  set: (theme: 'dark' | 'light' | 'slate') => api.put('/auth/theme', { theme }),
}

export const bulkApi = {
  deleteHosts: (ids: string[]) => api.delete('/hosts/bulk', { data: { ids } }),
  deleteSubdomains: (ids: string[]) => api.delete('/subdomains/bulk', { data: { ids } }),
}

export const udpProbeApi = {
  probe: (host: string, ports?: number[]) =>
    api.post('/scan/udp-probe', { host, ports }),
}

export const screenshotGalleryApi = {
  list: (limit?: number, offset?: number) =>
    api.get('/screenshots/gallery', { params: { limit, offset } }),
}

export const takeoverApi = {
  // GET /takeover — list all takeover findings for the org
  list: (params?: Record<string, unknown>) => api.get('/takeover', { params }),
  // GET /takeover/stats — summary counts by provider
  stats: () => api.get('/takeover/stats'),
}

export const intelligenceApi = {
  // Results
  listResults: (params?: { target?: string; provider?: string; limit?: number; offset?: number }) =>
    api.get('/intelligence/results', { params }),
  // On-demand enrichment
  enrichHost: (ip: string) => api.post('/intelligence/enrich/host', { ip }),
  enrichDomain: (domain: string) => api.post('/intelligence/enrich/domain', { domain }),
  // Continuous monitoring jobs
  listMonitors: () => api.get('/intelligence/monitors'),
  createMonitor: (data: {
    target: string
    target_type: 'host' | 'domain'
    providers?: string[]
    cadence?: string
    notes?: string
  }) => api.post('/intelligence/monitors', data),
  toggleMonitor: (id: string, enabled: boolean) =>
    api.put(`/intelligence/monitors/${id}/toggle`, { enabled }),
  deleteMonitor: (id: string) => api.delete(`/intelligence/monitors/${id}`),
}
