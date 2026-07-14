import { useCallback, useEffect, useState } from 'react'
import { Link } from 'react-router-dom'
import {
  Telescope, Globe, Network, Server, Shield, Cpu, Plus, X, RefreshCw,
  AlertTriangle, Clock, CheckCircle2, XCircle, Loader2, ChevronRight,
  ShieldAlert, KeyRound, LogIn, ShieldX, HelpCircle, Radar,
} from 'lucide-react'
import clsx from 'clsx'
import toast from 'react-hot-toast'
import { formatDistanceToNow } from 'date-fns'
import { discoveryApi } from '@/utils/api'
import { useWebSocket } from '@/hooks/useWebSocket'
import type {
  DiscoveryJob, DiscoveryEvent, DiscoveryRiskFlag, DiscoveryDashboard, DiscoveryFlagType,
} from '@/types'
import { Page, Loading, Empty, TableCard } from './shared'

const STATUS_BADGE: Record<string, string> = {
  pending: 'badge-gray', running: 'badge-blue', completed: 'badge-green',
  failed: 'badge-red', cancelled: 'badge-gray',
}

function JobStatusBadge({ status }: { status: string }) {
  return <span className={clsx('badge text-xs', STATUS_BADGE[status] ?? 'badge-gray')}>{status}</span>
}

const FLAG_META: Record<DiscoveryFlagType, { label: string; icon: React.ElementType; cls: string }> = {
  admin_panel:   { label: 'Admin Panel',  icon: KeyRound,    cls: 'badge-orange' },
  vpn_portal:    { label: 'VPN Portal',   icon: ShieldAlert, cls: 'badge-red' },
  login_page:    { label: 'Login Page',   icon: LogIn,       cls: 'badge-blue' },
  expired_cert:  { label: 'Expired Cert', icon: ShieldX,     cls: 'badge-orange' },
  unknown_asset: { label: 'Unknown Asset', icon: HelpCircle, cls: 'badge-gray' },
  shadow_it:     { label: 'Shadow IT',    icon: HelpCircle,  cls: 'badge-gray' },
}

function FlagBadge({ type }: { type: DiscoveryFlagType }) {
  const meta = FLAG_META[type] ?? FLAG_META.unknown_asset
  const Icon = meta.icon
  return (
    <span className={clsx('badge text-xs flex items-center gap-1 w-fit', meta.cls)}>
      <Icon className="w-3 h-3" />{meta.label}
    </span>
  )
}

// Start Discovery modal

function StartDiscoveryModal({ onClose, onStarted }: { onClose: () => void; onStarted: () => void }) {
  const [domainsText, setDomainsText] = useState('')
  const [depth, setDepth] = useState(2)
  const [scanPorts, setScanPorts] = useState(true)
  const [cadence, setCadence] = useState<'manual' | 'daily' | 'weekly' | 'monthly'>('manual')
  const [submitting, setSubmitting] = useState(false)

  async function submit() {
    const seedDomains = domainsText.split(/[\n,]/).map(d => d.trim()).filter(Boolean)
    if (seedDomains.length === 0) {
      toast.error('Enter at least one seed domain')
      return
    }
    setSubmitting(true)
    try {
      await discoveryApi.start({ seed_domains: seedDomains, depth, scan_ports: scanPorts, cadence })
      toast.success('Discovery started')
      onStarted()
      onClose()
    } catch {
      // interceptor already shows the error toast
    } finally {
      setSubmitting(false)
    }
  }

  return (
    <div className="fixed inset-0 z-40 bg-black/50 flex items-center justify-center p-4" onClick={onClose}>
      <div className="card w-full max-w-md p-5 space-y-4" onClick={e => e.stopPropagation()}>
        <div className="flex items-center justify-between">
          <h2 className="text-sm font-semibold text-text-primary flex items-center gap-2">
            <Telescope className="w-4 h-4 text-accent-cyan" /> Start External Discovery
          </h2>
          <button onClick={onClose} className="text-text-muted hover:text-text-primary"><X className="w-4 h-4" /></button>
        </div>

        <div>
          <label className="text-xs text-text-muted mb-1 block">Seed domains (one per line)</label>
          <textarea
            className="input text-sm h-24 font-mono"
            placeholder={'example.com\nexample.org'}
            value={domainsText}
            onChange={e => setDomainsText(e.target.value)}
          />
        </div>

        <div className="grid grid-cols-2 gap-3">
          <div>
            <label className="text-xs text-text-muted mb-1 block">Recursion depth</label>
            <select className="input text-sm" value={depth} onChange={e => setDepth(Number(e.target.value))}>
              {[1, 2, 3, 4, 5].map(d => <option key={d} value={d}>{d} hop{d > 1 ? 's' : ''}</option>)}
            </select>
          </div>
          <div>
            <label className="text-xs text-text-muted mb-1 block">Recurring cadence</label>
            <select className="input text-sm" value={cadence} onChange={e => setCadence(e.target.value as typeof cadence)}>
              <option value="manual">Manual (run once)</option>
              <option value="daily">Daily</option>
              <option value="weekly">Weekly</option>
              <option value="monthly">Monthly</option>
            </select>
          </div>
        </div>

        <label className="flex items-center gap-2 text-sm text-text-secondary">
          <input type="checkbox" checked={scanPorts} onChange={e => setScanPorts(e.target.checked)} />
          Probe open ports & services on discovered hosts
        </label>

        <div className="flex justify-end gap-2 pt-2">
          <button onClick={onClose} className="btn-secondary text-sm">Cancel</button>
          <button onClick={submit} disabled={submitting} className="btn-primary text-sm flex items-center gap-1.5">
            {submitting ? <Loader2 className="w-3.5 h-3.5 animate-spin" /> : <Telescope className="w-3.5 h-3.5" />}
            {submitting ? 'Starting…' : 'Start Discovery'}
          </button>
        </div>
      </div>
    </div>
  )
}

// External Discovery Dashboard

export function DiscoveryDashboardPage() {
  const [summary, setSummary] = useState<DiscoveryDashboard | null>(null)
  const [jobs, setJobs] = useState<DiscoveryJob[]>([])
  const [events, setEvents] = useState<DiscoveryEvent[]>([])
  const [loading, setLoading] = useState(true)
  const [showModal, setShowModal] = useState(false)

  const load = useCallback(async () => {
    setLoading(true)
    try {
      const [dashRes, jobsRes, eventsRes] = await Promise.all([
        discoveryApi.dashboard(),
        discoveryApi.jobs({ limit: 8 }),
        discoveryApi.events({ limit: 15 }),
      ])
      setSummary(dashRes.data)
      setJobs(jobsRes.data.data ?? [])
      setEvents(eventsRes.data.data ?? [])
    } catch {
      // Interceptor shows toast; dashboard gracefully shows zero/empty state
    } finally {
      setLoading(false)
    }
  }, [])

  useEffect(() => { load() }, [load])

  // Real-time updates: new assets, progress, and job status land here
  // without a page refresh.
  useWebSocket({
    onMessage: (msg) => {
      const evt = msg as { type?: string }
      if (evt.type?.startsWith('discovery_')) load()
    },
  })

  const hasRunningJob = jobs.some(j => j.status === 'pending' || j.status === 'running')

  return (
    <Page
      title="External Discovery"
      subtitle="Continuously map every internet-facing asset belonging to your organization, starting from a handful of seed domains"
      actions={
        <button onClick={() => setShowModal(true)} className="btn-primary text-sm flex items-center gap-1.5">
          <Plus className="w-3.5 h-3.5" /> Start Discovery
        </button>
      }
    >
      {loading && !summary ? <Loading /> : summary && (
        <>
          <div className="grid grid-cols-2 md:grid-cols-4 gap-4">
            <StatTile icon={Globe} label="Domains" value={summary.total_domains} to="/discovery/assets?type=domains" color="var(--accent-cyan)" />
            <StatTile icon={Network} label="Subdomains" value={summary.total_subdomains} to="/discovery/assets?type=subdomains" color="var(--accent-purple)" />
            <StatTile icon={Server} label="IPs / Hosts" value={summary.total_hosts} to="/discovery/assets?type=ips" color="var(--accent-green)" />
            <StatTile icon={Shield} label="Certificates" value={summary.total_certificates} to="/discovery/assets?type=certificates" color="var(--accent-orange)" />
          </div>

          <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
            <div className="card p-4">
              <div className="text-xs text-text-muted">Total Assets Discovered</div>
              <div className="text-2xl font-semibold text-text-primary mt-1 tabular-nums">{summary.total_assets.toLocaleString()}</div>
            </div>
            <div className="card p-4">
              <div className="text-xs text-text-muted flex items-center gap-1"><AlertTriangle className="w-3 h-3 text-accent-orange" /> Open Risk Flags</div>
              <Link to="/discovery/risk-flags" className="text-2xl font-semibold text-accent-orange mt-1 tabular-nums hover:underline block">
                {summary.open_risk_flags.toLocaleString()}
              </Link>
            </div>
            <div className="card p-4">
              <div className="text-xs text-text-muted flex items-center gap-1"><Clock className="w-3 h-3" /> Jobs Running</div>
              <div className="text-2xl font-semibold text-text-primary mt-1 tabular-nums">{summary.running_jobs.toLocaleString()}</div>
            </div>
          </div>

          {summary.last_job && (
            <DiscoveryProgressCard job={hasRunningJob ? (jobs.find(j => j.status === 'running' || j.status === 'pending') ?? summary.last_job) : summary.last_job} />
          )}

          <div className="grid grid-cols-1 lg:grid-cols-2 gap-4">
            <div className="card p-4">
              <div className="flex items-center justify-between mb-3">
                <h3 className="text-sm font-medium text-text-primary">Recent Discovery Jobs</h3>
                <Link to="/discovery/jobs" className="text-xs text-accent-cyan hover:underline flex items-center gap-0.5">
                  View all <ChevronRight className="w-3 h-3" />
                </Link>
              </div>
              {jobs.length === 0 ? <Empty label="No discovery jobs yet" /> : (
                <div className="space-y-2">
                  {jobs.slice(0, 6).map(job => <JobRow key={job.id} job={job} />)}
                </div>
              )}
            </div>

            <div className="card p-4">
              <h3 className="text-sm font-medium text-text-primary mb-3">Live Discovery Feed</h3>
              {events.length === 0 ? <Empty label="No discovery activity yet" /> : (
                <div className="space-y-2 max-h-80 overflow-y-auto">
                  {events.map(e => <EventRow key={e.id} event={e} />)}
                </div>
              )}
            </div>
          </div>
        </>
      )}

      {showModal && <StartDiscoveryModal onClose={() => setShowModal(false)} onStarted={load} />}
    </Page>
  )
}

function StatTile({ icon: Icon, label, value, to, color }: {
  icon: React.ElementType; label: string; value: number; to: string; color: string
}) {
  return (
    <Link to={to} className="stat-card hover:border-border transition-colors group">
      <div className="flex items-start justify-between">
        <div className="w-8 h-8 rounded-lg flex items-center justify-center" style={{ background: color + '15', border: `1px solid ${color}25` }}>
          <Icon className="w-4 h-4" style={{ color }} />
        </div>
      </div>
      <div>
        <div className="text-2xl font-semibold text-text-primary tabular-nums">{value.toLocaleString()}</div>
        <div className="text-xs text-text-muted mt-0.5">{label}</div>
      </div>
    </Link>
  )
}

function DiscoveryProgressCard({ job }: { job: DiscoveryJob }) {
  const isActive = job.status === 'pending' || job.status === 'running'
  return (
    <div className="card p-4">
      <div className="flex items-center justify-between mb-2">
        <div className="flex items-center gap-2">
          {isActive ? <Loader2 className="w-4 h-4 text-accent-cyan animate-spin" /> : job.status === 'completed' ? <CheckCircle2 className="w-4 h-4 text-accent-green" /> : <XCircle className="w-4 h-4 text-accent-red" />}
          <span className="text-sm font-medium text-text-primary">
            {isActive ? `Discovering ${job.seed_domains.join(', ')}` : `Last run: ${job.seed_domains.join(', ')}`}
          </span>
        </div>
        <JobStatusBadge status={job.status} />
      </div>
      {isActive && (
        <>
          <div className="w-full h-1.5 bg-surface-3 rounded-full overflow-hidden">
            <div className="h-full bg-accent-cyan transition-all duration-500" style={{ width: `${job.progress}%` }} />
          </div>
          <div className="text-xs text-text-muted mt-1.5 capitalize">Stage: {job.stage || 'starting'}</div>
        </>
      )}
      {!isActive && (
        <div className="flex gap-4 text-xs text-text-muted mt-1">
          <span>{job.new_assets} new assets</span>
          <span>{job.subdomains_found} subdomains</span>
          <span>{job.ips_found} IPs</span>
          <span>{job.certs_found} certs</span>
          <span>{job.services_found} services</span>
        </div>
      )}
    </div>
  )
}

function JobRow({ job }: { job: DiscoveryJob }) {
  return (
    <Link to="/discovery/jobs" className="flex items-center justify-between p-2 rounded-md hover:bg-surface-2/50 transition-colors">
      <div className="min-w-0">
        <div className="text-sm text-text-primary truncate">{job.seed_domains.join(', ')}</div>
        <div className="text-xs text-text-muted">
          {formatDistanceToNow(new Date(job.created_at), { addSuffix: true })} · {job.cadence}
        </div>
      </div>
      <JobStatusBadge status={job.status} />
    </Link>
  )
}

const EVENT_ICON: Record<string, React.ElementType> = {
  asset_discovered: Radar, job_started: Loader2, job_completed: CheckCircle2,
  job_failed: XCircle, risk_flag: AlertTriangle,
}

function EventRow({ event }: { event: DiscoveryEvent }) {
  const Icon = EVENT_ICON[event.event_type] ?? Radar
  return (
    <div className="flex items-start gap-2 text-xs">
      <Icon className="w-3.5 h-3.5 text-text-muted mt-0.5 flex-shrink-0" />
      <div className="min-w-0">
        <span className="text-text-secondary">{event.message || event.asset_label}</span>
        <span className="text-text-muted ml-1.5">{formatDistanceToNow(new Date(event.detected_at), { addSuffix: true })}</span>
      </div>
    </div>
  )
}

// Discovery Jobs (list + timeline)

export function DiscoveryJobsPage() {
  const [jobs, setJobs] = useState<DiscoveryJob[]>([])
  const [loading, setLoading] = useState(true)
  const [showModal, setShowModal] = useState(false)

  const load = useCallback(async () => {
    setLoading(true)
    try {
      const { data } = await discoveryApi.jobs({ limit: 100 })
      setJobs(data.data ?? [])
    } catch {
      // Interceptor shows toast
    } finally {
      setLoading(false)
    }
  }, [])

  useEffect(() => { load() }, [load])
  useWebSocket({ onMessage: (msg) => { if ((msg as { type?: string }).type === 'discovery_job_status') load() } })

  async function cancelJob(id: string) {
    try {
      await discoveryApi.cancel(id)
      toast.success('Discovery job cancelled')
      load()
    } catch {
      // interceptor handles error toast
    }
  }

  return (
    <Page
      title="Discovery Jobs"
      subtitle="History of every discovery pipeline run, including recurring scheduled runs"
      actions={
        <button onClick={() => setShowModal(true)} className="btn-primary text-sm flex items-center gap-1.5">
          <Plus className="w-3.5 h-3.5" /> Start Discovery
        </button>
      }
    >
      {loading ? <Loading /> : jobs.length === 0 ? (
        <Empty label="No discovery jobs yet — start one to map your external attack surface" />
      ) : (
        <TableCard>
          <thead><tr>
            <th>Seed Domains</th><th>Status</th><th>Stage</th><th>Cadence</th>
            <th>New Assets</th><th>Started</th><th></th>
          </tr></thead>
          <tbody>
            {jobs.map(job => (
              <tr key={job.id}>
                <td className="text-text-primary font-medium">{job.seed_domains.join(', ')}</td>
                <td><JobStatusBadge status={job.status} /></td>
                <td className="capitalize text-text-secondary">{job.stage || '—'}</td>
                <td className="capitalize text-text-secondary">{job.cadence}</td>
                <td className="tabular-nums">{job.new_assets}</td>
                <td className="text-text-muted text-xs">
                  {job.started_at ? formatDistanceToNow(new Date(job.started_at), { addSuffix: true }) : '—'}
                </td>
                <td>
                  {(job.status === 'pending' || job.status === 'running') && (
                    <button onClick={() => cancelJob(job.id)} className="text-xs text-accent-red hover:underline">Cancel</button>
                  )}
                </td>
              </tr>
            ))}
          </tbody>
        </TableCard>
      )}

      {showModal && <StartDiscoveryModal onClose={() => setShowModal(false)} onStarted={load} />}
    </Page>
  )
}

// Asset Inventory — filterable across domains/subdomains/IPs/certs/services

const ASSET_TABS = [
  { key: 'all', label: 'All' },
  { key: 'domains', label: 'Domains' },
  { key: 'subdomains', label: 'Subdomains' },
  { key: 'ips', label: 'IPs' },
  { key: 'certificates', label: 'Certificates' },
  { key: 'services', label: 'Services' },
]

export function DiscoveryAssetInventoryPage() {
  const [tab, setTab] = useState('all')
  const [data, setData] = useState<Record<string, unknown[]>>({})
  const [loading, setLoading] = useState(true)
  const [loadError, setLoadError] = useState(false)

  const load = useCallback(async () => {
    setLoading(true)
    setLoadError(false)
    try {
      const { data: res } = await discoveryApi.assets({ type: tab })
      setData(res)
    } catch {
      setLoadError(true)
    } finally {
      setLoading(false)
    }
  }, [tab])

  useEffect(() => { load() }, [load])

  const sections = tab === 'all'
    ? ['domains', 'subdomains', 'ips', 'certificates', 'services']
    : [tab]

  return (
    <Page title="Discovered Asset Inventory" subtitle="Every internet-facing asset surfaced by the External Discovery Engine">
      <div className="flex gap-1 border-b border-border">
        {ASSET_TABS.map(t => (
          <button
            key={t.key}
            onClick={() => setTab(t.key)}
            className={clsx(
              'px-3 py-2 text-sm border-b-2 -mb-px transition-colors',
              tab === t.key ? 'border-accent-cyan text-accent-cyan' : 'border-transparent text-text-muted hover:text-text-primary'
            )}
          >
            {t.label}
          </button>
        ))}
      </div>

      {loading ? <Loading /> : loadError ? (
        <div className="flex flex-col items-center gap-3 py-16 text-center">
          <AlertTriangle className="w-6 h-6 text-accent-orange" />
          <p className="text-sm text-text-muted">Failed to load asset inventory.</p>
          <button onClick={load} className="text-xs text-accent-cyan hover:underline">Retry</button>
        </div>
      ) : (
        <div className="space-y-6">
          {sections.includes('domains') && Array.isArray(data.domains) && data.domains.length > 0 && (
            <AssetSection title="Domains" icon={Globe}>
              <thead><tr><th>Domain</th><th>Status</th><th>First Seen</th></tr></thead>
              <tbody>
                {(data.domains as Array<{ id: string; name: string; status: string; first_seen_at?: string; created_at: string }>).map(d => (
                  <tr key={d.id}>
                    <td className="text-text-primary font-medium">{d.name}</td>
                    <td className="capitalize">{d.status}</td>
                    <td className="text-xs text-text-muted">{formatDistanceToNow(new Date(d.first_seen_at || d.created_at), { addSuffix: true })}</td>
                  </tr>
                ))}
              </tbody>
            </AssetSection>
          )}

          {sections.includes('subdomains') && Array.isArray(data.subdomains) && data.subdomains.length > 0 && (
            <AssetSection title="Subdomains" icon={Network}>
              <thead><tr><th>Subdomain</th><th>IPs</th><th>Source</th><th>Status</th><th>Last Seen</th></tr></thead>
              <tbody>
                {(data.subdomains as Array<{ id: string; fqdn: string; ips?: string[]; source: string; status: string; last_seen_at: string }>).map(s => (
                  <tr key={s.id}>
                    <td className="text-text-primary font-medium mono">{s.fqdn}</td>
                    <td className="text-xs text-text-muted">{(s.ips ?? []).join(', ') || '—'}</td>
                    <td className="text-xs text-text-muted">{s.source}</td>
                    <td className="capitalize">{s.status}</td>
                    <td className="text-xs text-text-muted">{formatDistanceToNow(new Date(s.last_seen_at), { addSuffix: true })}</td>
                  </tr>
                ))}
              </tbody>
            </AssetSection>
          )}

          {sections.includes('ips') && Array.isArray(data.ips) && data.ips.length > 0 && (
            <AssetSection title="IP Addresses" icon={Server}>
              <thead><tr><th>IP</th><th>ASN</th><th>Country</th><th>Status</th><th>Last Seen</th></tr></thead>
              <tbody>
                {(data.ips as Array<{ id: string; ip: string; asn?: string; asn_org?: string; country?: string; status: string; last_seen_at: string }>).map(h => (
                  <tr key={h.id}>
                    <td className="text-text-primary font-medium mono">{h.ip}</td>
                    <td className="text-xs text-text-muted">{h.asn ? `${h.asn}${h.asn_org ? ` (${h.asn_org})` : ''}` : '—'}</td>
                    <td className="text-xs text-text-muted">{h.country || '—'}</td>
                    <td className="capitalize">{h.status}</td>
                    <td className="text-xs text-text-muted">{formatDistanceToNow(new Date(h.last_seen_at), { addSuffix: true })}</td>
                  </tr>
                ))}
              </tbody>
            </AssetSection>
          )}

          {sections.includes('certificates') && Array.isArray(data.certificates) && data.certificates.length > 0 && (
            <AssetSection title="Certificates" icon={Shield}>
              <thead><tr><th>Subject</th><th>Issuer</th><th>Expires</th><th>Status</th></tr></thead>
              <tbody>
                {(data.certificates as Array<{ id: string; subject: string; issuer: string; not_after: string; is_expired: boolean; is_wildcard: boolean }>).map(c => (
                  <tr key={c.id}>
                    <td className="text-text-primary font-medium">{c.subject}{c.is_wildcard && <span className="badge-purple text-xs ml-2">wildcard</span>}</td>
                    <td className="text-xs text-text-muted">{c.issuer}</td>
                    <td className="text-xs text-text-muted">{formatDistanceToNow(new Date(c.not_after), { addSuffix: true })}</td>
                    <td>{c.is_expired ? <span className="badge-red text-xs">expired</span> : <span className="badge-green text-xs">valid</span>}</td>
                  </tr>
                ))}
              </tbody>
            </AssetSection>
          )}

          {sections.includes('services') && Array.isArray(data.services) && data.services.length > 0 && (
            <AssetSection title="Services" icon={Cpu}>
              <thead><tr><th>Host</th><th>Port</th><th>Protocol</th><th>Banner</th><th>State</th></tr></thead>
              <tbody>
                {(data.services as Array<{ id: string; host_ref: string; port: number; protocol: string; banner?: string; state: string }>).map(s => (
                  <tr key={s.id}>
                    <td className="text-text-primary font-medium mono">{s.host_ref}</td>
                    <td className="tabular-nums">{s.port}</td>
                    <td className="text-xs text-text-muted uppercase">{s.protocol}</td>
                    <td className="text-xs text-text-muted truncate max-w-xs">{s.banner || '—'}</td>
                    <td className="capitalize">{s.state}</td>
                  </tr>
                ))}
              </tbody>
            </AssetSection>
          )}

          {Object.values(data).every(arr => !Array.isArray(arr) || arr.length === 0) && (
            <Empty label="No discovered assets yet for this filter — start a discovery run from the dashboard" />
          )}
        </div>
      )}
    </Page>
  )
}

function AssetSection({ title, icon: Icon, children }: { title: string; icon: React.ElementType; children: React.ReactNode }) {
  return (
    <div>
      <h3 className="text-sm font-medium text-text-primary mb-2 flex items-center gap-1.5">
        <Icon className="w-4 h-4 text-text-muted" /> {title}
      </h3>
      <TableCard>{children}</TableCard>
    </div>
  )
}

// Risk Flags — admin panels, VPN portals, login pages, expired certs, shadow IT

export function DiscoveryRiskFlagsPage() {
  const [flags, setFlags] = useState<DiscoveryRiskFlag[]>([])
  const [status, setStatus] = useState('open')
  const [loading, setLoading] = useState(true)

  const load = useCallback(async () => {
    setLoading(true)
    try {
      const { data } = await discoveryApi.riskFlags({ status })
      setFlags(data.data ?? [])
    } catch {
      // Interceptor shows toast
    } finally {
      setLoading(false)
    }
  }, [status])

  useEffect(() => { load() }, [load])

  async function resolve(id: string) {
    try {
      await discoveryApi.resolveRiskFlag(id)
      toast.success('Risk flag resolved')
      setFlags(prev => prev.filter(f => f.id !== id))
    } catch {
      // interceptor handles error toast
    }
  }

  return (
    <Page title="Discovery Risk Flags" subtitle="Exposed admin panels, VPN portals, login pages, expired certificates, and shadow IT surfaced during discovery">
      <div className="flex items-center gap-2">
        <select className="input text-sm w-44" value={status} onChange={e => setStatus(e.target.value)}>
          <option value="open">Open</option>
          <option value="acknowledged">Acknowledged</option>
          <option value="resolved">Resolved</option>
        </select>
        <button onClick={load} className="btn-secondary text-sm flex items-center gap-1.5">
          <RefreshCw className="w-3.5 h-3.5" /> Refresh
        </button>
      </div>

      {loading ? <Loading /> : flags.length === 0 ? (
        <Empty label="No risk flags for this status" />
      ) : (
        <TableCard>
          <thead><tr><th>Flag</th><th>Asset</th><th>Severity</th><th>Evidence</th><th>Detected</th><th></th></tr></thead>
          <tbody>
            {flags.map(f => (
              <tr key={f.id}>
                <td><FlagBadge type={f.flag_type} /></td>
                <td className="text-text-primary font-medium mono">{f.asset_label}</td>
                <td className="capitalize">{f.severity}</td>
                <td className="text-xs text-text-muted max-w-md truncate">{f.evidence}</td>
                <td className="text-xs text-text-muted">{formatDistanceToNow(new Date(f.detected_at), { addSuffix: true })}</td>
                <td>
                  {f.status === 'open' && (
                    <button onClick={() => resolve(f.id)} className="text-xs text-accent-cyan hover:underline">Resolve</button>
                  )}
                </td>
              </tr>
            ))}
          </tbody>
        </TableCard>
      )}
    </Page>
  )
}
