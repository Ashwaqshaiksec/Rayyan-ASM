import { useEffect, useState } from 'react'
import { Link } from 'react-router-dom'
import {
  Scan, AlertTriangle, CheckCircle, Clock, Bug, Gauge, ArrowUpRight, Telescope, Globe, FlaskConical
} from 'lucide-react'
import {
  AreaChart, Area, Line, XAxis, YAxis, Tooltip, ResponsiveContainer
} from 'recharts'
import { dashboardApi, alertApi, scanApi, changeDetectApi } from '@/utils/api'
import type { DashboardSummary, Alert, ScanJob, AssetChangeEvent } from '@/types'
import { formatDistanceToNow } from 'date-fns'
import clsx from 'clsx'

interface RiskScore {
  score: number
  tier: string
  breakdown: {
    critical_findings: number
    high_findings: number
    medium_findings: number
    low_findings: number
    expiring_certs: number
    total_services: number
  }
}

const TIER_COLOR: Record<string, string> = {
  critical: '#C81E3A',
  high:     '#A75709',
  medium:   '#8D6608',
  low:      '#147D3B',
}

function RiskGauge({ score, tier }: { score: number; tier: string }) {
  // Defensive: risk-score API can return a partial/empty payload (e.g. before
  // the first score has been computed for a new org), which previously left
  // `score` as undefined and rendered NaN into the SVG arc and the label.
  const safeScore = Number.isFinite(score) ? score : 0
  const color = TIER_COLOR[tier] ?? '#147D3B'
  const radius = 52
  const circumference = Math.PI * radius
  const progress = circumference * (safeScore / 100)
  return (
    <div className="flex flex-col items-center flex-shrink-0">
      <svg width="128" height="74" viewBox="0 0 128 74">
        <path d="M 12 64 A 52 52 0 0 1 116 64" fill="none" stroke="var(--surface-3)" strokeWidth="10" strokeLinecap="round" />
        <path
          d="M 12 64 A 52 52 0 0 1 116 64"
          fill="none" stroke={color} strokeWidth="10" strokeLinecap="round"
          strokeDasharray={`${progress} ${circumference}`}
          style={{ transition: 'stroke-dasharray 0.8s ease' }}
        />
      </svg>
      <div className="-mt-5 text-center">
        <div className="text-[26px] leading-none font-semibold tabular-nums" style={{ color }}>{Math.round(safeScore)}</div>
        <div className="text-[10px] font-medium uppercase tracking-wider mt-1" style={{ color }}>{tier} risk</div>
      </div>
    </div>
  )
}

const SEVERITY_COLOR: Record<string, string> = {
  critical: '#C81E3A',
  high:     '#A75709',
  medium:   '#8D6608',
  low:      '#147D3B',
  info:     '#565D6D',
}

interface RailStatProps {
  label: string
  value: number | string
  to: string
  live?: boolean
}

// A quiet, numbers-forward readout instead of another row of icon+value+label
// cards — same "live instrument panel" language as the discovery feed on the
// login screen, just repurposed for inventory counts instead of a log.
function RailStat({ label, value, to, live }: RailStatProps) {
  return (
    <Link
      to={to}
      className="flex flex-col justify-center gap-1 px-4 py-3 min-w-[92px] group hover:bg-surface-3/50 transition-colors"
    >
      <div className="flex items-baseline gap-1.5">
        <span className="text-lg font-mono font-semibold tabular-nums text-text-primary group-hover:text-accent-cyan">
          {value.toLocaleString()}
        </span>
        {live && <span className="w-1.5 h-1.5 rounded-full bg-accent-green animate-pulse-slow" />}
      </div>
      <span className="text-[10px] font-mono uppercase tracking-wider text-text-muted whitespace-nowrap">{label}</span>
    </Link>
  )
}

interface TrendPoint { date: string; hosts: number; services: number; alerts: number; avg_risk_score?: number | null }

export default function DashboardPage() {
  const [summary, setSummary] = useState<DashboardSummary | null>(null)
  const [alerts, setAlerts] = useState<Alert[]>([])
  const [scans, setScans] = useState<ScanJob[]>([])
  const [trends, setTrends] = useState<TrendPoint[]>([])
  const [riskScore, setRiskScore] = useState<RiskScore | null>(null)
  const [changes, setChanges] = useState<AssetChangeEvent[]>([])
  const [loading, setLoading] = useState(true)

  useEffect(() => {
    const load = async () => {
      try {
        const [s, a, sc, tr] = await Promise.all([
          dashboardApi.summary(),
          alertApi.list({ status: 'open', limit: 5 }),
          scanApi.list({ limit: 5 }),
          dashboardApi.trends(),
        ])
        setSummary(s.data)
        setAlerts(a.data.data ?? [])
        setScans(sc.data.data ?? [])
        setTrends(tr.data.data ?? [])
        dashboardApi.riskScore().then(r => setRiskScore(r.data)).catch(() => {})
        changeDetectApi.timeline({ limit: 8 }).then(r => setChanges(r.data.data ?? [])).catch(() => {})
      } catch (err) {
        console.error('Failed to load dashboard data:', err)
      }
      setLoading(false)
    }
    load()
    // Auto-refresh every 30s for live scan progress
    const timer = setInterval(load, 30_000)
    return () => clearInterval(timer)
  }, [])

  if (loading) return (
    <div className="flex items-center justify-center h-64">
      <div className="w-6 h-6 border-2 border-accent-cyan/30 border-t-accent-cyan rounded-full animate-spin" />
    </div>
  )

  const criticalCount = summary?.critical_findings ?? 0
  const openFindings = summary?.open_findings ?? 0
  const expiringCerts = summary?.expiring_certs ?? 0

  const activeScans = summary?.active_scans ?? 0

  const inventory: RailStatProps[] = [
    { label: 'Domains',      value: summary?.domains ?? 0,      to: '/domains' },
    { label: 'Subdomains',   value: summary?.subdomains ?? 0,   to: '/subdomains' },
    { label: 'Hosts',        value: summary?.hosts ?? 0,        to: '/hosts' },
    { label: 'Services',     value: summary?.services ?? 0,     to: '/services' },
    { label: 'Certificates', value: summary?.certificates ?? 0, to: '/certificates' },
    { label: 'Technologies', value: summary?.technologies ?? 0, to: '/technologies' },
    { label: 'Active scans', value: activeScans, to: '/scans', live: activeScans > 0 },
  ]

  return (
    <div className="p-6 max-w-7xl mx-auto space-y-5 animate-fade-in">
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-lg font-semibold text-text-primary">Dashboard</h1>
          <p className="text-sm text-text-muted mt-0.5 flex items-center gap-1.5">
            <span className="w-1.5 h-1.5 rounded-full bg-accent-green" />
            Live attack surface overview
          </p>
        </div>
        <Link to="/scans" className="btn-primary">
          <Scan className="w-3.5 h-3.5" />
          New Scan
        </Link>
      </div>

      {/* Quick actions — the three most common next steps from this screen. */}
      <div className="grid grid-cols-2 sm:grid-cols-4 gap-3">
        <Link to="/scans" className="card-hover flex items-center gap-3 p-3">
          <div className="w-8 h-8 rounded-lg bg-accent-cyan/10 border border-accent-cyan/25 flex items-center justify-center flex-shrink-0">
            <Scan className="w-4 h-4 text-accent-cyan" />
          </div>
          <div className="min-w-0">
            <div className="text-sm font-medium text-text-primary truncate">New scan</div>
            <div className="text-xs text-text-muted truncate">Kick off a scan job</div>
          </div>
        </Link>
        <Link to="/discovery" className="card-hover flex items-center gap-3 p-3">
          <div className="w-8 h-8 rounded-lg bg-accent-purple/10 border border-accent-purple/25 flex items-center justify-center flex-shrink-0">
            <Telescope className="w-4 h-4 text-accent-purple" />
          </div>
          <div className="min-w-0">
            <div className="text-sm font-medium text-text-primary truncate">Discovery</div>
            <div className="text-xs text-text-muted truncate">Find new assets</div>
          </div>
        </Link>
        <Link to="/domains" className="card-hover flex items-center gap-3 p-3">
          <div className="w-8 h-8 rounded-lg bg-accent-green/10 border border-accent-green/25 flex items-center justify-center flex-shrink-0">
            <Globe className="w-4 h-4 text-accent-green" />
          </div>
          <div className="min-w-0">
            <div className="text-sm font-medium text-text-primary truncate">Add domain</div>
            <div className="text-xs text-text-muted truncate">Grow the inventory</div>
          </div>
        </Link>
        <Link to="/toolbox" className="card-hover flex items-center gap-3 p-3">
          <div className="w-8 h-8 rounded-lg bg-accent-orange/10 border border-accent-orange/25 flex items-center justify-center flex-shrink-0">
            <FlaskConical className="w-4 h-4 text-accent-orange" />
          </div>
          <div className="min-w-0">
            <div className="text-sm font-medium text-text-primary truncate">Toolbox</div>
            <div className="text-xs text-text-muted truncate">Run a one-off tool</div>
          </div>
        </Link>
      </div>

      {/* Hero: risk score + the two numbers that actually need attention first */}
      <div className="card p-5 flex flex-col sm:flex-row items-stretch gap-5">
        {riskScore && (
          <div className="flex items-center gap-4 pb-5 sm:pb-0 sm:pr-6 border-b sm:border-b-0 sm:border-r border-border-muted">
            <RiskGauge score={riskScore.score} tier={riskScore.tier} />
            <div className="hidden sm:block">
              <div className="flex items-center gap-1.5 text-xs font-medium text-text-secondary">
                <Gauge className="w-3.5 h-3.5 text-text-muted" /> Attack surface score
              </div>
              <Link to="/risk" className="text-xs text-accent-cyan hover:underline inline-flex items-center gap-0.5 mt-1.5">
                Per-asset breakdown <ArrowUpRight className="w-3 h-3" />
              </Link>
            </div>
          </div>
        )}

        <Link to="/findings" className="flex-1 flex items-center gap-4 group">
          <div className="w-11 h-11 rounded-lg flex items-center justify-center flex-shrink-0"
            style={{ background: criticalCount > 0 ? '#C81E3A15' : '#147D3B15', border: `1px solid ${criticalCount > 0 ? '#C81E3A30' : '#147D3B30'}` }}>
            <Bug className="w-5 h-5" style={{ color: criticalCount > 0 ? '#C81E3A' : '#147D3B' }} />
          </div>
          <div className="min-w-0">
            <div className="text-2xl font-mono font-semibold tabular-nums" style={{ color: criticalCount > 0 ? '#C81E3A' : 'var(--text-primary)' }}>
              {criticalCount}
            </div>
            <div className="text-xs text-text-muted">Critical findings · {openFindings} open total</div>
          </div>
          <ArrowUpRight className="w-3.5 h-3.5 text-text-muted ml-auto opacity-0 group-hover:opacity-100 transition-opacity flex-shrink-0" />
        </Link>

        <Link to="/certificates" className="flex-1 flex items-center gap-4 group">
          <div className="w-11 h-11 rounded-lg flex items-center justify-center flex-shrink-0"
            style={{ background: expiringCerts > 0 ? '#A7570915' : '#147D3B15', border: `1px solid ${expiringCerts > 0 ? '#A7570930' : '#147D3B30'}` }}>
            {expiringCerts > 0
              ? <AlertTriangle className="w-5 h-5" style={{ color: '#A75709' }} />
              : <CheckCircle className="w-5 h-5" style={{ color: '#147D3B' }} />}
          </div>
          <div className="min-w-0">
            <div className="text-2xl font-mono font-semibold tabular-nums" style={{ color: expiringCerts > 0 ? '#A75709' : 'var(--text-primary)' }}>
              {expiringCerts}
            </div>
            <div className="text-xs text-text-muted">
              {expiringCerts > 0 ? 'Certificates expiring within 30 days' : 'Certificates healthy'}
            </div>
          </div>
          <ArrowUpRight className="w-3.5 h-3.5 text-text-muted ml-auto opacity-0 group-hover:opacity-100 transition-opacity flex-shrink-0" />
        </Link>
      </div>

      {/* Inventory rail — same dark instrument-panel language as the login
          screen's live feed, so counts read as a live readout, not a static
          row of icon cards. */}
      <div
        className="rounded-lg border border-border overflow-hidden flex divide-x divide-border-muted overflow-x-auto"
        style={{ background: 'linear-gradient(180deg, var(--surface-2) 0%, var(--surface-1) 100%)' }}
      >
        {inventory.map((s) => <RailStat key={s.label} {...s} />)}
      </div>

      {/* Charts + Recent */}
      <div className="grid grid-cols-1 lg:grid-cols-3 gap-4">
        <div className="lg:col-span-2 card p-4">
          <div className="flex items-center justify-between mb-4">
            <div>
              <span className="text-[10px] font-medium uppercase tracking-wider text-text-muted">Discovery</span>
              <h2 className="text-sm font-medium text-text-primary">Hosts, services &amp; risk score, last 30 days</h2>
            </div>
          </div>
          <ResponsiveContainer width="100%" height={180}>
            <AreaChart data={trends}>
              <defs>
                <linearGradient id="hostsGrad" x1="0" y1="0" x2="0" y2="1">
                  <stop offset="5%" stopColor="#8A4B0A" stopOpacity={0.25} />
                  <stop offset="95%" stopColor="#8A4B0A" stopOpacity={0} />
                </linearGradient>
                <linearGradient id="svcGrad" x1="0" y1="0" x2="0" y2="1">
                  <stop offset="5%" stopColor="#147D3B" stopOpacity={0.22} />
                  <stop offset="95%" stopColor="#147D3B" stopOpacity={0} />
                </linearGradient>
              </defs>
              <XAxis dataKey="date" tick={{ fill: '#636873', fontSize: 11 }} axisLine={false} tickLine={false} />
              <YAxis yAxisId="count" tick={{ fill: '#636873', fontSize: 11 }} axisLine={false} tickLine={false} />
              <YAxis yAxisId="risk" orientation="right" domain={[0, 100]} tick={{ fill: '#C81E3A', fontSize: 11 }} axisLine={false} tickLine={false} />
              <Tooltip
                contentStyle={{ background: '#FFFFFF', border: '1px solid #DDE1E8', borderRadius: '3px', fontSize: '12px', boxShadow: '0 8px 20px rgba(18, 21, 28, 0.14)' }}
                labelStyle={{ color: '#565D6D' }}
                itemStyle={{ color: '#12151C' }}
              />
              <Area yAxisId="count" type="monotone" dataKey="hosts" stroke="#8A4B0A" strokeWidth={1.5} fill="url(#hostsGrad)" name="Hosts" />
              <Area yAxisId="count" type="monotone" dataKey="services" stroke="#147D3B" strokeWidth={1.5} fill="url(#svcGrad)" name="Services" />
              <Line yAxisId="risk" type="monotone" dataKey="avg_risk_score" stroke="#C81E3A" strokeWidth={1.5} dot={false} connectNulls name="Risk score" />
            </AreaChart>
          </ResponsiveContainer>
        </div>

        {/* Recent alerts */}
        <div className="card p-4 flex flex-col">
          <div className="flex items-center justify-between mb-3">
            <div>
              <span className="text-[10px] font-medium uppercase tracking-wider text-text-muted">Signal</span>
              <h2 className="text-sm font-medium text-text-primary">Recent alerts</h2>
            </div>
            <Link to="/alerts" className="text-xs text-text-muted hover:text-accent-cyan">View all</Link>
          </div>
          <div className="space-y-1 flex-1">
            {alerts.length === 0 && (
              <div className="flex flex-col items-center justify-center h-24 text-text-muted">
                <CheckCircle className="w-5 h-5 mb-1" />
                <span className="text-xs">No open alerts</span>
              </div>
            )}
            {alerts.map((a) => (
              <Link to="/alerts" key={a.id} className="flex items-start gap-2 px-2 py-2 rounded-md hover:bg-surface-2 transition-colors -mx-2">
                <span className="w-2 h-2 rounded-full mt-1.5 flex-shrink-0" style={{ background: SEVERITY_COLOR[a.severity] }} />
                <div className="min-w-0">
                  <div className="text-xs text-text-primary truncate">{a.title}</div>
                  <div className="text-xs text-text-muted mt-0.5">
                    <Clock className="inline w-3 h-3 mr-0.5" />
                    {formatDistanceToNow(new Date(a.created_at), { addSuffix: true })}
                  </div>
                </div>
              </Link>
            ))}
          </div>
        </div>
      </div>

      {/* What changed — surfaces the existing change-detection timeline
          (previously only visible on its own dedicated page, and only
          ever populated by a manual "Run" click) right on the landing
          view, and now runs automatically after every scan. */}
      <div className="card p-4">
        <div className="flex items-center justify-between mb-3">
          <div>
            <span className="text-[10px] font-medium uppercase tracking-wider text-text-muted">Change detection</span>
            <h2 className="text-sm font-medium text-text-primary">What changed since last scan</h2>
          </div>
          <Link to="/changes" className="text-xs text-text-muted hover:text-accent-cyan">View full timeline</Link>
        </div>
        {changes.length === 0 ? (
          <div className="flex flex-col items-center justify-center h-20 text-text-muted">
            <CheckCircle className="w-5 h-5 mb-1" />
            <span className="text-xs">No changes detected yet</span>
          </div>
        ) : (
          <div className="space-y-1">
            {changes.map(ev => (
              <div key={ev.id} className="flex items-center gap-2 px-2 py-1.5 rounded-md hover:bg-surface-2 -mx-2">
                <span className={clsx('badge text-[10px]',
                  ev.change_type === 'new' ? 'badge-green' : ev.change_type === 'removed' ? 'badge-red' : 'badge-blue')}>
                  {ev.change_type}
                </span>
                <span className="text-xs text-text-muted uppercase tracking-wide w-20 shrink-0">{ev.asset_type}</span>
                <span className="text-xs text-text-primary font-mono truncate flex-1">{ev.asset_label || ev.asset_key}</span>
                <span className="text-xs text-text-muted shrink-0">{formatDistanceToNow(new Date(ev.detected_at), { addSuffix: true })}</span>
              </div>
            ))}
          </div>
        )}
      </div>

      {/* Recent scans */}
      <div className="card">
        <div className="flex items-center justify-between px-4 py-3 border-b border-border">
          <div>
            <span className="text-[10px] font-medium uppercase tracking-wider text-text-muted">Activity</span>
            <h2 className="text-sm font-medium text-text-primary">Recent scans</h2>
          </div>
          <Link to="/scans" className="text-xs text-text-muted hover:text-accent-cyan">View all</Link>
        </div>
        <div className="table-container">
          <table className="table">
            <thead>
              <tr>
                <th>Name</th><th>Type</th><th>Status</th><th>Progress</th><th>Created</th>
              </tr>
            </thead>
            <tbody>
              {scans.length === 0 && (
                <tr><td colSpan={5} className="text-center text-text-muted py-6">No scans yet</td></tr>
              )}
              {scans.map((sc) => (
                <tr key={sc.id}>
                  <td className="text-text-primary font-medium">{sc.name}</td>
                  <td><span className="badge-gray">{sc.type}</span></td>
                  <td><ScanStatusBadge status={sc.status} /></td>
                  <td>
                    <div className="flex items-center gap-2">
                      <div className="flex-1 h-1.5 bg-surface-3 rounded-full overflow-hidden">
                        <div className="h-full bg-accent-cyan rounded-full" style={{ width: `${sc.progress}%` }} />
                      </div>
                      <span className="text-xs text-text-muted tabular-nums">{sc.progress}%</span>
                    </div>
                  </td>
                  <td className="text-xs">{formatDistanceToNow(new Date(sc.created_at), { addSuffix: true })}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </div>
    </div>
  )
}

function ScanStatusBadge({ status }: { status: ScanJob['status'] }) {
  const map: Record<string, string> = {
    pending:   'badge-gray',
    queued:    'badge-blue',
    running:   'badge-blue',
    completed: 'badge-green',
    failed:    'badge-red',
    cancelled: 'badge-gray',
  }
  return <span className={clsx('badge', map[status] ?? 'badge-gray')}>{status}</span>
}
