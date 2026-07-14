import { useEffect, useState, useCallback } from 'react'
import { Link } from 'react-router-dom'
import {
 RefreshCw, Layers, TrendingUp, Globe, AlertTriangle, Gauge, Clock, Briefcase, Bell, Crosshair, Radar,
} from 'lucide-react'
import {
 AreaChart, Area, XAxis, YAxis, Tooltip, ResponsiveContainer, CartesianGrid, BarChart, Bar,
} from 'recharts'
import { executiveApi, exposureApi } from '@/utils/api'
import type {
 ExecutiveSummary, ExecutiveKPISnapshot, ExecutiveSLACompliance, ExecutiveAttackPathOverview,
 ExecutiveBusinessImpact, ExposureDashboard,
} from '@/types'
import { format } from 'date-fns'
import clsx from 'clsx'
import toast from 'react-hot-toast'
import { Page, TableCard, SkeletonCards, Empty } from './shared'
import { EXEC_TIER_COLOR, ExposureGauge, KPITile, PERIODS, EXPOSURE_LEVEL_COLOR, ExposureLevelBadge } from './risk-shared'

export function ExecutiveDashboardPage() {
 const [summary, setSummary] = useState<ExecutiveSummary | null>(null)
 const [trends, setTrends] = useState<ExecutiveKPISnapshot[]>([])
 const [sla, setSla] = useState<ExecutiveSLACompliance | null>(null)
 const [paths, setPaths] = useState<ExecutiveAttackPathOverview | null>(null)
 const [impact, setImpact] = useState<ExecutiveBusinessImpact | null>(null)
 const [exposure, setExposure] = useState<ExposureDashboard | null>(null)
 const [period, setPeriod] = useState('daily')
 const [loading, setLoading] = useState(true)
 const [recomputing, setRecomputing] = useState(false)

 const loadAll = useCallback(async (p: string) => {
 setLoading(true)
 try {
 const [s, t, sl, ap, bi, ex] = await Promise.all([
 executiveApi.summary(),
 executiveApi.trends({ period: p, points: 30 }),
 executiveApi.slaCompliance(),
 executiveApi.attackPathOverview(),
 executiveApi.businessImpact(),
 exposureApi.dashboard(),
 ])
 setSummary(s.data)
 setTrends(t.data.data ?? [])
 setSla(sl.data)
 setPaths(ap.data)
 setImpact(bi.data)
 setExposure(ex.data)
 } catch {
 toast.error('Failed to load executive dashboard')
 } finally {
 setLoading(false)
 }
 }, [])

 useEffect(() => { loadAll(period) }, [loadAll, period])

 async function recompute() {
 setRecomputing(true)
 try {
 await executiveApi.recompute()
 toast.success('Executive KPI snapshot recomputed')
 loadAll(period)
 } catch {
 toast.error('Recompute failed')
 } finally {
 setRecomputing(false)
 }
 }

 if (loading && !summary) {
 return <Page title="Executive Dashboard" subtitle="Organization-wide exposure, risk and business impact overview"><SkeletonCards cards={6} /></Page>
 }

 return (
 <Page
 title="Executive Dashboard"
 subtitle="Organization-wide exposure, risk and business impact overview"
 actions={
 <button onClick={recompute} disabled={recomputing} className="btn-primary text-sm flex items-center gap-1">
 <RefreshCw className={clsx('w-3 h-3', recomputing && 'animate-spin')} />
 {recomputing ? 'Recomputing…' : 'Recompute KPIs'}
 </button>
 }
 >
 <div className="grid grid-cols-4 gap-4">
 <div className="card p-4 col-span-1 flex items-center justify-center">
 {summary && <ExposureGauge score={summary.exposure_score} />}
 </div>
 <div className="col-span-3 grid grid-cols-3 gap-4">
 <KPITile label="Total Assets" value={summary?.total_assets ?? 0} icon={Layers} />
 <KPITile
 label="New Assets (7d)" value={summary?.new_assets_7d ?? 0} icon={TrendingUp}
 color="text-accent-cyan"
 />
 <KPITile
 label="Internet-Facing" value={summary?.internet_facing_assets ?? 0} icon={Globe}
 color="text-accent-orange"
 />
 <KPITile
 label="Critical Findings" value={summary?.critical_findings ?? 0} icon={AlertTriangle}
 color="text-accent-red"
 />
 <KPITile
 label="Avg Risk Score" value={(summary?.avg_risk_score ?? 0).toFixed(1)} icon={Gauge}
 />
 <KPITile
 label="Critical Attack Paths" value={summary?.critical_attack_path_count ?? 0} icon={AlertTriangle}
 color="text-accent-red"
 />
 <KPITile
 label="SLA Compliance" value={`${(summary?.sla_compliance_pct ?? 100).toFixed(0)}%`} icon={Clock}
 color={(summary?.sla_compliance_pct ?? 100) >= 90 ? 'text-accent-green' : 'text-accent-orange'}
 />
 <KPITile
 label="Critical Assets Exposed" value={summary?.critical_assets_exposed ?? 0} icon={Briefcase}
 color="text-accent-red"
 />
 <KPITile label="Open Alerts" value={summary?.open_alerts ?? 0} icon={Bell} />
 </div>
 </div>

 <div className="card p-4">
 <div className="flex items-center justify-between mb-3">
 <div className="text-sm font-semibold text-text-primary">Exposure trend</div>
 <div className="flex items-center gap-1">
 {PERIODS.map(p => (
 <button
 key={p.value}
 onClick={() => setPeriod(p.value)}
 className={clsx(
 'px-2.5 py-1 text-xs rounded-md border',
 period === p.value
 ? 'bg-accent-cyan/10 border-accent-cyan/30 text-accent-cyan'
 : 'border-border text-text-muted hover:text-text-primary'
 )}
 >
 {p.label}
 </button>
 ))}
 </div>
 </div>
 {trends.length === 0 ? <Empty label="No KPI history yet — recompute to generate the first snapshot" /> : (
 <ResponsiveContainer width="100%" height={240}>
 <AreaChart data={trends}>
 <defs>
 <linearGradient id="exposureFill" x1="0" y1="0" x2="0" y2="1">
 <stop offset="0%" stopColor="#C81E3A" stopOpacity={0.35} />
 <stop offset="100%" stopColor="#C81E3A" stopOpacity={0} />
 </linearGradient>
 </defs>
 <CartesianGrid strokeDasharray="3 3" stroke="#DDE1E8" />
 <XAxis dataKey="date" tick={{ fontSize: 11 }} tickFormatter={(d) => format(new Date(d), 'MMM d')} />
 <YAxis tick={{ fontSize: 11 }} domain={[0, 100]} />
 <Tooltip labelFormatter={(d) => format(new Date(d as string), 'PPP')} />
 <Area type="monotone" dataKey="exposure_score" name="Exposure score" stroke="#C81E3A" fill="url(#exposureFill)" strokeWidth={2} />
 </AreaChart>
 </ResponsiveContainer>
 )}
 </div>

 <div className="grid grid-cols-2 gap-4">
 <div className="card p-4">
 <div className="text-sm font-semibold text-text-primary mb-3">Attack path overview</div>
 {paths && paths.total > 0 ? (
 <>
 <ResponsiveContainer width="100%" height={140}>
 <BarChart
 data={[
 { tier: 'Critical', count: paths.critical, fill: '#C81E3A' },
 { tier: 'High', count: paths.high, fill: '#A75709' },
 { tier: 'Medium', count: paths.medium, fill: '#8D6608' },
 { tier: 'Low', count: paths.low, fill: '#147D3B' },
 ]}
 layout="vertical"
 margin={{ left: 8 }}
 >
 <XAxis type="number" tick={{ fontSize: 11 }} />
 <YAxis dataKey="tier" type="category" tick={{ fontSize: 11 }} width={60} />
 <Tooltip />
 <Bar dataKey="count" radius={[0, 4, 4, 0]} />
 </BarChart>
 </ResponsiveContainer>
 <Link to="/attack-paths" className="text-xs text-accent-cyan hover:underline mt-2 inline-block">
 View all {paths.total} attack paths →
 </Link>
 </>
 ) : <Empty label="No attack paths computed yet" />}
 </div>

 <div className="card p-4">
 <div className="text-sm font-semibold text-text-primary mb-3">SLA compliance by severity</div>
 {sla && sla.total > 0 ? (
 <div className="space-y-2">
 {sla.by_severity.map(row => {
 const pct = row.total > 0 ? 100 * (1 - row.breached / row.total) : 100
 return (
 <div key={row.severity}>
 <div className="flex items-center justify-between text-xs mb-0.5">
 <span className="capitalize text-text-secondary">{row.severity}</span>
 <span className="text-text-muted">{row.total - row.breached}/{row.total} on time</span>
 </div>
 <div className="h-1.5 rounded-full bg-surface-3 overflow-hidden">
 <div
 className={clsx('h-full rounded-full', pct >= 90 ? 'bg-accent-green' : pct >= 60 ? 'bg-accent-orange' : 'bg-accent-red')}
 style={{ width: `${pct}%` }}
 />
 </div>
 </div>
 )
 })}
 <Link to="/findings/sla-report" className="text-xs text-accent-cyan hover:underline mt-2 inline-block">
 View full SLA report →
 </Link>
 </div>
 ) : <Empty label="No SLA-tracked findings yet" />}
 </div>
 </div>

 <div className="card">
 <div className="p-4 pb-0 text-sm font-semibold text-text-primary">Business impact — critical internet-facing assets</div>
 {impact && impact.assets.length > 0 ? (
 <TableCard>
 <thead>
 <tr>
 <th>Host</th><th>Business Unit</th><th>Owner</th><th>Risk</th><th>Open Findings</th><th>Critical</th>
 </tr>
 </thead>
 <tbody>
 {impact.assets.map(a => (
 <tr key={a.host_id}>
 <td className="font-mono text-xs">
 <Link to={`/hosts/${a.host_id}`} className="text-accent-cyan hover:underline">
 {a.hostname || a.ip}
 </Link>
 </td>
 <td>{a.business_unit || '—'}</td>
 <td>{a.owner || '—'}</td>
 <td>
 <span className={clsx('font-mono font-semibold', EXEC_TIER_COLOR[a.risk_tier] ? '' : '')} style={{ color: EXEC_TIER_COLOR[a.risk_tier] }}>
 {a.risk_score.toFixed(0)}
 </span>
 </td>
 <td>{a.open_findings}</td>
 <td className={a.critical_findings > 0 ? 'text-accent-red font-semibold' : ''}>{a.critical_findings}</td>
 </tr>
 ))}
 </tbody>
 </TableCard>
 ) : <div className="p-4"><Empty label="No business-critical internet-facing assets identified yet" /></div>}
 </div>

 <div className="card">
 <div className="flex items-center justify-between p-4 pb-0">
 <div className="text-sm font-semibold text-text-primary">Exposure prioritization</div>
 <Link to="/exposure" className="text-xs text-accent-cyan hover:underline">Open Exposure Center →</Link>
 </div>
 {!exposure || exposure.total_scored === 0 ? (
 <div className="p-4"><Empty label="No exposure scores yet — visit the Exposure Center to recompute" /></div>
 ) : (
 <div className="p-4 grid grid-cols-1 lg:grid-cols-3 gap-4">
 <div className="grid grid-cols-2 gap-3 lg:col-span-1">
 <KPITile label="Total Exposure Score" value={exposure.avg_exposure_score.toFixed(1)} icon={Crosshair} color="text-accent-red" />
 <KPITile label="Critical Exposures" value={exposure.critical} icon={AlertTriangle} color="text-accent-red" />
 <KPITile label="Public-Facing" value={exposure.public_facing_count} icon={Globe} color="text-accent-orange" />
 <KPITile label="Assets Scored" value={exposure.total_scored} icon={Radar} />
 </div>
 <div className="lg:col-span-2">
 <div className="text-xs text-text-muted mb-2">Most exposed assets</div>
 {exposure.top_exposed_assets.length === 0 ? <Empty label="No scored assets yet" /> : (
 <div className="space-y-1.5">
 {exposure.top_exposed_assets.slice(0, 5).map(a => {
 const link = a.asset_type === 'host' ? `/hosts/${a.asset_id}` : a.asset_type === 'domain' ? `/domains/${a.asset_id}` : null
 return (
 <div key={a.id} className="flex items-center gap-2 text-xs px-2 py-1.5 bg-surface-2 rounded-md">
 <span className={clsx('font-mono font-semibold w-10 text-right tabular-nums', EXPOSURE_LEVEL_COLOR[a.exposure_level])}>
 {a.exposure_score.toFixed(0)}
 </span>
 <span className="badge-gray text-xs shrink-0">{a.asset_type}</span>
 {link ? (
 <Link to={link} className="font-mono text-text-secondary truncate hover:underline hover:text-accent-cyan">{a.label}</Link>
 ) : (
 <span className="font-mono text-text-secondary truncate">{a.label}</span>
 )}
 <ExposureLevelBadge level={a.exposure_level} />
 </div>
 )
 })}
 </div>
 )}
 <div className="text-xs text-text-muted mt-3">
 Trend charts need historical snapshots — coming once exposure scores have a few days of history.
 </div>
 </div>
 </div>
 )}
 </div>
 </Page>
 )
}

export default ExecutiveDashboardPage
