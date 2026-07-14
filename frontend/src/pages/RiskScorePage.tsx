import { useEffect, useState, useCallback } from 'react'
import { Link } from 'react-router-dom'
import { RefreshCw } from 'lucide-react'
import {
 AreaChart, Area, XAxis, YAxis, Tooltip, ResponsiveContainer, CartesianGrid,
} from 'recharts'
import { riskApi } from '@/utils/api'
import type { RiskAssetRow, RiskTrendPoint, RiskHeatmapCell } from '@/types'
import { formatDistanceToNow } from 'date-fns'
import clsx from 'clsx'
import toast from 'react-hot-toast'
import { Page, TableCard, SkeletonCards, Empty, SeverityBadge } from './shared'
import { TIER_COLOR, assetDetailLink } from './risk-shared'

export function RiskScorePage() {
 const [assets, setAssets] = useState<RiskAssetRow[]>([])
 const [trends, setTrends] = useState<RiskTrendPoint[]>([])
 const [heatmap, setHeatmap] = useState<RiskHeatmapCell[]>([])
 const [loading, setLoading] = useState(true)
 const [typeFilter, setTypeFilter] = useState('')
 const [tierFilter, setTierFilter] = useState('')
 const [recomputing, setRecomputing] = useState(false)

 const load = useCallback(async () => {
 setLoading(true)
 try {
 const [a, t, h] = await Promise.all([
 riskApi.assets({ type: typeFilter || undefined, tier: tierFilter || undefined, limit: 100 }),
 riskApi.trends({ days: 30 }),
 riskApi.heatmap(),
 ])
 setAssets(a.data.data ?? [])
 setTrends(t.data.data ?? [])
 setHeatmap(h.data.data ?? [])
 } catch {
 toast.error('Failed to load risk scores')
 } finally {
 setLoading(false)
 }
 }, [typeFilter, tierFilter])

 useEffect(() => { load() }, [load])

 async function recompute() {
 setRecomputing(true)
 try {
 const { data } = await riskApi.recompute()
 const total = (data.hosts_scored ?? 0) + (data.subdomains_scored ?? 0) + (data.domains_scored ?? 0)
 toast.success(`Recomputed risk for ${total} assets`)
 load()
 } catch {
 toast.error('Recompute failed')
 } finally {
 setRecomputing(false)
 }
 }

 const counts = { critical: 0, high: 0, medium: 0, low: 0 }
 for (const a of assets) {
 if (a.tier in counts) counts[a.tier as keyof typeof counts]++
 }

 return (
 <Page title="Risk Scoring" subtitle="Asset risk across hosts, subdomains, and domains"
 actions={
 <button onClick={recompute} disabled={recomputing} className="btn-primary text-sm flex items-center gap-1">
 <RefreshCw className={clsx('w-3 h-3', recomputing && 'animate-spin')} />
 {recomputing ? 'Recomputing…' : 'Recompute now'}
 </button>
 }>
 <div className="grid grid-cols-4 gap-4">
 {([['Critical', counts.critical, TIER_COLOR.critical], ['High', counts.high, TIER_COLOR.high],
 ['Medium', counts.medium, TIER_COLOR.medium], ['Low', counts.low, TIER_COLOR.low]] as const).map(([label, value, cls]) => (
 <div key={label} className="card p-4">
 <div className="text-xs text-text-muted">{label}</div>
 <div className={clsx('text-2xl font-bold mt-1', cls)}>{value}</div>
 </div>
 ))}
 </div>

 <div className="grid grid-cols-1 lg:grid-cols-3 gap-4">
 <div className="lg:col-span-2 card p-4">
 <h2 className="text-sm font-medium text-text-primary mb-4">Average Risk Score (30d)</h2>
 <ResponsiveContainer width="100%" height={180}>
 <AreaChart data={trends}>
 <defs>
 <linearGradient id="riskGrad" x1="0" y1="0" x2="0" y2="1">
 <stop offset="5%" stopColor="#DC2626" stopOpacity={0.18} />
 <stop offset="95%" stopColor="#DC2626" stopOpacity={0} />
 </linearGradient>
 </defs>
 <CartesianGrid strokeDasharray="3 3" stroke="#DCE3ED" vertical={false} />
 <XAxis dataKey="date" tick={{ fill: '#8C99AD', fontSize: 11 }} axisLine={false} tickLine={false} />
 <YAxis domain={[0, 100]} tick={{ fill: '#8C99AD', fontSize: 11 }} axisLine={false} tickLine={false} />
 <Tooltip
 contentStyle={{ background: '#FFFFFF', border: '1px solid #DCE3ED', borderRadius: '6px', fontSize: '12px', boxShadow: '0 4px 12px rgba(15, 27, 45, 0.08)' }}
 labelStyle={{ color: '#5B6B82' }}
 />
 <Area type="monotone" dataKey="score" stroke="#DC2626" strokeWidth={1.5} fill="url(#riskGrad)" name="Avg score" />
 </AreaChart>
 </ResponsiveContainer>
 </div>

 <div className="card p-4">
 <h2 className="text-sm font-medium text-text-primary mb-3">Risk by Business Unit</h2>
 {heatmap.length === 0 ? <Empty label="No business units tagged yet" /> : (
 <div className="space-y-2">
 {heatmap.map(cell => {
 const total = cell.critical + cell.high + cell.medium + cell.low || 1
 return (
 <div key={cell.group}>
 <div className="flex items-center justify-between text-xs text-text-secondary mb-1">
 <span>{cell.group}</span>
 <span className="text-text-muted">{cell.critical + cell.high + cell.medium + cell.low}</span>
 </div>
 <div className="flex h-2 rounded-full overflow-hidden bg-surface-3">
 <div className="bg-accent-red" style={{ width: `${(cell.critical / total) * 100}%` }} />
 <div className="bg-accent-orange" style={{ width: `${(cell.high / total) * 100}%` }} />
 <div className="bg-accent-blue" style={{ width: `${(cell.medium / total) * 100}%` }} />
 <div className="bg-accent-green" style={{ width: `${(cell.low / total) * 100}%` }} />
 </div>
 </div>
 )
 })}
 </div>
 )}
 </div>
 </div>

 <div className="flex items-center gap-3">
 <select className="input text-sm w-auto" value={typeFilter} onChange={e => setTypeFilter(e.target.value)}>
 <option value="">All asset types</option>
 <option value="host">Hosts</option>
 <option value="subdomain">Subdomains</option>
 <option value="domain">Domains</option>
 </select>
 <select className="input text-sm w-auto" value={tierFilter} onChange={e => setTierFilter(e.target.value)}>
 <option value="">All tiers</option>
 <option value="critical">Critical</option>
 <option value="high">High</option>
 <option value="medium">Medium</option>
 <option value="low">Low</option>
 </select>
 </div>

 {loading ? <SkeletonCards /> : assets.length === 0 ? <Empty label="No scored assets yet — click Recompute now" /> : (
 <TableCard>
 <thead><tr><th>Asset</th><th>Type</th><th>Score</th><th>Tier</th><th>Top factors</th><th>Scored</th></tr></thead>
 <tbody>
 {assets.map(a => {
 const link = assetDetailLink(a)
 const factors = Object.entries(a.factors ?? {})
 .filter(([k, v]) => typeof v === 'number' && v > 0 && k !== 'vuln_severity_score')
 .sort((x, y) => (y[1] as number) - (x[1] as number))
 .slice(0, 3)
 return (
 <tr key={`${a.asset_type}-${a.id}`}>
 <td>
 {link ? (
 <Link to={link} className="font-mono text-sm text-accent-cyan hover:underline">{a.label}</Link>
 ) : (
 <span className="font-mono text-sm text-text-primary">{a.label}</span>
 )}
 </td>
 <td><span className="badge-gray text-xs">{a.asset_type}</span></td>
 <td><span className={clsx('text-sm font-semibold', TIER_COLOR[a.tier])}>{a.score.toFixed(1)}</span></td>
 <td><SeverityBadge s={a.tier} /></td>
 <td>
 <div className="flex flex-wrap gap-1">
 {factors.length === 0 ? <span className="text-xs text-text-muted">—</span> : factors.map(([k, v]) => (
 <span key={k} className="badge-gray text-xs">
 {k.replace(/_/g, ' ')}: {String(v)}
 </span>
 ))}
 </div>
 </td>
 <td><span className="text-xs text-text-muted">{a.scored_at ? formatDistanceToNow(new Date(a.scored_at), { addSuffix: true }) : '—'}</span></td>
 </tr>
 )
 })}
 </tbody>
 </TableCard>
 )}
 </Page>
 )
}

export default RiskScorePage
