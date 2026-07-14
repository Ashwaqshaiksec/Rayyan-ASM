import { useEffect, useState, useCallback } from 'react'
import { RefreshCw, AlertTriangle, Globe, Radar } from 'lucide-react'
import { exposureApi } from '@/utils/api'
import type { ExposureDashboard, ExposureAssetRow } from '@/types'
import clsx from 'clsx'
import toast from 'react-hot-toast'
import { Page, TableCard, SkeletonCards, Empty } from './shared'
import { TIER_COLOR, hexToRgba, EXEC_TIER_COLOR, ExposureGauge, KPITile, ExposureAssetTable } from './risk-shared'

export function ExposureCenterPage() {
 const [dashboard, setDashboard] = useState<ExposureDashboard | null>(null)
 const [assets, setAssets] = useState<ExposureAssetRow[]>([])
 const [loading, setLoading] = useState(true)
 const [levelFilter, setLevelFilter] = useState('')
 const [recomputing, setRecomputing] = useState(false)
 const [tab, setTab] = useState<'top' | 'public' | 'paths' | 'services' | 'tech' | 'matrix'>('top')

 const load = useCallback(async () => {
 setLoading(true)
 try {
 const [d, a] = await Promise.all([
 exposureApi.dashboard(),
 exposureApi.assets({ level: levelFilter || undefined, limit: 100 }),
 ])
 setDashboard(d.data)
 setAssets(a.data.data ?? [])
 } catch {
 toast.error('Failed to load exposure data')
 } finally {
 setLoading(false)
 }
 }, [levelFilter])

 useEffect(() => { load() }, [load])

 async function recompute() {
 setRecomputing(true)
 try {
 const { data } = await exposureApi.recompute()
 toast.success(`Recomputed exposure for ${data.assets_scored} assets`)
 load()
 } catch {
 toast.error('Recompute failed')
 } finally {
 setRecomputing(false)
 }
 }

 const maxMatrixCount = Math.max(1, ...(dashboard?.risk_vs_exposure_matrix ?? []).map(c => c.count))

 return (
 <Page
 title="Exposure Center"
 subtitle="Real-world attackability and business impact, blended across risk, exposure, attack paths, and the asset graph — not CVSS alone"
 actions={
 <button onClick={recompute} disabled={recomputing} className="btn-primary text-sm flex items-center gap-1">
 <RefreshCw className={clsx('w-3 h-3', recomputing && 'animate-spin')} />
 {recomputing ? 'Recomputing…' : 'Recompute now'}
 </button>
 }
 >
 {loading && !dashboard ? <SkeletonCards cards={4} /> : !dashboard ? <Empty label="No exposure data yet" /> : (
 <>
 <div className="grid grid-cols-1 lg:grid-cols-3 gap-4">
 <div className="card p-4 flex items-center justify-center">
 <ExposureGauge score={dashboard.avg_exposure_score} />
 </div>
 <div className="lg:col-span-2 grid grid-cols-2 sm:grid-cols-4 gap-3">
 <KPITile label="Critical exposures" value={dashboard.critical} icon={AlertTriangle} color="text-accent-red" />
 <KPITile label="High exposures" value={dashboard.high} icon={AlertTriangle} color="text-accent-orange" />
 <KPITile label="Public-facing assets" value={dashboard.public_facing_count} icon={Globe} color="text-accent-blue" />
 <KPITile label="Assets scored" value={dashboard.total_scored} icon={Radar} color="text-text-primary" />
 </div>
 </div>

 <div className="flex items-center gap-2 flex-wrap border-b border-border pb-2">
 {([
 ['top', 'Top Exposed Assets'], ['public', 'Public Facing'], ['paths', 'Attack Path Exposure'],
 ['services', 'High Risk Services'], ['tech', 'Dangerous Technologies'], ['matrix', 'Risk vs Exposure Matrix'],
 ] as const).map(([key, label]) => (
 <button
 key={key}
 onClick={() => setTab(key)}
 className={clsx(
 'text-xs font-medium px-3 py-1.5 rounded-md transition-colors',
 tab === key ? 'bg-accent-cyan/15 text-accent-cyan' : 'text-text-muted hover:text-text-secondary'
 )}
 >
 {label}
 </button>
 ))}
 </div>

 {tab === 'top' && (
 <>
 <div className="flex items-center gap-3">
 <select className="input text-sm w-auto" value={levelFilter} onChange={e => setLevelFilter(e.target.value)}>
 <option value="">All levels</option>
 <option value="critical">Critical</option>
 <option value="high">High</option>
 <option value="medium">Medium</option>
 <option value="low">Low</option>
 <option value="informational">Informational</option>
 </select>
 </div>
 <ExposureAssetTable rows={assets} emptyLabel="No scored assets yet — click Recompute now" />
 </>
 )}

 {tab === 'public' && (
 <ExposureAssetTable rows={dashboard.public_facing_assets} emptyLabel="No internet-facing assets detected" />
 )}

 {tab === 'paths' && (
 <ExposureAssetTable rows={dashboard.attack_path_exposure} emptyLabel="No assets currently sit on a known attack path" />
 )}

 {tab === 'services' && (
 dashboard.high_risk_services.length === 0 ? <Empty label="No high-risk services found" /> : (
 <TableCard>
 <thead><tr><th>Host</th><th>Port</th><th>Protocol</th><th>Product</th><th>Exposure</th></tr></thead>
 <tbody>
 {dashboard.high_risk_services.map(s => (
 <tr key={s.service_id}>
 <td><span className="font-mono text-sm text-text-primary">{s.host_ref || '—'}</span></td>
 <td><span className="text-sm text-text-secondary tabular-nums">{s.port}</span></td>
 <td><span className="badge-gray text-xs">{s.protocol}</span></td>
 <td><span className="text-sm text-text-secondary">{s.product || '—'}</span></td>
 <td><span className="text-sm font-semibold text-accent-orange tabular-nums">{s.exposure_score.toFixed(1)}</span></td>
 </tr>
 ))}
 </tbody>
 </TableCard>
 )
 )}

 {tab === 'tech' && (
 dashboard.most_dangerous_technologies.length === 0 ? <Empty label="No technology exposure data yet" /> : (
 <TableCard>
 <thead><tr><th>Technology</th><th>Category</th><th>Assets</th><th>Avg exposure</th></tr></thead>
 <tbody>
 {dashboard.most_dangerous_technologies.map(t => (
 <tr key={t.name}>
 <td><span className="text-sm font-medium text-text-primary">{t.name}</span></td>
 <td><span className="text-xs text-text-muted">{t.category || '—'}</span></td>
 <td><span className="text-sm text-text-secondary tabular-nums">{t.asset_count}</span></td>
 <td><span className="text-sm font-semibold text-accent-orange tabular-nums">{t.avg_exposure_score.toFixed(1)}</span></td>
 </tr>
 ))}
 </tbody>
 </TableCard>
 )
 )}

 {tab === 'matrix' && (
 <div className="card p-4 overflow-x-auto">
 <div className="text-xs text-text-muted mb-3">Asset count by Risk Score tier (rows) × Exposure Level (columns)</div>
 <table className="w-full text-xs">
 <thead>
 <tr>
 <th className="text-left text-text-muted pb-2 pr-3">Risk tier</th>
 {['critical', 'high', 'medium', 'low', 'informational'].map(level => (
 <th key={level} className="text-center text-text-muted pb-2 px-2 capitalize">{level}</th>
 ))}
 </tr>
 </thead>
 <tbody>
 {['critical', 'high', 'medium', 'low'].map(tier => (
 <tr key={tier}>
 <td className={clsx('font-medium capitalize pr-3 py-1', TIER_COLOR[tier])}>{tier}</td>
 {['critical', 'high', 'medium', 'low', 'informational'].map(level => {
 const cell = dashboard.risk_vs_exposure_matrix.find(c => c.risk_tier === tier && c.exposure_level === level)
 const count = cell?.count ?? 0
 const intensity = count / maxMatrixCount
 const color = EXEC_TIER_COLOR[level] ?? '#8C99AD'
 return (
 <td key={level} className="px-2 py-1">
 <div
 className="rounded-md text-center font-semibold tabular-nums py-1.5"
 style={{
 backgroundColor: count > 0 ? hexToRgba(color, 0.12 + intensity * 0.35) : 'transparent',
 color: count > 0 ? color : '#8C99AD',
 }}
 >
 {count}
 </div>
 </td>
 )
 })}
 </tr>
 ))}
 </tbody>
 </table>
 </div>
 )}
 </>
 )}
 </Page>
 )
}

export default ExposureCenterPage
