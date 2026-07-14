import { useEffect, useState, useCallback } from 'react'
import { Search as SearchIcon, Filter, X } from 'lucide-react'
import { graphApi } from '@/utils/api'
import type { AssetStat } from '@/types'
import clsx from 'clsx'
import toast from 'react-hot-toast'
import { Page, TableCard, SkeletonTable, Empty } from './shared'
import { NodePill, riskBadgeClass } from './risk-shared'

export function AssetRelationshipsPage() {
 const [stats, setStats] = useState<AssetStat[]>([])
 const [loading, setLoading] = useState(true)
 const [query, setQuery] = useState('')
 const [typeFilter, setTypeFilter] = useState<string>('all')
 const [view, setView] = useState<'all' | 'critical' | 'orphan'>('all')

 const load = useCallback(async () => {
 setLoading(true)
 try {
 const { data } = await graphApi.assetStats()
 setStats(data.data ?? [])
 } catch {
 toast.error('Failed to load asset relationships')
 } finally {
 setLoading(false)
 }
 }, [])

 useEffect(() => { load() }, [load])

 const types = Array.from(new Set(stats.map(s => s.asset.type))).sort()

 const filtered = stats.filter(s => {
 if (view === 'critical' && !s.critical) return false
 if (view === 'orphan' && !s.orphan) return false
 if (typeFilter !== 'all' && s.asset.type !== typeFilter) return false
 if (query && !s.asset.label.toLowerCase().includes(query.toLowerCase())) return false
 return true
 })

 const criticalCount = stats.filter(s => s.critical).length
 const orphanCount = stats.filter(s => s.orphan).length

 return (
 <Page title="Asset Relationships" subtitle="Connectivity, blast-radius hubs, and unmapped assets across the relationship graph">
 <div className="grid grid-cols-4 gap-4">
 <div className="card p-4">
 <div className="text-xs text-text-muted">Mapped assets</div>
 <div className="text-2xl font-bold mt-1 text-text-primary">{stats.length}</div>
 </div>
 <div className="card p-4">
 <div className="text-xs text-text-muted">Avg. degree</div>
 <div className="text-2xl font-bold mt-1 text-text-primary">
 {stats.length ? (stats.reduce((sum, s) => sum + s.degree, 0) / stats.length).toFixed(1) : '0'}
 </div>
 </div>
 <div className="card p-4 cursor-pointer" onClick={() => setView(view === 'critical' ? 'all' : 'critical')}>
 <div className="text-xs text-text-muted">Critical hubs</div>
 <div className="text-2xl font-bold mt-1 text-accent-red">{criticalCount}</div>
 </div>
 <div className="card p-4 cursor-pointer" onClick={() => setView(view === 'orphan' ? 'all' : 'orphan')}>
 <div className="text-xs text-text-muted">Orphan assets</div>
 <div className="text-2xl font-bold mt-1 text-accent-orange">{orphanCount}</div>
 </div>
 </div>

 <div className="flex flex-wrap items-center gap-3">
 <div className="relative flex-1 min-w-[220px]">
 <SearchIcon className="w-4 h-4 absolute left-3 top-1/2 -translate-y-1/2 text-text-muted" />
 <input
 value={query}
 onChange={e => setQuery(e.target.value)}
 placeholder="Search asset name…"
 className="input pl-9 w-full"
 />
 </div>
 <div className="flex items-center gap-1.5">
 <Filter className="w-3.5 h-3.5 text-text-muted" />
 <select value={typeFilter} onChange={e => setTypeFilter(e.target.value)} className="input text-sm">
 <option value="all">All types</option>
 {types.map(t => <option key={t} value={t}>{t}</option>)}
 </select>
 </div>
 {view !== 'all' && (
 <button onClick={() => setView('all')} className="badge text-xs bg-surface-3 text-text-secondary border border-surface-3 flex items-center gap-1">
 {view === 'critical' ? 'Critical only' : 'Orphans only'} <X className="w-3 h-3" />
 </button>
 )}
 </div>

 {loading ? <SkeletonTable /> : filtered.length === 0 ? (
 <Empty label={stats.length === 0 ? 'No relationship data yet — run a scan or rebuild the graph on the Correlation page' : 'No assets match this filter'} />
 ) : (
 <TableCard>
 <thead>
 <tr>
 <th>Asset</th>
 <th>Type</th>
 <th>Relationship count</th>
 <th>Connected assets</th>
 <th>Risk score</th>
 <th>Flags</th>
 </tr>
 </thead>
 <tbody>
 {filtered.slice(0, 300).map((s, i) => (
 <tr key={i}>
 <td className="text-text-primary">{s.asset.label}</td>
 <td><NodePill node={s.asset} /></td>
 <td className="text-text-secondary">{s.degree}</td>
 <td className="text-text-secondary">{s.connected_assets}</td>
 <td>
 <span className={clsx('badge text-xs border', riskBadgeClass(s.risk_score))}>
 {s.risk_score?.toFixed(0) ?? '—'}
 </span>
 </td>
 <td className="flex items-center gap-1.5">
 {s.critical && <span className="badge text-xs bg-accent-red/10 text-accent-red border border-accent-red/20">critical hub</span>}
 {s.orphan && <span className="badge text-xs bg-accent-orange/10 text-accent-orange border border-accent-orange/20">orphan</span>}
 </td>
 </tr>
 ))}
 </tbody>
 </TableCard>
 )}
 {filtered.length > 300 && (
 <div className="text-xs text-text-muted text-center pt-2">Showing first 300 of {filtered.length} assets</div>
 )}
 </Page>
 )
}

export default AssetRelationshipsPage
