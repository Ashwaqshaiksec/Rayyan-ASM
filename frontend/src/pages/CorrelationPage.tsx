import { useEffect, useState, useCallback } from 'react'
import { RefreshCw, ArrowRight } from 'lucide-react'
import { correlationApi } from '@/utils/api'
import type { CorrelationNode, CorrelationEdge, RelatedAsset, ExposurePathHop } from '@/types'
import clsx from 'clsx'
import toast from 'react-hot-toast'
import { Page, TableCard, SkeletonTable, Empty } from './shared'
import { NodePill, AssetPicker } from './risk-shared'

export function CorrelationPage() {
 const [nodes, setNodes] = useState<CorrelationNode[]>([])
 const [edges, setEdges] = useState<CorrelationEdge[]>([])
 const [loading, setLoading] = useState(true)
 const [rebuilding, setRebuilding] = useState(false)

 const [focusAsset, setFocusAsset] = useState<CorrelationNode | null>(null)
 const [related, setRelated] = useState<RelatedAsset[]>([])
 const [relatedLoading, setRelatedLoading] = useState(false)

 const [fromAsset, setFromAsset] = useState<CorrelationNode | null>(null)
 const [toAsset, setToAsset] = useState<CorrelationNode | null>(null)
 const [path, setPath] = useState<ExposurePathHop[] | null>(null)
 const [pathSearched, setPathSearched] = useState(false)
 const [pathLoading, setPathLoading] = useState(false)

 const load = useCallback(async () => {
 setLoading(true)
 const { data } = await correlationApi.graph()
 setNodes(data.nodes ?? [])
 setEdges(data.edges ?? [])
 setLoading(false)
 }, [])

 useEffect(() => { load() }, [load])

 useEffect(() => {
 if (!focusAsset) { setRelated([]); return }
 setRelatedLoading(true)
 correlationApi.related(focusAsset.type, focusAsset.id)
 .then(({ data }) => setRelated(data.data ?? []))
 .catch(() => setRelated([]))
 .finally(() => setRelatedLoading(false))
 }, [focusAsset])

 async function rebuild() {
 setRebuilding(true)
 try {
 const { data } = await correlationApi.rebuild()
 toast.success(`Rebuilt graph: ${data.edges_built} relationships`)
 load()
 } catch {
 toast.error('Rebuild failed')
 } finally {
 setRebuilding(false)
 }
 }

 async function findPath() {
 if (!fromAsset || !toAsset) return
 setPathLoading(true)
 setPathSearched(true)
 try {
 const { data } = await correlationApi.exposurePath({
 from_type: fromAsset.type, from_id: fromAsset.id,
 to_type: toAsset.type, to_id: toAsset.id,
 })
 setPath(data.found ? data.data : null)
 } catch {
 setPath(null)
 } finally {
 setPathLoading(false)
 }
 }

 const inferredCount = edges.filter(e => e.relation_type !== 'parent_child' && e.relation_type !== 'resolves_to').length

 return (
 <Page title="Asset Correlation" subtitle="Relationship graph across domains, hosts, services, and shared infrastructure"
 actions={
 <button onClick={rebuild} disabled={rebuilding} className="btn-primary text-sm flex items-center gap-1">
 <RefreshCw className={clsx('w-3 h-3', rebuilding && 'animate-spin')} />
 {rebuilding ? 'Rebuilding…' : 'Rebuild graph'}
 </button>
 }>
 <div className="grid grid-cols-3 gap-4">
 <div className="card p-4">
 <div className="text-xs text-text-muted">Assets in graph</div>
 <div className="text-2xl font-bold mt-1 text-text-primary">{nodes.length}</div>
 </div>
 <div className="card p-4">
 <div className="text-xs text-text-muted">Relationships</div>
 <div className="text-2xl font-bold mt-1 text-text-primary">{edges.length}</div>
 </div>
 <div className="card p-4">
 <div className="text-xs text-text-muted">Inferred (shared infra)</div>
 <div className="text-2xl font-bold mt-1 text-accent-orange">{inferredCount}</div>
 </div>
 </div>

 <div className="grid grid-cols-1 lg:grid-cols-2 gap-4">
 <div className="card p-4 space-y-3">
 <h2 className="text-sm font-medium text-text-primary">Explore an asset</h2>
 <AssetPicker placeholder="Search domain, subdomain, host, service…" value={focusAsset} onSelect={setFocusAsset} />
 {!focusAsset ? (
 <Empty label="Pick an asset to see its parents, children, and peers" />
 ) : relatedLoading ? <SkeletonTable rows={3} /> : related.length === 0 ? (
 <Empty label="No related assets found" />
 ) : (
 <div className="space-y-2">
 {(['parent', 'child', 'peer'] as const).map(dir => {
 const group = related.filter(r => r.direction === dir)
 if (group.length === 0) return null
 return (
 <div key={dir}>
 <div className="text-xs text-text-muted uppercase tracking-wide mb-1">{dir}s</div>
 <div className="flex flex-wrap gap-1.5">
 {group.map((r, i) => (
 <span key={i} className="flex items-center gap-1.5 badge text-xs bg-surface-3 text-text-secondary border border-surface-3">
 <NodePill node={r.asset} />
 {r.asset.label}
 </span>
 ))}
 </div>
 </div>
 )
 })}
 </div>
 )}
 </div>

 <div className="card p-4 space-y-3">
 <h2 className="text-sm font-medium text-text-primary">Exposure path</h2>
 <div className="space-y-2">
 <AssetPicker placeholder="From asset…" value={fromAsset} onSelect={setFromAsset} />
 <AssetPicker placeholder="To asset…" value={toAsset} onSelect={setToAsset} />
 <button onClick={findPath} disabled={!fromAsset || !toAsset || pathLoading} className="btn-primary text-sm w-full">
 {pathLoading ? 'Searching…' : 'Find exposure path'}
 </button>
 </div>
 {pathSearched && !pathLoading && (
 path === null ? <Empty label="No chain of relationships connects these assets" /> : (
 <div className="flex flex-wrap items-center gap-2 pt-2">
 {path.map((hop, i) => (
 <div key={i} className="flex items-center gap-2">
 {i > 0 && (
 <div className="flex items-center gap-1 text-text-muted">
 <ArrowRight className="w-3 h-3" />
 {hop.relation_type && <span className="text-xs">{hop.relation_type.replace(/_/g, ' ')}</span>}
 </div>
 )}
 <span className="flex items-center gap-1.5 badge text-xs bg-surface-3 text-text-secondary border border-surface-3">
 <NodePill node={hop.node} />
 {hop.node.label}
 </span>
 </div>
 ))}
 </div>
 )
 )}
 </div>
 </div>

 <div>
 <h2 className="text-sm font-medium text-text-primary mb-2">All relationships</h2>
 {loading ? <SkeletonTable /> : edges.length === 0 ? <Empty label="No relationships yet — click Rebuild graph" /> : (
 <TableCard>
 <thead><tr><th>From</th><th>Relation</th><th>To</th><th>Confidence</th></tr></thead>
 <tbody>
 {edges.slice(0, 200).map((e, i) => (
 <tr key={i}>
 <td><span className="flex items-center gap-1.5"><NodePill node={e.from} />{e.from.label}</span></td>
 <td><span className="text-xs text-text-muted">{e.relation_type.replace(/_/g, ' ')}</span></td>
 <td><span className="flex items-center gap-1.5"><NodePill node={e.to} />{e.to.label}</span></td>
 <td><span className="text-xs text-text-muted">{Math.round(e.confidence * 100)}%</span></td>
 </tr>
 ))}
 </tbody>
 </TableCard>
 )}
 {edges.length > 200 && (
 <div className="text-xs text-text-muted text-center pt-2">Showing first 200 of {edges.length} relationships</div>
 )}
 </div>
 </Page>
 )
}

export default CorrelationPage
