import { useEffect, useState, useCallback } from 'react'
import { RefreshCw, AlertTriangle, ArrowRight, ChevronUp, ChevronDown, List, Workflow } from 'lucide-react'
import { attackPathApi } from '@/utils/api'
import type { AttackPath } from '@/types'
import clsx from 'clsx'
import toast from 'react-hot-toast'
import { Page, SkeletonTable, Empty } from './shared'
import { AttackPathFlow } from '@/components/AttackPathFlow'

const SEVERITY_COLOR: Record<string, string> = {
 critical: 'text-accent-red',
 high: 'text-accent-orange',
 medium: 'text-accent-yellow',
 low: 'text-text-muted',
 info: 'text-text-muted',
}

export function AttackPathPage() {
 const [paths, setPaths] = useState<AttackPath[]>([])
 const [loading, setLoading] = useState(true)
 const [recomputing, setRecomputing] = useState(false)
 const [expanded, setExpanded] = useState<string | null>(null)
 const [loadError, setLoadError] = useState(false)
 // Graph is the default — previously the only view was a plain text
 // one-liner ("entry -> target") with the actual hop chain hidden behind
 // an expand click and rendered as a bare list even then.
 const [viewMode, setViewMode] = useState<'graph' | 'list'>('graph')

 const load = useCallback(async () => {
 setLoading(true)
 setLoadError(false)
 try {
 const { data } = await attackPathApi.list()
 setPaths(data.data ?? [])
 } catch {
 setLoadError(true)
 } finally {
 setLoading(false)
 }
 }, [])

 useEffect(() => { load() }, [load])

 async function recompute() {
 setRecomputing(true)
 try {
 const { data } = await attackPathApi.recompute()
 toast.success(`Recomputed: ${data.paths_found} attack path${data.paths_found === 1 ? '' : 's'} found`)
 load()
 } catch {
 toast.error('Recompute failed')
 } finally {
 setRecomputing(false)
 }
 }

 const critCount = paths.filter(p => p.weakest_score >= 75).length
 const highCount = paths.filter(p => p.weakest_score >= 50 && p.weakest_score < 75).length
 const medCount = paths.filter(p => p.weakest_score < 50).length

 return (
 <Page
 title="Attack Paths"
 subtitle="Ranked exposure chains from internet-facing assets to sensitive targets, ordered by weakest-link risk"
 actions={
 <div className="flex items-center gap-2">
 <div className="flex items-center rounded-lg border border-border p-0.5">
 <button
 onClick={() => setViewMode('graph')}
 className={clsx('flex items-center gap-1 px-2.5 py-1 text-xs rounded-md', viewMode === 'graph' ? 'bg-surface-2 text-text-primary' : 'text-text-muted')}
 >
 <Workflow className="w-3 h-3" />Graph
 </button>
 <button
 onClick={() => setViewMode('list')}
 className={clsx('flex items-center gap-1 px-2.5 py-1 text-xs rounded-md', viewMode === 'list' ? 'bg-surface-2 text-text-primary' : 'text-text-muted')}
 >
 <List className="w-3 h-3" />List
 </button>
 </div>
 <button onClick={recompute} disabled={recomputing} className="btn-primary text-sm flex items-center gap-1">
 <RefreshCw className={clsx('w-3 h-3', recomputing && 'animate-spin')} />
 {recomputing ? 'Recomputing…' : 'Recompute'}
 </button>
 </div>
 }
 >
 <div className="grid grid-cols-3 gap-4">
 <div className="card p-4">
 <div className="text-xs text-text-muted flex items-center gap-1">
 <AlertTriangle className="w-3 h-3 text-accent-red" /> Critical paths
 </div>
 <div className="text-2xl font-bold mt-1 text-accent-red">{critCount}</div>
 </div>
 <div className="card p-4">
 <div className="text-xs text-text-muted flex items-center gap-1">
 <AlertTriangle className="w-3 h-3 text-accent-orange" /> High-risk paths
 </div>
 <div className="text-2xl font-bold mt-1 text-accent-orange">{highCount}</div>
 </div>
 <div className="card p-4">
 <div className="text-xs text-text-muted flex items-center gap-1">
 <AlertTriangle className="w-3 h-3 text-accent-yellow" /> Medium / low
 </div>
 <div className="text-2xl font-bold mt-1 text-accent-yellow">{medCount}</div>
 </div>
 </div>

 <div className="card">
 {loading ? <SkeletonTable /> : loadError ? (
 <div className="flex flex-col items-center gap-3 py-16 text-center">
 <AlertTriangle className="w-6 h-6 text-accent-orange" />
 <p className="text-sm text-text-muted">Failed to load attack paths.</p>
 <button onClick={load} className="text-xs text-accent-cyan hover:underline">Retry</button>
 </div>
 ) : paths.length === 0 ? (
 <Empty label="No attack paths found — run Recompute after risk scoring and correlation have been run" />
 ) : (
 <div className="divide-y divide-border">
 {paths.map(path => {
 const isOpen = expanded === path.id
 const scoreColor = path.weakest_score >= 75
 ? 'text-accent-red'
 : path.weakest_score >= 50
 ? 'text-accent-orange'
 : 'text-accent-yellow'
 const hops: {type:string;id:string;label:string;relation_type?:string;risk_score:number}[] =
 path.hops?.hops ?? []

 return (
 <div key={path.id} className="p-4">
 <div
 className="flex items-start justify-between cursor-pointer"
 onClick={() => setExpanded(isOpen ? null : path.id)}
 >
 <div className="flex items-start gap-3 min-w-0 flex-1">
 <div className={clsx('text-xl font-bold font-mono w-14 shrink-0 tabular-nums', scoreColor)}>
 {path.weakest_score.toFixed(0)}
 </div>
 <div className="min-w-0 flex-1">
 <div className="text-xs text-text-muted mb-1 flex items-center gap-2">
 <span>{path.hop_count} hops</span>
 <span>·</span>
 <span>Weakest: <span className="font-medium text-text-secondary">{path.weakest_label}</span></span>
 {path.finding_severity && (
 <>
 <span>·</span>
 <span className={clsx('capitalize font-medium', SEVERITY_COLOR[path.finding_severity])}>
 {path.finding_severity} finding
 </span>
 </>
 )}
 </div>
 {viewMode === 'graph' ? (
 <div className="overflow-x-auto -mx-1 px-1">
 <AttackPathFlow path={path} />
 </div>
 ) : (
 <div className="flex items-center gap-1 text-sm font-medium text-text-primary flex-wrap">
 <span className="text-text-muted text-xs uppercase">{path.entry_type}</span>
 <span>{path.entry_label}</span>
 <ArrowRight className="w-3 h-3 text-text-muted shrink-0" />
 <span className="text-text-muted text-xs uppercase">{path.target_type}</span>
 <span>{path.target_label}</span>
 </div>
 )}
 </div>
 </div>
 <div className="ml-2 shrink-0">
 {isOpen ? <ChevronUp className="w-4 h-4 text-text-muted" /> : <ChevronDown className="w-4 h-4 text-text-muted" />}
 </div>
 </div>

 {isOpen && viewMode === 'list' && hops.length > 0 && (
 <div className="mt-3 ml-17 pl-4 border-l border-border space-y-1">
 {hops.map((hop, i) => (
 <div key={hop.id + i} className="flex items-center gap-2 text-xs">
 <span className={clsx(
 'font-mono w-8 text-right tabular-nums',
 hop.risk_score >= 75 ? 'text-accent-red' :
 hop.risk_score >= 50 ? 'text-accent-orange' : 'text-text-muted'
 )}>{hop.risk_score.toFixed(0)}</span>
 <span className="text-text-muted uppercase">{hop.type}</span>
 <span className="text-text-primary font-medium">{hop.label}</span>
 {hop.relation_type && (
 <span className="text-text-muted ml-auto">via {hop.relation_type.replace(/_/g, ' ')}</span>
 )}
 </div>
 ))}
 </div>
 )}
 </div>
 )
 })}
 </div>
 )}
 </div>
 </Page>
 )
}

export default AttackPathPage
