import { useEffect, useState, useCallback } from 'react'
import { RefreshCw, Shield } from 'lucide-react'
import { takeoverApi } from '@/utils/api'
import { formatDistanceToNow } from 'date-fns'
import clsx from 'clsx'
import { Page, TableCard, SkeletonTable} from './shared'

interface TakeoverResult {
 id: string
 subdomain: string
 cname: string
 provider: string
 fingerprint: string
 vulnerable: boolean
 confidence: 'high' | 'medium' | 'low'
 source: string
 created_at: string
}

export function TakeoverPage() {
 const [results, setResults] = useState<TakeoverResult[]>([])
 const [loading, setLoading] = useState(true)
 const [filter, setFilter] = useState<'all' | 'high' | 'medium'>('all')

 const load = useCallback(async () => {
 setLoading(true)
 try {
 const { data } = await takeoverApi.list({ limit: 500 })
 setResults(data.data ?? [])
 } catch { /* empty state shown */ }
 finally { setLoading(false) }
 }, [])

 useEffect(() => { load() }, [load])

 const filtered = results.filter(r =>
 filter === 'all' ? true : r.confidence === filter
 )

 const highCount = results.filter(r => r.confidence === 'high').length
 const medCount = results.filter(r => r.confidence === 'medium').length

 const confidenceBadge = (c: string) => {
 if (c === 'high') return <span className="badge badge-red text-xs">High</span>
 if (c === 'medium') return <span className="badge badge-yellow text-xs">Medium</span>
 return <span className="badge text-xs">{c}</span>
 }

 const sourceBadge = (s: string) => (
 <span className="badge text-xs bg-surface-2 border border-border text-text-muted">{s}</span>
 )

 return (
 <Page title="Subdomain Takeover" subtitle={`${results.length} findings`}
 actions={<button onClick={load} className="btn-primary text-xs flex items-center gap-1">
 <RefreshCw className="w-3 h-3" /> Refresh
 </button>}>

 {/* Stat bar */}
 <div className="flex gap-3 mb-4">
 {[
 { label: 'High Confidence', count: highCount, color: 'text-accent-red', key: 'high' as const },
 { label: 'Medium Confidence', count: medCount, color: 'text-accent-yellow', key: 'medium' as const },
 { label: 'Total Findings', count: results.length, color: 'text-accent-cyan', key: 'all' as const },
 ].map(({ label, count, color, key }) => (
 <button key={key} onClick={() => setFilter(key)}
 className={clsx('card p-3 text-left flex-1 transition-colors',
 filter === key && 'border-accent-cyan')}>
 <div className={clsx('text-xl font-bold', color)}>{count}</div>
 <div className="text-xs text-text-muted">{label}</div>
 </button>
 ))}
 </div>

 {loading ? <SkeletonTable /> : filtered.length === 0 ? (
 <div className="card p-10 text-center text-text-muted">
 <Shield className="w-10 h-10 mx-auto mb-3 opacity-30" />
 <p className="text-sm">
 {results.length === 0
 ? 'No takeover findings yet. Run a Takeover Scan from the Scans page.'
 : 'No findings match the current filter.'}
 </p>
 </div>
 ) : (
 <TableCard>
 <thead><tr>
 <th>Subdomain</th><th>CNAME Target</th><th>Provider</th>
 <th>Fingerprint</th><th>Confidence</th><th>Source</th><th>Found</th>
 </tr></thead>
 <tbody>
 {filtered.map(r => (
 <tr key={r.id}>
 <td><span className="font-mono text-sm text-text-primary">{r.subdomain}</span></td>
 <td><span className="font-mono text-xs text-text-muted">{r.cname || '—'}</span></td>
 <td><span className="text-sm text-text-secondary">{r.provider || '—'}</span></td>
 <td><span className="text-xs text-text-muted max-w-[200px] block truncate" title={r.fingerprint}>{r.fingerprint || '—'}</span></td>
 <td>{confidenceBadge(r.confidence)}</td>
 <td>{sourceBadge(r.source)}</td>
 <td><span className="text-xs text-text-muted">
 {r.created_at ? formatDistanceToNow(new Date(r.created_at), { addSuffix: true }) : '—'}
 </span></td>
 </tr>
 ))}
 </tbody>
 </TableCard>
 )}

 {/* Remediation note */}
 {results.length > 0 && (
 <div className="card p-4 border-l-4 border-l-accent-cyan mt-4">
 <p className="text-xs text-text-muted">
 <strong className="text-text-secondary">Remediation:</strong>{' '}
 For each finding, remove the dangling DNS CNAME record or re-provision the cloud resource it points to.
 Verify the CNAME target is under organisational control before removal.
 Re-run the takeover scan after DNS propagation to confirm resolution.
 </p>
 </div>
 )}
 </Page>
 )
}

export default TakeoverPage
