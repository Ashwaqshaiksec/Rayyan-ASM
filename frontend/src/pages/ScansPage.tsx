import { useEffect, useState, useCallback } from 'react'
import { Link } from 'react-router-dom'
import { XCircle, RefreshCw, Plus } from 'lucide-react'
import { scanApi } from '@/utils/api'
import type { ScanJob } from '@/types'
import { formatDistanceToNow } from 'date-fns'
import toast from 'react-hot-toast'
import NewScanModal from '@/components/scans/NewScanModal'
import { Page, TableCard, SkeletonTable, scanTargets, StatusBadge } from './shared'

export function ScansPage() {
 const [scans, setScans] = useState<ScanJob[]>([])
 const [loading, setLoading] = useState(true)
 const [showNew, setShowNew] = useState(false)

 const load = useCallback(async () => {
 const { data } = await scanApi.list({ limit: 100 })
 setScans(data.data ?? [])
 setLoading(false)
 }, [])

 useEffect(() => { load() }, [load])

 // Poll every 5 s while any scan is in-progress
 useEffect(() => {
 const hasActive = scans.some(s => ['pending', 'running', 'queued'].includes(s.status))
 if (!hasActive) return
 const t = setInterval(load, 5000)
 return () => clearInterval(t)
 }, [scans, load])

 async function rerun(id: string) {
 await scanApi.rerun(id)
 toast.success('Scan re-queued')
 load()
 }

 async function cancel(id: string) {
 await scanApi.cancel(id)
 toast.success('Scan cancelled')
 load()
 }

 async function handleCreate({ target, type, workflow }: { target: string; type: string; workflow: string }) {
 await scanApi.create({
 name: `${type} — ${target}`,
 type,
 workflow: workflow || undefined,
 targets: { targets: [target] },
 })
 toast.success('Scan queued')
 load()
 }

 return (
 <Page
 title="Scans"
 subtitle="All scan jobs"
 actions={
 <button onClick={() => setShowNew(true)} className="btn-primary">
 <Plus className="w-3.5 h-3.5" /> New Scan
 </button>
 }
 >
 {showNew && <NewScanModal onClose={() => setShowNew(false)} onSubmit={handleCreate} />}
 {loading ? <SkeletonTable /> : (
 <TableCard>
 <thead><tr><th>Name</th><th>Type</th><th>Status</th><th>Targets</th><th>Started</th><th>Actions</th></tr></thead>
 <tbody>
 {scans.map(s => (
 <tr key={s.id}>
 <td>
 <Link to={`/scans/${s.id}`} className="text-sm text-accent-cyan hover:underline">{s.name}</Link>
 </td>
 <td><span className="text-xs text-text-muted">{s.type}</span></td>
 <td><StatusBadge s={s.status} /></td>
 <td><span className="text-xs text-text-muted">{scanTargets(s.targets).slice(0, 2).join(', ')}{scanTargets(s.targets).length > 2 ? ` +${scanTargets(s.targets).length - 2}` : ''}</span></td>
 <td><span className="text-xs text-text-muted">{s.created_at ? formatDistanceToNow(new Date(s.created_at), { addSuffix: true }) : '—'}</span></td>
 <td>
 <div className="flex items-center gap-1">
 {['completed', 'failed'].includes(s.status) && (
 <button onClick={() => rerun(s.id)} className="btn-ghost text-xs"><RefreshCw className="w-3 h-3" /></button>
 )}
 {['pending', 'running', 'queued'].includes(s.status) && (
 <button onClick={() => cancel(s.id)} className="btn-ghost text-xs text-accent-red"><XCircle className="w-3 h-3" /></button>
 )}
 </div>
 </td>
 </tr>
 ))}
 </tbody>
 </TableCard>
 )}
 </Page>
 )
}

export default ScansPage
