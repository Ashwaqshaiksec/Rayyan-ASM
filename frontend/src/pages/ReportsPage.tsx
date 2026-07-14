import { useEffect, useState, useCallback } from 'react'
import { Download, Trash2, Plus } from 'lucide-react'
import { reportApi } from '@/utils/api'
import type { Report } from '@/types'
import { formatDistanceToNow } from 'date-fns'
import toast from 'react-hot-toast'
import { Page, TableCard, SkeletonTable, StatusBadge } from './shared'

export function ReportsPage() {
 const [reports, setReports] = useState<Report[]>([])
 const [loading, setLoading] = useState(true)
 const [generating, setGenerating] = useState(false)

 const load = useCallback(async () => {
 const { data } = await reportApi.list()
 setReports(data.data ?? [])
 setLoading(false)
 }, [])

 useEffect(() => { load() }, [load])

 async function generate() {
 setGenerating(true)
 try {
 await reportApi.generate({ name: `Report ${new Date().toISOString().slice(0, 10)}`, type: 'executive', format: 'json' })
 toast.success('Report generation started')
 setTimeout(load, 2000)
 } catch { toast.error('Failed') } finally { setGenerating(false) }
 }

 async function del(id: string) {
 if (!confirm('Delete this report?')) return
 await reportApi.delete(id)
 load()
 }

 return (
 <Page title="Reports"
 actions={<button onClick={generate} disabled={generating} className="btn-primary text-xs flex items-center gap-1">
 <Plus className="w-3 h-3" />{generating ? 'Generating…' : 'New Report'}
 </button>}>
 {loading ? <SkeletonTable /> : (
 <TableCard>
 <thead><tr><th>Name</th><th>Type</th><th>Status</th><th>Created</th><th>Actions</th></tr></thead>
 <tbody>
 {reports.map(r => (
 <tr key={r.id}>
 <td><span className="text-sm text-text-primary">{r.name}</span></td>
 <td><span className="text-xs text-text-muted">{r.type}</span></td>
 <td><StatusBadge s={r.status} /></td>
 <td><span className="text-xs text-text-muted">{formatDistanceToNow(new Date(r.created_at), { addSuffix: true })}</span></td>
 <td>
 <div className="flex items-center gap-1">
 {r.status === 'completed' && (
 <a href={`/api/v1/reports/${r.id}/download`}
 className="btn-ghost text-xs flex items-center gap-1">
 <Download className="w-3 h-3" />
 </a>
 )}
 <button onClick={() => del(r.id)} className="btn-ghost text-xs text-accent-red">
 <Trash2 className="w-3 h-3" />
 </button>
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

export default ReportsPage
