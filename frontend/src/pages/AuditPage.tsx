import { useEffect, useState } from 'react'
import { auditApi } from '@/utils/api'
import type { AuditLog } from '@/types'
import { formatDistanceToNow } from 'date-fns'
import toast from 'react-hot-toast'
import { Page, TableCard, SkeletonTable } from './shared'

export function AuditPage() {
 const [logs, setLogs] = useState<AuditLog[]>([])
 const [loading, setLoading] = useState(true)
 const [search, setSearch] = useState('')

 useEffect(() => {
 auditApi.list({ limit: 200 }).then(({ data }) => {
 setLogs(data.data ?? [])
 setLoading(false)
 }).catch(() => {
 toast.error('Failed to load audit log')
 setLoading(false)
 })
 }, [])

 const filtered = logs.filter(l =>
 !search || `${l.action} ${l.resource} ${l.user_id}`.includes(search)
 )

 return (
 <Page title="Audit Log" subtitle="All privileged actions">
 <input className="input w-full max-w-sm text-sm" placeholder="Filter action, resource…"
 value={search} onChange={e => setSearch(e.target.value)} />
 {loading ? <SkeletonTable /> : (
 <TableCard>
 <thead><tr><th>Action</th><th>Resource</th><th>Resource ID</th><th>User</th><th>IP</th><th>Time</th></tr></thead>
 <tbody>
 {filtered.map(l => (
 <tr key={l.id}>
 <td><span className="badge-gray text-xs">{l.action}</span></td>
 <td><span className="text-xs text-text-secondary">{l.resource}</span></td>
 <td><span className="font-mono text-xs text-text-muted truncate max-w-[120px] block">{l.resource_id}</span></td>
 <td><span className="font-mono text-xs text-text-muted truncate max-w-[120px] block">{l.user_id}</span></td>
 <td><span className="font-mono text-xs text-text-muted">{l.ip}</span></td>
 <td><span className="text-xs text-text-muted">{formatDistanceToNow(new Date(l.created_at), { addSuffix: true })}</span></td>
 </tr>
 ))}
 </tbody>
 </TableCard>
 )}
 </Page>
 )
}

export default AuditPage
