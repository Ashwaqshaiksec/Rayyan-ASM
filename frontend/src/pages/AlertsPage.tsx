import { useEffect, useState, useCallback } from 'react'
import { Eye, CheckCircle } from 'lucide-react'
import { alertApi } from '@/utils/api'
import type { Alert } from '@/types'
import { formatDistanceToNow } from 'date-fns'
import clsx from 'clsx'
import { Page, TableCard, SkeletonTable, SeverityBadge, StatusBadge } from './shared'

export function AlertsPage() {
 const [alerts, setAlerts] = useState<Alert[]>([])
 const [loading, setLoading] = useState(true)
 const [sevFilter, setSevFilter] = useState('')
 const [typeFilter, setTypeFilter] = useState('')

 const load = useCallback(async () => {
 const { data } = await alertApi.list({ limit: 200 })
 setAlerts(data.data ?? [])
 setLoading(false)
 }, [])

 useEffect(() => { load() }, [load])

 const types = [...new Set(alerts.map(a => a.type))].sort()
 const filtered = alerts.filter(a =>
 (!sevFilter || a.severity === sevFilter) &&
 (!typeFilter || a.type === typeFilter)
 )

 const counts = { open: 0, critical: 0, high: 0 }
 alerts.forEach(a => {
 if (a.status === 'open') counts.open++
 if (a.severity === 'critical') counts.critical++
 if (a.severity === 'high') counts.high++
 })

 async function ack(id: string) {
 await alertApi.acknowledge(id)
 load()
 }
 async function resolve(id: string) {
 await alertApi.resolve(id)
 load()
 }

 return (
 <Page title="Alerts">
 <div className="grid grid-cols-3 gap-4">
 {[['Open', counts.open, 'text-accent-orange'], ['Critical', counts.critical, 'text-accent-red'], ['High', counts.high, 'text-accent-orange']].map(([k, v, cls]) => (
 <div key={String(k)} className="card p-4">
 <div className="text-xs text-text-muted">{k}</div>
 <div className={clsx('text-2xl font-bold mt-1', cls)}>{v}</div>
 </div>
 ))}
 </div>
 <div className="flex items-center gap-3">
 <select className="input text-sm" value={sevFilter} onChange={e => setSevFilter(e.target.value)}>
 <option value="">All severities</option>
 {['critical', 'high', 'medium', 'low', 'info'].map(s => <option key={s}>{s}</option>)}
 </select>
 <select className="input text-sm" value={typeFilter} onChange={e => setTypeFilter(e.target.value)}>
 <option value="">All types</option>
 {types.map(t => <option key={t}>{t}</option>)}
 </select>
 </div>
 {loading ? <SkeletonTable /> : (
 <TableCard>
 <thead><tr><th>Severity</th><th>Title</th><th>Type</th><th>Message</th><th>Status</th><th>Created</th><th>Actions</th></tr></thead>
 <tbody>
 {filtered.map(a => (
 <tr key={a.id}>
 <td><SeverityBadge s={a.severity} /></td>
 <td><span className="text-sm text-text-primary">{a.title}</span></td>
 <td><span className="text-xs text-text-muted">{a.type}</span></td>
 <td><span className="text-xs text-text-muted truncate max-w-xs block">{a.message}</span></td>
 <td><StatusBadge s={a.status} /></td>
 <td><span className="text-xs text-text-muted">{formatDistanceToNow(new Date(a.created_at), { addSuffix: true })}</span></td>
 <td>
 <div className="flex items-center gap-1">
 {a.status === 'open' && <>
 <button onClick={() => ack(a.id)} className="btn-ghost text-xs" title="Acknowledge"><Eye className="w-3 h-3" /></button>
 <button onClick={() => resolve(a.id)} className="btn-ghost text-xs text-accent-green" title="Resolve"><CheckCircle className="w-3 h-3" /></button>
 </>}
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

export default AlertsPage
