import { useEffect, useState } from 'react'
import { CheckCircle, XCircle } from 'lucide-react'
import { findingSLAApi } from '@/utils/api'
import { format } from 'date-fns'
import clsx from 'clsx'
import { Page, TableCard, SkeletonTable, SeverityBadge, StatusBadge } from './shared'

type SLARow = { id: string; title: string; severity: string; status: string; sla_due_at?: string; sla_breached: boolean; days_left: number }

export function SLAReportPage() {
 const [rows, setRows] = useState<SLARow[]>([])
 const [stats, setStats] = useState({ total: 0, overdue: 0, ontrack: 0 })
 const [loading, setLoading] = useState(true)
 const [sortOverdueFirst, setSortOverdueFirst] = useState(true)

 function load() {
 setLoading(true)
 findingSLAApi.slaReport().then(({ data }) => {
 setRows(data.data ?? [])
 setStats({ total: data.total ?? 0, overdue: data.overdue ?? 0, ontrack: data.ontrack ?? 0 })
 setLoading(false)
 }).catch(() => setLoading(false))
 }

 useEffect(() => { load() }, [])

 function exportCSV() {
 const header = ['ID', 'Title', 'Severity', 'Status', 'Due Date', 'Days Left', 'Breached']
 const csvRows = sortedRows.map(r => [
 r.id, r.title, r.severity, r.status,
 r.sla_due_at ? format(new Date(r.sla_due_at), 'yyyy-MM-dd') : '',
 r.sla_breached ? 'BREACHED' : String(r.days_left),
 r.sla_breached ? 'YES' : 'NO',
 ])
 const csv = [header, ...csvRows].map(r => r.map(v => `"${String(v).replace(/"/g, '""')}"`).join(',')).join('\n')
 const blob = new Blob([csv], { type: 'text/csv' })
 const url = URL.createObjectURL(blob)
 const a = document.createElement('a')
 a.href = url; a.download = `sla-report-${format(new Date(), 'yyyy-MM-dd')}.csv`; a.click()
 URL.revokeObjectURL(url)
 }

 const sortedRows = sortOverdueFirst
 ? [...rows].sort((a, b) => (b.sla_breached ? 1 : 0) - (a.sla_breached ? 1 : 0) || a.days_left - b.days_left)
 : rows

 return (
 <Page title="SLA Report" subtitle="Findings with SLA tracking">
 {/* KPI badges */}
 <div className="grid grid-cols-3 gap-4">
 <div className="card p-4">
 <div className="text-xs text-text-muted">Total</div>
 <div className="text-2xl font-bold mt-1 text-text-primary">{stats.total}</div>
 </div>
 <div className="card p-4 border border-accent-red/30">
 <div className="flex items-center justify-between">
 <div className="text-xs text-text-muted">Overdue</div>
 {stats.overdue > 0 && (
 <span className="inline-flex items-center justify-center w-5 h-5 rounded-full bg-accent-red text-white text-xs font-bold">
 {stats.overdue > 99 ? '99+' : stats.overdue}
 </span>
 )}
 </div>
 <div className="text-2xl font-bold mt-1 text-accent-red">{stats.overdue}</div>
 </div>
 <div className="card p-4 border border-accent-green/30">
 <div className="text-xs text-text-muted">On Track</div>
 <div className="text-2xl font-bold mt-1 text-accent-green">{stats.ontrack}</div>
 </div>
 </div>

 {/* Toolbar */}
 <div className="flex items-center justify-between gap-3 mt-2">
 <button
 onClick={() => setSortOverdueFirst(v => !v)}
 className={clsx('text-xs px-3 py-1.5 rounded-md border transition-all',
 sortOverdueFirst
 ? 'border-accent-red/50 text-accent-red bg-accent-red/10'
 : 'border-surface-3 text-text-muted hover:text-text-secondary')}
 >
 {sortOverdueFirst ? '⬆ Overdue first' : 'Sort: default'}
 </button>
 <div className="flex gap-2">
 <button onClick={load} className="btn-ghost text-xs">Refresh</button>
 <button onClick={exportCSV} className="btn-primary text-xs">Export CSV</button>
 </div>
 </div>

 {loading ? <SkeletonTable /> : (
 <TableCard>
 <thead>
 <tr>
 <th>Title</th><th>Severity</th><th>Status</th>
 <th>Due Date</th><th>Days Left</th><th>SLA</th>
 </tr>
 </thead>
 <tbody>
 {sortedRows.map(r => (
 <tr key={r.id} className={clsx(r.sla_breached && 'bg-accent-red/5')}>
 <td>
 <div className="flex items-center gap-2">
 <span className="text-sm text-text-primary">{r.title}</span>
 {r.sla_breached && (
 <span className="inline-flex items-center px-1.5 py-0.5 rounded-md text-xs font-bold bg-accent-red text-white">
 BREACHED
 </span>
 )}
 </div>
 </td>
 <td><SeverityBadge s={r.severity} /></td>
 <td><StatusBadge s={r.status} /></td>
 <td><span className="text-xs text-text-muted">{r.sla_due_at ? format(new Date(r.sla_due_at), 'yyyy-MM-dd') : '—'}</span></td>
 <td>
 <span className={clsx('text-xs font-mono font-medium',
 r.sla_breached ? 'text-accent-red' : r.days_left <= 3 ? 'text-accent-orange' : 'text-accent-green'
 )}>{r.sla_breached ? `${Math.abs(r.days_left)}d ago` : `${r.days_left}d`}</span>
 </td>
 <td className="text-center">
 {r.sla_breached
 ? <XCircle className="w-4 h-4 text-accent-red inline" />
 : <CheckCircle className="w-4 h-4 text-accent-green inline" />}
 </td>
 </tr>
 ))}
 {sortedRows.length === 0 && (
 <tr><td colSpan={6} className="text-center text-text-muted py-8 text-sm">No findings with SLA tracking</td></tr>
 )}
 </tbody>
 </TableCard>
 )}
 </Page>
 )
}

export default SLAReportPage
