import { useEffect, useState } from 'react'
import { dnsApi } from '@/utils/api'
import type { DNSRecord } from '@/types'
import toast from 'react-hot-toast'
import { Page, TableCard, SkeletonTable } from './shared'

export function DNSPage() {
 const [records, setRecords] = useState<DNSRecord[]>([])
 const [loading, setLoading] = useState(true)
 const [typeFilter, setTypeFilter] = useState('')
 const [search, setSearch] = useState('')

 useEffect(() => {
 dnsApi.list({ limit: 1000 }).then(({ data }) => {
 setRecords(data.data ?? [])
 setLoading(false)
 }).catch(() => {
 toast.error('Failed to load DNS records')
 setLoading(false)
 })
 }, [])

 const types = [...new Set(records.map(r => r.type))].sort()
 const filtered = records.filter(r =>
 (!typeFilter || r.type === typeFilter) &&
 (!search || r.name.includes(search) || r.value.includes(search))
 )

 return (
 <Page title="DNS Records" subtitle={`${records.length} records`}>
 <div className="flex items-center gap-3">
 <input className="input flex-1 text-sm" placeholder="Filter name or value…"
 value={search} onChange={e => setSearch(e.target.value)} />
 <select className="input" value={typeFilter} onChange={e => setTypeFilter(e.target.value)}>
 <option value="">All types</option>
 {types.map(t => <option key={t}>{t}</option>)}
 </select>
 </div>
 {loading ? <SkeletonTable /> : (
 <TableCard>
 <thead><tr><th>Type</th><th>Name</th><th>Value</th><th>TTL</th><th>Priority</th><th>Domain</th></tr></thead>
 <tbody>
 {filtered.map(r => (
 <tr key={r.id}>
 <td><span className="badge-blue badge text-xs">{r.type}</span></td>
 <td><span className="font-mono text-xs text-text-primary">{r.name}</span></td>
 <td><span className="font-mono text-xs text-text-secondary truncate max-w-xs block" title={r.value}>{r.value}</span></td>
 <td><span className="text-xs text-text-muted">{r.ttl}s</span></td>
 <td><span className="text-xs text-text-muted">{r.type === 'MX' ? r.priority : '—'}</span></td>
 <td><span className="text-xs text-text-secondary">{r.domain_name || r.domain_id}</span></td>
 </tr>
 ))}
 </tbody>
 </TableCard>
 )}
 </Page>
 )
}

export default DNSPage
