import { useEffect, useState, useCallback } from 'react'
import { Download } from 'lucide-react'
import { subdomainApi, exportApi, bulkApi } from '@/utils/api'
import type { Subdomain } from '@/types'
import { formatDistanceToNow } from 'date-fns'
import clsx from 'clsx'
import toast from 'react-hot-toast'
import { Page, TableCard, SkeletonTable, Empty, StatusBadge, Checkbox, BulkBar } from './shared'

export function SubdomainsPage() {
 const [subs, setSubs] = useState<Subdomain[]>([])
 const [loading, setLoading] = useState(true)
 const [selected, setSelected] = useState<Set<string>>(new Set())
 const [filter, setFilter] = useState<'all' | 'live' | 'dead'>('all')
 const [search, setSearch] = useState('')

 const load = useCallback(async () => {
 setLoading(true)
 const { data } = await subdomainApi.list({ limit: 500 })
 setSubs(data.data ?? [])
 setLoading(false)
 }, [])

 useEffect(() => { load() }, [load])

 const filtered = subs.filter(s => {
 if (filter === 'live' && s.dead) return false
 if (filter === 'dead' && !s.dead) return false
 if (search && !s.fqdn.includes(search)) return false
 return true
 })

 function toggleAll() {
 if (selected.size === filtered.length) setSelected(new Set())
 else setSelected(new Set(filtered.map(s => s.id)))
 }

 async function bulkDelete() {
 if (!selected.size) return
 if (!confirm(`Delete ${selected.size} subdomains?`)) return
 await bulkApi.deleteSubdomains([...selected])
 toast.success('Deleted')
 setSelected(new Set())
 load()
 }

 async function bulkTag() {
 const tags = prompt('Tags (comma-separated):')
 if (!tags) return
 await subdomainApi.bulkTag([...selected], tags.split(',').map(t => t.trim()), 'add')
 toast.success('Tagged')
 load()
 }

 return (
 <Page title="Subdomains" subtitle={`${subs.length} total`}
 actions={
 <a href={exportApi.subdomains('csv')} className="btn-ghost text-xs flex items-center gap-1">
 <Download className="w-3 h-3" />CSV
 </a>
 }>
 <div className="flex items-center gap-3">
 <input className="input flex-1 text-sm" placeholder="Filter by FQDN…"
 value={search} onChange={e => setSearch(e.target.value)} />
 {(['all', 'live', 'dead'] as const).map(f => (
 <button key={f} onClick={() => setFilter(f)}
 className={clsx('btn-ghost text-xs capitalize', filter === f && 'text-accent-cyan border-accent-cyan/30')}>
 {f}
 </button>
 ))}
 </div>
 <BulkBar count={selected.size} onDelete={bulkDelete} onTag={bulkTag} />
 {loading ? <SkeletonTable /> : (
 <TableCard>
 <thead><tr>
 <th><Checkbox checked={selected.size === filtered.length && filtered.length > 0} onChange={toggleAll} /></th>
 <th>FQDN</th><th>IPs</th><th>Source</th><th>Status</th><th>First Seen</th><th>Tags</th>
 </tr></thead>
 <tbody>
 {filtered.map(s => (
 <tr key={s.id}>
 <td><Checkbox checked={selected.has(s.id)} onChange={() => {
 const n = new Set(selected)
 n.has(s.id) ? n.delete(s.id) : n.add(s.id)
 setSelected(n)
 }} /></td>
 <td><span className="font-mono text-sm text-text-primary">{s.fqdn}</span></td>
 <td><span className="font-mono text-xs text-text-muted">{(s.ips ?? []).join(', ')}</span></td>
 <td><span className="text-xs text-text-muted">{s.source}</span></td>
 <td><StatusBadge s={s.dead ? 'dead' : s.status} /></td>
 <td><span className="text-xs text-text-muted">{s.first_seen_at ? formatDistanceToNow(new Date(s.first_seen_at), { addSuffix: true }) : '—'}</span></td>
 <td>
 <div className="flex flex-wrap gap-1">
 {(s.tags ?? []).map(t => <span key={t} className="badge-gray text-xs">{t}</span>)}
 </div>
 </td>
 </tr>
 ))}
 </tbody>
 </TableCard>
 )}
 {!loading && filtered.length === 0 && <Empty label="No subdomains match filter" />}
 </Page>
 )
}

export default SubdomainsPage
