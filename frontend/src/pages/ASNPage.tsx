import { useEffect, useState } from 'react'
import { asnApi } from '@/utils/api'
import toast from 'react-hot-toast'
import { Page, TableCard, SkeletonTable } from './shared'

type ASNRange = { id: string; asn: string; asn_org: string; cidr: string; country: string; rir: string }

export function ASNPage() {
 const [ranges, setRanges] = useState<ASNRange[]>([])
 const [loading, setLoading] = useState(false)
 const [asnInput, setAsnInput] = useState('')
 const [expanding, setExpanding] = useState(false)
 const [page, setPage] = useState(1)
 const [totalPages, setTotalPages] = useState(1)
 const [total, setTotal] = useState(0)
 const [filterAsn, setFilterAsn] = useState<string | undefined>()
 const PER_PAGE = 50

 async function expand() {
 if (!asnInput.trim()) return
 setExpanding(true)
 try {
 const { data } = await asnApi.expand(asnInput.trim())
 toast.success(`Found ${data.count} CIDRs for ${data.asn}`)
 // Filter by the normalized ASN the backend actually stored (e.g. "AS12345"),
 // not the raw input — if the user typed a bare number ("12345") the two
 // don't match and the ranges we just fetched would show up as "no results".
 setAsnInput(data.asn)
 setFilterAsn(data.asn)
 load(1, data.asn)
 } catch { toast.error('ASN expansion failed') } finally { setExpanding(false) }
 }

 async function load(p: number = page, asn?: string) {
 setLoading(true)
 try {
 const params: Record<string, unknown> = { page: p, per_page: PER_PAGE }
 if (asn) params.asn = asn
 const { data } = await asnApi.list(asn, params)
 setRanges(data.data ?? [])
 setTotal(data.total ?? 0)
 setTotalPages(data.pages ?? 1)
 setPage(p)
 } catch { toast.error('Failed to load ASN ranges') } finally { setLoading(false) }
 }

 // Mount-only: load() is redefined every render (reads page/filterAsn via
 // closure for refresh calls elsewhere), so including it here would re-run
 // the effect on every render rather than just once on mount.
 // eslint-disable-next-line react-hooks/exhaustive-deps
 useEffect(() => { load(1) }, [])

 function clearFilter() { setFilterAsn(undefined); setAsnInput(''); load(1, undefined) }

 return (
 <Page title="ASN Ranges" subtitle="Enumerate CIDRs belonging to an ASN">
 <div className="flex items-center gap-3">
 <input className="input flex-1 font-mono text-sm" placeholder="AS12345 or 12345"
 value={asnInput} onChange={e => setAsnInput(e.target.value)}
 onKeyDown={e => e.key === 'Enter' && expand()} />
 <button onClick={expand} disabled={expanding} className="btn-primary text-sm">
 {expanding ? 'Expanding…' : 'Expand & Filter'}
 </button>
 {filterAsn && (
 <button onClick={clearFilter} className="btn-ghost text-xs text-text-muted">
 ✕ Clear filter
 </button>
 )}
 </div>

 {/* Stats row */}
 <div className="flex items-center justify-between text-xs text-text-muted">
 <span>{total} total range{total !== 1 ? 's' : ''}{filterAsn ? ` for ${filterAsn}` : ''}</span>
 {totalPages > 1 && (
 <div className="flex items-center gap-2">
 <button disabled={page <= 1} onClick={() => load(page - 1, filterAsn)}
 className="px-2 py-1 rounded-md border border-surface-3 disabled:opacity-30 hover:border-accent-cyan/50 transition-colors">
 ‹ Prev
 </button>
 <span>{page} / {totalPages}</span>
 <button disabled={page >= totalPages} onClick={() => load(page + 1, filterAsn)}
 className="px-2 py-1 rounded-md border border-surface-3 disabled:opacity-30 hover:border-accent-cyan/50 transition-colors">
 Next ›
 </button>
 </div>
 )}
 </div>

 {loading ? <SkeletonTable /> : (
 <TableCard>
 <thead><tr><th>ASN</th><th>Org</th><th>CIDR</th><th>Country</th><th>RIR</th></tr></thead>
 <tbody>
 {ranges.map(r => (
 <tr key={r.id}>
 <td><span className="font-mono text-xs text-accent-cyan">{r.asn}</span></td>
 <td><span className="text-xs text-text-secondary">{r.asn_org}</span></td>
 <td><span className="font-mono text-xs text-text-primary">{r.cidr}</span></td>
 <td><span className="text-xs text-text-muted">{r.country}</span></td>
 <td><span className="badge-gray text-xs">{r.rir}</span></td>
 </tr>
 ))}
 {ranges.length === 0 && (
 <tr><td colSpan={5} className="text-center text-text-muted py-8 text-sm">
 {filterAsn ? `No ranges found for ${filterAsn}` : 'No ASN ranges. Expand an ASN to populate.'}
 </td></tr>
 )}
 </tbody>
 </TableCard>
 )}
 </Page>
 )
}

export default ASNPage
