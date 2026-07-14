import { useEffect, useState, useCallback } from 'react'
import { Link } from 'react-router-dom'
import { Download } from 'lucide-react'
import { hostApi, exportApi, bulkApi } from '@/utils/api'
import type { Host } from '@/types'
import { formatDistanceToNow } from 'date-fns'
import toast from 'react-hot-toast'
import { Page, TableCard, SkeletonTable, StatusBadge, Checkbox, BulkBar, FacetFilterBar, FacetDropdown } from './shared'
import { useFacetFilters, countBy } from '@/utils/useFacetFilters'

const FACETS = ['status', 'country', 'os'] as const

export function HostsPage() {
  const [hosts, setHosts] = useState<Host[]>([])
  const [loading, setLoading] = useState(true)
  const [selected, setSelected] = useState<Set<string>>(new Set())
  const [search, setSearch] = useState('')
  const { values, toggle, clear, activeCount } = useFacetFilters(FACETS)

  const load = useCallback(async () => {
    setLoading(true)
    const { data } = await hostApi.list({ limit: 500 })
    setHosts(data.data ?? [])
    setLoading(false)
  }, [])

  useEffect(() => { load() }, [load])

  const matchesSearch = (h: Host) => !search || h.ip.includes(search) || (h.hostname ?? '').includes(search)

  const filtered = hosts.filter(h => {
    if (!matchesSearch(h)) return false
    for (const facet of FACETS) {
      const sel = values[facet]
      if (sel.length && !sel.includes(String(h[facet] ?? ''))) return false
    }
    return true
  })

  // Same "reachable-from-here" counting as ServicesPage: a facet's own
  // options are computed against the OTHER active facets, not itself, so
  // selecting a value doesn't collapse its own option list.
  const facetOptions = (facet: typeof FACETS[number]) => {
    const rest = hosts.filter(h => {
      if (!matchesSearch(h)) return false
      for (const f of FACETS) {
        if (f === facet) continue
        const sel = values[f]
        if (sel.length && !sel.includes(String(h[f] ?? ''))) return false
      }
      return true
    })
    return countBy(rest, h => String(h[facet] ?? ''))
  }

  function toggleAll() {
    if (selected.size === filtered.length) setSelected(new Set())
    else setSelected(new Set(filtered.map(h => h.id)))
  }

  async function bulkDelete() {
    if (!confirm(`Delete ${selected.size} hosts?`)) return
    await bulkApi.deleteHosts([...selected])
    toast.success('Deleted')
    setSelected(new Set())
    load()
  }

  async function bulkTag() {
    const tags = prompt('Tags (comma-separated):')
    if (!tags) return
    await hostApi.bulkTag([...selected], tags.split(',').map(t => t.trim()), 'add')
    toast.success('Tagged')
    load()
  }

  return (
    <Page title="Hosts" subtitle={`${filtered.length} of ${hosts.length} discovered`}
      actions={
        <a href={exportApi.hosts('csv')} className="btn-ghost text-xs flex items-center gap-1">
          <Download className="w-3 h-3" />CSV
        </a>
      }>
      <div className="flex items-center gap-3 flex-wrap">
        <input className="input flex-1 min-w-[200px] text-sm" placeholder="Filter by IP or hostname…"
          value={search} onChange={e => setSearch(e.target.value)} />
        <FacetFilterBar activeCount={activeCount} onClearAll={() => clear()}>
          <FacetDropdown label="Status" options={facetOptions('status')} selected={values.status}
            onToggle={v => toggle('status', v)} onClear={() => clear('status')} />
          <FacetDropdown label="Country" options={facetOptions('country')} selected={values.country}
            onToggle={v => toggle('country', v)} onClear={() => clear('country')} />
          <FacetDropdown label="OS" options={facetOptions('os')} selected={values.os}
            onToggle={v => toggle('os', v)} onClear={() => clear('os')} />
        </FacetFilterBar>
      </div>
      <BulkBar count={selected.size} onDelete={bulkDelete} onTag={bulkTag}
        onExport={() => window.location.href = exportApi.hosts('csv')} />
      {loading ? <SkeletonTable /> : (
        <TableCard>
          <thead><tr>
            <th><Checkbox checked={selected.size === filtered.length && filtered.length > 0} onChange={toggleAll} /></th>
            <th>IP</th><th>Hostname</th><th>ASN</th><th>Country</th><th>OS</th><th>Status</th><th>Last Seen</th><th>Tags</th>
          </tr></thead>
          <tbody>
            {filtered.map(h => (
              <tr key={h.id}>
                <td><Checkbox checked={selected.has(h.id)} onChange={() => {
                  const n = new Set(selected)
                  n.has(h.id) ? n.delete(h.id) : n.add(h.id)
                  setSelected(n)
                }} /></td>
                <td>
                  <Link to={`/hosts/${h.id}`} className="font-mono text-sm text-accent-cyan hover:underline">{h.ip}</Link>
                </td>
                <td><span className="text-sm text-text-secondary">{h.hostname ?? '—'}</span></td>
                <td><span className="text-xs text-text-muted">{h.asn} {h.asn_org}</span></td>
                <td><span className="text-xs text-text-muted">{h.country ?? '—'}</span></td>
                <td><span className="text-xs text-text-muted">{h.os ?? '—'}</span></td>
                <td><StatusBadge s={h.status} /></td>
                <td><span className="text-xs text-text-muted">{formatDistanceToNow(new Date(h.last_seen_at), { addSuffix: true })}</span></td>
                <td>
                  <div className="flex flex-wrap gap-1">
                    {(h.tags ?? []).map(t => <span key={t} className="badge-gray text-xs">{t}</span>)}
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

export default HostsPage
