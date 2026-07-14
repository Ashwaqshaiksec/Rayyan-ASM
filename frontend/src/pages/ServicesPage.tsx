import { useEffect, useState } from 'react'
import { serviceApi } from '@/utils/api'
import type { Service } from '@/types'
import { formatDistanceToNow } from 'date-fns'
import toast from 'react-hot-toast'
import { Page, TableCard, SkeletonTable, StatusBadge, FacetFilterBar, FacetDropdown } from './shared'
import { useFacetFilters, countBy } from '@/utils/useFacetFilters'

const FACETS = ['protocol', 'state', 'service'] as const

export function ServicesPage() {
  const [services, setServices] = useState<Service[]>([])
  const [loading, setLoading] = useState(true)
  const [search, setSearch] = useState('')
  const { values, toggle, clear, activeCount } = useFacetFilters(FACETS)

  useEffect(() => {
    serviceApi.list({ limit: 500 }).then(({ data }) => {
      setServices(data.data ?? [])
      setLoading(false)
    }).catch(() => {
      toast.error('Failed to load services')
      setLoading(false)
    })
  }, [])

  // Facets are combinable with AND across facets, OR within a facet's
  // selected values — e.g. protocol=tcp,udp AND state=open matches any
  // tcp-or-udp service that's also open.
  const filtered = services.filter(s => {
    if (search && !`${s.port} ${s.service} ${s.host_ref}`.includes(search)) return false
    for (const facet of FACETS) {
      const selected = values[facet]
      if (selected.length && !selected.includes(String(s[facet] ?? ''))) return false
    }
    return true
  })

  // Facet option counts reflect the OTHER active facets' current
  // selection (not this facet's own), so picking "tcp" under Protocol
  // doesn't make every other protocol option vanish from its own list —
  // it recomputes what's still reachable, not what's already chosen.
  const facetOptions = (facet: typeof FACETS[number]) => {
    const rest = services.filter(s => {
      for (const f of FACETS) {
        if (f === facet) continue
        const selected = values[f]
        if (selected.length && !selected.includes(String(s[f] ?? ''))) return false
      }
      if (search && !`${s.port} ${s.service} ${s.host_ref}`.includes(search)) return false
      return true
    })
    return countBy(rest, s => String(s[facet] ?? ''))
  }

  return (
    <Page title="Services" subtitle={`${filtered.length} of ${services.length} discovered`}>
      <div className="flex items-center gap-3 flex-wrap">
        <input className="input flex-1 min-w-[200px] max-w-sm text-sm" placeholder="Filter port, service, host…"
          value={search} onChange={e => setSearch(e.target.value)} />
        <FacetFilterBar activeCount={activeCount} onClearAll={() => clear()}>
          <FacetDropdown label="Protocol" options={facetOptions('protocol')} selected={values.protocol}
            onToggle={v => toggle('protocol', v)} onClear={() => clear('protocol')} />
          <FacetDropdown label="State" options={facetOptions('state')} selected={values.state}
            onToggle={v => toggle('state', v)} onClear={() => clear('state')} />
          <FacetDropdown label="Service" options={facetOptions('service')} selected={values.service}
            onToggle={v => toggle('service', v)} onClear={() => clear('service')} />
        </FacetFilterBar>
      </div>
      {loading ? <SkeletonTable /> : (
        <TableCard>
          <thead><tr><th>Host</th><th>Port</th><th>Protocol</th><th>Service</th><th>Product</th><th>Version</th><th>Tunnel</th><th>Banner</th><th>State</th><th>Last Seen</th></tr></thead>
          <tbody>
            {filtered.map(s => (
              <tr key={s.id}>
                <td><span className="font-mono text-xs text-text-secondary">{s.host_ref}</span></td>
                <td><span className="font-mono text-sm text-accent-cyan">{s.port}</span></td>
                <td><span className="badge-gray text-xs">{s.protocol}</span></td>
                <td><span className="text-sm text-text-primary">{s.service}</span></td>
                <td><span className="text-xs text-text-muted">{s.product}</span></td>
                <td><span className="text-xs text-text-muted">{s.version}</span></td>
                <td><span className="text-xs text-text-muted">{s.tunnel || '—'}</span></td>
                <td><span className="font-mono text-xs text-text-muted truncate max-w-[220px] block" title={s.banner}>{s.banner || '—'}</span></td>
                <td><StatusBadge s={s.state} /></td>
                <td><span className="text-xs text-text-muted">{formatDistanceToNow(new Date(s.last_seen_at), { addSuffix: true })}</span></td>
              </tr>
            ))}
          </tbody>
        </TableCard>
      )}
    </Page>
  )
}

export default ServicesPage
