import { useEffect, useState } from 'react'
import { useParams } from 'react-router-dom'
import { Network, Globe, Clock } from 'lucide-react'
import { domainApi, domainCadenceApi } from '@/utils/api'
import type { Subdomain, DNSRecord } from '@/types'
import toast from 'react-hot-toast'
import { Page, Empty } from './shared'
import { WHOISHistoryWidget } from '@/components/WHOISHistoryWidget'

export function DomainDetailPage() {
  const { id } = useParams<{ id: string }>()
  const [subs, setSubs] = useState<Subdomain[]>([])
  const [dns, setDns] = useState<DNSRecord[]>([])
  const [cadence, setCadence] = useState({ cron: '', depth: 'full' })
  const [savingCadence, setSavingCadence] = useState(false)
  const [domainName, setDomainName] = useState('')

  useEffect(() => {
    if (!id) return
    domainApi.subdomains(id).then(({ data }) => setSubs(data.data ?? []))
    domainApi.dnsRecords(id).then(({ data }) => setDns(data.data ?? []))
    domainApi.get(id).then(({ data }) => {
      setCadence({ cron: data.scan_cron ?? '', depth: data.scan_depth ?? 'full' })
      setDomainName(data.name ?? '')
    })
  }, [id])

  async function saveCadence() {
    if (!id) return
    setSavingCadence(true)
    try {
      await domainCadenceApi.set(id, cadence.cron, cadence.depth)
      toast.success('Scan cadence updated')
    } catch { toast.error('Failed') } finally { setSavingCadence(false) }
  }

  return (
    <Page title={domainName || 'Domain Detail'} subtitle={domainName ? 'Subdomains, DNS records, and scan cadence' : undefined}>
      <div className="grid grid-cols-1 lg:grid-cols-2 gap-4">
        <div className="card p-4">
          <h2 className="text-sm font-medium text-text-primary mb-3 flex items-center gap-2">
            <Network className="w-4 h-4 text-accent-purple" />Subdomains ({subs.length})
          </h2>
          <div className="space-y-1 max-h-64 overflow-y-auto">
            {subs.map(s => (
              <div key={s.id} className="flex items-center gap-2 text-sm px-2.5 py-1.5 rounded-lg hover:bg-surface-2 transition-colors">
                <span className="font-mono text-text-secondary flex-1 truncate">{s.fqdn}</span>
                {s.dead && <span className="badge-red badge text-xs">dead</span>}
              </div>
            ))}
            {subs.length === 0 && <Empty label="No subdomains discovered" />}
          </div>
        </div>
        <div className="card p-4">
          <h2 className="text-sm font-medium text-text-primary mb-3 flex items-center gap-2">
            <Globe className="w-4 h-4 text-accent-blue" />DNS Records ({dns.length})
          </h2>
          <div className="space-y-1 max-h-64 overflow-y-auto">
            {dns.map(r => (
              <div key={r.id} className="flex items-center gap-2 text-xs px-2.5 py-1.5 rounded-lg hover:bg-surface-2 transition-colors">
                <span className="badge-blue badge w-10 justify-center flex-shrink-0">{r.type}</span>
                <span className="font-mono text-text-secondary flex-1 truncate">{r.value}</span>
                {r.ttl > 0 && <span className="text-text-muted flex-shrink-0">{r.ttl}s</span>}
              </div>
            ))}
            {dns.length === 0 && <Empty label="No DNS records found" />}
          </div>
        </div>

        <div className="card p-4 col-span-full">
          <h2 className="text-sm font-medium text-text-primary mb-3 flex items-center gap-2">
            <Clock className="w-4 h-4 text-accent-cyan" />Scan Cadence
          </h2>
          <div className="flex items-end gap-3 flex-wrap">
            <div className="flex-1 min-w-[200px]">
              <label className="text-xs text-text-muted mb-1 block">Cron Expression</label>
              <input className="input w-full font-mono text-sm" placeholder="0 2 * * * (daily at 2am)"
                value={cadence.cron} onChange={e => setCadence(c => ({ ...c, cron: e.target.value }))} />
            </div>
            <div>
              <label className="text-xs text-text-muted mb-1 block">Depth</label>
              <select className="input" value={cadence.depth} onChange={e => setCadence(c => ({ ...c, depth: e.target.value }))}>
                <option value="full">Full</option>
                <option value="quick">Quick</option>
                <option value="passive">Passive</option>
              </select>
            </div>
            <button onClick={saveCadence} disabled={savingCadence}
              className="btn-primary">{savingCadence ? 'Saving…' : 'Save'}</button>
          </div>
        </div>

        <div className="card p-4 col-span-full">
          {domainName && <WHOISHistoryWidget domain={domainName} />}
        </div>
      </div>
    </Page>
  )
}

export default DomainDetailPage
