import { useEffect, useState } from 'react'
import { useParams } from 'react-router-dom'
import { Server, Activity, Radar, BarChart2 } from 'lucide-react'
import { hostApi, serviceDiffApi, udpProbeApi } from '@/utils/api'
import type { Host, Service } from '@/types'
import { format } from 'date-fns'
import clsx from 'clsx'
import toast from 'react-hot-toast'
import { Page, Empty, StatusBadge } from './shared'

export function HostDetailPage() {
  const { id } = useParams<{ id: string }>()
  const [services, setServices] = useState<Service[]>([])
  const [diff, setDiff] = useState<unknown[]>([])
  const [host, setHost] = useState<Host | null>(null)
  const [udpResult, setUDPResult] = useState<unknown[] | null>(null)
  const [probingUDP, setProbingUDP] = useState(false)

  useEffect(() => {
    if (!id) return
    hostApi.get(id).then(({ data }) => setHost(data))
    hostApi.services(id).then(({ data }) => setServices(data.data ?? []))
    serviceDiffApi.diff(id).then(({ data }) => setDiff(data.data ?? [])).catch(() => {})
  }, [id])

  async function runUDPProbe() {
    if (!host) return
    setProbingUDP(true)
    try {
      const { data } = await udpProbeApi.probe(host.ip)
      setUDPResult(data.results)
    } catch { toast.error('UDP probe failed') } finally { setProbingUDP(false) }
  }

  return (
    <Page title={host?.ip ?? 'Host Detail'} subtitle={host?.hostname ?? undefined}>
      <div className="grid grid-cols-1 lg:grid-cols-3 gap-4">
        <div className="card p-4 space-y-2">
          <h2 className="text-sm font-medium text-text-primary flex items-center gap-2"><Server className="w-4 h-4 text-accent-cyan" />Host Info</h2>
          {host && (
            <dl className="space-y-1.5 text-sm">
              {[['IP', host.ip], ['Hostname', host.hostname], ['ASN', `${host.asn} ${host.asn_org}`],
                ['Country', host.country], ['OS', host.os], ['Status', host.status],
                ['First Seen', host.first_seen_at ? format(new Date(host.first_seen_at), 'yyyy-MM-dd') : '—'],
              ].map(([k, v]) => v && (
                <div key={k} className="flex justify-between gap-2">
                  <dt className="text-text-muted">{k}</dt>
                  <dd className="text-text-secondary font-mono text-xs text-right">{v}</dd>
                </div>
              ))}
            </dl>
          )}
        </div>

        <div className="card p-4 col-span-2">
          <h2 className="text-sm font-medium text-text-primary mb-3 flex items-center gap-2">
            <Activity className="w-4 h-4 text-accent-purple" />Open Ports ({services.length})
          </h2>
          <div className="space-y-1.5 max-h-48 overflow-y-auto">
            {services.map(s => (
              <div key={s.id} className="flex items-center gap-3 text-xs px-2 py-1.5 bg-surface-2 rounded-md">
                <span className="font-mono text-accent-cyan w-16">{s.port}/{s.protocol}</span>
                <span className="text-text-secondary">{s.service}</span>
                <span className="text-text-muted">{s.product} {s.version}</span>
                <StatusBadge s={s.state} />
              </div>
            ))}
            {services.length === 0 && <Empty label="No open ports recorded" />}
          </div>

          {/* UDP probe */}
          <div className="mt-4 pt-4 border-t border-surface-3">
            <div className="flex items-center justify-between mb-2">
              <span className="text-xs font-medium text-text-primary">UDP Service Probe</span>
              <button onClick={runUDPProbe} disabled={probingUDP}
                className="btn-ghost text-xs flex items-center gap-1">
                <Radar className={clsx('w-3 h-3', probingUDP && 'animate-spin')} />
                {probingUDP ? 'Probing…' : 'Run UDP Probe'}
              </button>
            </div>
            {udpResult && (
              <div className="space-y-1 max-h-32 overflow-y-auto">
                {(udpResult as Array<{ port: number; open: boolean; service: string }>)
                  .filter(r => r.open)
                  .map(r => (
                    <div key={r.port} className="flex items-center gap-2 text-xs px-2 py-1 bg-surface-2 rounded-md">
                      <span className="font-mono text-accent-cyan">{r.port}/udp</span>
                      <span className="text-text-muted">{r.service}</span>
                      <span className="badge-green badge ml-auto">open</span>
                    </div>
                  ))
                }
                {(udpResult as Array<{ open: boolean }>).filter(r => r.open).length === 0 &&
                  <p className="text-xs text-text-muted">No open UDP ports detected</p>
                }
              </div>
            )}
          </div>
        </div>

        {/* Service Diff */}
        {diff.length > 0 && (
          <div className="card p-4 col-span-full">
            <h2 className="text-sm font-medium text-text-primary mb-3 flex items-center gap-2">
              <BarChart2 className="w-4 h-4 text-accent-orange" />Service Changes
            </h2>
            <div className="space-y-1.5">
              {(diff as Array<{ port: number; protocol: string; service: string; change_type: string; current_state?: string; prev_state?: string }>).map((d, i) => (
                <div key={i} className="flex items-center gap-3 text-xs px-2 py-1.5 bg-surface-2 rounded-md">
                  <span className={clsx('badge text-xs',
                    d.change_type === 'appeared' ? 'badge-green' :
                    d.change_type === 'disappeared' ? 'badge-red' : 'badge-yellow'
                  )}>{d.change_type}</span>
                  <span className="font-mono text-accent-cyan">{d.port}/{d.protocol}</span>
                  <span className="text-text-muted">{d.service}</span>
                  {d.prev_state && <span className="text-text-muted">{d.prev_state} → {d.current_state}</span>}
                </div>
              ))}
            </div>
          </div>
        )}
      </div>
    </Page>
  )
}

export default HostDetailPage
