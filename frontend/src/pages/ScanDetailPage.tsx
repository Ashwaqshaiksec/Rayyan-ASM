import { useEffect, useState, useCallback } from 'react'
import { Link, useParams } from 'react-router-dom'
import { RefreshCw, BarChart2 } from 'lucide-react'
import { scanApi } from '@/utils/api'
import type { ScanJob } from '@/types'
import { format } from 'date-fns'
import { Page, Empty, scanTargets } from './shared'

export function ScanDetailPage() {
  const { id } = useParams<{ id: string }>()
  const [scan, setScan] = useState<ScanJob | null>(null)
  const [results, setResults] = useState<unknown[]>([])

  const load = useCallback(() => {
    if (!id) return
    scanApi.get(id).then(({ data }) => setScan(data))
    scanApi.results(id).then(({ data }) => setResults(data.data ?? []))
  }, [id])

  useEffect(() => { load() }, [load])

  // Poll every 5 s while the scan is still active. Depends on scan?.status
  // (not the whole scan object) so polling doesn't restart on every field
  // change in the scan payload — only when its active/inactive state flips.
  useEffect(() => {
    if (!scan) return
    if (!['pending', 'running', 'queued'].includes(scan.status)) return
    const t = setInterval(load, 5000)
    return () => clearInterval(t)
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [scan?.status, load])

  const isActive = scan ? ['pending', 'running', 'queued'].includes(scan.status) : false

  return (
    <Page title={scan?.name ?? 'Scan Detail'} subtitle={scan ? `${scan.type} · ${scan.status}` : undefined}
      actions={id && scan?.status === 'completed' ? (
        <Link to={`/scans/${id}/compare`} className="btn-ghost text-xs flex items-center gap-1">
          <BarChart2 className="w-3 h-3" />Compare
        </Link>
      ) : undefined}>
      {scan && (
        <div className="grid grid-cols-2 lg:grid-cols-4 gap-4">
          {[['Type', scan.type], ['Status', scan.status], ['Targets', scanTargets(scan.targets).length],
            ['Created', scan.created_at ? format(new Date(scan.created_at), 'yyyy-MM-dd HH:mm') : '—']
          ].map(([k, v]) => (
            <div key={String(k)} className="card p-4">
              <div className="text-xs text-text-muted mb-1">{k}</div>
              <div className="text-sm font-medium text-text-primary">{String(v)}</div>
            </div>
          ))}
        </div>
      )}
      <div className="card p-4">
        <h2 className="text-sm font-medium text-text-primary mb-3 flex items-center gap-2">
          Results ({results.length})
          {isActive && <RefreshCw className="w-3 h-3 text-accent-blue animate-spin" />}
        </h2>
        {results.length === 0 ? (
          <Empty label={isActive ? 'Scan in progress — results will appear here' : 'No results'} />
        ) : (
          <pre className="text-xs text-text-secondary font-mono overflow-auto max-h-[32rem] bg-surface-2 rounded-md p-3">
            {JSON.stringify(results, null, 2)}
          </pre>
        )}
      </div>
    </Page>
  )
}

export default ScanDetailPage
