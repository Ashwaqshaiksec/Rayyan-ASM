import { useEffect, useState, useCallback } from 'react'
import { useParams, useNavigate } from 'react-router-dom'
import {
  History, ArrowLeft, CheckCircle, XCircle, AlertCircle,
  Clock, RefreshCw, AlertTriangle
} from 'lucide-react'
import api from '@/utils/api'
import { formatDistanceToNow, format } from 'date-fns'
import clsx from 'clsx'
import toast from 'react-hot-toast'


interface ToolRunRow {
  id: string
  scan_id: string
  tool_name: string
  result_count: number
  duration_ms: number
  status: 'ok' | 'error' | 'skipped'
  truncated: boolean
  created_at: string
}


const fetchRuns = (name: string) =>
  api.get<{ data: ToolRunRow[]; tool: string }>(`/tools/${name}/runs`)


function RunStatusBadge({ status }: { status: ToolRunRow['status'] }) {
  if (status === 'ok') {
    return (
      <span className="inline-flex items-center gap-1 px-2 py-0.5 rounded-md text-xs font-medium bg-accent-green/10 text-accent-green border border-accent-green/20">
        <CheckCircle className="w-3 h-3" /> ok
      </span>
    )
  }
  if (status === 'skipped') {
    return (
      <span className="inline-flex items-center gap-1 px-2 py-0.5 rounded-md text-xs font-medium bg-accent-orange/10 text-accent-orange border border-accent-orange/20">
        <AlertCircle className="w-3 h-3" /> skipped
      </span>
    )
  }
  return (
    <span className="inline-flex items-center gap-1 px-2 py-0.5 rounded-md text-xs font-medium bg-accent-red/10 text-accent-red border border-accent-red/20">
      <XCircle className="w-3 h-3" /> error
    </span>
  )
}


function fmtDuration(ms: number): string {
  if (ms < 1000)   return `${ms}ms`
  if (ms < 60_000) return `${(ms / 1000).toFixed(1)}s`
  const m = Math.floor(ms / 60_000)
  const s = Math.round((ms % 60_000) / 1000)
  return `${m}m ${s}s`
}


function EmptyState({ tool }: { tool: string }) {
  return (
    <div className="card p-12 flex flex-col items-center gap-3 text-center">
      <History className="w-10 h-10 text-text-muted/30" />
      <div className="text-sm font-medium text-text-secondary">No run history yet</div>
      <div className="text-xs text-text-muted max-w-xs">
        <span className="font-mono text-accent-cyan">{tool}</span> hasn't been executed as part
        of any workflow scan yet. Runs will appear here once the tool completes at least one stage.
      </div>
    </div>
  )
}


export default function ToolRunHistoryPage() {
  const { name }          = useParams<{ name: string }>()
  const navigate          = useNavigate()
  const [runs, setRuns]   = useState<ToolRunRow[]>([])
  const [loading, setLoading] = useState(true)

  const load = useCallback(async () => {
    if (!name) return
    setLoading(true)
    try {
      const { data } = await fetchRuns(name)
      setRuns(data.data ?? [])
    } catch {
      toast.error(`Failed to load run history for ${name}`)
    } finally {
      setLoading(false)
    }
  }, [name])

  useEffect(() => { load() }, [load])

  // Quick stats
  const totalRuns  = runs.length
  const okRuns     = runs.filter(r => r.status === 'ok').length
  const errRuns    = runs.filter(r => r.status === 'error').length
  const avgDuration = totalRuns > 0
    ? Math.round(runs.reduce((s, r) => s + r.duration_ms, 0) / totalRuns)
    : 0
  const totalResults = runs.reduce((s, r) => s + r.result_count, 0)

  return (
    <div className="p-6 max-w-5xl mx-auto space-y-4 animate-fade-in">
      <div className="flex items-center gap-3">
        <button
          onClick={() => navigate('/tools')}
          className="p-1.5 rounded-md hover:bg-surface-2 text-text-muted hover:text-text-primary transition-colors"
        >
          <ArrowLeft className="w-4 h-4" />
        </button>
        <div className="flex-1">
          <h1 className="text-lg font-semibold text-text-primary flex items-center gap-2">
            <History className="w-5 h-5 text-accent-cyan" />
            Run History —{' '}
            <span className="font-mono text-accent-cyan">{name}</span>
          </h1>
          <p className="text-sm text-text-muted mt-0.5">
            Past executions from workflow scans (most recent first, up to 50)
          </p>
        </div>
        <button
          onClick={load}
          disabled={loading}
          className="btn-secondary inline-flex items-center gap-1.5"
        >
          <RefreshCw className={clsx('w-3.5 h-3.5', loading && 'animate-spin')} />
          Refresh
        </button>
      </div>

      {!loading && totalRuns > 0 && (
        <div className="grid grid-cols-2 sm:grid-cols-4 gap-3">
          {[
            { label: 'Total Runs',      value: totalRuns,                       color: 'text-text-primary' },
            { label: 'Successful',      value: okRuns,                          color: 'text-accent-green' },
            { label: 'Errors',          value: errRuns,                         color: errRuns > 0 ? 'text-accent-red' : 'text-text-muted' },
            { label: 'Avg Duration',    value: fmtDuration(avgDuration),        color: 'text-accent-cyan' },
          ].map(({ label, value, color }) => (
            <div key={label} className="card p-4 text-center">
              <div className={clsx('text-2xl font-bold', color)}>{value}</div>
              <div className="text-xs text-text-muted mt-1">{label}</div>
            </div>
          ))}
        </div>
      )}

      {loading ? (
        <div className="flex justify-center py-12">
          <div className="w-5 h-5 border-2 border-accent-cyan/30 border-t-accent-cyan rounded-full animate-spin" />
        </div>
      ) : runs.length === 0 ? (
        <EmptyState tool={name ?? ''} />
      ) : (
        <div className="card overflow-hidden">
          <div className="table-container">
            <table className="table">
              <thead>
                <tr>
                  <th>Timestamp</th>
                  <th>Scan ID</th>
                  <th>Status</th>
                  <th>Results</th>
                  <th>Duration</th>
                  <th>Notes</th>
                </tr>
              </thead>
              <tbody>
                {runs.map(run => (
                  <tr key={run.id}>
                    <td>
                      <div className="flex flex-col">
                        <span className="text-xs text-text-primary font-mono">
                          {format(new Date(run.created_at), 'yyyy-MM-dd HH:mm:ss')}
                        </span>
                        <span className="text-xs text-text-muted">
                          {formatDistanceToNow(new Date(run.created_at), { addSuffix: true })}
                        </span>
                      </div>
                    </td>

                    <td>
                      <button
                        onClick={() => navigate(`/scans/${run.scan_id}`)}
                        className="font-mono text-xs text-accent-cyan hover:underline"
                        title={run.scan_id}
                      >
                        {run.scan_id.slice(0, 8)}…
                      </button>
                    </td>

                    <td><RunStatusBadge status={run.status} /></td>

                    <td>
                      <span className="text-sm font-medium text-text-primary">
                        {run.result_count.toLocaleString()}
                      </span>
                    </td>

                    <td>
                      <span className="inline-flex items-center gap-1 text-xs text-text-secondary">
                        <Clock className="w-3 h-3" />
                        {fmtDuration(run.duration_ms)}
                      </span>
                    </td>

                    {/* Notes (truncation warning) */}
                    <td>
                      {run.truncated && (
                        <span className="inline-flex items-center gap-1 text-xs text-accent-orange">
                          <AlertTriangle className="w-3 h-3" />
                          Output truncated
                        </span>
                      )}
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>

          <div className="px-4 py-2 border-t border-border text-xs text-text-muted">
            Showing {runs.length} most recent run{runs.length !== 1 ? 's' : ''} ·{' '}
            {totalResults.toLocaleString()} total results collected
          </div>
        </div>
      )}
    </div>
  )
}
