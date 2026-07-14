import { useState, useEffect } from 'react'
import { useParams, Link } from 'react-router-dom'
import {
  GitCompare, Plus, Minus, ArrowLeft,
  ChevronDown, ChevronRight, AlertTriangle
} from 'lucide-react'
import { scanApi } from '@/utils/api'
import type { ScanJob } from '@/types'
import { formatDistanceToNow } from 'date-fns'
import toast from 'react-hot-toast'


interface ScanMeta {
  id: string
  name: string
  created_at: string
}

interface Finding {
  id: string
  title: string
  severity: string
  category: string
  url: string
  description: string
  cvss?: number
  cvss_vector?: string
}

interface DiffResult {
  scan_a: ScanMeta
  scan_b: ScanMeta
  new: Finding[]
  removed: Finding[]
  persistent: Finding[]
  summary: { new: number; removed: number; persistent: number }
}


const severityColor: Record<string, string> = {
  critical: 'text-accent-red bg-accent-red/10 border-accent-red/30',
  high:     'text-accent-orange bg-accent-orange/10 border-accent-orange/30',
  medium:   'text-accent-yellow bg-accent-yellow/10 border-accent-yellow/30',
  low:      'text-accent-green bg-accent-green/10 border-accent-green/30',
  info:     'text-text-muted bg-surface-3 border-border',
}

const SeverityBadge = ({ sev }: { sev: string }) => (
  <span className={`text-[10px] font-semibold px-2 py-0.5 rounded-md border uppercase tracking-wide ${severityColor[sev] ?? severityColor.info}`}>
    {sev}
  </span>
)


function FindingRow({ f, highlight }: { f: Finding; highlight: 'new' | 'removed' | 'persistent' }) {
  const [open, setOpen] = useState(false)
  const borderClass =
    highlight === 'new'        ? 'border-l-2 border-l-accent-green'  :
    highlight === 'removed'    ? 'border-l-2 border-l-accent-red'      :
                                 'border-l-2 border-l-border'

  return (
    <div className={`card mb-2 overflow-hidden ${borderClass}`}>
      <button
        className="w-full flex items-center gap-3 px-4 py-3 text-left hover:bg-surface-2/50 transition-colors"
        onClick={() => setOpen(o => !o)}
      >
        <span className="text-text-muted">{open ? <ChevronDown className="w-4 h-4" /> : <ChevronRight className="w-4 h-4" />}</span>
        <SeverityBadge sev={f.severity} />
        <span className="flex-1 text-sm text-text-primary font-medium truncate">{f.title}</span>
        <span className="text-xs text-text-muted hidden sm:block">{f.category}</span>
        {f.cvss != null && f.cvss > 0 && (
          <span className="text-xs font-mono text-text-muted">CVSS {f.cvss.toFixed(1)}</span>
        )}
      </button>
      {open && (
        <div className="px-4 pb-4 pt-1 space-y-2 border-t border-border bg-surface-1/40">
          {f.url && <p className="text-xs font-mono text-accent-cyan break-all">{f.url}</p>}
          {f.description && <p className="text-xs text-text-secondary leading-relaxed">{f.description}</p>}
          {f.cvss_vector && <p className="text-xs font-mono text-text-muted">{f.cvss_vector}</p>}
        </div>
      )}
    </div>
  )
}


function Section({
  title, icon, count, findings, highlight, emptyMsg
}: {
  title: string
  icon: React.ReactNode
  count: number
  findings: Finding[]
  highlight: 'new' | 'removed' | 'persistent'
  emptyMsg: string
}) {
  const [collapsed, setCollapsed] = useState(false)

  return (
    <div className="space-y-2">
      <button
        className="flex items-center gap-2 w-full text-left"
        onClick={() => setCollapsed(c => !c)}
      >
        {icon}
        <span className="text-sm font-semibold text-text-primary">{title}</span>
        <span className="text-xs font-mono px-2 py-0.5 rounded-md bg-surface-2 text-text-muted">{count}</span>
        <span className="ml-auto text-text-muted">{collapsed ? <ChevronRight className="w-4 h-4" /> : <ChevronDown className="w-4 h-4" />}</span>
      </button>
      {!collapsed && (
        findings.length === 0
          ? <p className="text-xs text-text-muted pl-6">{emptyMsg}</p>
          : findings.map(f => <FindingRow key={f.id} f={f} highlight={highlight} />)
      )}
    </div>
  )
}


export default function ScanComparePage() {
  const { id } = useParams<{ id: string }>()

  const [scans, setScans] = useState<{ id: string; name: string }[]>([])
  const [otherScanId, setOtherScanId] = useState('')
  const [result, setResult] = useState<DiffResult | null>(null)
  const [loading, setLoading] = useState(false)
  const [scansLoading, setScansLoading] = useState(true)

  useEffect(() => {
    scanApi.list({ limit: 100, status: 'completed' }).then(({ data }) => {
      setScans((data.data ?? []).filter((s: ScanJob) => s.id !== id))
      setScansLoading(false)
    }).catch(() => setScansLoading(false))
  }, [id])

  const runDiff = async () => {
    if (!id || !otherScanId) { toast.error('Select a scan to compare'); return }
    setLoading(true)
    setResult(null)
    try {
      const { data } = await scanApi.diff(id, otherScanId)
      setResult(data)
    } catch {
      toast.error('Diff failed')
    } finally {
      setLoading(false)
    }
  }

  return (
    <div className="p-6 space-y-6 max-w-5xl mx-auto">
      <div className="flex items-center gap-3">
        <Link to={`/scans/${id}`} className="text-text-muted hover:text-text-primary transition-colors">
          <ArrowLeft className="w-5 h-5" />
        </Link>
        <GitCompare className="w-5 h-5 text-accent-cyan" />
        <h1 className="text-lg font-semibold text-text-primary">Scan Comparison</h1>
      </div>

      {/* Selector */}
      <div className="card p-4 flex flex-col sm:flex-row gap-3 items-end">
        <div className="flex-1">
          <label className="text-xs text-text-muted mb-1 block">Compare this scan against</label>
          <select
            className="input w-full"
            value={otherScanId}
            onChange={e => setOtherScanId(e.target.value)}
            disabled={scansLoading}
          >
            <option value="">— select completed scan —</option>
            {scans.map(s => (
              <option key={s.id} value={s.id}>{s.name || s.id.slice(0, 8)}</option>
            ))}
          </select>
        </div>
        <button
          className="btn-primary flex items-center gap-2 shrink-0"
          onClick={runDiff}
          disabled={loading || !otherScanId}
        >
          {loading
            ? <><span className="w-4 h-4 border-2 border-current border-t-transparent rounded-full animate-spin" /> Comparing…</>
            : <><GitCompare className="w-4 h-4" /> Run Diff</>
          }
        </button>
      </div>

      {/* Results */}
      {result && (
        <div className="space-y-6">
          {/* Scan labels */}
          <div className="grid grid-cols-2 gap-3">
            {[result.scan_a, result.scan_b].map((s, i) => (
              <div key={s.id} className="card p-3">
                <p className="text-xs text-text-muted">Scan {i === 0 ? 'A (baseline)' : 'B (latest)'}</p>
                <p className="text-sm font-medium text-text-primary mt-1">{s.name || s.id.slice(0, 12)}</p>
                <p className="text-xs text-text-muted">{formatDistanceToNow(new Date(s.created_at), { addSuffix: true })}</p>
              </div>
            ))}
          </div>

          {/* Summary bar */}
          <div className="grid grid-cols-3 gap-3">
            <div className="card p-3 text-center border-accent-green/20">
              <p className="text-2xl font-bold text-accent-green">{result.summary.new}</p>
              <p className="text-xs text-text-muted mt-1">New findings</p>
            </div>
            <div className="card p-3 text-center border-accent-red/20">
              <p className="text-2xl font-bold text-accent-red">{result.summary.removed}</p>
              <p className="text-xs text-text-muted mt-1">Removed / fixed</p>
            </div>
            <div className="card p-3 text-center">
              <p className="text-2xl font-bold text-text-secondary">{result.summary.persistent}</p>
              <p className="text-xs text-text-muted mt-1">Persistent</p>
            </div>
          </div>

          {/* Sections */}
          <Section
            title="New Findings"
            icon={<Plus className="w-4 h-4 text-accent-green" />}
            count={result.summary.new}
            findings={result.new ?? []}
            highlight="new"
            emptyMsg="No new findings — nothing introduced."
          />
          <Section
            title="Removed / Fixed"
            icon={<Minus className="w-4 h-4 text-accent-red" />}
            count={result.summary.removed}
            findings={result.removed ?? []}
            highlight="removed"
            emptyMsg="No findings were removed between these scans."
          />
          <Section
            title="Persistent"
            icon={<AlertTriangle className="w-4 h-4 text-accent-orange" />}
            count={result.summary.persistent}
            findings={result.persistent ?? []}
            highlight="persistent"
            emptyMsg="No findings persist across both scans."
          />
        </div>
      )}
    </div>
  )
}
