import { useEffect, useState, useCallback } from 'react'
import { Link } from 'react-router-dom'
import { Bug, AlertTriangle, CheckCircle, XCircle, DownloadCloud, RefreshCw, Filter, Plus, Clock } from 'lucide-react'
import { findingApi } from '@/utils/api'
import { formatDistanceToNow } from 'date-fns'
import clsx from 'clsx'
import toast from 'react-hot-toast'
import { FacetFilterBar, FacetDropdown } from './shared'
import { useFacetFilters } from '@/utils/useFacetFilters'

const FINDING_FACETS = ['severity', 'status', 'category'] as const

interface Finding {
  id: string
  title: string
  severity: 'critical' | 'high' | 'medium' | 'low' | 'info'
  category: string
  status: 'open' | 'acknowledged' | 'false_positive' | 'fixed'
  url: string
  cve: string
  cvss: number
  description: string
  remediation: string
  created_at: string
}

interface Summary {
  total: number
  by_severity: { severity: string; count: number }[]
  by_status: { status: string; count: number }[]
  by_category: { category: string; count: number }[]
}

const SEV_COLOR: Record<string, string> = {
  critical: 'text-accent-red bg-accent-red/10 border-accent-red/30',
  high:     'text-accent-orange bg-accent-orange/10 border-accent-orange/30',
  medium:   'text-accent-yellow bg-accent-yellow/10 border-accent-yellow/30',
  low:      'text-accent-green bg-accent-green/10 border-accent-green/30',
  info:     'text-text-muted bg-surface-3 border-border',
}

const STATUS_COLOR: Record<string, string> = {
  open:           'text-accent-red bg-accent-red/10',
  acknowledged:   'text-accent-orange bg-accent-orange/10',
  false_positive: 'text-text-muted bg-surface-3',
  fixed:          'text-accent-green bg-accent-green/10',
}

export default function FindingsPage() {
  const [findings, setFindings] = useState<Finding[]>([])
  const [summary, setSummary] = useState<Summary | null>(null)
  const [loading, setLoading] = useState(true)
  const { values, toggle, clear, activeCount } = useFacetFilters(FINDING_FACETS)
  const [selected, setSelected] = useState<Finding | null>(null)
  const [showCreate, setShowCreate] = useState(false)
  const [creating, setCreating] = useState(false)
  const [createForm, setCreateForm] = useState({
    title: '', severity: 'medium', category: '', url: '', description: '', remediation: '', cve: '', cvss: 0,
  })

  const load = useCallback(async () => {
    setLoading(true)
    try {
      const [fRes, sRes] = await Promise.all([
        findingApi.list({
          severity: values.severity.length ? values.severity.join(',') : undefined,
          status: values.status.length ? values.status.join(',') : undefined,
          category: values.category.length ? values.category.join(',') : undefined,
        }),
        findingApi.summary(),
      ])
      setFindings(fRes.data.data ?? [])
      setSummary(sRes.data)
    } catch {
      toast.error('Failed to load findings')
    } finally {
      setLoading(false)
    }
  }, [values.severity, values.status, values.category])

  useEffect(() => { load() }, [load])

  const handleExport = async () => {
    window.open(findingApi.exportUrl(), '_blank')
  }

  const handleStatusChange = async (id: string, status: string) => {
    try {
      if (status === 'acknowledged') await findingApi.acknowledge(id)
      else if (status === 'fixed') await findingApi.markFixed(id)
      else await findingApi.falsePositive(id)
      toast.success('Status updated')
      load()
      if (selected?.id === id) setSelected(null)
    } catch {
      toast.error('Failed to update status')
    }
  }

  const handleCreate = async () => {
    if (!createForm.title.trim()) { toast.error('Title is required'); return }
    setCreating(true)
    try {
      await findingApi.create(createForm)
      toast.success('Finding created')
      setShowCreate(false)
      setCreateForm({ title: '', severity: 'medium', category: '', url: '', description: '', remediation: '', cve: '', cvss: 0 })
      load()
    } catch {
      toast.error('Failed to create finding')
    } finally {
      setCreating(false)
    }
  }

  const sevCount = (sev: string) =>
    summary?.by_severity.find(s => s.severity === sev)?.count ?? 0

  return (
    <div className="p-6 space-y-6">
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-xl font-semibold text-text-primary flex items-center gap-2">
            <Bug className="w-5 h-5 text-accent-cyan" /> Findings
          </h1>
          <p className="text-sm text-text-muted mt-0.5">Vulnerability and web test results</p>
        </div>
        <div className="flex gap-2">
          <Link to="/findings/sla-report" className="btn-ghost flex items-center gap-1.5 text-sm">
            <Clock className="w-4 h-4" /> SLA Report
          </Link>
          <button onClick={load} className="btn-ghost"><RefreshCw className="w-4 h-4" /></button>
          <button onClick={handleExport} className="btn-ghost flex items-center gap-1.5 text-sm">
            <DownloadCloud className="w-4 h-4" /> Export CSV
          </button>
          <button onClick={() => setShowCreate(true)} className="btn-primary flex items-center gap-1.5 text-sm">
            <Plus className="w-4 h-4" /> Add Finding
          </button>
        </div>
      </div>

      {/* Summary cards */}
      {summary && (
        <div className="grid grid-cols-2 sm:grid-cols-5 gap-3">
          {(['critical','high','medium','low','info'] as const).map(sev => (
            <button
              key={sev}
              onClick={() => toggle('severity', sev)}
              className={clsx(
                'rounded-lg border p-3 text-left transition-all',
                SEV_COLOR[sev],
                values.severity.includes(sev) ? 'ring-1 ring-current' : 'opacity-80 hover:opacity-100'
              )}
            >
              <div className="text-xs font-medium uppercase tracking-wide">{sev}</div>
              <div className="text-2xl font-bold mt-1">{sevCount(sev)}</div>
            </button>
          ))}
        </div>
      )}

      {/* Filters */}
      <div className="flex items-center gap-3 flex-wrap">
        <Filter className="w-4 h-4 text-text-muted" />
        <FacetFilterBar activeCount={activeCount} onClearAll={() => clear()}>
          <FacetDropdown
            label="Status"
            options={(summary?.by_status ?? []).map(s => ({ value: s.status, count: s.count }))}
            selected={values.status}
            onToggle={v => toggle('status', v)}
            onClear={() => clear('status')}
          />
          <FacetDropdown
            label="Category"
            options={(summary?.by_category ?? []).map(c => ({ value: c.category, count: c.count }))}
            selected={values.category}
            onToggle={v => toggle('category', v)}
            onClear={() => clear('category')}
          />
        </FacetFilterBar>
        <span className="ml-auto text-sm text-text-muted">{findings.length} finding{findings.length !== 1 ? 's' : ''}</span>
      </div>

      <div className="rounded-lg border border-border overflow-hidden">
        {loading ? (
          <div className="p-12 text-center text-text-muted text-sm">Loading...</div>
        ) : findings.length === 0 ? (
          <div className="p-12 text-center text-text-muted text-sm">No findings found</div>
        ) : (
          <table className="w-full text-sm">
            <thead className="bg-surface-2 border-b border-border">
              <tr>
                <th className="text-left px-4 py-2.5 text-text-muted font-medium">Severity</th>
                <th className="text-left px-4 py-2.5 text-text-muted font-medium">Title</th>
                <th className="text-left px-4 py-2.5 text-text-muted font-medium hidden md:table-cell">Category</th>
                <th className="text-left px-4 py-2.5 text-text-muted font-medium hidden lg:table-cell">URL</th>
                <th className="text-left px-4 py-2.5 text-text-muted font-medium">Status</th>
                <th className="text-left px-4 py-2.5 text-text-muted font-medium hidden xl:table-cell">Found</th>
                <th className="px-4 py-2.5" />
              </tr>
            </thead>
            <tbody className="divide-y divide-border">
              {findings.map(f => (
                <tr key={f.id} className="hover:bg-surface-2 transition-colors">
                  <td className="px-4 py-3">
                    <span className={clsx('text-xs font-medium px-2 py-0.5 rounded-md border uppercase', SEV_COLOR[f.severity])}>
                      {f.severity}
                    </span>
                  </td>
                  <td className="px-4 py-3">
                    <button onClick={() => setSelected(f)} className="text-text-primary hover:text-accent-cyan text-left font-medium">
                      {f.title}
                    </button>
                    {f.cve && <div className="text-xs text-text-muted mt-0.5">{f.cve}</div>}
                  </td>
                  <td className="px-4 py-3 text-text-secondary hidden md:table-cell">{f.category || '—'}</td>
                  <td className="px-4 py-3 hidden lg:table-cell">
                    <span className="text-text-muted text-xs truncate max-w-[200px] block">{f.url || '—'}</span>
                  </td>
                  <td className="px-4 py-3">
                    <span className={clsx('text-xs px-2 py-0.5 rounded-md font-medium', STATUS_COLOR[f.status])}>
                      {f.status.replace('_', ' ')}
                    </span>
                  </td>
                  <td className="px-4 py-3 text-text-muted text-xs hidden xl:table-cell">
                    {formatDistanceToNow(new Date(f.created_at), { addSuffix: true })}
                  </td>
                  <td className="px-4 py-3">
                    {f.status === 'open' && (
                      <div className="flex items-center gap-1">
                        <button onClick={() => handleStatusChange(f.id, 'acknowledged')} title="Acknowledge" className="p-1 text-accent-orange hover:text-accent-orange transition-colors">
                          <AlertTriangle className="w-3.5 h-3.5" />
                        </button>
                        <button onClick={() => handleStatusChange(f.id, 'fixed')} title="Mark Fixed" className="p-1 text-accent-green hover:text-accent-green/70 transition-colors">
                          <CheckCircle className="w-3.5 h-3.5" />
                        </button>
                        <button onClick={() => handleStatusChange(f.id, 'false_positive')} title="False Positive" className="p-1 text-text-muted hover:text-text-secondary transition-colors">
                          <XCircle className="w-3.5 h-3.5" />
                        </button>
                      </div>
                    )}
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        )}
      </div>

      {/* Detail panel */}
      {selected && (
        <div className="fixed inset-0 z-50 flex items-end sm:items-center justify-center p-4 bg-black/60" onClick={() => setSelected(null)}>
          <div className="bg-surface-1 border border-border rounded-xl w-full max-w-2xl max-h-[80vh] overflow-y-auto" onClick={e => e.stopPropagation()}>
            <div className="p-5 border-b border-border flex items-start gap-3">
              <span className={clsx('text-xs font-medium px-2 py-0.5 rounded-md border uppercase mt-0.5', SEV_COLOR[selected.severity])}>
                {selected.severity}
              </span>
              <div className="flex-1">
                <h2 className="text-base font-semibold text-text-primary">{selected.title}</h2>
                {selected.cve && <div className="text-xs text-text-muted mt-0.5">{selected.cve} {selected.cvss > 0 && `· CVSS ${selected.cvss}`}</div>}
              </div>
              <button onClick={() => setSelected(null)} className="text-text-muted hover:text-text-primary">✕</button>
            </div>
            <div className="p-5 space-y-4 text-sm">
              {selected.url && <div><div className="text-xs text-text-muted mb-1">URL</div><div className="text-text-secondary font-mono text-xs break-all">{selected.url}</div></div>}
              {selected.description && <div><div className="text-xs text-text-muted mb-1">Description</div><p className="text-text-secondary">{selected.description}</p></div>}
              {selected.remediation && <div><div className="text-xs text-text-muted mb-1">Remediation</div><p className="text-text-secondary">{selected.remediation}</p></div>}
            </div>
          </div>
        </div>
      )}
      {/* Create Finding Modal */}
      {showCreate && (
        <div className="fixed inset-0 z-50 flex items-end sm:items-center justify-center p-4 bg-black/60" onClick={() => setShowCreate(false)}>
          <div className="bg-surface-1 border border-border rounded-xl w-full max-w-lg" onClick={e => e.stopPropagation()}>
            <div className="p-5 border-b border-border flex items-center justify-between">
              <h2 className="text-base font-semibold text-text-primary flex items-center gap-2"><Bug className="w-4 h-4 text-accent-cyan" /> Add Finding</h2>
              <button onClick={() => setShowCreate(false)} className="text-text-muted hover:text-text-primary">✕</button>
            </div>
            <div className="p-5 space-y-3 text-sm">
              <div>
                <label className="text-xs text-text-muted mb-1 block">Title *</label>
                <input value={createForm.title} onChange={e => setCreateForm(f => ({ ...f, title: e.target.value }))}
                  className="w-full bg-surface-2 border border-border rounded-md px-3 py-1.5 text-text-primary" placeholder="e.g. Missing Content-Security-Policy header" />
              </div>
              <div className="grid grid-cols-2 gap-3">
                <div>
                  <label className="text-xs text-text-muted mb-1 block">Severity</label>
                  <select value={createForm.severity} onChange={e => setCreateForm(f => ({ ...f, severity: e.target.value }))}
                    className="w-full bg-surface-2 border border-border rounded-md px-3 py-1.5 text-text-primary">
                    {(['critical','high','medium','low','info'] as const).map(s => <option key={s} value={s}>{s}</option>)}
                  </select>
                </div>
                <div>
                  <label className="text-xs text-text-muted mb-1 block">Category</label>
                  <input value={createForm.category} onChange={e => setCreateForm(f => ({ ...f, category: e.target.value }))}
                    className="w-full bg-surface-2 border border-border rounded-md px-3 py-1.5 text-text-primary" placeholder="e.g. Headers" />
                </div>
              </div>
              <div>
                <label className="text-xs text-text-muted mb-1 block">URL</label>
                <input value={createForm.url} onChange={e => setCreateForm(f => ({ ...f, url: e.target.value }))}
                  className="w-full bg-surface-2 border border-border rounded-md px-3 py-1.5 text-text-primary font-mono text-xs" placeholder="https://example.com/page" />
              </div>
              <div className="grid grid-cols-2 gap-3">
                <div>
                  <label className="text-xs text-text-muted mb-1 block">CVE</label>
                  <input value={createForm.cve} onChange={e => setCreateForm(f => ({ ...f, cve: e.target.value }))}
                    className="w-full bg-surface-2 border border-border rounded-md px-3 py-1.5 text-text-primary" placeholder="CVE-2024-XXXX" />
                </div>
                <div>
                  <label className="text-xs text-text-muted mb-1 block">CVSS Score</label>
                  <input type="number" min={0} max={10} step={0.1} value={createForm.cvss} onChange={e => setCreateForm(f => ({ ...f, cvss: parseFloat(e.target.value) || 0 }))}
                    className="w-full bg-surface-2 border border-border rounded-md px-3 py-1.5 text-text-primary" />
                </div>
              </div>
              <div>
                <label className="text-xs text-text-muted mb-1 block">Description</label>
                <textarea value={createForm.description} onChange={e => setCreateForm(f => ({ ...f, description: e.target.value }))}
                  rows={3} className="w-full bg-surface-2 border border-border rounded-md px-3 py-1.5 text-text-primary resize-none" />
              </div>
              <div>
                <label className="text-xs text-text-muted mb-1 block">Remediation</label>
                <textarea value={createForm.remediation} onChange={e => setCreateForm(f => ({ ...f, remediation: e.target.value }))}
                  rows={2} className="w-full bg-surface-2 border border-border rounded-md px-3 py-1.5 text-text-primary resize-none" />
              </div>
            </div>
            <div className="p-5 pt-0 flex justify-end gap-2">
              <button onClick={() => setShowCreate(false)} className="btn-ghost text-sm">Cancel</button>
              <button onClick={handleCreate} disabled={creating} className="btn-primary text-sm">
                {creating ? 'Creating…' : 'Create Finding'}
              </button>
            </div>
          </div>
        </div>
      )}
    </div>
  )
}
