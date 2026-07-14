// DomainsPage.tsx
import { useEffect, useState, useCallback } from 'react'
import { Link } from 'react-router-dom'
import { Globe, Plus, Tag, ExternalLink, RefreshCw, Search, X } from 'lucide-react'
import { domainApi, scanApi } from '@/utils/api'
import type { Domain } from '@/types'
import { formatDistanceToNow } from 'date-fns'
import toast from 'react-hot-toast'

export function DomainsPage() {
  const [domains, setDomains] = useState<Domain[]>([])
  const [total, setTotal] = useState(0)
  const [loading, setLoading] = useState(true)
  const [page, setPage] = useState(1)
  const [search, setSearch] = useState('')
  const [showAdd, setShowAdd] = useState(false)
  const [addForm, setAddForm] = useState({
    name: '', environment: 'production', owner: '', business_unit: '', notes: '', tags: '',
  })
  const [adding, setAdding] = useState(false)

  const load = useCallback(() => {
    setLoading(true)
    domainApi.list({ page, limit: 50, search: search || undefined }).then(({ data }) => {
      setDomains(data.data ?? [])
      setTotal(data.total ?? 0)
    }).catch(() => {}).finally(() => setLoading(false))
  }, [page, search])

  useEffect(() => { load() }, [load])

  const handleAdd = async () => {
    if (!addForm.name.trim()) { toast.error('Domain name is required'); return }
    setAdding(true)
    try {
      await domainApi.create({
        name: addForm.name.trim(),
        environment: addForm.environment,
        owner: addForm.owner,
        business_unit: addForm.business_unit,
        notes: addForm.notes,
        tags: addForm.tags ? addForm.tags.split(',').map(t => t.trim()).filter(Boolean) : [],
        monitored: true,
      })
      toast.success(`Domain ${addForm.name} added`)
      setShowAdd(false)
      setAddForm({ name: '', environment: 'production', owner: '', business_unit: '', notes: '', tags: '' })
      load()
    } catch {
      toast.error('Failed to add domain')
    } finally {
      setAdding(false)
    }
  }

  const handleScan = async (id: string, name: string) => {
    try {
      await scanApi.create({
        name: `DNS + Subdomain scan: ${name}`,
        type: 'subdomain',
        targets: { targets: [name] },
        options: {},
      })
      toast.success(`Scan started for ${name}`)
    } catch {
      toast.error('Failed to start scan')
    }
  }

  const handleDelete = async (id: string, name: string) => {
    if (!confirm(`Delete domain ${name}?`)) return
    try {
      await domainApi.delete(id)
      toast.success('Domain deleted')
      load()
    } catch {
      toast.error('Failed to delete domain')
    }
  }

  const totalPages = Math.ceil(total / 50)

  return (
    <div className="p-6 max-w-7xl mx-auto space-y-4 animate-fade-in">
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-lg font-semibold text-text-primary">Domains</h1>
          <p className="text-sm text-text-muted">{total.toLocaleString()} domains tracked</p>
        </div>
        <div className="flex gap-2">
          <button onClick={load} className="btn-ghost"><RefreshCw className="w-4 h-4" /></button>
          <button onClick={() => setShowAdd(true)} className="btn-primary"><Plus className="w-3.5 h-3.5" />Add Domain</button>
        </div>
      </div>

      {/* Search */}
      <div className="relative max-w-sm">
        <Search className="absolute left-3 top-1/2 -translate-y-1/2 w-4 h-4 text-text-muted" />
        <input
          value={search}
          onChange={e => { setSearch(e.target.value); setPage(1) }}
          className="w-full bg-surface-2 border border-border rounded-md pl-9 pr-3 py-1.5 text-sm text-text-primary placeholder:text-text-muted"
          placeholder="Filter domains…"
        />
        {search && <button onClick={() => setSearch('')} className="absolute right-3 top-1/2 -translate-y-1/2 text-text-muted hover:text-text-primary"><X className="w-3.5 h-3.5" /></button>}
      </div>

      <div className="card">
        <div className="table-container">
          <table className="table">
            <thead>
              <tr>
                <th>Domain</th>
                <th>Status</th>
                <th>Environment</th>
                <th>Owner</th>
                <th>Tags</th>
                <th>Last Scanned</th>
                <th></th>
              </tr>
            </thead>
            <tbody>
              {loading && <tr><td colSpan={7} className="text-center py-8 text-text-muted">Loading…</td></tr>}
              {!loading && domains.length === 0 && (
                <tr><td colSpan={7} className="text-center py-12 text-text-muted">
                  {search ? `No domains matching "${search}"` : 'No domains yet. Add your first domain to start tracking.'}
                </td></tr>
              )}
              {domains.map((d) => (
                <tr key={d.id} className="group">
                  <td>
                    <div className="flex items-center gap-2">
                      <Globe className="w-3.5 h-3.5 text-accent-blue flex-shrink-0" />
                      <Link to={`/domains/${d.id}`} className="font-medium text-text-primary hover:text-accent-cyan transition-colors">{d.name}</Link>
                    </div>
                  </td>
                  <td><span className={d.status === 'active' ? 'badge-green' : 'badge-gray'}>{d.status}</span></td>
                  <td><span className="badge-blue">{d.environment}</span></td>
                  <td className="text-xs text-text-secondary">{d.owner || '—'}</td>
                  <td>
                    <div className="flex gap-1 flex-wrap">
                      {(d.tags ?? []).slice(0, 3).map(t => <span key={t} className="badge-gray"><Tag className="w-2.5 h-2.5" />{t}</span>)}
                      {(d.tags ?? []).length > 3 && <span className="badge-gray">+{d.tags.length - 3}</span>}
                    </div>
                  </td>
                  <td className="text-xs">{d.last_scanned_at ? formatDistanceToNow(new Date(d.last_scanned_at), { addSuffix: true }) : 'Never'}</td>
                  <td>
                    <div className="flex items-center gap-1 opacity-0 group-hover:opacity-100 transition-opacity">
                      <button onClick={() => handleScan(d.id, d.name)} className="btn-ghost py-1 px-2 text-xs text-accent-cyan">Scan</button>
                      <Link to={`/domains/${d.id}`} className="btn-ghost py-1 px-2"><ExternalLink className="w-3 h-3" /></Link>
                      <button onClick={() => handleDelete(d.id, d.name)} className="btn-ghost py-1 px-2 text-accent-red hover:text-accent-red">✕</button>
                    </div>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </div>

      {/* Pagination */}
      {totalPages > 1 && (
        <div className="flex items-center justify-between text-sm text-text-muted">
          <span className="text-xs font-mono">Page {page} / {totalPages}</span>
          <div className="flex gap-1.5">
            <button onClick={() => setPage(p => Math.max(1, p - 1))} disabled={page <= 1} className="btn-secondary py-1 px-3 text-xs disabled:opacity-40">Prev</button>
            <button onClick={() => setPage(p => Math.min(totalPages, p + 1))} disabled={page >= totalPages} className="btn-secondary py-1 px-3 text-xs disabled:opacity-40">Next</button>
          </div>
        </div>
      )}

      {/* Add Domain Modal */}
      {showAdd && (
        <div className="fixed inset-0 z-50 flex items-center justify-center p-4 bg-black/60" onClick={() => setShowAdd(false)}>
          <div className="bg-surface-1 border border-border rounded-xl w-full max-w-md" onClick={e => e.stopPropagation()}>
            <div className="p-5 border-b border-border flex items-center justify-between">
              <h2 className="text-base font-semibold text-text-primary flex items-center gap-2">
                <Globe className="w-4 h-4 text-accent-blue" /> Add Domain
              </h2>
              <button onClick={() => setShowAdd(false)} className="text-text-muted hover:text-text-primary">✕</button>
            </div>
            <div className="p-5 space-y-3 text-sm">
              <div>
                <label className="text-xs text-text-muted mb-1 block">Domain name *</label>
                <input
                  value={addForm.name}
                  onChange={e => setAddForm(f => ({ ...f, name: e.target.value }))}
                  className="w-full bg-surface-2 border border-border rounded-md px-3 py-1.5 text-text-primary font-mono"
                  placeholder="example.com"
                  autoFocus
                />
              </div>
              <div className="grid grid-cols-2 gap-3">
                <div>
                  <label className="text-xs text-text-muted mb-1 block">Environment</label>
                  <select value={addForm.environment} onChange={e => setAddForm(f => ({ ...f, environment: e.target.value }))}
                    className="w-full bg-surface-2 border border-border rounded-md px-3 py-1.5 text-text-primary">
                    {['production', 'staging', 'development', 'testing'].map(e => <option key={e} value={e}>{e}</option>)}
                  </select>
                </div>
                <div>
                  <label className="text-xs text-text-muted mb-1 block">Owner</label>
                  <input value={addForm.owner} onChange={e => setAddForm(f => ({ ...f, owner: e.target.value }))}
                    className="w-full bg-surface-2 border border-border rounded-md px-3 py-1.5 text-text-primary" placeholder="team or person" />
                </div>
              </div>
              <div>
                <label className="text-xs text-text-muted mb-1 block">Business Unit</label>
                <input value={addForm.business_unit} onChange={e => setAddForm(f => ({ ...f, business_unit: e.target.value }))}
                  className="w-full bg-surface-2 border border-border rounded-md px-3 py-1.5 text-text-primary" placeholder="e.g. Engineering, Marketing" />
              </div>
              <div>
                <label className="text-xs text-text-muted mb-1 block">Tags <span className="text-text-muted/60">(comma-separated)</span></label>
                <input value={addForm.tags} onChange={e => setAddForm(f => ({ ...f, tags: e.target.value }))}
                  className="w-full bg-surface-2 border border-border rounded-md px-3 py-1.5 text-text-primary" placeholder="e.g. external, critical, pci" />
              </div>
              <div>
                <label className="text-xs text-text-muted mb-1 block">Notes</label>
                <textarea value={addForm.notes} onChange={e => setAddForm(f => ({ ...f, notes: e.target.value }))}
                  rows={2} className="w-full bg-surface-2 border border-border rounded-md px-3 py-1.5 text-text-primary resize-none" />
              </div>
            </div>
            <div className="p-5 pt-0 flex justify-end gap-2">
              <button onClick={() => setShowAdd(false)} className="btn-ghost text-sm">Cancel</button>
              <button onClick={handleAdd} disabled={adding} className="btn-primary text-sm">
                {adding ? 'Adding…' : 'Add Domain'}
              </button>
            </div>
          </div>
        </div>
      )}
    </div>
  )
}

export default DomainsPage
