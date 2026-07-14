import { useState, useEffect, useCallback } from 'react'
import toast from 'react-hot-toast'
import {
  Search, Globe, Server, RefreshCw, PlusCircle, Trash2,
  ToggleLeft, ToggleRight, ChevronDown, ChevronUp,
  AlertTriangle, CheckCircle, Info, Shield, Activity,
  Eye, Clock, Database, Wifi
} from 'lucide-react'
import { intelligenceApi } from '@/utils/api'

// ─── types ────────────────────────────────────────────────────────────────

interface IntelResult {
  id: string
  provider: 'shodan' | 'censys' | 'securitytrails' | 'historical_dns'
  target: string
  target_type: 'host' | 'domain'
  summary: string
  severity: 'info' | 'low' | 'medium' | 'high' | 'critical'
  fetched_at: string
  tags?: string[]
  raw_data?: Record<string, unknown>
}

interface MonitorJob {
  id: string
  target: string
  target_type: 'host' | 'domain'
  providers: string[]
  cadence: string
  enabled: boolean
  last_run_at?: string
  next_run_at: string
  run_count: number
  notes?: string
  created_at: string
}

// ─── constants ────────────────────────────────────────────────────────────

const PROVIDERS = [
  { id: 'shodan',          label: 'Shodan',          icon: '🔭', color: 'text-accent-orange' },
  { id: 'censys',          label: 'Censys',          icon: '🔍', color: 'text-accent-cyan' },
  { id: 'securitytrails',  label: 'SecurityTrails',  icon: '🛤️',  color: 'text-accent-purple' },
  { id: 'historical_dns',  label: 'Historical DNS',  icon: '📜', color: 'text-accent-green' },
]

const SEVERITY_CONFIG: Record<string, { label: string; bg: string; text: string; icon: typeof AlertTriangle }> = {
  critical: { label: 'Critical', bg: 'bg-accent-red/10',     text: 'text-accent-red',    icon: AlertTriangle },
  high:     { label: 'High',     bg: 'bg-accent-orange/10',  text: 'text-accent-orange', icon: AlertTriangle },
  medium:   { label: 'Medium',   bg: 'bg-accent-yellow/10',  text: 'text-accent-yellow', icon: AlertTriangle },
  low:      { label: 'Low',      bg: 'bg-accent-green/10',    text: 'text-accent-green',   icon: Info },
  info:     { label: 'Info',     bg: 'bg-surface-2',      text: 'text-text-muted',  icon: Info },
}

const providerBadge: Record<string, string> = {
  shodan:         'bg-accent-orange/10 text-accent-orange border-accent-orange/25',
  censys:         'bg-accent-cyan/10 text-accent-cyan border-accent-cyan/25',
  securitytrails: 'bg-accent-purple/10 text-accent-purple border-accent-purple/25',
  historical_dns: 'bg-accent-green/10 text-accent-green border-accent-green/25',
}

// ─── helpers ──────────────────────────────────────────────────────────────

function relativeTime(iso?: string): string {
  if (!iso) return 'Never'
  const diff = Date.now() - new Date(iso).getTime()
  const mins = Math.floor(diff / 60000)
  if (mins < 1) return 'Just now'
  if (mins < 60) return `${mins}m ago`
  const hrs = Math.floor(mins / 60)
  if (hrs < 24) return `${hrs}h ago`
  return `${Math.floor(hrs / 24)}d ago`
}

// ─── sub-components ───────────────────────────────────────────────────────

function SeverityBadge({ severity }: { severity: string }) {
  const cfg = SEVERITY_CONFIG[severity] ?? SEVERITY_CONFIG.info
  const Icon = cfg.icon
  return (
    <span className={`inline-flex items-center gap-1 px-2 py-0.5 rounded-md text-xs font-medium ${cfg.bg} ${cfg.text}`}>
      <Icon size={10} />
      {cfg.label}
    </span>
  )
}

function ProviderBadge({ provider }: { provider: string }) {
  const p = PROVIDERS.find(x => x.id === provider)
  return (
    <span className={`inline-flex items-center gap-1 px-2 py-0.5 rounded-md border text-xs font-medium ${providerBadge[provider] ?? 'bg-surface-2 text-text-secondary border-border'}`}>
      {p?.icon} {p?.label ?? provider}
    </span>
  )
}

function RawDataDrawer({ data }: { data: Record<string, unknown> }) {
  const [open, setOpen] = useState(false)
  return (
    <div>
      <button
        onClick={() => setOpen(v => !v)}
        className="text-xs text-text-muted hover:text-text-primary flex items-center gap-1 mt-1 transition-colors"
      >
        {open ? <ChevronUp size={12} /> : <ChevronDown size={12} />}
        {open ? 'Hide raw data' : 'Show raw data'}
      </button>
      {open && (
        <pre className="mt-2 p-3 rounded font-mono text-[11px] leading-relaxed overflow-x-auto max-h-64"
          style={{ background: '#14161B', color: '#B8BCC4', border: '1px solid #2A2D35' }}>
          {JSON.stringify(data, null, 2)}
        </pre>
      )}
    </div>
  )
}

// ─── main page ────────────────────────────────────────────────────────────

export default function IntelligencePage() {
  const [tab, setTab] = useState<'results' | 'monitors' | 'enrich'>('results')

  // results state
  const [results, setResults] = useState<IntelResult[]>([])
  const [resultTotal, setResultTotal] = useState(0)
  const [resultFilter, setResultFilter] = useState({ target: '', provider: '' })
  const [resultLoading, setResultLoading] = useState(false)

  // monitors state
  const [monitors, setMonitors] = useState<MonitorJob[]>([])
  const [monitorLoading, setMonitorLoading] = useState(false)
  const [showCreateMonitor, setShowCreateMonitor] = useState(false)
  const [monitorForm, setMonitorForm] = useState({
    target: '',
    target_type: 'domain' as 'host' | 'domain',
    providers: ['shodan', 'censys', 'securitytrails', 'historical_dns'],
    cadence: 'daily',
    notes: '',
  })

  // enrich state
  const [enrichTarget, setEnrichTarget] = useState('')
  const [enrichType, setEnrichType] = useState<'host' | 'domain'>('domain')
  const [enrichLoading, setEnrichLoading] = useState(false)
  const [enrichResults, setEnrichResults] = useState<IntelResult[]>([])
  const [enrichError, setEnrichError] = useState('')

  const loadResults = useCallback(async () => {
    setResultLoading(true)
    try {
      const resp = await intelligenceApi.listResults({
        target: resultFilter.target || undefined,
        provider: resultFilter.provider || undefined,
        limit: 50,
      })
      setResults(resp.data.results ?? [])
      setResultTotal(resp.data.total ?? 0)
    } catch {
      // silently fail — API keys may not be configured
    } finally {
      setResultLoading(false)
    }
  }, [resultFilter])

  const loadMonitors = useCallback(async () => {
    setMonitorLoading(true)
    try {
      const resp = await intelligenceApi.listMonitors()
      setMonitors(resp.data.jobs ?? [])
    } catch {
      // ignore
    } finally {
      setMonitorLoading(false)
    }
  }, [])

  useEffect(() => { loadResults() }, [loadResults])
  useEffect(() => { loadMonitors() }, [loadMonitors])

  async function handleEnrich() {
    if (!enrichTarget.trim()) return
    setEnrichLoading(true)
    setEnrichError('')
    setEnrichResults([])
    try {
      const fn = enrichType === 'host'
        ? intelligenceApi.enrichHost(enrichTarget.trim())
        : intelligenceApi.enrichDomain(enrichTarget.trim())
      const resp = await fn
      setEnrichResults(resp.data.results ?? [])
      // Also refresh results list
      loadResults()
    } catch (e: unknown) {
      const err = e as { response?: { data?: { error?: string } } }
      setEnrichError(err?.response?.data?.error ?? 'Enrichment failed. Check that API keys are configured.')
    } finally {
      setEnrichLoading(false)
    }
  }

  async function handleCreateMonitor() {
    try {
      await intelligenceApi.createMonitor(monitorForm)
      setShowCreateMonitor(false)
      setMonitorForm({ target: '', target_type: 'domain', providers: ['shodan', 'censys', 'securitytrails', 'historical_dns'], cadence: 'daily', notes: '' })
      loadMonitors()
    } catch {
      // ignore
    }
  }

  async function handleToggleMonitor(id: string, enabled: boolean) {
    try {
      await intelligenceApi.toggleMonitor(id, !enabled)
      loadMonitors()
    } catch {
      toast.error('Failed to save monitor')
    }
  }

  async function handleDeleteMonitor(id: string) {
    if (!confirm('Delete this monitoring job?')) return
    try {
      await intelligenceApi.deleteMonitor(id)
      loadMonitors()
    } catch {
      toast.error('Failed to delete monitor')
    }
  }

  function toggleMonitorProvider(p: string) {
    setMonitorForm(f => ({
      ...f,
      providers: f.providers.includes(p)
        ? f.providers.filter(x => x !== p)
        : [...f.providers, p],
    }))
  }

  // ── provider stats (for header)
  const providerCounts = results.reduce<Record<string, number>>((acc, r) => {
    acc[r.provider] = (acc[r.provider] ?? 0) + 1
    return acc
  }, {})

  return (
    <div className="p-6 space-y-6">
      {/* Header */}
      <div>
        <h1 className="text-2xl font-bold text-text-primary flex items-center gap-2">
          <Database size={22} className="text-primary" />
          Threat Intelligence
        </h1>
        <p className="text-text-muted text-sm mt-1">
          Shodan · Censys · SecurityTrails · Historical DNS · Continuous Monitoring
        </p>
      </div>

      {/* Provider stat pills */}
      <div className="flex flex-wrap gap-3">
        {PROVIDERS.map(p => (
          <div key={p.id} className="flex items-center gap-2 px-3 py-2 rounded-lg bg-surface border border-border text-sm">
            <span>{p.icon}</span>
            <span className={`font-medium ${p.color}`}>{p.label}</span>
            <span className="text-text-muted">·</span>
            <span className="text-text-primary font-semibold">{providerCounts[p.id] ?? 0}</span>
            <span className="text-text-muted text-xs">results</span>
          </div>
        ))}
        <div className="flex items-center gap-2 px-3 py-2 rounded-lg bg-surface border border-border text-sm">
          <Activity size={14} className="text-primary" />
          <span className="text-text-muted">Active Monitors:</span>
          <span className="text-text-primary font-semibold">{monitors.filter(m => m.enabled).length}</span>
        </div>
      </div>

      {/* Tab bar */}
      <div className="flex gap-1 border-b border-border">
        {([
          { id: 'results',  label: 'Intel Results',          icon: Database },
          { id: 'enrich',   label: 'On-Demand Enrichment',   icon: Search },
          { id: 'monitors', label: 'Continuous Monitoring',  icon: Activity },
        ] as const).map(t => (
          <button
            key={t.id}
            onClick={() => setTab(t.id)}
            className={`flex items-center gap-2 px-4 py-2.5 text-sm font-medium border-b-2 transition-colors ${
              tab === t.id
                ? 'border-primary text-primary'
                : 'border-transparent text-text-muted hover:text-text-primary'
            }`}
          >
            <t.icon size={14} />
            {t.label}
          </button>
        ))}
      </div>

      {/* ── RESULTS TAB ── */}
      {tab === 'results' && (
        <div className="space-y-4">
          {/* Filters */}
          <div className="flex flex-wrap gap-3">
            <div className="relative flex-1 min-w-[200px]">
              <Search size={14} className="absolute left-3 top-1/2 -translate-y-1/2 text-text-muted" />
              <input
                className="w-full pl-9 pr-3 py-2 rounded-lg bg-surface border border-border text-sm text-text-primary placeholder-text-muted focus:outline-none focus:border-primary"
                placeholder="Filter by IP or domain…"
                value={resultFilter.target}
                onChange={e => setResultFilter(f => ({ ...f, target: e.target.value }))}
              />
            </div>
            <select
              className="px-3 py-2 rounded-lg bg-surface border border-border text-sm text-text-primary focus:outline-none focus:border-primary"
              value={resultFilter.provider}
              onChange={e => setResultFilter(f => ({ ...f, provider: e.target.value }))}
            >
              <option value="">All Providers</option>
              {PROVIDERS.map(p => (
                <option key={p.id} value={p.id}>{p.label}</option>
              ))}
            </select>
            <button
              onClick={loadResults}
              className="flex items-center gap-2 px-3 py-2 rounded-lg bg-surface border border-border text-sm text-text-muted hover:text-text-primary transition-colors"
            >
              <RefreshCw size={14} className={resultLoading ? 'animate-spin' : ''} />
              Refresh
            </button>
          </div>

          <p className="text-xs text-text-muted">{resultTotal} total results</p>

          {/* Results list */}
          {resultLoading ? (
            <div className="flex items-center justify-center py-12 text-text-muted">
              <RefreshCw size={20} className="animate-spin mr-2" />
              Loading…
            </div>
          ) : results.length === 0 ? (
            <div className="py-16 text-center text-text-muted">
              <Database size={40} className="mx-auto mb-3 opacity-30" />
              <p className="font-medium">No intelligence results yet.</p>
              <p className="text-sm mt-1">Run an on-demand enrichment or set up a monitoring job to populate this view.</p>
            </div>
          ) : (
            <div className="space-y-3">
              {results.map(r => {
                const sev = SEVERITY_CONFIG[r.severity] ?? SEVERITY_CONFIG.info
                return (
                  <div key={r.id} className={`rounded-lg border p-4 ${sev.bg} border-border`}>
                    <div className="flex flex-wrap items-start gap-2 justify-between">
                      <div className="flex items-center gap-2 flex-wrap">
                        <ProviderBadge provider={r.provider} />
                        <SeverityBadge severity={r.severity} />
                        {r.target_type === 'host'
                          ? <span className="flex items-center gap-1 text-xs text-text-muted"><Server size={10} /> Host</span>
                          : <span className="flex items-center gap-1 text-xs text-text-muted"><Globe size={10} /> Domain</span>
                        }
                      </div>
                      <span className="text-xs text-text-muted flex items-center gap-1">
                        <Clock size={10} />
                        {relativeTime(r.fetched_at)}
                      </span>
                    </div>
                    <p className="mt-2 text-sm font-semibold text-text-primary">{r.target}</p>
                    <p className="text-sm text-text-muted mt-1 leading-relaxed">{r.summary}</p>
                    {r.tags && r.tags.length > 0 && (
                      <div className="flex flex-wrap gap-1 mt-2">
                        {r.tags.map(t => (
                          <span key={t} className="px-1.5 py-0.5 rounded-sm bg-surface-2 text-xs text-text-muted border border-border">{t}</span>
                        ))}
                      </div>
                    )}
                    {r.raw_data && <RawDataDrawer data={r.raw_data} />}
                  </div>
                )
              })}
            </div>
          )}
        </div>
      )}

      {/* ── ENRICH TAB ── */}
      {tab === 'enrich' && (
        <div className="space-y-6 max-w-2xl">
          <div className="rounded-lg bg-surface border border-border p-5 space-y-4">
            <h2 className="font-semibold text-text-primary flex items-center gap-2">
              <Search size={16} className="text-primary" />
              On-Demand Enrichment
            </h2>
            <p className="text-sm text-text-muted">
              Query Shodan + Censys for a host IP, or SecurityTrails + Historical DNS for a domain.
              Results are stored and appear in the Intel Results tab.
            </p>

            <div className="flex gap-2">
              <button
                onClick={() => setEnrichType('domain')}
                className={`flex items-center gap-2 px-3 py-2 rounded-lg border text-sm transition-colors ${enrichType === 'domain' ? 'border-primary bg-primary/10 text-primary' : 'border-border text-text-muted hover:text-text-primary'}`}
              >
                <Globe size={14} /> Domain
              </button>
              <button
                onClick={() => setEnrichType('host')}
                className={`flex items-center gap-2 px-3 py-2 rounded-lg border text-sm transition-colors ${enrichType === 'host' ? 'border-primary bg-primary/10 text-primary' : 'border-border text-text-muted hover:text-text-primary'}`}
              >
                <Server size={14} /> Host / IP
              </button>
            </div>

            <div className="flex gap-2">
              <input
                className="flex-1 px-3 py-2.5 rounded-lg bg-background border border-border text-sm text-text-primary placeholder-text-muted focus:outline-none focus:border-primary"
                placeholder={enrichType === 'host' ? 'e.g. 192.168.1.1' : 'e.g. example.com'}
                value={enrichTarget}
                onChange={e => setEnrichTarget(e.target.value)}
                onKeyDown={e => e.key === 'Enter' && handleEnrich()}
              />
              <button
                onClick={handleEnrich}
                disabled={enrichLoading || !enrichTarget.trim()}
                className="flex items-center gap-2 px-4 py-2.5 rounded-lg bg-primary text-white text-sm font-medium hover:bg-primary/90 disabled:opacity-50 transition-colors"
              >
                {enrichLoading ? <RefreshCw size={14} className="animate-spin" /> : <Search size={14} />}
                Enrich
              </button>
            </div>

            {/* Providers that will be queried */}
            <div className="flex flex-wrap gap-2 pt-1">
              <span className="text-xs text-text-muted">Will query:</span>
              {(enrichType === 'host' ? ['shodan', 'censys'] : ['securitytrails', 'historical_dns']).map(p => (
                <ProviderBadge key={p} provider={p} />
              ))}
            </div>
          </div>

          {enrichError && (
            <div className="rounded-lg bg-accent-red/10 border border-accent-red/25 p-4 text-sm text-accent-red flex items-start gap-2">
              <AlertTriangle size={16} className="mt-0.5 shrink-0" />
              {enrichError}
            </div>
          )}

          {enrichResults.length > 0 && (
            <div className="space-y-3">
              <h3 className="font-medium text-text-primary flex items-center gap-2">
                <CheckCircle size={16} className="text-accent-green" />
                {enrichResults.length} result{enrichResults.length !== 1 ? 's' : ''} returned
              </h3>
              {enrichResults.map(r => (
                <div key={r.id} className="rounded-lg bg-surface border border-border p-4">
                  <div className="flex items-center gap-2 flex-wrap">
                    <ProviderBadge provider={r.provider} />
                    <SeverityBadge severity={r.severity} />
                  </div>
                  <p className="mt-2 text-sm font-semibold text-text-primary">{r.target}</p>
                  <p className="text-sm text-text-muted mt-1">{r.summary}</p>
                  {r.raw_data && <RawDataDrawer data={r.raw_data} />}
                </div>
              ))}
            </div>
          )}
        </div>
      )}

      {/* ── MONITORS TAB ── */}
      {tab === 'monitors' && (
        <div className="space-y-4">
          <div className="flex items-center justify-between">
            <p className="text-sm text-text-muted">
              Continuously re-enriches targets on a schedule and surfaces new findings automatically.
            </p>
            <button
              onClick={() => setShowCreateMonitor(v => !v)}
              className="flex items-center gap-2 px-4 py-2 rounded-lg bg-primary text-white text-sm font-medium hover:bg-primary/90 transition-colors"
            >
              <PlusCircle size={15} />
              New Monitor
            </button>
          </div>

          {/* Create form */}
          {showCreateMonitor && (
            <div className="rounded-lg bg-surface border border-border p-5 space-y-4">
              <h3 className="font-semibold text-text-primary">New Monitoring Job</h3>

              <div className="grid grid-cols-1 sm:grid-cols-2 gap-4">
                <div>
                  <label className="block text-xs text-text-muted mb-1">Target</label>
                  <input
                    className="w-full px-3 py-2 rounded-lg bg-background border border-border text-sm text-text-primary placeholder-text-muted focus:outline-none focus:border-primary"
                    placeholder="e.g. example.com or 1.2.3.4"
                    value={monitorForm.target}
                    onChange={e => setMonitorForm(f => ({ ...f, target: e.target.value }))}
                  />
                </div>
                <div>
                  <label className="block text-xs text-text-muted mb-1">Target Type</label>
                  <select
                    className="w-full px-3 py-2 rounded-lg bg-background border border-border text-sm text-text-primary focus:outline-none focus:border-primary"
                    value={monitorForm.target_type}
                    onChange={e => setMonitorForm(f => ({ ...f, target_type: e.target.value as 'host' | 'domain' }))}
                  >
                    <option value="domain">Domain</option>
                    <option value="host">Host / IP</option>
                  </select>
                </div>
                <div>
                  <label className="block text-xs text-text-muted mb-1">Cadence</label>
                  <select
                    className="w-full px-3 py-2 rounded-lg bg-background border border-border text-sm text-text-primary focus:outline-none focus:border-primary"
                    value={monitorForm.cadence}
                    onChange={e => setMonitorForm(f => ({ ...f, cadence: e.target.value }))}
                  >
                    <option value="hourly">Hourly</option>
                    <option value="daily">Daily</option>
                    <option value="weekly">Weekly</option>
                  </select>
                </div>
                <div>
                  <label className="block text-xs text-text-muted mb-1">Notes (optional)</label>
                  <input
                    className="w-full px-3 py-2 rounded-lg bg-background border border-border text-sm text-text-primary placeholder-text-muted focus:outline-none focus:border-primary"
                    placeholder="E.g. main customer-facing domain"
                    value={monitorForm.notes}
                    onChange={e => setMonitorForm(f => ({ ...f, notes: e.target.value }))}
                  />
                </div>
              </div>

              <div>
                <label className="block text-xs text-text-muted mb-2">Providers</label>
                <div className="flex flex-wrap gap-2">
                  {PROVIDERS.map(p => (
                    <button
                      key={p.id}
                      onClick={() => toggleMonitorProvider(p.id)}
                      className={`flex items-center gap-1.5 px-3 py-1.5 rounded-lg border text-sm transition-colors ${
                        monitorForm.providers.includes(p.id)
                          ? 'border-primary bg-primary/10 text-primary'
                          : 'border-border text-text-muted hover:text-text-primary'
                      }`}
                    >
                      {p.icon} {p.label}
                    </button>
                  ))}
                </div>
              </div>

              <div className="flex gap-2 pt-2">
                <button
                  onClick={handleCreateMonitor}
                  disabled={!monitorForm.target.trim() || monitorForm.providers.length === 0}
                  className="flex items-center gap-2 px-4 py-2 rounded-lg bg-primary text-white text-sm font-medium hover:bg-primary/90 disabled:opacity-50 transition-colors"
                >
                  <CheckCircle size={14} />
                  Create Monitor
                </button>
                <button
                  onClick={() => setShowCreateMonitor(false)}
                  className="px-4 py-2 rounded-lg border border-border text-sm text-text-muted hover:text-text-primary transition-colors"
                >
                  Cancel
                </button>
              </div>
            </div>
          )}

          {/* Monitor list */}
          {monitorLoading ? (
            <div className="flex items-center justify-center py-12 text-text-muted">
              <RefreshCw size={20} className="animate-spin mr-2" />
              Loading…
            </div>
          ) : monitors.length === 0 ? (
            <div className="py-16 text-center text-text-muted">
              <Wifi size={40} className="mx-auto mb-3 opacity-30" />
              <p className="font-medium">No monitoring jobs yet.</p>
              <p className="text-sm mt-1">Create a job to continuously watch domains and hosts for new intel.</p>
            </div>
          ) : (
            <div className="space-y-3">
              {monitors.map(job => (
                <div key={job.id} className={`rounded-lg border p-4 ${job.enabled ? 'bg-surface border-border' : 'bg-surface-2/60 border-border opacity-60'}`}>
                  <div className="flex items-start justify-between gap-3">
                    <div className="space-y-1 flex-1 min-w-0">
                      <div className="flex items-center gap-2 flex-wrap">
                        {job.target_type === 'host'
                          ? <Server size={14} className="text-text-muted shrink-0" />
                          : <Globe size={14} className="text-text-muted shrink-0" />}
                        <span className="font-semibold text-text-primary truncate">{job.target}</span>
                        <span className={`text-xs px-2 py-0.5 rounded-full font-medium ${job.enabled ? 'bg-accent-green/10 text-accent-green' : 'bg-surface-2 text-text-muted'}`}>
                          {job.enabled ? 'Active' : 'Paused'}
                        </span>
                        <span className="text-xs text-text-muted capitalize">{job.cadence}</span>
                      </div>
                      <div className="flex flex-wrap gap-1 mt-1">
                        {job.providers.map(p => <ProviderBadge key={p} provider={p} />)}
                      </div>
                      <div className="flex items-center gap-4 text-xs text-text-muted mt-1">
                        <span className="flex items-center gap-1"><Eye size={10} /> {job.run_count} runs</span>
                        <span className="flex items-center gap-1"><Clock size={10} /> Last: {relativeTime(job.last_run_at)}</span>
                        <span className="flex items-center gap-1"><Shield size={10} /> Next: {relativeTime(job.next_run_at)}</span>
                      </div>
                      {job.notes && <p className="text-xs text-text-muted italic mt-1">{job.notes}</p>}
                    </div>
                    <div className="flex items-center gap-2 shrink-0">
                      <button
                        onClick={() => handleToggleMonitor(job.id, job.enabled)}
                        className="text-text-muted hover:text-primary transition-colors"
                        title={job.enabled ? 'Pause' : 'Enable'}
                      >
                        {job.enabled ? <ToggleRight size={22} className="text-accent-green" /> : <ToggleLeft size={22} />}
                      </button>
                      <button
                        onClick={() => handleDeleteMonitor(job.id)}
                        className="text-text-muted hover:text-accent-red transition-colors"
                        title="Delete"
                      >
                        <Trash2 size={16} />
                      </button>
                    </div>
                  </div>
                </div>
              ))}
            </div>
          )}
        </div>
      )}
    </div>
  )
}
