import { useEffect, useState, useCallback, useRef } from 'react'
import { useNavigate } from 'react-router-dom'
import {
  Wrench, CheckCircle, XCircle, AlertCircle, RefreshCw,
  ChevronDown, ChevronRight,
  Network, Globe, Shield, Search, Server, Bug, Wifi, Users, MapPin,
  Download, History, Settings2, Terminal, Lock, KeyRound, Trash2, Plus, X
} from 'lucide-react'
import api from '@/utils/api'
import { formatDistanceToNow } from 'date-fns'
import clsx from 'clsx'
import toast from 'react-hot-toast'
import { isAxiosError } from 'axios'


interface Tool {
  name: string
  category: string
  description: string
  binary_path: string
  version: string
  status: 'installed' | 'missing' | 'wrong_version'
  enabled: boolean
  max_concurrent: number
  min_interval_seconds: number
  last_run: string | null
  last_run_ok: boolean
}

interface CategoryGroup {
  category: string
  tools: Tool[]
}

interface ToolRunRow {
  id: string
  scan_id: string
  tool_name: string
  result_count: number
  duration_ms: number
  status: string
  truncated: boolean
  created_at: string
}


const toolsApi = {
  list:       () => api.get<{ data: CategoryGroup[]; total: number }>('/tools'),
  get:        (name: string) => api.get<Tool>(`/tools/${name}`),
  verify:     (name: string) => api.post<{ message: string; tool: Tool }>(`/tools/${name}/verify`),
  enable:     (name: string) => api.post<{ message: string; tool: Tool }>(`/tools/${name}/enable`),
  disable:    (name: string) => api.post<{ message: string; tool: Tool }>(`/tools/${name}/disable`),
  verifyAll:  () => api.post<{ message: string; installed: number; missing: number; total: number }>('/tools/verify-all'),
  runs:       (name: string) => api.get<{ data: ToolRunRow[]; tool: string }>(`/tools/${name}/runs`),
  install:    () => api.post<{ message: string }>('/tools/install'),
  setRateLimits: (name: string, maxConcurrent: number, minIntervalSeconds: number) =>
    api.patch<{ message: string; tool: Tool }>(`/tools/${name}/rate-limits`, { max_concurrent: maxConcurrent, min_interval_seconds: minIntervalSeconds }),
}


interface ToolCredential {
  id: string
  tool_name: string
  label: string
  username: string
  domain: string
  has_secret: boolean
  created_at: string
  updated_at: string
}

interface NewCredentialForm {
  tool_name: string
  label: string
  username: string
  password: string
  domain: string
  nt_hash: string
}

const credentialsApi = {
  list: () => api.get<{ credentials: ToolCredential[] }>('/tool-credentials'),
  create: (body: NewCredentialForm) => api.post<ToolCredential>('/tool-credentials', body),
  delete: (id: string) => api.delete<{ deleted: boolean }>(`/tool-credentials/${id}`),
}

const CREDENTIAL_TOOLS = ['smbclient', 'enum4linux-ng', 'crackmapexec'] as const


const categoryIcon: Record<string, React.ElementType> = {
  subdomain:     Network,
  dns:           Globe,
  network:       Server,
  web:           Globe,
  content:       Search,
  vulnerability: Bug,
  waf:           Shield,
  smb:           Users,
  origin_ip:     MapPin,
  injection:     Bug,
  secrets:       KeyRound,
  fingerprint:   Search,
  js_analysis:   Globe,
  auth:          Lock,
  params:        Settings2,
  takeover:      AlertCircle,
  screenshot:    Wifi,
  cloud:         Server,
}

const categoryLabel: Record<string, string> = {
  subdomain:     'Subdomain Enumeration',
  dns:           'DNS Analysis',
  network:       'Network / Port Scanning',
  web:           'Web Probing & Crawling',
  content:       'Content Discovery',
  vulnerability: 'Vulnerability Scanning',
  waf:           'WAF Detection',
  smb:           'SMB Enumeration',
  origin_ip:     'Origin IP Discovery',
  injection:     'Injection Testing',
  secrets:       'Secret & Credential Scanning',
  fingerprint:   'Technology Fingerprinting',
  js_analysis:   'JavaScript Analysis',
  auth:          'Authentication Testing',
  params:        'Parameter Discovery',
  takeover:      'Subdomain Takeover',
  screenshot:    'Screenshot Capture',
  cloud:         'Cloud Enumeration',
}


function StatusBadge({ status }: { status: Tool['status'] }) {
  if (status === 'installed') {
    return (
      <span className="inline-flex items-center gap-1 px-2 py-0.5 rounded-md text-xs font-medium bg-accent-green/10 text-accent-green border border-accent-green/20">
        <CheckCircle className="w-3 h-3" /> Installed
      </span>
    )
  }
  if (status === 'wrong_version') {
    return (
      <span className="inline-flex items-center gap-1 px-2 py-0.5 rounded-md text-xs font-medium bg-accent-orange/10 text-accent-orange border border-accent-orange/20">
        <AlertCircle className="w-3 h-3" /> Wrong Version
      </span>
    )
  }
  return (
    <span className="inline-flex items-center gap-1 px-2 py-0.5 rounded-md text-xs font-medium bg-accent-red/10 text-accent-red border border-accent-red/20">
      <XCircle className="w-3 h-3" /> Missing
    </span>
  )
}


function RateLimitEditor({ tool, onSave }: { tool: Tool; onSave: (name: string, max: number, interval: number) => Promise<void> }) {
  const [open, setOpen]         = useState(false)
  const [maxC, setMaxC]         = useState(String(tool.max_concurrent))
  const [minI, setMinI]         = useState(String(tool.min_interval_seconds))
  const [saving, setSaving]     = useState(false)

  const handleSave = async () => {
    setSaving(true)
    try {
      await onSave(tool.name, Number(maxC), Number(minI))
      setOpen(false)
    } finally { setSaving(false) }
  }

  return (
    <div className="relative">
      <button
        onClick={() => setOpen(o => !o)}
        className="inline-flex items-center gap-1 px-2 py-1 rounded-md text-xs font-medium bg-surface-2 border border-border text-text-secondary hover:text-text-primary transition-colors"
        title="Edit rate limits"
      >
        <Settings2 className="w-3 h-3" />
        Limits
      </button>
      {open && (
        <div className="absolute right-0 top-full mt-1 w-56 z-20 bg-surface-1 border border-border rounded-lg shadow-xl p-3 space-y-2">
          <div className="text-xs font-medium text-text-primary mb-1">{tool.name} rate limits</div>
          <label className="block text-xs text-text-muted">
            Max concurrent (0 = unlimited)
            <input
              type="number" min={0}
              value={maxC}
              onChange={e => setMaxC(e.target.value)}
              className="mt-0.5 w-full bg-surface-2 border border-border rounded-md px-2 py-1 text-xs text-text-primary"
            />
          </label>
          <label className="block text-xs text-text-muted">
            Min interval between runs (seconds)
            <input
              type="number" min={0}
              value={minI}
              onChange={e => setMinI(e.target.value)}
              className="mt-0.5 w-full bg-surface-2 border border-border rounded-md px-2 py-1 text-xs text-text-primary"
            />
          </label>
          <button
            onClick={handleSave}
            disabled={saving}
            className="btn-primary w-full text-xs py-1"
          >
            {saving ? 'Saving…' : 'Save'}
          </button>
        </div>
      )}
    </div>
  )
}


function ToolRow({
  tool,
  onVerify,
  onToggle,
  onSetRateLimits,
}: {
  tool: Tool
  onVerify: (name: string) => void
  onToggle: (name: string, enabled: boolean) => void
  onSetRateLimits: (name: string, max: number, interval: number) => Promise<void>
}) {
  const navigate         = useNavigate()
  const [verifying, setVerifying] = useState(false)
  const [toggling,  setToggling]  = useState(false)

  const handleVerify = async () => {
    setVerifying(true)
    try { await onVerify(tool.name) } finally { setVerifying(false) }
  }

  const handleToggle = async () => {
    setToggling(true)
    try { await onToggle(tool.name, !tool.enabled) } finally { setToggling(false) }
  }

  return (
    <tr className={clsx(!tool.enabled && 'opacity-50')}>
      {/* Name + description */}
      <td>
        <div className="flex flex-col">
          <span className="font-mono text-sm font-medium text-text-primary">{tool.name}</span>
          <span className="text-xs text-text-muted mt-0.5">{tool.description}</span>
        </div>
      </td>

      {/* Version */}
      <td>
        {tool.version
          ? <span className="font-mono text-xs text-text-secondary">{tool.version.slice(0, 40)}</span>
          : <span className="text-xs text-text-muted">—</span>
        }
      </td>

      {/* Status */}
      <td><StatusBadge status={tool.status} /></td>

      {/* Last Run */}
      <td>
        {tool.last_run ? (
          <div className="flex flex-col">
            <span className="text-xs text-text-secondary">
              {formatDistanceToNow(new Date(tool.last_run), { addSuffix: true })}
            </span>
            <span className={clsx('text-xs', tool.last_run_ok ? 'text-accent-green' : 'text-accent-red')}>
              {tool.last_run_ok ? 'success' : 'failed'}
            </span>
          </div>
        ) : (
          <span className="text-xs text-text-muted">Never</span>
        )}
      </td>

      {/* Actions */}
      <td>
        <div className="flex items-center gap-1.5 flex-wrap">
          <button
            onClick={handleVerify}
            disabled={verifying}
            className="inline-flex items-center gap-1 px-2 py-1 rounded-md text-xs font-medium bg-surface-2 border border-border text-text-secondary hover:text-text-primary hover:border-accent-cyan/40 transition-colors disabled:opacity-50"
            title="Re-check installation"
          >
            <RefreshCw className={clsx('w-3 h-3', verifying && 'animate-spin')} />
            Verify
          </button>

          <button
            onClick={handleToggle}
            disabled={toggling}
            className={clsx(
              'inline-flex items-center gap-1 px-2 py-1 rounded-md text-xs font-medium border transition-colors disabled:opacity-50',
              tool.enabled
                ? 'bg-accent-cyan/10 border-accent-cyan/30 text-accent-cyan hover:bg-accent-cyan/20'
                : 'bg-surface-2 border-border text-text-muted hover:text-text-secondary'
            )}
          >
            {tool.enabled ? 'Enabled' : 'Disabled'}
          </button>

          {/* history button */}
          <button
            onClick={() => navigate(`/tools/${tool.name}/history`)}
            className="inline-flex items-center gap-1 px-2 py-1 rounded-md text-xs font-medium bg-surface-2 border border-border text-text-secondary hover:text-text-primary transition-colors"
            title="View run history"
          >
            <History className="w-3 h-3" />
            History
          </button>

          {/* rate limits */}
          <RateLimitEditor tool={tool} onSave={onSetRateLimits} />
        </div>
      </td>
    </tr>
  )
}


function CategorySection({
  group, onVerify, onToggle, onSetRateLimits,
}: {
  group: CategoryGroup
  onVerify: (name: string) => void
  onToggle: (name: string, enabled: boolean) => void
  onSetRateLimits: (name: string, max: number, interval: number) => Promise<void>
}) {
  const [open, setOpen] = useState(true)
  const Icon = categoryIcon[group.category] ?? Wifi
  const installed = group.tools.filter(t => t.status === 'installed').length
  const enabled   = group.tools.filter(t => t.enabled).length

  return (
    <div className="card overflow-hidden">
      <button
        onClick={() => setOpen(o => !o)}
        className="w-full flex items-center gap-3 px-4 py-3 hover:bg-surface-2/50 transition-colors"
      >
        <Icon className="w-4 h-4 text-accent-cyan flex-shrink-0" />
        <span className="text-sm font-medium text-text-primary flex-1 text-left">
          {categoryLabel[group.category] ?? group.category}
        </span>
        <div className="flex items-center gap-2 mr-2">
          <span className="badge-gray ml-1">{group.tools.length} tools</span>
          <span className={clsx(
            'text-xs px-1.5 py-0.5 rounded-md',
            installed > 0 ? 'text-accent-green bg-accent-green/10' : 'text-accent-red bg-accent-red/10'
          )}>
            {installed}/{group.tools.length} installed
          </span>
          <span className="text-xs text-text-muted">{enabled} enabled</span>
        </div>
        {open
          ? <ChevronDown  className="w-4 h-4 text-text-muted" />
          : <ChevronRight className="w-4 h-4 text-text-muted" />
        }
      </button>

      {open && (
        <div className="table-container">
          <table className="table">
            <thead>
              <tr>
                <th>Tool</th>
                <th>Version</th>
                <th>Status</th>
                <th>Last Run</th>
                <th>Actions</th>
              </tr>
            </thead>
            <tbody>
              {group.tools.map(t => (
                <ToolRow
                  key={t.name}
                  tool={t}
                  onVerify={onVerify}
                  onToggle={onToggle}
                  onSetRateLimits={onSetRateLimits}
                />
              ))}
            </tbody>
          </table>
        </div>
      )}
    </div>
  )
}


function SummaryBar({ groups }: { groups: CategoryGroup[] }) {
  const allTools  = groups.flatMap(g => g.tools)
  const installed = allTools.filter(t => t.status === 'installed').length
  const missing   = allTools.filter(t => t.status === 'missing').length
  const enabled   = allTools.filter(t => t.enabled).length
  const total     = allTools.length

  return (
    <div className="grid grid-cols-2 sm:grid-cols-4 gap-3">
      {[
        { label: 'Total',     value: total,     color: 'text-text-primary' },
        { label: 'Installed', value: installed,  color: 'text-accent-green'   },
        { label: 'Missing',   value: missing,    color: missing > 0 ? 'text-accent-red' : 'text-text-muted' },
        { label: 'Enabled',   value: enabled,    color: 'text-accent-cyan' },
      ].map(({ label, value, color }) => (
        <div key={label} className="card p-4 text-center">
          <div className={clsx('text-2xl font-bold', color)}>{value}</div>
          <div className="text-xs text-text-muted mt-1">{label}</div>
        </div>
      ))}
    </div>
  )
}


function InstallPanel() {
  const [running, setRunning] = useState(false)
  const [lines,   setLines]   = useState<string[]>([])
  const [done,    setDone]    = useState(false)
  const logsRef               = useRef<HTMLDivElement>(null)
  const wsRef                 = useRef<WebSocket | null>(null)

  // Subscribe to WebSocket install_log events
  useEffect(() => {
    const proto = window.location.protocol === 'https:' ? 'wss' : 'ws'
    const token = localStorage.getItem('rayyan_token') ?? ''
    let cancelled = false
    // Use a one-time ticket instead of embedding the JWT in the URL.
    void fetch('/api/v1/ws/ticket', {
      method: 'POST',
      headers: { 'Authorization': `Bearer ${token}`, 'Content-Type': 'application/json' },
    })
      .then(r => r.ok ? r.json() : Promise.reject(new Error('ticket fetch failed')))
      .then((d: { ticket: string }) => {
        if (cancelled) return
        const ws = new WebSocket(`${proto}://${window.location.host}/ws?ticket=${encodeURIComponent(d.ticket)}`)
        wsRef.current = ws
        ws.onmessage = (ev) => {
          try {
            const msg = JSON.parse(ev.data as string)
            if (msg.type === 'install_log' && msg.line) {
              setLines(prev => [...prev, msg.line])
              // Auto-scroll
              setTimeout(() => {
                logsRef.current?.scrollTo({ top: logsRef.current.scrollHeight, behavior: 'smooth' })
              }, 0)
            }
            if (msg.type === 'install_done') {
              setRunning(false)
              setDone(true)
            }
          } catch (err) {
            console.warn('Ignoring malformed install WebSocket message:', err)
          }
        }
      })
      .catch((err) => {
        console.warn('Install log WebSocket setup failed:', err)
      })

    return () => {
      cancelled = true
      wsRef.current?.close()
      wsRef.current = null
    }
  }, [])

  const handleInstall = async () => {
    setLines([])
    setDone(false)
    setRunning(true)
    try {
      await toolsApi.install()
    } catch {
      toast.error('Failed to start install script')
      setRunning(false)
    }
  }

  return (
    <div className="card p-4 space-y-3">
      <div className="flex items-center justify-between">
        <div className="flex items-center gap-2">
          <Download className="w-4 h-4 text-accent-cyan" />
          <span className="text-sm font-medium text-text-primary">Install Tools</span>
        </div>
        <button
          onClick={handleInstall}
          disabled={running}
          className="btn-primary inline-flex items-center gap-1.5 text-sm"
        >
          <Download className={clsx('w-3.5 h-3.5', running && 'animate-bounce')} />
          {running ? 'Installing…' : 'Run install-tools.sh'}
        </button>
      </div>
      <p className="text-xs text-text-muted">
        Runs <code className="text-accent-cyan">scripts/install-tools.sh</code> as a subprocess.
        Live output appears below. Re-verifies registry on completion.
      </p>

      {(lines.length > 0 || running) && (
        <div
          ref={logsRef}
          className="rounded p-3 h-48 overflow-y-auto font-mono text-[11px] leading-relaxed space-y-0.5"
            style={{ background: '#14161B', color: '#8FD19E', border: '1px solid #2A2D35' }}
        >
          {lines.map((l, i) => (
            <div key={i}>{l}</div>
          ))}
          {running && (
            <div className="flex items-center gap-1 text-accent-cyan">
              <span className="animate-pulse">▮</span>
            </div>
          )}
          {done && (
            <div className="text-[#8FD19E] font-bold mt-1">✓ Installation complete</div>
          )}
        </div>
      )}
    </div>
  )
}


function Loading() {
  return (
    <div className="flex justify-center py-12">
      <div className="w-5 h-5 border-2 border-accent-cyan/30 border-t-accent-cyan rounded-full animate-spin" />
    </div>
  )
}


// Manage stored, AES-256-GCM encrypted credentials for SMB/AD-capable tools
// (smbclient, enum4linux-ng, crackmapexec). Returns a friendly message if the
// server has not configured RAYYAN_AUTH_CREDENTIALKEY (503).

const emptyCredForm: NewCredentialForm = {
  tool_name: CREDENTIAL_TOOLS[0],
  label: '',
  username: '',
  password: '',
  domain: '',
  nt_hash: '',
}

function CredentialsPanel() {
  const [open, setOpen] = useState(false)
  const [creds, setCreds] = useState<ToolCredential[]>([])
  const [loading, setLoading] = useState(false)
  const [disabled, setDisabled] = useState(false)
  const [showForm, setShowForm] = useState(false)
  const [form, setForm] = useState<NewCredentialForm>(emptyCredForm)
  const [saving, setSaving] = useState(false)

  const load = useCallback(async () => {
    setLoading(true)
    try {
      const { data } = await credentialsApi.list()
      setCreds(data.credentials ?? [])
      setDisabled(false)
    } catch (err) {
      if (isAxiosError(err) && err.response?.status === 503) {
        setDisabled(true)
      } else {
        toast.error('Failed to load tool credentials')
      }
    } finally {
      setLoading(false)
    }
  }, [])

  useEffect(() => { if (open) load() }, [open, load])

  const handleCreate = useCallback(async () => {
    if (!form.username.trim()) {
      toast.error('Username is required')
      return
    }
    setSaving(true)
    try {
      await credentialsApi.create(form)
      toast.success('Credential saved')
      setForm(emptyCredForm)
      setShowForm(false)
      load()
    } catch (err) {
      const message = isAxiosError<{ error: string }>(err)
        ? err.response?.data?.error
        : undefined
      toast.error(message ?? 'Failed to save credential')
    } finally {
      setSaving(false)
    }
  }, [form, load])

  const handleDelete = useCallback(async (id: string) => {
    try {
      await credentialsApi.delete(id)
      setCreds(prev => prev.filter(c => c.id !== id))
      toast.success('Credential deleted')
    } catch {
      toast.error('Failed to delete credential')
    }
  }, [])

  return (
    <div className="card">
      <button
        onClick={() => setOpen(o => !o)}
        className="w-full flex items-center gap-2 px-4 py-3 hover:bg-surface-2/50 transition-colors"
      >
        <Lock className="w-4 h-4 text-accent-cyan flex-shrink-0" />
        <span className="text-sm font-medium text-text-primary flex-1 text-left">
          Tool Credentials
        </span>
        <span className="text-xs text-text-muted">SMB / AD auth for smbclient, enum4linux-ng, crackmapexec</span>
        {open
          ? <ChevronDown className="w-4 h-4 text-text-muted" />
          : <ChevronRight className="w-4 h-4 text-text-muted" />
        }
      </button>

      {open && (
        <div className="px-4 pb-4 space-y-3">
          {loading ? (
            <div className="text-xs text-text-muted py-2">Loading…</div>
          ) : disabled ? (
            <div className="text-xs text-text-muted py-2">
              Tool credential storage is not configured on the server. Set{' '}
              <code className="font-mono text-text-secondary">RAYYAN_AUTH_CREDENTIALKEY</code>{' '}
              (32-byte AES-256 key, e.g. <code className="font-mono text-text-secondary">openssl rand -hex 32</code>) to enable this feature.
            </div>
          ) : (
            <>
              {creds.length === 0 && !showForm && (
                <div className="text-xs text-text-muted py-1">No stored credentials. Authenticated SMB scans will fall back to null sessions.</div>
              )}

              {creds.length > 0 && (
                <div className="space-y-1.5">
                  {creds.map(c => (
                    <div key={c.id} className="flex items-center gap-3 bg-surface-2 border border-border rounded-lg px-3 py-2">
                      <KeyRound className="w-3.5 h-3.5 text-accent-cyan flex-shrink-0" />
                      <div className="flex flex-col flex-1 min-w-0">
                        <span className="text-xs font-mono text-text-primary">
                          {c.tool_name}
                          {c.domain ? `\\${c.domain}` : ''}{c.username ? `\\${c.username}` : ''}
                        </span>
                        {c.label && <span className="text-xs text-text-muted">{c.label}</span>}
                      </div>
                      <span className="text-xs text-text-muted">{formatDistanceToNow(new Date(c.created_at), { addSuffix: true })}</span>
                      <button
                        onClick={() => handleDelete(c.id)}
                        className="p-1 rounded-md hover:bg-accent-red/10 hover:text-accent-red text-text-muted transition-colors"
                        title="Delete credential"
                      >
                        <Trash2 className="w-3.5 h-3.5" />
                      </button>
                    </div>
                  ))}
                </div>
              )}

              {showForm ? (
                <div className="bg-surface-2 border border-border rounded-lg p-3 space-y-2">
                  <div className="flex items-center justify-between">
                    <span className="text-xs font-medium text-text-primary">New credential</span>
                    <button onClick={() => { setShowForm(false); setForm(emptyCredForm) }} className="text-text-muted hover:text-text-primary">
                      <X className="w-3.5 h-3.5" />
                    </button>
                  </div>
                  <div className="grid grid-cols-2 gap-2">
                    <select
                      value={form.tool_name}
                      onChange={e => setForm(f => ({ ...f, tool_name: e.target.value }))}
                      className="bg-surface border border-border rounded-md px-2 py-1.5 text-xs text-text-primary"
                    >
                      {CREDENTIAL_TOOLS.map(t => <option key={t} value={t}>{t}</option>)}
                    </select>
                    <input
                      value={form.label}
                      onChange={e => setForm(f => ({ ...f, label: e.target.value }))}
                      placeholder="Label (optional)"
                      className="bg-surface border border-border rounded-md px-2 py-1.5 text-xs text-text-primary placeholder-text-muted"
                    />
                    <input
                      value={form.domain}
                      onChange={e => setForm(f => ({ ...f, domain: e.target.value }))}
                      placeholder="Domain (optional, e.g. CORP)"
                      className="bg-surface border border-border rounded-md px-2 py-1.5 text-xs text-text-primary placeholder-text-muted"
                    />
                    <input
                      value={form.username}
                      onChange={e => setForm(f => ({ ...f, username: e.target.value }))}
                      placeholder="Username"
                      className="bg-surface border border-border rounded-md px-2 py-1.5 text-xs text-text-primary placeholder-text-muted"
                    />
                    <input
                      type="password"
                      value={form.password}
                      onChange={e => setForm(f => ({ ...f, password: e.target.value }))}
                      placeholder="Password"
                      className="bg-surface border border-border rounded-md px-2 py-1.5 text-xs text-text-primary placeholder-text-muted"
                    />
                    <input
                      value={form.nt_hash}
                      onChange={e => setForm(f => ({ ...f, nt_hash: e.target.value }))}
                      placeholder="NT hash (optional, for pass-the-hash)"
                      className="bg-surface border border-border rounded-md px-2 py-1.5 text-xs text-text-primary placeholder-text-muted font-mono"
                    />
                  </div>
                  <div className="flex justify-end">
                    <button
                      onClick={handleCreate}
                      disabled={saving}
                      className="btn-primary text-xs px-3 py-1.5 disabled:opacity-50"
                    >
                      {saving ? 'Saving…' : 'Save credential'}
                    </button>
                  </div>
                  <p className="text-xs text-text-muted">
                    Stored encrypted (AES-256-GCM) and never logged. Used for authenticated SMB/AD enumeration during workflow scans.
                  </p>
                </div>
              ) : (
                <button
                  onClick={() => setShowForm(true)}
                  className="inline-flex items-center gap-1.5 text-xs font-medium text-accent-cyan hover:text-accent-cyan/80 transition-colors"
                >
                  <Plus className="w-3.5 h-3.5" />
                  Add credential
                </button>
              )}
            </>
          )}
        </div>
      )}
    </div>
  )
}


export default function ToolsPage() {
  const [groups,      setGroups]      = useState<CategoryGroup[]>([])
  const [loading,     setLoading]     = useState(true)
  const [verifyingAll, setVerifyingAll] = useState(false)
  const [showInstall, setShowInstall] = useState(false)

  const load = useCallback(async () => {
    setLoading(true)
    try {
      const { data } = await toolsApi.list()
      setGroups(data.data ?? [])
    } catch {
      toast.error('Failed to load tool registry')
    } finally {
      setLoading(false)
    }
  }, [])

  useEffect(() => { load() }, [load])

  const handleVerify = useCallback(async (name: string) => {
    try {
      const { data } = await toolsApi.verify(name)
      toast.success(`${name}: ${data.tool.status}`)
      setGroups(prev => prev.map(g => ({
        ...g,
        tools: g.tools.map(t => t.name === name ? data.tool : t),
      })))
    } catch {
      toast.error(`Failed to verify ${name}`)
    }
  }, [])

  const handleToggle = useCallback(async (name: string, enable: boolean) => {
    try {
      const fn = enable ? toolsApi.enable : toolsApi.disable
      const { data } = await fn(name)
      toast.success(data.message)
      setGroups(prev => prev.map(g => ({
        ...g,
        tools: g.tools.map(t => t.name === name ? data.tool : t),
      })))
    } catch {
      toast.error(`Failed to ${enable ? 'enable' : 'disable'} ${name}`)
    }
  }, [])

  const handleSetRateLimits = useCallback(async (name: string, max: number, interval: number) => {
    try {
      const { data } = await toolsApi.setRateLimits(name, max, interval)
      toast.success(data.message)
      setGroups(prev => prev.map(g => ({
        ...g,
        tools: g.tools.map(t => t.name === name ? data.tool : t),
      })))
    } catch {
      toast.error(`Failed to update rate limits for ${name}`)
    }
  }, [])

  const handleVerifyAll = async () => {
    setVerifyingAll(true)
    try {
      const { data } = await toolsApi.verifyAll()
      toast.success(`Verification complete — ${data.installed}/${data.total} installed`)
      await load()
    } catch {
      toast.error('Verify-all failed')
    } finally {
      setVerifyingAll(false)
    }
  }

  return (
    <div className="p-6 max-w-7xl mx-auto space-y-4 animate-fade-in">
      {/* Page header */}
      <div className="flex items-start justify-between">
        <div>
          <h1 className="text-lg font-semibold text-text-primary flex items-center gap-2">
            <Wrench className="w-5 h-5 text-accent-cyan" />
            External Tools
          </h1>
          <p className="text-sm text-text-muted mt-0.5">
            Manage installed security tools used during scans
          </p>
        </div>
        <div className="flex items-center gap-2">
          <button
            onClick={() => setShowInstall(s => !s)}
            className={clsx(
              'btn-secondary inline-flex items-center gap-1.5',
              showInstall && 'border-accent-cyan/40 text-accent-cyan'
            )}
          >
            <Terminal className="w-3.5 h-3.5" />
            Install
          </button>
          <button onClick={load} disabled={loading} className="btn-secondary inline-flex items-center gap-1.5">
            <RefreshCw className={clsx('w-3.5 h-3.5', loading && 'animate-spin')} />
            Refresh
          </button>
          <button
            onClick={handleVerifyAll}
            disabled={verifyingAll || loading}
            className="btn-primary inline-flex items-center gap-1.5"
          >
            <CheckCircle className={clsx('w-3.5 h-3.5', verifyingAll && 'animate-spin')} />
            Verify All
          </button>
        </div>
      </div>

      {/* Install panel (collapsible) */}
      {showInstall && <InstallPanel />}

      {/* Stored tool credentials (SMB/AD) */}
      <CredentialsPanel />

      {/* Summary */}
      {!loading && groups.length > 0 && <SummaryBar groups={groups} />}

      {/* Tool groups */}
      {loading ? (
        <Loading />
      ) : groups.length === 0 ? (
        <div className="card p-12 text-center text-text-muted text-sm">
          No tools registered. Check server logs.
        </div>
      ) : (
        <div className="space-y-3">
          {groups.map(g => (
            <CategorySection
              key={g.category}
              group={g}
              onVerify={handleVerify}
              onToggle={handleToggle}
              onSetRateLimits={handleSetRateLimits}
            />
          ))}
        </div>
      )}
    </div>
  )
}
