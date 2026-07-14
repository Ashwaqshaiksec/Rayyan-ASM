import { useEffect, useState } from 'react'
import { CheckCircle, XCircle, Database, Bell, PlusCircle, Trash2, Pencil, Send, KeyRound, Copy, Check, AlertTriangle } from 'lucide-react'
import { webhookLogApi, orgApi, themeApi, notificationApi, apiKeyApi } from '@/utils/api'
import { applyTheme, cacheTheme } from '@/utils/theme'
import { formatDistanceToNow } from 'date-fns'
import clsx from 'clsx'
import toast from 'react-hot-toast'
import { Page, TableCard } from './shared'
import NotificationConfigModal, { type NotificationConfigValue } from '@/components/settings/NotificationConfigModal'

interface APIKeyRow {
  id: string
  name: string
  key_prefix: string
  active: boolean
  expires_at: string | null
  last_used_at: string | null
  created_at: string
}

interface NotificationConfigRow extends NotificationConfigValue {
  id: string
  active: boolean
  created_at: string
}

export function SettingsPage() {
  const [theme, setThemeState] = useState<'dark' | 'light' | 'slate'>('slate')
  const [webhooks, setWebhooks] = useState<unknown[]>([])
  const [limits, setLimits] = useState<Record<string, string | number | boolean | null> | null>(null)
  const [backingUp, setBackingUp] = useState(false)
  const [tab, setTab] = useState<'appearance' | 'notifications' | 'webhooks' | 'backup' | 'org' | 'apikeys'>('appearance')
  const [notifConfigs, setNotifConfigs] = useState<NotificationConfigRow[]>([])
  const [notifModalOpen, setNotifModalOpen] = useState(false)
  const [editingNotif, setEditingNotif] = useState<NotificationConfigRow | undefined>(undefined)
  const [testingId, setTestingId] = useState<string | null>(null)
  const [apiKeys, setApiKeys] = useState<APIKeyRow[]>([])
  const [newKeyName, setNewKeyName] = useState('')
  const [newKeyExpiry, setNewKeyExpiry] = useState('')
  const [creatingKey, setCreatingKey] = useState(false)
  const [revealedKey, setRevealedKey] = useState<string | null>(null)
  const [copied, setCopied] = useState(false)

  useEffect(() => {
    themeApi.get().then(({ data }) => {
      const t: 'dark' | 'light' | 'slate' = data.theme === 'dark' || data.theme === 'light' ? data.theme : 'slate'
      setThemeState(t)
      applyTheme(t)
      cacheTheme(t)
    })
    webhookLogApi.list(20).then(({ data }) => setWebhooks(data.data ?? []))
    orgApi.scanLimits().then(({ data }) => setLimits(data))
    loadNotifConfigs()
    loadApiKeys()
  }, [])

  function loadApiKeys() {
    apiKeyApi.list().then(({ data }) => setApiKeys(data.data ?? [])).catch(() => {})
  }

  async function createApiKey() {
    if (!newKeyName.trim()) { toast.error('Name is required'); return }
    setCreatingKey(true)
    try {
      // Backend reads `name` and `expires_at` (RFC3339 or omitted for no
      // expiry) — see APIKeyHandler.Create in internal/api/handlers/handlers.go.
      const { data } = await apiKeyApi.create({
        name: newKeyName.trim(),
        expires_at: newKeyExpiry ? new Date(newKeyExpiry).toISOString() : undefined,
      })
      // The raw key is only ever returned on this response — the backend
      // stores just a hash, so this is the one chance to show it.
      setRevealedKey(data.key)
      setNewKeyName('')
      setNewKeyExpiry('')
      loadApiKeys()
    } catch {
      toast.error('Failed to create API key')
    } finally {
      setCreatingKey(false)
    }
  }

  async function deleteApiKey(id: string) {
    if (!confirm('Revoke this API key? Anything using it will stop working immediately.')) return
    try {
      await apiKeyApi.delete(id)
      toast.success('API key revoked')
      loadApiKeys()
    } catch { toast.error('Failed to revoke API key') }
  }

  async function copyRevealedKey() {
    if (!revealedKey) return
    try {
      await navigator.clipboard.writeText(revealedKey)
      setCopied(true)
      setTimeout(() => setCopied(false), 2000)
    } catch { toast.error('Copy failed — select and copy manually') }
  }

  function loadNotifConfigs() {
    notificationApi.list().then(({ data }) => setNotifConfigs(data ?? [])).catch(() => {})
  }

  async function saveNotifConfig(payload: NotificationConfigValue) {
    if (editingNotif) {
      await notificationApi.update(editingNotif.id, payload)
      toast.success('Notification channel updated')
    } else {
      await notificationApi.create(payload)
      toast.success('Notification channel created')
    }
    loadNotifConfigs()
  }

  async function deleteNotifConfig(id: string) {
    if (!confirm('Delete this notification channel?')) return
    try {
      await notificationApi.delete(id)
      toast.success('Notification channel deleted')
      loadNotifConfigs()
    } catch { toast.error('Failed to delete channel') }
  }

  async function toggleNotifActive(cfg: NotificationConfigRow) {
    try {
      await notificationApi.update(cfg.id, { active: !cfg.active })
      loadNotifConfigs()
    } catch { toast.error('Failed to update channel') }
  }

  async function testNotifConfig(id: string) {
    setTestingId(id)
    try {
      await notificationApi.test(id)
      toast.success('Test notification dispatched — check the delivery target')
    } catch { toast.error('Failed to dispatch test notification') } finally { setTestingId(null) }
  }

  async function saveTheme(t: 'dark' | 'light' | 'slate') {
    setThemeState(t)
    applyTheme(t)
    cacheTheme(t)
    await themeApi.set(t)
    toast.success('Theme updated')
  }

  async function backup() {
    setBackingUp(true)
    try {
      const { data } = await orgApi.backup()
      const url = window.URL.createObjectURL(new Blob([data]))
      const a = document.createElement('a')
      a.href = url
      a.download = `rayyan-backup-${new Date().toISOString().split('T')[0]}.zip`
      a.click()
      window.URL.revokeObjectURL(url)
      toast.success('Backup downloaded')
    } catch { toast.error('Backup failed') } finally { setBackingUp(false) }
  }

  const tabs = [
    { key: 'appearance', label: 'Appearance' },
    { key: 'notifications', label: 'Notifications' },
    { key: 'webhooks', label: 'Webhook Log' },
    { key: 'apikeys', label: 'API Keys' },
    { key: 'backup', label: 'Backup / Restore' },
    { key: 'org', label: 'Org' },
  ] as const

  return (
    <Page title="Settings">
      <div className="flex gap-2 border-b border-surface-3 pb-3">
        {tabs.map(t => (
          <button key={t.key} onClick={() => setTab(t.key)}
            className={clsx('text-sm px-3 py-1.5 rounded-md', tab === t.key
              ? 'bg-surface-3 text-text-primary' : 'text-text-muted hover:text-text-secondary')}>
            {t.label}
          </button>
        ))}
      </div>

      {tab === 'appearance' && (
        <div className="card p-5 space-y-4">
          <h3 className="text-sm font-medium text-text-primary">Theme</h3>
          <div className="flex gap-3">
            {(['slate', 'light', 'dark'] as const).map(t => (
              <button key={t} onClick={() => saveTheme(t)}
                className={clsx('px-4 py-2 rounded-lg text-sm border capitalize transition-all',
                  theme === t
                    ? 'border-accent-cyan text-accent-cyan bg-accent-cyan/10'
                    : 'border-surface-3 text-text-muted hover:border-surface-3')}>
                {t}
              </button>
            ))}
          </div>
        </div>
      )}

      {tab === 'notifications' && (
        <div className="space-y-3">
          <div className="flex items-center justify-between">
            <p className="text-sm text-text-muted">
              Slack, Discord, Telegram, Teams, and email (SMTP) channels used for alert delivery and email verification.
            </p>
            <button
              onClick={() => { setEditingNotif(undefined); setNotifModalOpen(true) }}
              className="btn-primary inline-flex items-center gap-1.5 text-sm"
            >
              <PlusCircle className="w-4 h-4" />
              Add Channel
            </button>
          </div>

          {notifConfigs.length === 0 ? (
            <div className="card p-8 text-center text-sm text-text-muted flex flex-col items-center gap-2">
              <Bell className="w-6 h-6 text-text-muted" />
              No notification channels configured yet.
            </div>
          ) : (
            <TableCard>
              <thead>
                <tr>
                  <th>Channel</th>
                  <th>Name</th>
                  <th>Min Severity</th>
                  <th>Active</th>
                  <th>Created</th>
                  <th></th>
                </tr>
              </thead>
              <tbody>
                {notifConfigs.map(cfg => (
                  <tr key={cfg.id}>
                    <td><span className="badge-gray text-xs capitalize">{cfg.channel}</span></td>
                    <td><span className="text-text-primary text-sm">{cfg.name}</span></td>
                    <td><span className="text-xs text-text-muted capitalize">{cfg.min_severity}</span></td>
                    <td>
                      <button onClick={() => toggleNotifActive(cfg)}>
                        {cfg.active
                          ? <CheckCircle className="w-4 h-4 text-accent-green" />
                          : <XCircle className="w-4 h-4 text-text-muted" />}
                      </button>
                    </td>
                    <td><span className="text-xs text-text-muted">{formatDistanceToNow(new Date(cfg.created_at), { addSuffix: true })}</span></td>
                    <td>
                      <div className="flex items-center gap-1 justify-end">
                        <button
                          onClick={() => testNotifConfig(cfg.id)}
                          disabled={testingId === cfg.id}
                          title="Send test notification"
                          className="p-1.5 rounded-md hover:bg-surface-3 text-text-muted hover:text-accent-cyan transition-colors disabled:opacity-50"
                        >
                          <Send className="w-4 h-4" />
                        </button>
                        <button
                          onClick={() => { setEditingNotif(cfg); setNotifModalOpen(true) }}
                          title="Edit"
                          className="p-1.5 rounded-md hover:bg-surface-3 text-text-muted hover:text-text-primary transition-colors"
                        >
                          <Pencil className="w-4 h-4" />
                        </button>
                        <button
                          onClick={() => deleteNotifConfig(cfg.id)}
                          title="Delete"
                          className="p-1.5 rounded-md hover:bg-surface-3 text-text-muted hover:text-accent-red transition-colors"
                        >
                          <Trash2 className="w-4 h-4" />
                        </button>
                      </div>
                    </td>
                  </tr>
                ))}
              </tbody>
            </TableCard>
          )}
        </div>
      )}

      {notifModalOpen && (
        <NotificationConfigModal
          initial={editingNotif}
          onClose={() => setNotifModalOpen(false)}
          onSubmit={saveNotifConfig}
        />
      )}

      {tab === 'webhooks' && (
        <div className="space-y-3">
          <p className="text-sm text-text-muted">Last 20 webhook delivery attempts</p>
          <TableCard>
            <thead><tr><th>Channel</th><th>Endpoint</th><th>Status</th><th>HTTP</th><th>Sent</th><th>Error</th></tr></thead>
            <tbody>
              {(webhooks as Array<{ id: string; channel: string; endpoint: string; success: boolean; status_code: number; sent_at: string; error_message: string }>).map(w => (
                <tr key={w.id}>
                  <td><span className="badge-gray text-xs">{w.channel}</span></td>
                  <td><span className="font-mono text-xs text-text-muted truncate max-w-xs block">{w.endpoint}</span></td>
                  <td>{w.success ? <CheckCircle className="w-4 h-4 text-accent-green" /> : <XCircle className="w-4 h-4 text-accent-red" />}</td>
                  <td><span className="font-mono text-xs text-text-muted">{w.status_code || '—'}</span></td>
                  <td><span className="text-xs text-text-muted">{formatDistanceToNow(new Date(w.sent_at), { addSuffix: true })}</span></td>
                  <td><span className="text-xs text-accent-red truncate max-w-xs block">{w.error_message}</span></td>
                </tr>
              ))}
            </tbody>
          </TableCard>
        </div>
      )}

      {tab === 'apikeys' && (
        <div className="space-y-3">
          <p className="text-sm text-text-muted">
            Personal API keys for scripting or CI access. Each key is only ever shown once, right after creation.
          </p>

          <div className="card p-4 flex flex-col sm:flex-row items-start sm:items-end gap-3">
            <div className="flex-1 space-y-1">
              <label className="text-xs text-text-muted">Name</label>
              <input
                value={newKeyName}
                onChange={e => setNewKeyName(e.target.value)}
                placeholder="e.g. CI pipeline"
                className="input text-sm w-full"
              />
            </div>
            <div className="space-y-1">
              <label className="text-xs text-text-muted">Expires (optional)</label>
              <input
                type="date"
                value={newKeyExpiry}
                onChange={e => setNewKeyExpiry(e.target.value)}
                className="input text-sm"
              />
            </div>
            <button
              onClick={createApiKey}
              disabled={creatingKey}
              className="btn-primary inline-flex items-center gap-1.5 text-sm whitespace-nowrap disabled:opacity-50"
            >
              <PlusCircle className="w-4 h-4" />
              {creatingKey ? 'Creating…' : 'Create Key'}
            </button>
          </div>

          {apiKeys.length === 0 ? (
            <div className="card p-8 text-center text-sm text-text-muted flex flex-col items-center gap-2">
              <KeyRound className="w-6 h-6 text-text-muted" />
              No API keys yet.
            </div>
          ) : (
            <TableCard>
              <thead>
                <tr>
                  <th>Name</th>
                  <th>Key</th>
                  <th>Active</th>
                  <th>Last Used</th>
                  <th>Expires</th>
                  <th>Created</th>
                  <th></th>
                </tr>
              </thead>
              <tbody>
                {apiKeys.map(k => (
                  <tr key={k.id}>
                    <td><span className="text-text-primary text-sm">{k.name}</span></td>
                    <td><span className="font-mono text-xs text-text-muted">{k.key_prefix}…</span></td>
                    <td>
                      {k.active
                        ? <CheckCircle className="w-4 h-4 text-accent-green" />
                        : <XCircle className="w-4 h-4 text-text-muted" />}
                    </td>
                    <td>
                      <span className="text-xs text-text-muted">
                        {k.last_used_at ? formatDistanceToNow(new Date(k.last_used_at), { addSuffix: true }) : 'Never'}
                      </span>
                    </td>
                    <td>
                      <span className="text-xs text-text-muted">
                        {k.expires_at ? formatDistanceToNow(new Date(k.expires_at), { addSuffix: true }) : 'Never'}
                      </span>
                    </td>
                    <td><span className="text-xs text-text-muted">{formatDistanceToNow(new Date(k.created_at), { addSuffix: true })}</span></td>
                    <td>
                      <div className="flex items-center justify-end">
                        <button
                          onClick={() => deleteApiKey(k.id)}
                          title="Revoke"
                          className="p-1.5 rounded-md hover:bg-surface-3 text-text-muted hover:text-accent-red transition-colors"
                        >
                          <Trash2 className="w-4 h-4" />
                        </button>
                      </div>
                    </td>
                  </tr>
                ))}
              </tbody>
            </TableCard>
          )}
        </div>
      )}

      {revealedKey && (
        <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/60 backdrop-blur-sm p-4">
          <div className="w-full max-w-md bg-surface-1 border border-border rounded-xl shadow-2xl animate-fade-in p-5 space-y-4">
            <div className="flex items-center gap-2">
              <KeyRound className="w-4 h-4 text-accent-cyan" />
              <h2 className="text-base font-semibold text-text-primary">API key created</h2>
            </div>

            <div className="flex items-start gap-2 p-3 rounded-md bg-accent-orange/10 border border-accent-orange/30">
              <AlertTriangle className="w-4 h-4 text-accent-orange flex-shrink-0 mt-0.5" />
              <p className="text-xs text-accent-orange">
                This is the only time the full key is shown. Copy it now — it can't be retrieved again, only revoked and replaced.
              </p>
            </div>

            <div className="flex items-center gap-2">
              <code className="flex-1 text-xs font-mono text-text-primary bg-surface-2 border border-border rounded-md px-3 py-2 break-all">
                {revealedKey}
              </code>
              <button
                onClick={copyRevealedKey}
                title="Copy"
                className="p-2 rounded-md border border-border hover:bg-surface-2 text-text-muted hover:text-text-primary transition-colors flex-shrink-0"
              >
                {copied ? <Check className="w-4 h-4 text-accent-green" /> : <Copy className="w-4 h-4" />}
              </button>
            </div>

            <button
              onClick={() => setRevealedKey(null)}
              className="btn-primary w-full text-sm"
            >
              Done
            </button>
          </div>
        </div>
      )}

      {tab === 'backup' && (
        <div className="card p-5 space-y-4">
          <h3 className="text-sm font-medium text-text-primary">Backup</h3>
          <p className="text-xs text-text-muted">Downloads a ZIP containing all your org data as JSON (domains, hosts, subdomains, findings, projects, notes).</p>
          <button onClick={backup} disabled={backingUp} className="btn-primary flex items-center gap-2">
            <Database className={clsx('w-4 h-4', backingUp && 'animate-pulse')} />
            {backingUp ? 'Preparing…' : 'Download Backup'}
          </button>
        </div>
      )}

      {tab === 'org' && limits && (
        <div className="card p-5 space-y-3">
          <h3 className="text-sm font-medium text-text-primary">Organization Limits</h3>
          <dl className="space-y-2 text-sm">
            {Object.entries(limits).map(([k, v]) => (
              <div key={k} className="flex justify-between">
                <dt className="text-text-muted capitalize">{k.replace(/_/g, ' ')}</dt>
                <dd className="text-text-primary font-medium">{String(v)}</dd>
              </div>
            ))}
          </dl>
        </div>
      )}
    </Page>
  )
}

export default SettingsPage
