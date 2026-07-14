import { useState } from 'react'
import { X, Bell, ChevronDown } from 'lucide-react'
import clsx from 'clsx'
import { isAxiosError } from 'axios'

export type NotificationChannel = 'slack' | 'discord' | 'telegram' | 'teams' | 'email'

const CHANNELS: { id: NotificationChannel; label: string }[] = [
  { id: 'slack', label: 'Slack' },
  { id: 'discord', label: 'Discord' },
  { id: 'telegram', label: 'Telegram' },
  { id: 'teams', label: 'Microsoft Teams' },
  { id: 'email', label: 'Email (SMTP)' },
]

const ALERT_TYPES = ['new_asset', 'cert_expiry', 'new_service', 'finding'] as const
const SEVERITIES = ['info', 'low', 'medium', 'high', 'critical'] as const

export interface NotificationConfigValue {
  [key: string]: unknown
  id?: string
  channel: NotificationChannel
  name: string
  webhook_url?: string
  bot_token?: string
  chat_id?: string
  smtp_host?: string
  smtp_port?: number
  smtp_username?: string
  smtp_password?: string
  smtp_from?: string
  smtp_to?: string[]
  smtp_use_tls?: boolean
  alert_types?: string[]
  min_severity?: string
}

interface NotificationConfigModalProps {
  initial?: NotificationConfigValue
  onClose: () => void
  onSubmit: (payload: NotificationConfigValue) => Promise<void>
}

export default function NotificationConfigModal({ initial, onClose, onSubmit }: NotificationConfigModalProps) {
  const editing = Boolean(initial?.id)
  const [channel, setChannel] = useState<NotificationChannel>(initial?.channel ?? 'email')
  const [name, setName] = useState(initial?.name ?? '')
  const [webhookUrl, setWebhookUrl] = useState(initial?.webhook_url ?? '')
  const [botToken, setBotToken] = useState('')
  const [chatId, setChatId] = useState(initial?.chat_id ?? '')
  const [smtpHost, setSmtpHost] = useState(initial?.smtp_host ?? '')
  const [smtpPort, setSmtpPort] = useState(initial?.smtp_port ?? 587)
  const [smtpUser, setSmtpUser] = useState(initial?.smtp_username ?? '')
  const [smtpPass, setSmtpPass] = useState('')
  const [smtpFrom, setSmtpFrom] = useState(initial?.smtp_from ?? '')
  const [smtpTo, setSmtpTo] = useState((initial?.smtp_to ?? []).join(', '))
  const [smtpUseTLS, setSmtpUseTLS] = useState(initial?.smtp_use_tls ?? true)
  const [alertTypes, setAlertTypes] = useState<string[]>(initial?.alert_types ?? [...ALERT_TYPES])
  const [minSeverity, setMinSeverity] = useState(initial?.min_severity ?? 'info')
  const [submitting, setSubmitting] = useState(false)
  const [error, setError] = useState('')

  function toggleAlertType(t: string) {
    setAlertTypes(prev => prev.includes(t) ? prev.filter(x => x !== t) : [...prev, t])
  }

  function validate(): string {
    if (!name.trim()) return 'Name is required'
    if ((channel === 'slack' || channel === 'discord' || channel === 'teams') && !webhookUrl.trim()) {
      return `${channel} requires a webhook URL`
    }
    if (channel === 'telegram' && (!botToken.trim() && !editing || !chatId.trim())) {
      return 'Telegram requires a bot token and chat ID'
    }
    if (channel === 'email') {
      if (!smtpHost.trim() || !smtpFrom.trim() || !smtpTo.trim()) {
        return 'Email requires SMTP host, from address, and at least one recipient'
      }
    }
    return ''
  }

  async function handleSubmit() {
    const v = validate()
    if (v) { setError(v); return }
    setError('')
    setSubmitting(true)
    try {
      const payload: NotificationConfigValue = { channel, name: name.trim() }
      if (channel === 'slack' || channel === 'discord' || channel === 'teams') {
        payload.webhook_url = webhookUrl.trim()
      }
      if (channel === 'telegram') {
        if (botToken.trim()) payload.bot_token = botToken.trim()
        payload.chat_id = chatId.trim()
      }
      if (channel === 'email') {
        payload.smtp_host = smtpHost.trim()
        payload.smtp_port = smtpPort || 587
        payload.smtp_username = smtpUser.trim()
        if (smtpPass.trim()) payload.smtp_password = smtpPass.trim()
        payload.smtp_from = smtpFrom.trim()
        payload.smtp_to = smtpTo.split(',').map(s => s.trim()).filter(Boolean)
        payload.smtp_use_tls = smtpUseTLS
      }
      payload.alert_types = alertTypes
      payload.min_severity = minSeverity
      await onSubmit(payload)
      onClose()
    } catch (e) {
      const message = isAxiosError<{ error: string }>(e) ? e.response?.data?.error : undefined
      setError(message ?? 'Failed to save notification channel')
    } finally {
      setSubmitting(false)
    }
  }

  return (
    <div
      className="fixed inset-0 z-50 flex items-center justify-center bg-black/60 backdrop-blur-sm p-4"
      onClick={e => { if (e.target === e.currentTarget) onClose() }}
    >
      <div className="w-full max-w-lg bg-surface-1 border border-border rounded-xl shadow-2xl animate-fade-in max-h-[90vh] overflow-y-auto">
        <div className="flex items-center justify-between px-5 py-4 border-b border-border sticky top-0 bg-surface-1">
          <h2 className="text-base font-semibold text-text-primary flex items-center gap-2">
            <Bell className="w-4 h-4 text-accent-cyan" />
            {editing ? 'Edit Notification Channel' : 'New Notification Channel'}
          </h2>
          <button onClick={onClose} className="p-1 rounded-md hover:bg-surface-2 text-text-muted hover:text-text-primary transition-colors">
            <X className="w-4 h-4" />
          </button>
        </div>

        <div className="px-5 py-4 space-y-4">
          <div className="space-y-1.5">
            <label className="text-xs font-medium text-text-secondary uppercase tracking-wide">Channel</label>
            <div className="flex flex-wrap gap-1.5">
              {CHANNELS.map(c => (
                <button
                  key={c.id}
                  disabled={editing}
                  onClick={() => setChannel(c.id)}
                  className={clsx(
                    'px-3 py-1 rounded-md text-xs font-medium border transition-colors',
                    channel === c.id
                      ? 'bg-accent-cyan/10 border-accent-cyan/40 text-accent-cyan'
                      : 'bg-surface-2 border-border text-text-muted hover:text-text-secondary',
                    editing && 'opacity-50 cursor-not-allowed'
                  )}
                >
                  {c.label}
                </button>
              ))}
            </div>
          </div>

          <div className="space-y-1.5">
            <label className="text-xs font-medium text-text-secondary uppercase tracking-wide">Name</label>
            <input
              type="text"
              placeholder="e.g. Registration verification"
              value={name}
              onChange={e => setName(e.target.value)}
              className="w-full bg-surface-2 border border-border rounded-lg px-3 py-2 text-sm text-text-primary placeholder-text-muted focus:outline-none focus:border-accent-cyan/50"
              autoFocus
            />
          </div>

          {(channel === 'slack' || channel === 'discord' || channel === 'teams') && (
            <div className="space-y-1.5">
              <label className="text-xs font-medium text-text-secondary uppercase tracking-wide">Webhook URL</label>
              <input
                type="text"
                placeholder="https://hooks.slack.com/services/..."
                value={webhookUrl}
                onChange={e => setWebhookUrl(e.target.value)}
                className="w-full bg-surface-2 border border-border rounded-lg px-3 py-2 text-sm text-text-primary placeholder-text-muted focus:outline-none focus:border-accent-cyan/50"
              />
            </div>
          )}

          {channel === 'telegram' && (
            <>
              <div className="space-y-1.5">
                <label className="text-xs font-medium text-text-secondary uppercase tracking-wide">
                  Bot Token {editing && <span className="text-text-muted font-normal normal-case">(leave blank to keep existing)</span>}
                </label>
                <input
                  type="password"
                  placeholder={editing ? '••••••••' : '123456:ABC-DEF...'}
                  value={botToken}
                  onChange={e => setBotToken(e.target.value)}
                  className="w-full bg-surface-2 border border-border rounded-lg px-3 py-2 text-sm text-text-primary placeholder-text-muted focus:outline-none focus:border-accent-cyan/50"
                />
              </div>
              <div className="space-y-1.5">
                <label className="text-xs font-medium text-text-secondary uppercase tracking-wide">Chat ID</label>
                <input
                  type="text"
                  placeholder="-1001234567890"
                  value={chatId}
                  onChange={e => setChatId(e.target.value)}
                  className="w-full bg-surface-2 border border-border rounded-lg px-3 py-2 text-sm text-text-primary placeholder-text-muted focus:outline-none focus:border-accent-cyan/50"
                />
              </div>
            </>
          )}

          {channel === 'email' && (
            <>
              <div className="grid grid-cols-3 gap-3">
                <div className="col-span-2 space-y-1.5">
                  <label className="text-xs font-medium text-text-secondary uppercase tracking-wide">SMTP Host</label>
                  <input
                    type="text"
                    placeholder="smtp.yourprovider.com"
                    value={smtpHost}
                    onChange={e => setSmtpHost(e.target.value)}
                    className="w-full bg-surface-2 border border-border rounded-lg px-3 py-2 text-sm text-text-primary placeholder-text-muted focus:outline-none focus:border-accent-cyan/50"
                  />
                </div>
                <div className="space-y-1.5">
                  <label className="text-xs font-medium text-text-secondary uppercase tracking-wide">Port</label>
                  <input
                    type="number"
                    value={smtpPort}
                    onChange={e => setSmtpPort(Number(e.target.value))}
                    className="w-full bg-surface-2 border border-border rounded-lg px-3 py-2 text-sm text-text-primary focus:outline-none focus:border-accent-cyan/50"
                  />
                </div>
              </div>

              <div className="space-y-1.5">
                <label className="text-xs font-medium text-text-secondary uppercase tracking-wide">Username</label>
                <input
                  type="text"
                  placeholder="smtp username"
                  value={smtpUser}
                  onChange={e => setSmtpUser(e.target.value)}
                  className="w-full bg-surface-2 border border-border rounded-lg px-3 py-2 text-sm text-text-primary placeholder-text-muted focus:outline-none focus:border-accent-cyan/50"
                />
              </div>

              <div className="space-y-1.5">
                <label className="text-xs font-medium text-text-secondary uppercase tracking-wide">
                  Password {editing && <span className="text-text-muted font-normal normal-case">(leave blank to keep existing)</span>}
                </label>
                <input
                  type="password"
                  placeholder={editing ? '••••••••' : 'smtp password / app password'}
                  value={smtpPass}
                  onChange={e => setSmtpPass(e.target.value)}
                  className="w-full bg-surface-2 border border-border rounded-lg px-3 py-2 text-sm text-text-primary placeholder-text-muted focus:outline-none focus:border-accent-cyan/50"
                />
              </div>

              <div className="space-y-1.5">
                <label className="text-xs font-medium text-text-secondary uppercase tracking-wide">From Address</label>
                <input
                  type="text"
                  placeholder="noreply@yourdomain.com"
                  value={smtpFrom}
                  onChange={e => setSmtpFrom(e.target.value)}
                  className="w-full bg-surface-2 border border-border rounded-lg px-3 py-2 text-sm text-text-primary placeholder-text-muted focus:outline-none focus:border-accent-cyan/50"
                />
              </div>

              <div className="space-y-1.5">
                <label className="text-xs font-medium text-text-secondary uppercase tracking-wide flex items-center gap-1">
                  Recipients
                  <span className="text-text-muted font-normal normal-case tracking-normal">(comma-separated, used for alert delivery)</span>
                </label>
                <input
                  type="text"
                  placeholder="alerts@yourdomain.com, oncall@yourdomain.com"
                  value={smtpTo}
                  onChange={e => setSmtpTo(e.target.value)}
                  className="w-full bg-surface-2 border border-border rounded-lg px-3 py-2 text-sm text-text-primary placeholder-text-muted focus:outline-none focus:border-accent-cyan/50"
                />
              </div>

              <label className="flex items-center gap-2 text-sm text-text-secondary cursor-pointer">
                <input
                  type="checkbox"
                  checked={smtpUseTLS}
                  onChange={e => setSmtpUseTLS(e.target.checked)}
                  className="rounded-md border-border bg-surface-2 text-accent-cyan focus:ring-accent-cyan/50"
                />
                Use TLS
              </label>
            </>
          )}

          <div className="space-y-1.5">
            <label className="text-xs font-medium text-text-secondary uppercase tracking-wide">Alert Types</label>
            <div className="flex flex-wrap gap-1.5">
              {ALERT_TYPES.map(t => (
                <button
                  key={t}
                  onClick={() => toggleAlertType(t)}
                  className={clsx(
                    'px-3 py-1 rounded-md text-xs font-medium border transition-colors',
                    alertTypes.includes(t)
                      ? 'bg-accent-cyan/10 border-accent-cyan/40 text-accent-cyan'
                      : 'bg-surface-2 border-border text-text-muted hover:text-text-secondary'
                  )}
                >
                  {t.replace(/_/g, ' ')}
                </button>
              ))}
            </div>
          </div>

          <div className="space-y-1.5">
            <label className="text-xs font-medium text-text-secondary uppercase tracking-wide">Minimum Severity</label>
            <div className="relative">
              <select
                value={minSeverity}
                onChange={e => setMinSeverity(e.target.value)}
                className="w-full appearance-none bg-surface-2 border border-border rounded-lg px-3 py-2 pr-8 text-sm text-text-primary focus:outline-none focus:border-accent-cyan/50 capitalize"
              >
                {SEVERITIES.map(s => (
                  <option key={s} value={s}>{s}</option>
                ))}
              </select>
              <ChevronDown className="absolute right-2 top-1/2 -translate-y-1/2 w-4 h-4 text-text-muted pointer-events-none" />
            </div>
          </div>

          {error && (
            <p className="text-xs text-accent-red bg-accent-red/10 border border-accent-red/20 rounded-md px-3 py-2">
              {error}
            </p>
          )}
        </div>

        <div className="flex items-center justify-end gap-2 px-5 py-4 border-t border-border sticky bottom-0 bg-surface-1">
          <button onClick={onClose} className="btn-secondary">Cancel</button>
          <button
            onClick={handleSubmit}
            disabled={submitting || !name.trim()}
            className="btn-primary inline-flex items-center gap-1.5"
          >
            {submitting
              ? <><div className="w-3.5 h-3.5 border-2 border-white/30 border-t-white rounded-full animate-spin" /> Saving…</>
              : <><Bell className="w-3.5 h-3.5" /> {editing ? 'Save Changes' : 'Create Channel'}</>
            }
          </button>
        </div>
      </div>
    </div>
  )
}
