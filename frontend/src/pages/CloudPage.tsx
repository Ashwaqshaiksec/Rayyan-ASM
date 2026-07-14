import { useEffect, useState, useCallback } from 'react'
import { Shield, Cloud, RefreshCw, X } from 'lucide-react'
import { cloudApi } from '@/utils/api'
import type { CloudAsset } from '@/types'
import { formatDistanceToNow } from 'date-fns'
import clsx from 'clsx'
import toast from 'react-hot-toast'
import { Page, TableCard, SkeletonTable, StatusBadge } from './shared'

export function CloudPage() {
 const [assets, setAssets] = useState<CloudAsset[]>([])
 const [loading, setLoading] = useState(true)
 const [syncing, setSyncing] = useState(false)
 const [scanning, setScanning] = useState(false)
 const [providerFilter, setProviderFilter] = useState('')
 const [showModal, setShowModal] = useState(false)
 const [activeTab, setActiveTab] = useState<'assets' | 'findings'>('assets')
 const [scanFindings, setScanFindings] = useState<Array<{ id: string; title: string; severity: string; url: string; status: string; created_at: string }>>([])
 const [findingsLoading, setFindingsLoading] = useState(false)
 const [syncForm, setSyncForm] = useState({
 provider: 'aws',
 aws_access_key_id: '', aws_secret_access_key: '', aws_session_token: '', aws_region: '',
 azure_client_id: '', azure_client_secret: '', azure_tenant_id: '', azure_subscription_id: '',
 gcp_project: '', gcp_service_account_json: '',
 })

 const load = useCallback(async () => {
 setLoading(true)
 try { const { data } = await cloudApi.list(); setAssets(data.data ?? []) }
 finally { setLoading(false) }
 }, [])

 const loadFindings = useCallback(async () => {
 setFindingsLoading(true)
 try {
 const { data } = await cloudApi.listFindings({ limit: 200 })
 setScanFindings(data.data ?? [])
 } catch { /* empty state */ }
 finally { setFindingsLoading(false) }
 }, [])

 useEffect(() => { load() }, [load])
 useEffect(() => { if (activeTab === 'findings') loadFindings() }, [activeTab, loadFindings])

 async function doSync() {
 setSyncing(true)
 try {
 await cloudApi.sync(syncForm)
 toast.success('Cloud sync initiated — assets will appear shortly')
 setShowModal(false)
 setTimeout(load, 5000)
 } catch { toast.error('Sync failed') } finally { setSyncing(false) }
 }

 async function doScan() {
 setScanning(true)
 try {
 await cloudApi.scan({ provider: providerFilter || undefined })
 toast.success('Nuclei scan initiated against cloud assets — findings will appear shortly')
 setTimeout(loadFindings, 8000)
 } catch { toast.error('Scan failed') } finally { setScanning(false) }
 }

 const providers = [...new Set(assets.map(a => a.provider))].sort()
 const filtered = assets.filter(a => !providerFilter || a.provider === providerFilter)

 const providerIcon = (p: string) => {
 const icons: Record<string, string> = { aws: '🟠', azure: '🔵', gcp: '🟢', do: '🔵', cloudflare: '🟤' }
 return icons[p] ?? '☁️'
 }

 const statsPerProvider = providers.map(p => ({
 p, count: assets.filter(a => a.provider === p).length
 }))

 return (
 <Page title="Cloud Assets" subtitle={`${assets.length} assets across ${providers.length} provider${providers.length !== 1 ? 's' : ''}`}
 actions={
 <div className="flex items-center gap-2">
 <button onClick={doScan} disabled={scanning || assets.length === 0}
 className="btn-secondary text-xs flex items-center gap-1"
 title={assets.length === 0 ? 'Sync assets first' : 'Run nuclei scan against cloud asset IPs'}>
 <Shield className="w-3 h-3" />
 {scanning ? 'Scanning…' : 'Nuclei Scan'}
 </button>
 <button onClick={() => setShowModal(true)} className="btn-primary text-xs flex items-center gap-1">
 <Cloud className="w-3 h-3" /> Sync Cloud
 </button>
 </div>
 }>

 {/* Tabs */}
 <div className="flex gap-1 mb-4 border-b border-border">
 {(['assets', 'findings'] as const).map(tab => (
 <button key={tab} onClick={() => setActiveTab(tab)}
 className={clsx('px-4 py-2 text-sm font-medium border-b-2 transition-colors -mb-px',
 activeTab === tab
 ? 'border-accent-cyan text-accent-cyan'
 : 'border-transparent text-text-muted hover:text-text-primary'
 )}>
 {tab === 'assets' ? `Assets (${assets.length})` : `Scan Findings (${scanFindings.length})`}
 </button>
 ))}
 </div>

 {activeTab === 'assets' && (
 <>
 {/* Provider stat pills */}
 {statsPerProvider.length > 0 && (
 <div className="flex flex-wrap gap-2 mb-4">
 {statsPerProvider.map(({ p, count }) => (
 <button key={p}
 onClick={() => setProviderFilter(providerFilter === p ? '' : p)}
 className={clsx('flex items-center gap-1 px-3 py-1 rounded-full text-xs font-medium border transition-colors',
 providerFilter === p
 ? 'bg-accent-cyan/20 border-accent-cyan text-accent-cyan'
 : 'bg-surface-2 border-border text-text-muted hover:border-accent-cyan'
 )}>
 {providerIcon(p)} {p.toUpperCase()} — {count}
 </button>
 ))}
 </div>
 )}

 {loading ? <SkeletonTable /> : filtered.length === 0 ? (
 <div className="card p-10 text-center text-text-muted">
 <Cloud className="w-10 h-10 mx-auto mb-3 opacity-30" />
 <p className="text-sm">No cloud assets found. Click <strong>Sync Cloud</strong> to connect a provider.</p>
 </div>
 ) : (
 <TableCard>
 <thead><tr>
 <th>Provider</th><th>Type</th><th>Name</th><th>Region</th>
 <th>Account</th><th>IPs / Endpoints</th><th>Status</th><th>Synced</th>
 </tr></thead>
 <tbody>
 {filtered.map(a => (
 <tr key={a.id}>
 <td><span className="badge-blue badge text-xs">{providerIcon(a.provider)} {a.provider}</span></td>
 <td><span className="text-xs text-text-muted font-mono">{a.resource_type}</span></td>
 <td><span className="text-sm text-text-primary font-medium">{a.name}</span></td>
 <td><span className="text-xs text-text-muted">{a.region}</span></td>
 <td><span className="font-mono text-xs text-text-muted truncate max-w-[120px] block">{a.account_id}</span></td>
 <td><span className="font-mono text-xs text-text-muted">{(a.ips ?? []).slice(0, 2).join(', ') || '—'}
 {(a.ips ?? []).length > 2 && <span className="text-text-muted"> +{(a.ips ?? []).length - 2}</span>}
 </span></td>
 <td><StatusBadge s={a.status || 'active'} /></td>
 <td><span className="text-xs text-text-muted">{a.last_synced_at ? formatDistanceToNow(new Date(a.last_synced_at), { addSuffix: true }) : '—'}</span></td>
 </tr>
 ))}
 </tbody>
 </TableCard>
 )}
 </>
 )}

 {activeTab === 'findings' && (
 findingsLoading ? <SkeletonTable rows={4} /> : scanFindings.length === 0 ? (
 <div className="card p-10 text-center text-text-muted">
 <Shield className="w-10 h-10 mx-auto mb-3 opacity-30" />
 <p className="text-sm">No cloud scan findings yet. Click <strong>Nuclei Scan</strong> to run a vulnerability scan against your cloud assets.</p>
 </div>
 ) : (
 <TableCard>
 <thead><tr>
 <th>Target</th><th>Title</th><th>Severity</th><th>Status</th><th>Found</th>
 </tr></thead>
 <tbody>
 {scanFindings.map(f => (
 <tr key={f.id}>
 <td><span className="font-mono text-xs text-accent-cyan">{f.url || '—'}</span></td>
 <td><span className="text-sm text-text-primary">{f.title}</span></td>
 <td><StatusBadge s={f.severity} /></td>
 <td><StatusBadge s={f.status} /></td>
 <td><span className="text-xs text-text-muted">
 {f.created_at ? formatDistanceToNow(new Date(f.created_at), { addSuffix: true }) : '—'}
 </span></td>
 </tr>
 ))}
 </tbody>
 </TableCard>
 )
 )}

 {/* Sync credentials modal */}
 {showModal && (
 <div className="fixed inset-0 bg-black/60 z-50 flex items-center justify-center p-4">
 <div className="bg-surface-1 border border-border rounded-xl shadow-2xl w-full max-w-lg max-h-[90vh] overflow-y-auto">
 <div className="flex items-center justify-between p-5 border-b border-border">
 <div className="flex items-center gap-2">
 <Cloud className="w-5 h-5 text-accent-cyan" />
 <h3 className="font-semibold text-text-primary">Sync Cloud Assets</h3>
 </div>
 <button onClick={() => setShowModal(false)} className="text-text-muted hover:text-text-primary">
 <X className="w-5 h-5" />
 </button>
 </div>
 <div className="p-5 space-y-4">
 <div>
 <label className="label text-xs">Provider</label>
 <select className="input text-sm" value={syncForm.provider}
 onChange={e => setSyncForm(f => ({ ...f, provider: e.target.value }))}>
 <option value="aws">AWS</option>
 <option value="azure">Azure</option>
 <option value="gcp">GCP</option>
 <option value="">All (if credentials set above)</option>
 </select>
 </div>

 {(syncForm.provider === 'aws' || syncForm.provider === '') && (
 <div className="space-y-2 p-3 bg-surface-2 rounded-lg border border-border">
 <p className="text-xs font-semibold text-text-muted uppercase tracking-wider">🟠 AWS</p>
 {([
 ['aws_access_key_id', 'Access Key ID'],
 ['aws_secret_access_key', 'Secret Access Key'],
 ['aws_session_token', 'Session Token (optional)'],
 ['aws_region', 'Region (optional — all regions if blank)'],
 ] as const).map(([key, label]) => (
 <div key={key}>
 <label className="label text-xs">{label}</label>
 <input type={key.includes('secret') || key.includes('token') ? 'password' : 'text'}
 className="input text-sm font-mono"
 placeholder={label}
 value={syncForm[key]}
 onChange={e => setSyncForm(f => ({ ...f, [key]: e.target.value }))} />
 </div>
 ))}
 </div>
 )}

 {(syncForm.provider === 'azure' || syncForm.provider === '') && (
 <div className="space-y-2 p-3 bg-surface-2 rounded-lg border border-border">
 <p className="text-xs font-semibold text-text-muted uppercase tracking-wider">🔵 Azure</p>
 {([
 ['azure_client_id', 'Client ID (App ID)'],
 ['azure_client_secret', 'Client Secret'],
 ['azure_tenant_id', 'Tenant ID'],
 ['azure_subscription_id', 'Subscription ID'],
 ] as const).map(([key, label]) => (
 <div key={key}>
 <label className="label text-xs">{label}</label>
 <input type={key.includes('secret') ? 'password' : 'text'}
 className="input text-sm font-mono"
 placeholder={label}
 value={syncForm[key]}
 onChange={e => setSyncForm(f => ({ ...f, [key]: e.target.value }))} />
 </div>
 ))}
 </div>
 )}

 {(syncForm.provider === 'gcp' || syncForm.provider === '') && (
 <div className="space-y-2 p-3 bg-surface-2 rounded-lg border border-border">
 <p className="text-xs font-semibold text-text-muted uppercase tracking-wider">🟢 GCP</p>
 <div>
 <label className="label text-xs">Project ID</label>
 <input type="text" className="input text-sm font-mono" placeholder="my-gcp-project"
 value={syncForm.gcp_project}
 onChange={e => setSyncForm(f => ({ ...f, gcp_project: e.target.value }))} />
 </div>
 <div>
 <label className="label text-xs">Service Account JSON path or raw JSON</label>
 <textarea className="input text-sm font-mono h-20 resize-none"
 placeholder='/path/to/key.json or {"type":"service_account",...}'
 value={syncForm.gcp_service_account_json}
 onChange={e => setSyncForm(f => ({ ...f, gcp_service_account_json: e.target.value }))} />
 </div>
 </div>
 )}

 <p className="text-xs text-text-muted">
 Credentials are used only for this sync request and are not stored here.
 To sync automatically using saved credentials, use <strong>Settings → Cloud Credentials</strong> and trigger sync from there.
 </p>
 </div>
 <div className="flex justify-end gap-2 p-5 border-t border-border">
 <button onClick={() => setShowModal(false)} className="btn-secondary text-xs">Cancel</button>
 <button onClick={doSync} disabled={syncing} className="btn-primary text-xs flex items-center gap-1">
 <RefreshCw className={clsx('w-3 h-3', syncing && 'animate-spin')} />
 {syncing ? 'Syncing…' : 'Start Sync'}
 </button>
 </div>
 </div>
 </div>
 )}
 </Page>
 )
}

export default CloudPage
