import { useEffect, useState, useCallback } from 'react'
import { RefreshCw, Plus, Minus } from 'lucide-react'
import { changeDetectApi } from '@/utils/api'
import type { AssetChangeEvent } from '@/types'
import clsx from 'clsx'
import toast from 'react-hot-toast'
import { Page, SkeletonTable, Empty } from './shared'
import { ASSET_TYPE_LABEL, ChangeEventRow } from './risk-shared'

export function ChangeTimelinePage() {
 const [events, setEvents] = useState<AssetChangeEvent[]>([])
 const [loading, setLoading] = useState(true)
 const [running, setRunning] = useState(false)
 const [assetType, setAssetType] = useState('')
 const [changeType, setChangeType] = useState('')

 const load = useCallback(async () => {
 setLoading(true)
 try {
 const params: Record<string, unknown> = {}
 if (assetType) params.asset_type = assetType
 if (changeType) params.change_type = changeType
 const { data } = await changeDetectApi.timeline(params)
 setEvents(data.data ?? [])
 } finally {
 setLoading(false)
 }
 }, [assetType, changeType])

 useEffect(() => { load() }, [load])

 async function runDetection() {
 setRunning(true)
 try {
 const { data } = await changeDetectApi.run()
 toast.success(`Detection run: ${data.events_found} change${data.events_found === 1 ? '' : 's'} found`)
 load()
 } catch {
 toast.error('Change detection run failed')
 } finally {
 setRunning(false)
 }
 }

 const counts = { new: 0, removed: 0, changed: 0 }
 for (const e of events) counts[e.change_type]++

 return (
 <Page title="Change Timeline" subtitle="New, removed, and changed assets across domains, hosts, services, certificates, DNS, and technologies"
 actions={
 <button onClick={runDetection} disabled={running} className="btn-primary text-sm flex items-center gap-1">
 <RefreshCw className={clsx('w-3 h-3', running && 'animate-spin')} />
 {running ? 'Running…' : 'Run detection'}
 </button>
 }>
 <div className="grid grid-cols-3 gap-4">
 <div className="card p-4">
 <div className="text-xs text-text-muted flex items-center gap-1"><Plus className="w-3 h-3 text-accent-green" /> New</div>
 <div className="text-2xl font-bold mt-1 text-accent-green">{counts.new}</div>
 </div>
 <div className="card p-4">
 <div className="text-xs text-text-muted flex items-center gap-1"><Minus className="w-3 h-3 text-accent-red" /> Removed</div>
 <div className="text-2xl font-bold mt-1 text-accent-red">{counts.removed}</div>
 </div>
 <div className="card p-4">
 <div className="text-xs text-text-muted flex items-center gap-1"><RefreshCw className="w-3 h-3 text-accent-orange" /> Changed</div>
 <div className="text-2xl font-bold mt-1 text-accent-orange">{counts.changed}</div>
 </div>
 </div>

 <div className="flex items-center gap-2">
 <select className="input text-sm" value={assetType} onChange={e => setAssetType(e.target.value)}>
 <option value="">All asset types</option>
 {Object.entries(ASSET_TYPE_LABEL).map(([v, label]) => <option key={v} value={v}>{label}</option>)}
 </select>
 <select className="input text-sm" value={changeType} onChange={e => setChangeType(e.target.value)}>
 <option value="">All change types</option>
 <option value="new">New</option>
 <option value="removed">Removed</option>
 <option value="changed">Changed</option>
 </select>
 </div>

 <div className="card p-4">
 {loading ? <SkeletonTable /> : events.length === 0 ? (
 <Empty label="No changes recorded yet — click Run detection to take a baseline" />
 ) : (
 <div>{events.map(e => <ChangeEventRow key={e.id} event={e} />)}</div>
 )}
 </div>
 </Page>
 )
}

export default ChangeTimelinePage
