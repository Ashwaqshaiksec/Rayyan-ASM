import { useEffect, useState } from 'react'
import { Camera, ExternalLink } from 'lucide-react'
import { screenshotGalleryApi } from '@/utils/api'
import { formatDistanceToNow } from 'date-fns'
import toast from 'react-hot-toast'
import { Page, SkeletonTable, Empty } from './shared'

export function ScreenshotsPage() {
 const [assets, setAssets] = useState<unknown[]>([])
 const [loading, setLoading] = useState(true)

 useEffect(() => {
 screenshotGalleryApi.list(50).then(({ data }) => {
 setAssets(data.data ?? [])
 setLoading(false)
 }).catch(() => {
 toast.error('Failed to load screenshots')
 setLoading(false)
 })
 }, [])

 return (
 <Page title="Screenshots" subtitle="Captured web assets">
 {loading ? <SkeletonTable /> : (
 <div className="grid grid-cols-2 lg:grid-cols-3 xl:grid-cols-4 gap-4">
 {(assets as Array<{ id: string; url: string; title: string; status_code: number; screenshotted: boolean; scanned_at: string }>).map(a => (
 <div key={a.id} className="card overflow-hidden group">
 <div className="aspect-video bg-surface-2 flex items-center justify-center relative">
 {a.screenshotted ? (
 <img src={`/api/v1/screenshots/${a.id}`} alt={a.title || a.url}
 className="w-full h-full object-cover" onError={e => (e.currentTarget.style.display = 'none')} />
 ) : (
 <Camera className="w-8 h-8 text-text-muted" />
 )}
 <div className="absolute inset-0 bg-black/60 opacity-0 group-hover:opacity-100 transition-opacity flex items-center justify-center">
 <a href={a.url} target="_blank" rel="noreferrer"
 className="text-white text-xs flex items-center gap-1">
 <ExternalLink className="w-3 h-3" />Visit
 </a>
 </div>
 </div>
 <div className="p-2">
 <p className="text-xs text-text-primary truncate">{a.title || a.url}</p>
 <p className="text-xs text-text-muted truncate">{a.url}</p>
 <div className="flex items-center justify-between mt-1">
 <span className="badge-gray text-xs">{a.status_code}</span>
 <span className="text-xs text-text-muted">{formatDistanceToNow(new Date(a.scanned_at), { addSuffix: true })}</span>
 </div>
 </div>
 </div>
 ))}
 {assets.length === 0 && <div className="col-span-full"><Empty label="No screenshots captured yet" /></div>}
 </div>
 )}
 </Page>
 )
}

export default ScreenshotsPage
