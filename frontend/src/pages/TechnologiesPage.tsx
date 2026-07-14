import { useEffect, useState } from 'react'
import { techApi } from '@/utils/api'
import type { Technology } from '@/types'
import toast from 'react-hot-toast'
import { Page, TableCard, SkeletonTable } from './shared'

export function TechnologiesPage() {
 const [techs, setTechs] = useState<Technology[]>([])
 const [summary, setSummary] = useState<Record<string, number>>({})
 const [loading, setLoading] = useState(true)

 useEffect(() => {
 Promise.all([techApi.list({ limit: 500 }), techApi.summary()]).then(([a, b]) => {
 setTechs(a.data.data ?? [])
 setSummary(b.data ?? {})
 setLoading(false)
 }).catch(() => {
 toast.error('Failed to load technologies')
 setLoading(false)
 })
 }, [])

 const topCats = Object.entries(summary).sort((a, b) => b[1] - a[1]).slice(0, 6)

 return (
 <Page title="Technologies" subtitle={`${techs.length} detected`}>
 {topCats.length > 0 && (
 <div className="grid grid-cols-3 lg:grid-cols-6 gap-3">
 {topCats.map(([cat, count]) => (
 <div key={cat} className="card p-3 text-center">
 <div className="text-lg font-bold text-accent-cyan">{count}</div>
 <div className="text-xs text-text-muted truncate">{cat}</div>
 </div>
 ))}
 </div>
 )}
 {loading ? <SkeletonTable /> : (
 <TableCard>
 <thead><tr><th>Name</th><th>Category</th><th>Version</th><th>Confidence</th></tr></thead>
 <tbody>
 {techs.map(t => (
 <tr key={t.id}>
 <td><span className="text-sm text-text-primary">{t.name}</span></td>
 <td><span className="badge-gray text-xs">{t.category}</span></td>
 <td><span className="font-mono text-xs text-text-muted">{t.version || '—'}</span></td>
 <td>
 <div className="flex items-center gap-2">
 <div className="h-1 w-16 bg-surface-3 rounded-full overflow-hidden">
 <div className="h-full bg-accent-cyan rounded-full" style={{ width: `${t.confidence ?? 100}%` }} />
 </div>
 <span className="text-xs text-text-muted">{t.confidence ?? 100}%</span>
 </div>
 </td>
 </tr>
 ))}
 </tbody>
 </TableCard>
 )}
 </Page>
 )
}

export default TechnologiesPage
