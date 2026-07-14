import { useEffect, useState } from 'react'
import { certificateApi } from '@/utils/api'
import type { Certificate } from '@/types'
import { format, differenceInDays } from 'date-fns'
import clsx from 'clsx'
import toast from 'react-hot-toast'
import { Page, TableCard, SkeletonTable, StatusBadge } from './shared'

export function CertificatesPage() {
 const [certs, setCerts] = useState<Certificate[]>([])
 const [expiring, setExpiring] = useState<Certificate[]>([])
 const [loading, setLoading] = useState(true)
 const [tab, setTab] = useState<'all' | 'expiring'>('all')

 useEffect(() => {
 Promise.all([
 certificateApi.list({ limit: 300 }),
 certificateApi.expiring(30),
 ]).then(([a, b]) => {
 setCerts(a.data.data ?? [])
 setExpiring(b.data.data ?? [])
 setLoading(false)
 }).catch(() => {
 toast.error('Failed to load certificates')
 setLoading(false)
 })
 }, [])

 const shown = tab === 'expiring' ? expiring : certs

 return (
 <Page title="Certificates" subtitle={`${certs.length} total, ${expiring.length} expiring in 30d`}>
 <div className="flex gap-2">
 {(['all', 'expiring'] as const).map(t => (
 <button key={t} onClick={() => setTab(t)}
 className={clsx('btn-ghost text-xs capitalize', tab === t && 'text-accent-cyan border-accent-cyan/30')}>
 {t === 'all' ? `All (${certs.length})` : `Expiring (${expiring.length})`}
 </button>
 ))}
 </div>
 {loading ? <SkeletonTable /> : (
 <TableCard>
 <thead><tr><th>Subject</th><th>Issuer</th><th>SANs</th><th>Not Before</th><th>Not After</th><th>Days Left</th><th>Status</th></tr></thead>
 <tbody>
 {shown.map(c => {
 const daysLeft = c.not_after ? differenceInDays(new Date(c.not_after), new Date()) : null
 return (
 <tr key={c.id}>
 <td><span className="font-mono text-xs text-text-primary truncate max-w-[200px] block" title={c.subject}>{c.subject}</span></td>
 <td><span className="text-xs text-text-muted truncate max-w-[160px] block" title={c.issuer}>{c.issuer}</span></td>
 <td><span className="text-xs text-text-muted" title={(c.subject_alt_names ?? []).join(', ') || undefined}>{(c.subject_alt_names ?? []).length} SANs</span></td>
 <td><span className="text-xs text-text-muted">{c.not_before ? format(new Date(c.not_before), 'yyyy-MM-dd') : '—'}</span></td>
 <td><span className="text-xs text-text-muted">{c.not_after ? format(new Date(c.not_after), 'yyyy-MM-dd') : '—'}</span></td>
 <td>
 {daysLeft !== null && (
 <span className={clsx('text-xs font-medium',
 daysLeft <= 7 ? 'text-accent-red' : daysLeft <= 30 ? 'text-accent-orange' : 'text-accent-green'
 )}>{daysLeft}d</span>
 )}
 </td>
 <td><StatusBadge s={c.is_expired ? 'expired' : 'active'} /></td>
 </tr>
 )
 })}
 </tbody>
 </TableCard>
 )}
 </Page>
 )
}

export default CertificatesPage
