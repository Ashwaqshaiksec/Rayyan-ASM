import { useEffect, useState } from 'react'
import { Trash2, Lock, Unlock } from 'lucide-react'
import { userApi } from '@/utils/api'
import type { User } from '@/types'
import { formatDistanceToNow } from 'date-fns'
import toast from 'react-hot-toast'
import { Page, TableCard, SkeletonTable, StatusBadge } from './shared'

export function UsersPage() {
 const [users, setUsers] = useState<User[]>([])
 const [loading, setLoading] = useState(true)

 useEffect(() => {
 userApi.list().then(({ data }) => {
 setUsers(data.data ?? [])
 setLoading(false)
 }).catch(() => {
 toast.error('Failed to load users')
 setLoading(false)
 })
 }, [])

 async function del(id: string) {
 if (!confirm('Delete user?')) return
 await userApi.delete(id)
 setUsers(u => u.filter(x => x.id !== id))
 }

 return (
 <Page title="Users" subtitle={`${users.length} members`}>
 {loading ? <SkeletonTable /> : (
 <TableCard>
 <thead><tr><th>Name</th><th>Email</th><th>Role</th><th>MFA</th><th>Status</th><th>Last Login</th><th>Actions</th></tr></thead>
 <tbody>
 {users.map(u => (
 <tr key={u.id}>
 <td><span className="text-sm text-text-primary">{u.first_name} {u.last_name}</span></td>
 <td><span className="text-sm text-text-secondary">{u.email}</span></td>
 <td><span className="badge-gray text-xs">{u.role}</span></td>
 <td>{u.mfa_enabled ? <Lock className="w-4 h-4 text-accent-green" /> : <Unlock className="w-4 h-4 text-text-muted" />}</td>
 <td><StatusBadge s={u.active ? 'active' : 'inactive'} /></td>
 <td><span className="text-xs text-text-muted">{u.last_login_at ? formatDistanceToNow(new Date(u.last_login_at), { addSuffix: true }) : 'Never'}</span></td>
 <td>
 <button onClick={() => del(u.id)} className="btn-ghost text-xs text-accent-red">
 <Trash2 className="w-3 h-3" />
 </button>
 </td>
 </tr>
 ))}
 </tbody>
 </TableCard>
 )}
 </Page>
 )
}

export default UsersPage
