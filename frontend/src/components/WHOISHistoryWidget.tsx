import { useEffect, useState } from 'react'
import { Camera } from 'lucide-react'
import { whoisHistoryApi } from '@/utils/api'
import { format } from 'date-fns'
import toast from 'react-hot-toast'
import { Loading, Empty } from '@/pages/shared'

export function WHOISHistoryWidget({ domain }: { domain: string }) {
  const [history, setHistory] = useState<unknown[]>([])
  const [loading, setLoading] = useState(false)
  const [snapping, setSnapping] = useState(false)

  async function load(d: string) {
    if (!d) return
    setLoading(true)
    try {
      const { data } = await whoisHistoryApi.list(d, 10)
      setHistory(data.data ?? [])
    } catch {
      toast.error('Failed to load WHOIS history')
    } finally {
      setLoading(false)
    }
  }

  useEffect(() => { if (domain) load(domain) }, [domain])

  async function snap() {
    setSnapping(true)
    try {
      await whoisHistoryApi.snap(domain)
      await load(domain)
      toast.success('WHOIS snapshot saved')
    } catch {
      toast.error('WHOIS snapshot failed')
    } finally {
      setSnapping(false)
    }
  }

  return (
    <div className="space-y-2">
      <div className="flex items-center justify-between">
        <span className="text-xs font-medium text-text-primary">WHOIS History ({history.length})</span>
        <button onClick={snap} disabled={snapping} className="btn-ghost text-xs flex items-center gap-1">
          <Camera className="w-3 h-3" />{snapping ? 'Snapping…' : 'Snap now'}
        </button>
      </div>
      {loading ? <Loading /> : (
        <div className="space-y-2 max-h-48 overflow-y-auto">
          {(history as Array<{ id: string; registrar: string; expiry_date?: string; snapped_at: string }>).map(h => (
            <div key={h.id} className="px-3 py-2 bg-surface-2 rounded-md text-xs space-y-1">
              <div className="flex items-center justify-between">
                <span className="text-text-muted">{format(new Date(h.snapped_at), 'yyyy-MM-dd HH:mm')}</span>
                {h.expiry_date && <span className="text-text-muted">Exp: {format(new Date(h.expiry_date), 'yyyy-MM-dd')}</span>}
              </div>
              <div className="text-text-secondary">{h.registrar || 'Unknown registrar'}</div>
            </div>
          ))}
          {history.length === 0 && <Empty label="No history — snap one to start" />}
        </div>
      )}
    </div>
  )
}

export default WHOISHistoryWidget
