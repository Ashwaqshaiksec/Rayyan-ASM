import { useState } from 'react'
import { Search } from 'lucide-react'
import { WHOISHistoryWidget } from '@/components/WHOISHistoryWidget'
import { Page } from './shared'

export function WHOISHistoryPage() {
  const [domain, setDomain] = useState('')
  const [active, setActive] = useState('')

  function submit(e: React.FormEvent) {
    e.preventDefault()
    const d = domain.trim()
    if (d) setActive(d)
  }

  return (
    <Page title="WHOIS History" subtitle="Track WHOIS record changes over time for any domain">
      <div className="card p-4 max-w-lg">
        <form onSubmit={submit} className="flex gap-2">
          <input
            className="input flex-1 font-mono text-sm"
            placeholder="example.com"
            value={domain}
            onChange={e => setDomain(e.target.value)}
          />
          <button type="submit" className="btn-primary flex items-center gap-1">
            <Search className="w-3 h-3" />Lookup
          </button>
        </form>
      </div>
      {active && (
        <div className="card p-4 max-w-lg">
          <WHOISHistoryWidget domain={active} />
        </div>
      )}
    </Page>
  )
}

export default WHOISHistoryPage
