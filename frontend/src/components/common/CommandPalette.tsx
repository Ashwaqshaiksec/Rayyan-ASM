import { useState, useEffect, useRef, useCallback, useMemo } from 'react'
import { useNavigate } from 'react-router-dom'
import {
  Search, X, Clock, Bookmark, BookmarkPlus, ArrowRight, Loader2,
} from 'lucide-react'
import { searchApi, savedSearchApi } from '@/utils/api'
import { loadRecentSearches, saveRecentSearch } from '@/utils/recentSearches'
import { allNavItems } from '@/utils/navigation'
import type { SavedSearch } from '@/types'
import toast from 'react-hot-toast'

interface CommandPaletteProps {
  open: boolean
  onClose: () => void
}

interface SearchResponse {
  domains: { id: string; name: string; status?: string }[]
  hosts: { id: string; ip: string; hostname?: string }[]
  subdomains: { id: string; fqdn: string }[]
  services: { id: string; port: number; service: string; host_ref?: string }[]
  technologies: { id: string; name: string; version?: string }[]
  findings: { id: string; title: string; severity: string }[]
  cloud_assets: { id: string; provider: string; account_id?: string; resource_id: string; name?: string }[]
}

const EMPTY_RESULTS: SearchResponse = {
  domains: [], hosts: [], subdomains: [], services: [], technologies: [], findings: [], cloud_assets: [],
}

// One row the palette can render and select, in whichever section it
// belongs to. Building a single flat list up front — rather than tracking
// keyboard position per-section — means ArrowUp/ArrowDown/Enter can stay
// completely agnostic to which section is currently on screen.
interface PaletteEntry {
  key: string
  section: string
  icon: typeof Search
  label: string
  sublabel?: string
  badge?: string
  onSelect: () => void
}

// Search syntax hint — matches the fields the backend parser
// (internal/modules/searchquery) knows, including asn: and cloud_account:.
const EXAMPLES = ['severity:critical', 'port:443', 'cve:CVE-2024-', 'asn:AS15169', 'cloud_account:']

export default function CommandPalette({ open, onClose }: CommandPaletteProps) {
  const [query, setQuery] = useState('')
  const [results, setResults] = useState<SearchResponse | null>(null)
  const [suggestions, setSuggestions] = useState<string[]>([])
  const [loading, setLoading] = useState(false)
  const [recents, setRecents] = useState<string[]>([])
  const [saved, setSaved] = useState<SavedSearch[]>([])
  const [activeIndex, setActiveIndex] = useState(0)
  const inputRef = useRef<HTMLInputElement>(null)
  const searchDebounce = useRef<ReturnType<typeof setTimeout>>()
  const suggestDebounce = useRef<ReturnType<typeof setTimeout>>()
  const navigate = useNavigate()

  // Reset to a clean slate and refresh recents/saved every time the
  // palette opens, so it never shows stale data from a previous session.
  useEffect(() => {
    if (!open) return
    setQuery('')
    setResults(null)
    setSuggestions([])
    setActiveIndex(0)
    setRecents(loadRecentSearches())
    savedSearchApi.list().then(({ data }) => setSaved(data.data ?? [])).catch(() => {})
    // Focus on next tick so the modal has actually mounted first.
    const t = setTimeout(() => inputRef.current?.focus(), 10)
    return () => clearTimeout(t)
  }, [open])

  useEffect(() => {
    if (!open) return
    const onKey = (e: KeyboardEvent) => {
      if (e.key === 'Escape') onClose()
    }
    window.addEventListener('keydown', onKey)
    return () => window.removeEventListener('keydown', onKey)
  }, [open, onClose])

  const runSearch = useCallback((q: string) => {
    if (!q.trim()) { setResults(null); return }
    setLoading(true)
    searchApi.search(q)
      .then(({ data }) => {
        setResults(data)
        saveRecentSearch(q)
        setRecents(loadRecentSearches())
      })
      .catch(() => setResults(null))
      .finally(() => setLoading(false))
  }, [])

  function onChange(value: string) {
    setQuery(value)
    setActiveIndex(0)

    clearTimeout(searchDebounce.current)
    clearTimeout(suggestDebounce.current)

    if (value.trim().length < 2) {
      setResults(null)
      setSuggestions([])
      return
    }

    suggestDebounce.current = setTimeout(() => {
      searchApi.suggestions(value).then(({ data }) => setSuggestions(data.suggestions ?? [])).catch(() => setSuggestions([]))
    }, 150)

    searchDebounce.current = setTimeout(() => runSearch(value), 300)
  }

  function goTo(path: string) {
    navigate(path)
    onClose()
  }

  async function saveCurrentSearch() {
    if (!query.trim()) return
    const name = prompt('Name this search:', query)
    if (!name) return
    await savedSearchApi.create(name, query)
    toast.success('Search saved')
    savedSearchApi.list().then(({ data }) => setSaved(data.data ?? [])).catch(() => {})
  }

  function applySaved(s: SavedSearch) {
    setQuery(s.query)
    savedSearchApi.use(s.id).catch(() => {})
    runSearch(s.query)
  }

  const r = results ?? EMPTY_RESULTS
  const hasQuery = query.trim().length > 0
  const showResults = query.trim().length >= 2

  // Nav items matching the current query — shown as "Go to" shortcuts.
  // Empty query shows every top-level destination (a quick launcher);
  // once typing starts, only label matches survive, capped so results
  // below the fold aren't crowded out.
  const navMatches = useMemo(() => {
    const q = query.trim().toLowerCase()
    const matches = q ? allNavItems.filter((i) => i.label.toLowerCase().includes(q)) : allNavItems
    return matches.slice(0, hasQuery ? 5 : 8)
  }, [query, hasQuery])

  // Build the flat, keyboard-navigable entry list in exactly the order
  // sections render below.
  const entries = useMemo<PaletteEntry[]>(() => {
    const list: PaletteEntry[] = []

    if (!hasQuery) {
      for (const s of saved) {
        list.push({
          key: `saved-${s.id}`, section: 'saved', icon: Bookmark, label: s.name, sublabel: s.query,
          onSelect: () => applySaved(s),
        })
      }
      for (const rec of recents) {
        list.push({
          key: `recent-${rec}`, section: 'recent', icon: Clock, label: rec,
          onSelect: () => { setQuery(rec); runSearch(rec) },
        })
      }
    }

    for (const item of navMatches) {
      list.push({
        key: `nav-${item.path}`, section: 'nav', icon: item.icon, label: item.label, badge: 'Go to',
        onSelect: () => goTo(item.path),
      })
    }

    if (showResults && results) {
      const push = <T extends { id: string },>(
        section: string, items: T[], badge: string,
        label: (x: T) => string, sublabel: (x: T) => string | undefined, path: (x: T) => string,
      ) => {
        for (const item of items) {
          list.push({
            key: `${section}-${item.id}`, section, icon: ArrowRight, label: label(item), sublabel: sublabel(item), badge,
            onSelect: () => goTo(path(item)),
          })
        }
      }
      push('domains', r.domains ?? [], 'Domain', (d) => d.name, (d) => d.status, (d) => `/domains/${d.id}`)
      push('hosts', r.hosts ?? [], 'Host', (h) => h.ip, (h) => h.hostname, () => '/hosts')
      push('subdomains', r.subdomains ?? [], 'Subdomain', (s) => s.fqdn, () => undefined, () => '/subdomains')
      push('services', r.services ?? [], 'Service', (s) => `${s.host_ref ?? ''}:${s.port}`, (s) => s.service, () => '/services')
      push('technologies', r.technologies ?? [], 'Technology', (t) => t.name, (t) => t.version, () => '/technologies')
      push('findings', r.findings ?? [], 'Finding', (f) => f.title, (f) => f.severity, () => '/findings')
      push('cloud_assets', r.cloud_assets ?? [], 'Cloud', (c) => c.name || c.resource_id, (c) => c.account_id, () => '/cloud')
    }

    return list
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [hasQuery, showResults, results, saved, recents, navMatches])

  useEffect(() => {
    setActiveIndex((i) => Math.min(i, Math.max(entries.length - 1, 0)))
  }, [entries.length])

  function onKeyDown(e: React.KeyboardEvent) {
    if (e.key === 'ArrowDown') {
      e.preventDefault()
      setActiveIndex((i) => Math.min(i + 1, entries.length - 1))
    } else if (e.key === 'ArrowUp') {
      e.preventDefault()
      setActiveIndex((i) => Math.max(i - 1, 0))
    } else if (e.key === 'Enter') {
      e.preventDefault()
      const active = entries[activeIndex]
      if (active) {
        active.onSelect()
      } else if (query.trim()) {
        runSearch(query)
        navigate(`/search?q=${encodeURIComponent(query)}`)
        onClose()
      }
    }
  }

  function applySuggestion(s: string) {
    setQuery(s)
    if (!s.endsWith(':')) {
      searchApi.suggestions(s).then(({ data }) => setSuggestions(data.suggestions ?? [])).catch(() => {})
      runSearch(s)
    } else {
      searchApi.suggestions(s).then(({ data }) => setSuggestions(data.suggestions ?? [])).catch(() => {})
    }
  }

  if (!open) return null

  const sectionLabel: Record<string, string> = {
    saved: 'Saved searches',
    recent: 'Recent searches',
    nav: hasQuery ? 'Jump to' : 'Go to',
    domains: 'Domains', hosts: 'Hosts', subdomains: 'Subdomains', services: 'Services',
    technologies: 'Technologies', findings: 'Findings', cloud_assets: 'Cloud assets',
  }
  const sectionOrder = ['saved', 'recent', 'nav', 'domains', 'hosts', 'subdomains', 'services', 'technologies', 'findings', 'cloud_assets']

  let runningIndex = -1

  return (
    <div
      className="fixed inset-0 z-50 flex items-start justify-center bg-black/60 backdrop-blur-sm p-4 pt-[10vh]"
      onClick={(e) => { if (e.target === e.currentTarget) onClose() }}
    >
      <div className="w-full max-w-2xl bg-surface-1 border border-border rounded-xl shadow-popover overflow-hidden animate-fade-in flex flex-col max-h-[70vh]">
        <div className="flex items-center gap-3 px-4 py-3.5 border-b border-border flex-shrink-0">
          <Search className="w-5 h-5 text-text-muted flex-shrink-0" />
          <input
            ref={inputRef}
            value={query}
            onChange={(e) => onChange(e.target.value)}
            onKeyDown={onKeyDown}
            placeholder="Search domains, IPs, CVEs, ASNs, cloud accounts…"
            className="flex-1 bg-transparent text-base text-text-primary placeholder-text-muted focus:outline-none"
          />
          {loading && <Loader2 className="w-4 h-4 text-text-muted animate-spin flex-shrink-0" />}
          {hasQuery && (
            <button
              onClick={saveCurrentSearch}
              title="Save this search"
              className="flex-shrink-0 p-1 text-text-muted hover:text-accent-cyan transition-colors"
            >
              <BookmarkPlus className="w-4 h-4" />
            </button>
          )}
          <button onClick={onClose} className="flex-shrink-0 p-1 text-text-muted hover:text-text-primary transition-colors">
            <X className="w-4 h-4" />
          </button>
        </div>

        {!hasQuery && (
          <div className="flex items-center gap-2 px-4 py-2 border-b border-border-muted flex-wrap flex-shrink-0">
            <span className="text-xs text-text-muted">Try:</span>
            {EXAMPLES.map((ex) => (
              <button
                key={ex}
                onClick={() => onChange(ex)}
                className="text-xs font-mono text-accent-cyan hover:underline"
              >
                {ex}
              </button>
            ))}
          </div>
        )}

        {suggestions.length > 0 && (
          <div className="flex items-center gap-1.5 px-4 py-2 border-b border-border-muted overflow-x-auto flex-shrink-0">
            {suggestions.map((s) => (
              <button
                key={s}
                onClick={() => applySuggestion(s)}
                className="flex-shrink-0 px-2.5 py-1 rounded-full text-xs font-mono border border-border text-text-secondary hover:border-accent-cyan/40 hover:text-accent-cyan transition-colors"
              >
                {s}
              </button>
            ))}
          </div>
        )}

        <div className="overflow-y-auto flex-1">
          {sectionOrder.map((section) => {
            const rows = entries.filter((e) => e.section === section)
            if (rows.length === 0) return null
            return (
              <div key={section} className="py-1.5">
                <div className="section-label px-4 py-1.5">{sectionLabel[section]}</div>
                {rows.map((entry) => {
                  runningIndex += 1
                  const idx = runningIndex
                  const active = idx === activeIndex
                  return (
                    <button
                      key={entry.key}
                      onMouseEnter={() => setActiveIndex(idx)}
                      onClick={entry.onSelect}
                      className={`w-full flex items-center gap-3 px-4 py-2.5 text-left transition-colors ${
                        active ? 'bg-surface-2' : 'hover:bg-surface-2'
                      }`}
                    >
                      <entry.icon className="w-3.5 h-3.5 text-text-muted flex-shrink-0" />
                      <div className="flex-1 min-w-0">
                        <div className="text-sm text-text-primary truncate font-mono">{entry.label}</div>
                        {entry.sublabel && <div className="text-xs text-text-muted truncate">{entry.sublabel}</div>}
                      </div>
                      {entry.badge && (
                        <span className="flex-shrink-0 text-[10px] uppercase tracking-wide text-text-muted bg-surface-3 px-1.5 py-0.5 rounded-md">
                          {entry.badge}
                        </span>
                      )}
                    </button>
                  )
                })}
              </div>
            )
          })}

          {showResults && !loading && results && entries.filter((e) => e.section !== 'nav').length === 0 && (
            <div className="px-4 py-8 text-center text-sm text-text-muted">No results for "{query}"</div>
          )}
        </div>

        <div className="flex items-center gap-3 px-4 py-2 border-t border-border-muted text-[11px] text-text-muted flex-shrink-0">
          <span><kbd className="px-1 py-0.5 rounded border border-border bg-surface-2 font-mono">↑↓</kbd> navigate</span>
          <span><kbd className="px-1 py-0.5 rounded border border-border bg-surface-2 font-mono">↵</kbd> select</span>
          <span><kbd className="px-1 py-0.5 rounded border border-border bg-surface-2 font-mono">esc</kbd> close</span>
        </div>
      </div>
    </div>
  )
}
