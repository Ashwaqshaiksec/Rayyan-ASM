import { useEffect, useRef, useState, useCallback } from 'react'
import { useSearchParams } from 'react-router-dom'
import { Search as SearchIcon, BookmarkPlus, Bookmark, X } from 'lucide-react'
import { searchApi, savedSearchApi } from '@/utils/api'
import type { SavedSearch } from '@/types'
import toast from 'react-hot-toast'
import { Page, Empty } from './shared'
import { flatten, type SearchResponse } from './searchPage.utils'

// Search syntax hint shown under the box — discoverable without docs, and
// matches the same fields the parser (internal/modules/searchquery) knows.
const EXAMPLES = ['port:443', 'severity:critical', 'asn:AS15169', 'cloud_account:111111111111']

export function SearchPage() {
  const [params, setParams] = useSearchParams()
  const [q, setQ] = useState(params.get('q') ?? '')
  const [results, setResults] = useState<SearchResponse | null>(null)
  const [loading, setLoading] = useState(false)
  const [suggestions, setSuggestions] = useState<string[]>([])
  const [showSuggestions, setShowSuggestions] = useState(false)
  const [saved, setSaved] = useState<SavedSearch[]>([])
  const debounceRef = useRef<ReturnType<typeof setTimeout>>()

  const loadSaved = useCallback(() => {
    savedSearchApi.list().then(({ data }) => setSaved(data.data ?? [])).catch(() => {})
  }, [])

  useEffect(() => { loadSaved() }, [loadSaved])

  const runSearch = useCallback(async (query: string) => {
    if (!query.trim()) { setResults(null); return }
    setLoading(true)
    setShowSuggestions(false)
    try {
      const { data } = await searchApi.search(query)
      setResults(data)
      setParams({ q: query }, { replace: true })
    } catch {
      toast.error('Search failed')
    } finally {
      setLoading(false)
    }
  }, [setParams])

  // Run the query already in the URL on first load, so a shared/bookmarked
  // search link actually shows results instead of an empty box.
  useEffect(() => {
    const initial = params.get('q')
    if (initial) runSearch(initial)
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [])

  function onChange(value: string) {
    setQ(value)
    clearTimeout(debounceRef.current)
    if (value.trim().length < 2) { setSuggestions([]); setShowSuggestions(false); return }
    debounceRef.current = setTimeout(async () => {
      try {
        const { data } = await searchApi.suggestions(value)
        setSuggestions(data.suggestions ?? [])
        setShowSuggestions(true)
      } catch {
        setSuggestions([])
      }
    }, 150)
  }

  function applySuggestion(s: string) {
    setQ(s)
    setShowSuggestions(false)
    // Field-name suggestions end in ":" — keep typing the value instead of
    // firing a search on an incomplete query.
    if (!s.endsWith(':')) runSearch(s)
  }

  async function saveCurrentSearch() {
    if (!q.trim()) return
    const name = prompt('Name this search:', q)
    if (!name) return
    await savedSearchApi.create(name, q)
    toast.success('Search saved')
    loadSaved()
  }

  async function applySavedSearch(s: SavedSearch) {
    setQ(s.query)
    savedSearchApi.use(s.id).catch(() => {})
    runSearch(s.query)
  }

  async function deleteSaved(s: SavedSearch, e: React.MouseEvent) {
    e.stopPropagation()
    await savedSearchApi.delete(s.id)
    setSaved(prev => prev.filter(x => x.id !== s.id))
  }

  const flat = results ? flatten(results) : []

  return (
    <Page title="Global Search" subtitle="Field-qualified query syntax — combine filters and free text">
      <div className="relative">
        <div className="flex items-center gap-3">
          <div className="relative flex-1">
            <input
              className="input w-full"
              placeholder='Try "severity:critical" or "port:443 admin"'
              value={q}
              onChange={e => onChange(e.target.value)}
              onFocus={() => suggestions.length > 0 && setShowSuggestions(true)}
              onKeyDown={e => e.key === 'Enter' && runSearch(q)}
            />
            {showSuggestions && suggestions.length > 0 && (
              <div className="absolute z-20 mt-1 w-full card p-1 shadow-lg max-h-64 overflow-y-auto">
                {suggestions.map(s => (
                  <button key={s} onClick={() => applySuggestion(s)}
                    className="w-full text-left px-3 py-1.5 text-sm rounded hover:bg-surface-2 font-mono text-text-primary">
                    {s}
                  </button>
                ))}
              </div>
            )}
          </div>
          <button onClick={() => runSearch(q)} className="btn-primary flex items-center gap-2">
            <SearchIcon className="w-4 h-4" />{loading ? 'Searching…' : 'Search'}
          </button>
          <button onClick={saveCurrentSearch} disabled={!q.trim()} title="Save this search"
            className="btn-ghost flex items-center gap-2 disabled:opacity-40">
            <BookmarkPlus className="w-4 h-4" />Save
          </button>
        </div>
        <div className="flex items-center gap-2 mt-2 flex-wrap">
          <span className="text-xs text-text-muted">Try:</span>
          {EXAMPLES.map(ex => (
            <button key={ex} onClick={() => { setQ(ex); runSearch(ex) }}
              className="text-xs font-mono text-accent-cyan hover:underline">{ex}</button>
          ))}
        </div>
      </div>

      {saved.length > 0 && (
        <div className="flex items-center gap-2 flex-wrap">
          {saved.map(s => (
            <button key={s.id} onClick={() => applySavedSearch(s)}
              className="flex items-center gap-1.5 px-3 py-1.5 rounded-lg border border-border text-sm hover:border-accent-cyan/40 group">
              <Bookmark className="w-3 h-3 text-accent-cyan" />
              {s.name}
              <span onClick={e => deleteSaved(s, e)} className="opacity-0 group-hover:opacity-100 text-text-muted hover:text-accent-red">
                <X className="w-3 h-3" />
              </span>
            </button>
          ))}
        </div>
      )}

      {results?.filters && Object.keys(results.filters).length > 0 && (
        <div className="flex items-center gap-2 flex-wrap">
          {Object.entries(results.filters).map(([k, v]) => (
            <span key={k} className="badge-blue text-xs font-mono">{k}:{v}</span>
          ))}
        </div>
      )}

      {flat.length > 0 && (
        <div className="space-y-2">
          {flat.map((r, i) => (
            <div key={`${r.type}-${r.id}-${i}`} className="card p-3 flex items-center gap-3">
              <span className="badge-gray text-xs w-24 justify-center shrink-0">{r.type}</span>
              <div>
                <div className="text-sm text-text-primary font-mono">{r.title}</div>
                {r.subtitle && <div className="text-xs text-text-muted">{r.subtitle}</div>}
              </div>
            </div>
          ))}
        </div>
      )}
      {!loading && results && flat.length === 0 && <Empty label="No results found" />}
    </Page>
  )
}

export default SearchPage
