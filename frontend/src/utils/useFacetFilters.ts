import { useCallback, useMemo } from 'react'
import { useSearchParams } from 'react-router-dom'

/**
 * Multi-select, URL-persisted facet filters.
 *
 * Every inventory page previously kept filters (search text, a single
 * severity/status dropdown) in local useState — reloading the page or
 * sharing a link silently dropped whatever the user had filtered down to,
 * and only one value per facet could be selected at a time. This hook
 * keeps each facet as a comma-separated value in the URL query string, so
 * filters are combinable (AND across facets, OR within a facet's selected
 * values), shareable, and survive a reload/back-button.
 *
 * Usage:
 *   const { values, toggle, clear, isActive, activeCount } = useFacetFilters(['severity', 'status'])
 *   values.severity // string[] currently selected
 *   toggle('severity', 'critical') // add/remove one value from that facet
 */
export function useFacetFilters<F extends string>(facets: readonly F[]) {
  const [searchParams, setSearchParams] = useSearchParams()

  const values = useMemo(() => {
    const out = {} as Record<F, string[]>
    for (const f of facets) {
      const raw = searchParams.get(f)
      out[f] = raw ? raw.split(',').filter(Boolean) : []
    }
    return out
  }, [searchParams, facets])

  const toggle = useCallback((facet: F, value: string) => {
    setSearchParams(prev => {
      const next = new URLSearchParams(prev)
      const current = (next.get(facet) ?? '').split(',').filter(Boolean)
      const idx = current.indexOf(value)
      if (idx >= 0) current.splice(idx, 1)
      else current.push(value)
      if (current.length) next.set(facet, current.join(','))
      else next.delete(facet)
      return next
    }, { replace: true })
  }, [setSearchParams])

  const clear = useCallback((facet?: F) => {
    setSearchParams(prev => {
      const next = new URLSearchParams(prev)
      if (facet) next.delete(facet)
      else for (const f of facets) next.delete(f)
      return next
    }, { replace: true })
  }, [setSearchParams, facets])

  const isActive = useCallback((facet: F, value: string) => values[facet]?.includes(value) ?? false, [values])

  const activeCount = useMemo(
    () => facets.reduce((n, f) => n + (values[f]?.length ?? 0), 0),
    [facets, values],
  )

  return { values, toggle, clear, isActive, activeCount }
}

/** Tally occurrences of a field across a client-side dataset into facet
 * option counts, e.g. countBy(services, 'protocol') -> [{value:'tcp',count:120},...].
 * Sorted by count descending so the most common options surface first. */
export function countBy<T>(items: T[], key: (item: T) => string | null | undefined): { value: string; count: number }[] {
  const counts = new Map<string, number>()
  for (const item of items) {
    const v = key(item)
    if (!v) continue
    counts.set(v, (counts.get(v) ?? 0) + 1)
  }
  return [...counts.entries()]
    .map(([value, count]) => ({ value, count }))
    .sort((a, b) => b.count - a.count)
}
