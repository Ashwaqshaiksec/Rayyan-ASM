import { describe, it, expect, beforeEach } from 'vitest'
import { loadRecentSearches, saveRecentSearch, clearRecentSearches } from './recentSearches'

describe('recentSearches', () => {
  beforeEach(() => {
    localStorage.clear()
  })

  it('returns an empty array when nothing has been saved', () => {
    expect(loadRecentSearches()).toEqual([])
  })

  it('saves and reloads a search', () => {
    saveRecentSearch('severity:critical')
    expect(loadRecentSearches()).toEqual(['severity:critical'])
  })

  it('moves a repeated search to the front instead of duplicating it', () => {
    saveRecentSearch('port:443')
    saveRecentSearch('severity:high')
    saveRecentSearch('port:443')
    expect(loadRecentSearches()).toEqual(['port:443', 'severity:high'])
  })

  it('caps history at 8 entries, dropping the oldest', () => {
    for (let i = 0; i < 10; i++) saveRecentSearch(`query-${i}`)
    const recents = loadRecentSearches()
    expect(recents).toHaveLength(8)
    expect(recents[0]).toBe('query-9')
    expect(recents).not.toContain('query-0')
    expect(recents).not.toContain('query-1')
  })

  it('ignores blank/whitespace-only searches', () => {
    saveRecentSearch('   ')
    expect(loadRecentSearches()).toEqual([])
  })

  it('clearRecentSearches empties the stored history', () => {
    saveRecentSearch('asn:AS15169')
    clearRecentSearches()
    expect(loadRecentSearches()).toEqual([])
  })
})
