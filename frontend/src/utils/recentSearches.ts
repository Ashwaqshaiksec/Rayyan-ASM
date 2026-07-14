// Shared "recent searches" storage, used by both the inline header
// GlobalSearch box and the full CommandPalette (Ctrl+K) so a search made in
// either place shows up as a recent in both, instead of each keeping its
// own separate history.
const RECENTS_KEY = 'rayyan.recent-searches'
const MAX_RECENTS = 8

export function loadRecentSearches(): string[] {
  try {
    const raw = localStorage.getItem(RECENTS_KEY)
    return raw ? (JSON.parse(raw) as string[]) : []
  } catch {
    return []
  }
}

export function saveRecentSearch(q: string) {
  const trimmed = q.trim()
  if (!trimmed) return
  try {
    const next = [trimmed, ...loadRecentSearches().filter((r) => r !== trimmed)].slice(0, MAX_RECENTS)
    localStorage.setItem(RECENTS_KEY, JSON.stringify(next))
  } catch {
    // Ignore storage errors (e.g. private browsing, quota exceeded).
  }
}

export function clearRecentSearches() {
  try {
    localStorage.removeItem(RECENTS_KEY)
  } catch {
    // Ignore storage errors.
  }
}
