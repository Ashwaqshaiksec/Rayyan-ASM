export type Theme = 'dark' | 'light' | 'slate'

const STORAGE_KEY = 'rayyan-theme'
const VALID: Theme[] = ['dark', 'light', 'slate']

// Applies the theme to <html> so every CSS var / Tailwind color that
// derives from [data-theme] picks it up, on every page — not just while
// Settings happens to be mounted.
export function applyTheme(t: Theme) {
  const root = document.documentElement
  root.classList.remove('theme-dark', 'theme-light', 'theme-slate', 'dark', 'light', 'slate')
  root.classList.add(`theme-${t}`, t)
  root.setAttribute('data-theme', t)
}

// Applied synchronously (before the API call resolves) from whatever was
// last saved locally, so there's no flash of the wrong theme on reload —
// then reconciled with the server value once /auth/theme responds, in case
// the user changed it from another device/session.
export function initTheme() {
  const cached = localStorage.getItem(STORAGE_KEY) as Theme | null
  applyTheme(cached && VALID.includes(cached) ? cached : 'slate')
}

export function cacheTheme(t: Theme) {
  localStorage.setItem(STORAGE_KEY, t)
}
