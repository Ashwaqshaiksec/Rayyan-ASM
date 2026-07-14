import { useEffect, useMemo, useRef, useState } from 'react'
import { useLocation, useNavigate } from 'react-router-dom'
import { X, Search, Sparkles, ChevronRight, ArrowLeft } from 'lucide-react'
import clsx from 'clsx'
import { helpModules, helpGroups, findHelpModule, type HelpModule } from '@/content/helpContent'
import { reopenTutorial } from './onboardingTutorial.utils'

interface HelpPanelProps {
  open: boolean
  onClose: () => void
}

/**
 * Slide-over help panel: leads with contextual help for whatever page the
 * user is currently on, and falls back to a searchable, grouped index of
 * every module in the app so help is reachable even when you're not sure
 * what a page is called.
 */
export default function HelpPanel({ open, onClose }: HelpPanelProps) {
  const location = useLocation()
  const navigate = useNavigate()
  const [query, setQuery] = useState('')
  const [selected, setSelected] = useState<HelpModule | null>(null)
  const inputRef = useRef<HTMLInputElement>(null)

  const currentModule = useMemo(() => findHelpModule(location.pathname), [location.pathname])

  // Reset to the contextual view for the current page each time the panel
  // opens, rather than remembering whatever was last browsed.
  useEffect(() => {
    if (open) {
      setSelected(null)
      setQuery('')
      const t = setTimeout(() => inputRef.current?.focus(), 50)
      return () => clearTimeout(t)
    }
  }, [open])

  useEffect(() => {
    if (!open) return
    const onKey = (e: KeyboardEvent) => { if (e.key === 'Escape') onClose() }
    window.addEventListener('keydown', onKey)
    return () => window.removeEventListener('keydown', onKey)
  }, [open, onClose])

  const filtered = useMemo(() => {
    const q = query.trim().toLowerCase()
    if (!q) return helpModules
    return helpModules.filter((m) =>
      m.label.toLowerCase().includes(q) ||
      m.summary.toLowerCase().includes(q) ||
      m.overview.toLowerCase().includes(q) ||
      m.group.toLowerCase().includes(q)
    )
  }, [query])

  if (!open) return null

  const goTo = (m: HelpModule) => {
    if (!m.path.includes(':')) navigate(m.path)
    onClose()
  }

  const detail = selected ?? (query.trim() ? null : currentModule)

  return (
    <div className="fixed inset-0 z-50 flex justify-end">
      <div className="absolute inset-0 bg-text-primary/20 backdrop-blur-sm" onClick={onClose} />

      <div className="relative w-full max-w-md h-full bg-surface-1 border-l border-border shadow-popover flex flex-col animate-slide-up">
        <div className="flex-shrink-0 flex items-center justify-between px-4 h-14 border-b border-border">
          <div className="flex items-center gap-2">
            {detail && (
              <button
                onClick={() => setSelected(null)}
                aria-label="Back to all modules"
                className="p-1 -ml-1 text-text-muted hover:text-text-primary hover:bg-surface-2 rounded-md transition-colors"
              >
                <ArrowLeft className="w-4 h-4" />
              </button>
            )}
            <h2 className="text-sm font-semibold text-text-primary">Help</h2>
          </div>
          <button
            onClick={onClose}
            aria-label="Close help"
            className="p-1.5 text-text-muted hover:text-text-primary hover:bg-surface-2 rounded-md transition-colors"
          >
            <X className="w-4 h-4" />
          </button>
        </div>

        {!detail && (
          <div className="flex-shrink-0 px-4 py-3 border-b border-border-muted">
            <div className="relative">
              <Search className="absolute left-2.5 top-1/2 -translate-y-1/2 w-3.5 h-3.5 text-text-muted" />
              <input
                ref={inputRef}
                value={query}
                onChange={(e) => setQuery(e.target.value)}
                placeholder="Search modules and pages..."
                className="w-full pl-8 pr-3 py-2 text-sm bg-surface-2 border border-border rounded-md text-text-primary placeholder:text-text-muted focus:outline-none focus:ring-1 focus:ring-accent-cyan/50 focus:border-accent-cyan/50"
              />
            </div>
          </div>
        )}

        <div className="flex-1 overflow-y-auto">
          {detail ? (
            <ModuleDetail module={detail} onNavigate={() => goTo(detail)} />
          ) : (
            <>
              <button
                onClick={() => { reopenTutorial(); onClose() }}
                className="w-full flex items-center gap-2.5 px-4 py-3 text-left border-b border-border-muted hover:bg-surface-2 transition-colors"
              >
                <Sparkles className="w-4 h-4 text-accent-cyan flex-shrink-0" />
                <div>
                  <div className="text-sm font-medium text-text-primary">Replay the walkthrough</div>
                  <div className="text-xs text-text-muted">The full getting-started tour, from zero to first scan.</div>
                </div>
              </button>

              {query.trim() ? (
                <ModuleList modules={filtered} onSelect={setSelected} />
              ) : (
                helpGroups.map((group) => (
                  <div key={group}>
                    <div className="section-label px-4 pt-3 pb-1">{group}</div>
                    <ModuleList modules={helpModules.filter((m) => m.group === group)} onSelect={setSelected} />
                  </div>
                ))
              )}

              {query.trim() && filtered.length === 0 && (
                <div className="px-4 py-8 text-center text-sm text-text-muted">
                  No modules match "{query}".
                </div>
              )}
            </>
          )}
        </div>
      </div>
    </div>
  )
}

function ModuleList({ modules, onSelect }: { modules: HelpModule[]; onSelect: (m: HelpModule) => void }) {
  return (
    <div className="pb-2">
      {modules.map((m) => (
        <button
          key={m.path}
          onClick={() => onSelect(m)}
          className="w-full flex items-center gap-2.5 px-4 py-2 text-left hover:bg-surface-2 transition-colors group"
        >
          <m.icon className="w-3.5 h-3.5 text-text-muted flex-shrink-0" />
          <div className="min-w-0 flex-1">
            <div className="text-sm text-text-primary truncate">{m.label}</div>
            <div className="text-xs text-text-muted truncate">{m.summary}</div>
          </div>
          <ChevronRight className="w-3.5 h-3.5 text-text-muted flex-shrink-0 opacity-0 group-hover:opacity-100 transition-opacity" />
        </button>
      ))}
    </div>
  )
}

function ModuleDetail({ module, onNavigate }: { module: HelpModule; onNavigate: () => void }) {
  return (
    <div className="p-4">
      <div className="flex items-center gap-2.5 mb-3">
        <div className="reticle w-9 h-9 bg-surface-2 border border-border flex items-center justify-center flex-shrink-0">
          <module.icon className="w-4 h-4 text-accent-cyan" />
        </div>
        <div>
          <div className="text-sm font-semibold text-text-primary">{module.label}</div>
          <div className="text-xs text-text-muted">{module.group}</div>
        </div>
      </div>

      <p className="text-sm text-text-secondary leading-relaxed mb-4">{module.overview}</p>

      <div className="mb-4">
        <div className="section-label mb-1.5">How to use it</div>
        <ol className="space-y-1.5">
          {module.howTo.map((step, i) => (
            <li key={i} className="flex gap-2 text-sm text-text-secondary leading-relaxed">
              <span className="flex-shrink-0 w-4 h-4 mt-0.5 rounded-full bg-surface-2 border border-border text-[10px] font-mono flex items-center justify-center text-text-muted">
                {i + 1}
              </span>
              <span>{step}</span>
            </li>
          ))}
        </ol>
      </div>

      {module.tips && module.tips.length > 0 && (
        <div className="mb-4">
          <div className="section-label mb-1.5">Tips</div>
          <ul className="space-y-1.5">
            {module.tips.map((tip, i) => (
              <li key={i} className="text-sm text-text-secondary leading-relaxed pl-3 border-l-2 border-accent-cyan/30">
                {tip}
              </li>
            ))}
          </ul>
        </div>
      )}

      {!module.path.includes(':') && (
        <button
          onClick={onNavigate}
          className={clsx(
            'inline-flex items-center gap-1.5 px-3 py-1.5 text-xs font-medium rounded-md transition-colors',
            'bg-accent-cyan/10 text-accent-cyan border border-accent-cyan/40 hover:bg-accent-cyan/20'
          )}
        >
          Go to {module.label}
          <ChevronRight className="w-3.5 h-3.5" />
        </button>
      )}
    </div>
  )
}
