// shared.tsx — small UI building blocks reused across multiple page modules.
// Extracted from AllPages.tsx so individual pages can be code-split into
// their own lazy-loaded chunks without pulling in the rest of the old
// monolithic barrel file.
//
// One export here (scanTargets) is a plain helper rather than a component,
// which trips react-refresh/only-export-components. Moving it to its own
// file would mean updating every page that imports from this shared module
// for a Fast-Refresh nicety with no behavioral effect, so disabled at file
// scope instead.
/* eslint-disable react-refresh/only-export-components */
import { useEffect, useRef, useState, type ReactNode, type ElementType } from 'react'
import { Download, Tag, Trash2, Radar, ChevronDown, X } from 'lucide-react'
import clsx from 'clsx'

export function Page({ title, subtitle, actions, children }: {
  title: string; subtitle?: string
  actions?: ReactNode; children: ReactNode
}) {
  return (
    <div className="p-6 max-w-7xl mx-auto space-y-4 animate-fade-in">
      <div className="flex items-center justify-between gap-4 flex-wrap">
        <div>
          <h1 className="text-lg font-semibold text-text-primary tracking-tight">{title}</h1>
          {subtitle && <p className="text-sm text-text-muted mt-0.5">{subtitle}</p>}
        </div>
        {actions && <div className="flex items-center gap-2 flex-shrink-0">{actions}</div>}
      </div>
      {children}
    </div>
  )
}

export function TableCard({ children }: { children: ReactNode }) {
  return <div className="card overflow-hidden"><div className="table-container"><table className="table">{children}</table></div></div>
}

export function Loading() {
  return (
    <div className="flex flex-col items-center justify-center gap-2 py-14 text-text-muted">
      <div className="w-5 h-5 border-2 border-accent-cyan/25 border-t-accent-cyan rounded-full animate-spin" />
      <span className="text-xs">Loading…</span>
    </div>
  )
}

/** Skeleton shimmer for table-based pages (most common layout). */
export function SkeletonTable({ rows = 8, cols = 5 }: { rows?: number; cols?: number }) {
  return (
    <div className="card overflow-hidden">
      <div className="table-container">
        <table className="table">
          <thead>
            <tr>
              {Array.from({ length: cols }).map((_, i) => (
                <th key={i}><div className="skeleton-bar h-3 w-20" /></th>
              ))}
            </tr>
          </thead>
          <tbody>
            {Array.from({ length: rows }).map((_, r) => (
              <tr key={r} className="!cursor-default hover:!bg-transparent">
                {Array.from({ length: cols }).map((_, c) => (
                  <td key={c}>
                    <div
                      className="skeleton-bar h-3"
                      style={{ width: `${55 + ((r * 3 + c * 7) % 40)}%` }}
                    />
                  </td>
                ))}
              </tr>
            ))}
          </tbody>
        </table>
      </div>
    </div>
  )
}

/** Skeleton shimmer for stat-card / dashboard grid pages. */
export function SkeletonCards({ cards = 4 }: { cards?: number }) {
  return (
    <div className="space-y-4">
      <div className={`grid gap-4 grid-cols-2 md:grid-cols-${Math.min(cards, 4)}`}>
        {Array.from({ length: cards }).map((_, i) => (
          <div key={i} className="stat-card">
            <div className="w-8 h-8 skeleton-bar rounded-lg" />
            <div className="h-6 skeleton-bar w-16" />
            <div className="h-3 skeleton-bar w-24" />
          </div>
        ))}
      </div>
      <SkeletonTable rows={5} />
    </div>
  )
}

/**
 * Empty state — deliberately not just muted centered text. An empty screen
 * is an invitation to act, so it gets an icon for visual weight and its
 * label is expected to say what to do next (most call sites already phrase
 * it that way, e.g. "No relationships yet — click Rebuild graph").
 * `icon` defaults to Radar (this app's own "scanning for something" motif,
 * echoed in the discovery iconography) so most call sites need no change.
 */
export function Empty({ label, icon: Icon = Radar, action }: {
  label: string; icon?: ElementType; action?: ReactNode
}) {
  return (
    <div className="flex flex-col items-center justify-center gap-3 py-12 px-6 text-center">
      <div className="w-10 h-10 rounded-full border border-dashed border-border flex items-center justify-center text-text-muted">
        <Icon className="w-4 h-4" />
      </div>
      <p className="text-sm text-text-muted max-w-sm leading-relaxed">{label}</p>
      {action}
    </div>
  )
}

export function scanTargets(targets: Record<string, unknown> | undefined): string[] {
  const raw = targets?.targets
  if (Array.isArray(raw)) return raw.map(String)
  if (typeof raw === 'string') return [raw]
  return []
}

const SEVERITY_DOT: Record<string, string> = {
  critical: 'bg-accent-red', high: 'bg-accent-orange', medium: 'bg-accent-yellow',
  low: 'bg-accent-blue', info: 'bg-text-muted',
}

export function SeverityBadge({ s }: { s: string }) {
  const cls: Record<string, string> = {
    critical: 'badge-red', high: 'bg-accent-orange/10 text-accent-orange border border-accent-orange/25',
    medium: 'badge-yellow', low: 'badge-blue', info: 'bg-surface-2 text-text-muted border border-border',
  }
  return (
    <span className={clsx('badge text-xs', cls[s] ?? 'badge-blue')}>
      <span className={clsx('w-1.5 h-1.5 rounded-full flex-shrink-0', SEVERITY_DOT[s] ?? 'bg-accent-blue')} />
      {s}
    </span>
  )
}

const STATUS_DOT: Record<string, string> = {
  open: 'bg-accent-red', acknowledged: 'bg-accent-yellow', fixed: 'bg-accent-green',
  false_positive: 'bg-text-muted', risk_accepted: 'bg-accent-blue', active: 'bg-accent-green',
  dead: 'bg-accent-red', completed: 'bg-accent-green', failed: 'bg-accent-red',
  running: 'bg-accent-yellow', pending: 'bg-text-muted',
}

export function StatusBadge({ s }: { s: string }) {
  const cls: Record<string, string> = {
    open: 'badge-red', acknowledged: 'badge-yellow', fixed: 'badge-green',
    false_positive: 'bg-surface-2 text-text-muted border border-border',
    risk_accepted: 'badge-blue', active: 'badge-green', dead: 'badge-red',
    completed: 'badge-green', failed: 'badge-red', running: 'badge-yellow',
    pending: 'bg-surface-2 text-text-muted border border-border',
  }
  const isLive = s === 'running' || s === 'active'
  return (
    <span className={clsx('badge text-xs', cls[s] ?? 'badge-blue')}>
      <span className={clsx(
        'w-1.5 h-1.5 rounded-full flex-shrink-0',
        STATUS_DOT[s] ?? 'bg-accent-blue',
        isLive && 'animate-pulse-slow'
      )} />
      {s.replace(/_/g, ' ')}
    </span>
  )
}

export function Checkbox({ checked, onChange }: { checked: boolean; onChange: () => void }) {
  return (
    <input
      type="checkbox" checked={checked} onChange={onChange}
      className="w-4 h-4 rounded-md border-border bg-surface-1 accent-accent-cyan cursor-pointer"
    />
  )
}

export function BulkBar({ count, onDelete, onTag, onExport }: {
  count: number; onDelete?: () => void; onTag?: () => void; onExport?: () => void
}) {
  if (!count) return null
  return (
    <div className="flex items-center gap-3 px-4 py-2 bg-accent-cyan/[0.06] border border-accent-cyan/25 rounded-lg text-sm shadow-xs animate-slide-up">
      <span className="text-accent-cyan font-medium">{count} selected</span>
      <div className="flex items-center gap-1 ml-auto">
        {onExport && <button onClick={onExport} className="btn-ghost text-xs flex items-center gap-1"><Download className="w-3 h-3" />Export</button>}
        {onTag && <button onClick={onTag} className="btn-ghost text-xs flex items-center gap-1"><Tag className="w-3 h-3" />Tag</button>}
        {onDelete && <button onClick={onDelete} className="btn-ghost text-xs text-accent-red hover:bg-accent-red/10 flex items-center gap-1"><Trash2 className="w-3 h-3" />Delete</button>}
      </div>
    </div>
  )
}

/** One facet's dropdown: label, active-count badge, and a checklist of
 * options each showing how many rows in the current dataset match it.
 * Options with zero matches are skipped — there's nothing commercial ASM
 * tools show less useful than a filter option that returns nothing. */
export function FacetDropdown({ label, options, selected, onToggle, onClear }: {
  label: string
  options: { value: string; count: number }[]
  selected: string[]
  onToggle: (value: string) => void
  onClear: () => void
}) {
  const [open, setOpen] = useState(false)
  const ref = useRef<HTMLDivElement>(null)

  useEffect(() => {
    if (!open) return
    const onClick = (e: MouseEvent) => {
      if (ref.current && !ref.current.contains(e.target as Node)) setOpen(false)
    }
    document.addEventListener('mousedown', onClick)
    return () => document.removeEventListener('mousedown', onClick)
  }, [open])

  if (!options.length) return null

  return (
    <div className="relative" ref={ref}>
      <button
        onClick={() => setOpen(o => !o)}
        className={clsx(
          'flex items-center gap-1.5 px-3 py-1.5 rounded-lg border text-sm transition-colors',
          selected.length ? 'border-accent-cyan/40 text-accent-cyan bg-accent-cyan/[0.06]' : 'border-border text-text-secondary hover:border-border-muted',
        )}
      >
        {label}
        {selected.length > 0 && <span className="badge-blue text-[10px] px-1.5 py-0">{selected.length}</span>}
        <ChevronDown className="w-3.5 h-3.5" />
      </button>
      {open && (
        <div className="absolute z-20 mt-1 min-w-[220px] max-h-72 overflow-y-auto card p-1.5 shadow-lg">
          {selected.length > 0 && (
            <button onClick={onClear} className="w-full text-left px-2 py-1 text-xs text-text-muted hover:text-accent-red rounded">
              Clear {label.toLowerCase()}
            </button>
          )}
          {options.map(opt => (
            <label key={opt.value} className="flex items-center gap-2 px-2 py-1.5 rounded hover:bg-surface-2 cursor-pointer text-sm">
              <input
                type="checkbox" checked={selected.includes(opt.value)}
                onChange={() => onToggle(opt.value)}
                className="w-3.5 h-3.5 rounded border-border accent-accent-cyan"
              />
              <span className="flex-1 truncate text-text-primary">{opt.value}</span>
              <span className="text-xs text-text-muted tabular-nums">{opt.count}</span>
            </label>
          ))}
        </div>
      )}
    </div>
  )
}

/** Row of FacetDropdowns plus a "clear all" pill shown once any facet is
 * active — the combinable multi-facet filter bar used across inventory
 * pages (Services, Hosts, Findings, ...). */
export function FacetFilterBar({ children, activeCount, onClearAll }: {
  children: ReactNode; activeCount: number; onClearAll: () => void
}) {
  return (
    <div className="flex items-center gap-2 flex-wrap">
      {children}
      {activeCount > 0 && (
        <button onClick={onClearAll} className="flex items-center gap-1 px-2.5 py-1.5 text-xs text-text-muted hover:text-accent-red">
          <X className="w-3 h-3" />Clear all ({activeCount})
        </button>
      )}
    </div>
  )
}
