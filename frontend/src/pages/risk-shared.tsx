// risk-shared.tsx — helpers shared across the risk/correlation/exposure family
// of pages. These pages were all originally defined back-to-back in
// AllPages.tsx and informally shared a handful of small components and
// color maps via closure over the module scope. Splitting each page into
// its own file means those shared pieces need an explicit home; this is it.
//
// This file intentionally exports both components and plain constants/
// helpers side by side. Splitting them into separate files would mean
// touching every one of the ~30 page files that import from here for a
// purely cosmetic Fast-Refresh optimization (non-component exports here
// just mean an extra full reload on edit, not broken behavior), so the
// rule is disabled at file scope rather than refactored away.
/* eslint-disable react-refresh/only-export-components */
import { useEffect, useRef, useState, type ElementType } from 'react'
import { Link } from 'react-router-dom'
import { X, TrendingUp, TrendingDown, Plus, Minus, RefreshCw, ArrowRight } from 'lucide-react'
import clsx from 'clsx'
import { formatDistanceToNow } from 'date-fns'
import { searchApi } from '@/utils/api'
import type {
  RiskAssetRow, CorrelationNode, AssetChangeEvent, ChangeAssetType, ChangeType,
  ExposureAssetRow,
} from '@/types'
import { Empty, TableCard } from './shared'

// ---------------------------------------------------------------------------
// RiskScorePage helpers
// ---------------------------------------------------------------------------

export const TIER_COLOR: Record<string, string> = {
  critical: 'text-accent-red', high: 'text-accent-orange', medium: 'text-accent-blue', low: 'text-accent-green',
}

export function hexToRgba(hex: string, alpha: number): string {
  const m = hex.replace('#', '')
  const r = parseInt(m.substring(0, 2), 16)
  const g = parseInt(m.substring(2, 4), 16)
  const b = parseInt(m.substring(4, 6), 16)
  return `rgba(${r}, ${g}, ${b}, ${alpha})`
}

export function assetDetailLink(a: RiskAssetRow): string | null {
  if (a.asset_type === 'host') return `/hosts/${a.id}`
  if (a.asset_type === 'domain') return `/domains/${a.id}`
  return null
}

// ---------------------------------------------------------------------------
// CorrelationPage / AssetRelationshipsPage helpers
// ---------------------------------------------------------------------------

const NODE_TYPE_COLOR: Record<string, string> = {
  domain: 'text-accent-blue bg-accent-blue/10 border-accent-blue/20',
  subdomain: 'text-accent-purple bg-accent-purple/10 border-accent-purple/20',
  host: 'text-accent-green bg-accent-green/10 border-accent-green/20',
  service: 'text-accent-cyan bg-accent-cyan/10 border-accent-cyan/20',
  certificate: 'text-accent-orange bg-accent-orange/10 border-accent-orange/20',
  asn: 'text-text-secondary bg-surface-3 border-surface-3',
  asn_range: 'text-text-secondary bg-surface-3 border-surface-3',
  registrant: 'text-accent-red bg-accent-red/10 border-accent-red/20',
  technology: 'text-accent-cyan bg-accent-cyan/10 border-accent-cyan/20',
  finding: 'text-accent-red bg-accent-red/10 border-accent-red/20',
}

export function NodePill({ node }: { node: CorrelationNode }) {
  return (
    <span className={clsx('badge text-xs border', NODE_TYPE_COLOR[node.type] ?? 'bg-surface-3 text-text-muted border-surface-3')}>
      {node.type}
    </span>
  )
}

export function pickerRows(results: Record<string, unknown[]>): CorrelationNode[] {
  const rows: CorrelationNode[] = []
  for (const d of (results.domains ?? []) as { id: string; name: string }[]) {
    rows.push({ type: 'domain', id: d.id, label: d.name })
  }
  for (const s of (results.subdomains ?? []) as { id: string; fqdn: string }[]) {
    rows.push({ type: 'subdomain', id: s.id, label: s.fqdn })
  }
  for (const h of (results.hosts ?? []) as { id: string; ip: string }[]) {
    rows.push({ type: 'host', id: h.id, label: h.ip })
  }
  for (const s of (results.services ?? []) as { id: string; port: number; protocol: string; service?: string }[]) {
    rows.push({ type: 'service', id: s.id, label: `${s.port}/${s.protocol}${s.service ? ' ' + s.service : ''}` })
  }
  return rows
}

export function AssetPicker({ placeholder, value, onSelect }: {
  placeholder: string
  value: CorrelationNode | null
  onSelect: (node: CorrelationNode | null) => void
}) {
  const [query, setQuery] = useState('')
  const [results, setResults] = useState<Record<string, unknown[]> | null>(null)
  const [open, setOpen] = useState(false)
  const timer = useRef<ReturnType<typeof setTimeout>>()

  useEffect(() => {
    if (query.length < 2) { setResults(null); return }
    clearTimeout(timer.current)
    timer.current = setTimeout(async () => {
      try {
        const { data } = await searchApi.search(query)
        setResults(data)
      } catch { setResults(null) }
    }, 250)
    return () => clearTimeout(timer.current)
  }, [query])

  if (value) {
    return (
      <div className="input flex items-center gap-2">
        <NodePill node={value} />
        <span className="text-sm text-text-primary flex-1 truncate">{value.label}</span>
        <button onClick={() => onSelect(null)} className="text-text-muted hover:text-text-primary">
          <X className="w-3 h-3" />
        </button>
      </div>
    )
  }

  const rows = results ? pickerRows(results) : []

  return (
    <div className="relative">
      <input
        className="input w-full text-sm"
        placeholder={placeholder}
        value={query}
        onChange={e => { setQuery(e.target.value); setOpen(true) }}
        onFocus={() => setOpen(true)}
      />
      {open && query.length >= 2 && (
        <>
          <div className="fixed inset-0 z-10" onClick={() => setOpen(false)} />
          <div className="absolute top-full mt-1 left-0 right-0 z-20 bg-surface-2 border border-border rounded-lg shadow-xl max-h-64 overflow-y-auto">
            {!results && <div className="px-3 py-2 text-xs text-text-muted">Searching…</div>}
            {results && rows.length === 0 && <div className="px-3 py-2 text-xs text-text-muted">No matches</div>}
            {rows.map(row => (
              <button
                key={`${row.type}-${row.id}`}
                onClick={() => { onSelect(row); setOpen(false); setQuery('') }}
                className="w-full flex items-center gap-2 px-3 py-2 text-left hover:bg-surface-3 text-sm"
              >
                <NodePill node={row} />
                <span className="text-text-primary truncate">{row.label}</span>
              </button>
            ))}
          </div>
        </>
      )}
    </div>
  )
}

export function riskBadgeClass(score?: number) {
  const s = score ?? 0
  if (s >= 75) return 'text-accent-red bg-accent-red/10 border-accent-red/20'
  if (s >= 50) return 'text-accent-orange bg-accent-orange/10 border-accent-orange/20'
  if (s >= 25) return 'text-accent-yellow bg-accent-yellow/10 border-accent-yellow/20'
  return 'text-text-secondary bg-surface-3 border-surface-3'
}

// ---------------------------------------------------------------------------
// ChangeTimelinePage / AssetRelationshipsPage helpers
// ---------------------------------------------------------------------------

export const CHANGE_TYPE_STYLE: Record<ChangeType, { icon: ElementType; cls: string }> = {
  new: { icon: Plus, cls: 'text-accent-green bg-accent-green/10 border-accent-green/20' },
  removed: { icon: Minus, cls: 'text-accent-red bg-accent-red/10 border-accent-red/20' },
  changed: { icon: RefreshCw, cls: 'text-accent-orange bg-accent-orange/10 border-accent-orange/20' },
}

export const ASSET_TYPE_LABEL: Record<ChangeAssetType, string> = {
  domain: 'domain', subdomain: 'subdomain', host: 'host', service: 'service',
  certificate: 'certificate', dns_record: 'dns record', technology: 'technology',
}

export function ChangeEventRow({ event }: { event: AssetChangeEvent }) {
  const style = CHANGE_TYPE_STYLE[event.change_type]
  const Icon = style.icon
  return (
    <div className="flex items-start gap-3 py-3 border-b border-border-muted last:border-0">
      <span className={clsx('mt-0.5 flex items-center justify-center w-6 h-6 rounded-full border', style.cls)}>
        <Icon className="w-3.5 h-3.5" />
      </span>
      <div className="flex-1 min-w-0">
        <div className="flex items-center gap-2 flex-wrap">
          <span className="badge-gray text-xs">
            {ASSET_TYPE_LABEL[event.asset_type]}
          </span>
          <span className="text-sm text-text-primary truncate">{event.asset_label || event.asset_key}</span>
        </div>
        {event.change_type === 'changed' ? (
          <div className="text-xs text-text-muted mt-1 flex items-center gap-1.5">
            <span className="font-mono">{event.field}</span>
            <span className="text-text-secondary">{event.old_value || '—'}</span>
            <ArrowRight className="w-3 h-3" />
            <span className="text-text-primary">{event.new_value || '—'}</span>
          </div>
        ) : (
          <div className="text-xs text-text-muted mt-1">
            {event.change_type === 'new' ? 'newly discovered' : 'no longer observed'}
          </div>
        )}
      </div>
      <span className="text-xs text-text-muted whitespace-nowrap">
        {formatDistanceToNow(new Date(event.detected_at), { addSuffix: true })}
      </span>
    </div>
  )
}

// ---------------------------------------------------------------------------
// ExposureCenterPage / ExecutiveDashboardPage helpers
// ---------------------------------------------------------------------------

export const EXEC_TIER_COLOR: Record<string, string> = {
  critical: '#C81E3A', high: '#A75709', medium: '#8D6608', low: '#147D3B',
}

export function ExposureGauge({ score }: { score: number }) {
  const tier = score >= 75 ? 'critical' : score >= 50 ? 'high' : score >= 25 ? 'medium' : 'low'
  const color = EXEC_TIER_COLOR[tier]
  const radius = 52
  const circumference = Math.PI * radius
  const progress = circumference * (score / 100)
  return (
    <div className="flex flex-col items-center">
      <svg width="130" height="74" viewBox="0 0 130 74">
        <path d="M 13 65 A 52 52 0 0 1 117 65" fill="none" stroke="var(--surface-3)" strokeWidth="11" strokeLinecap="round" />
        <path
          d="M 13 65 A 52 52 0 0 1 117 65"
          fill="none" stroke={color} strokeWidth="11" strokeLinecap="round"
          strokeDasharray={`${progress} ${circumference}`}
          style={{ transition: 'stroke-dasharray 0.8s ease' }}
        />
      </svg>
      <div className="-mt-5 text-center">
        <div className="text-3xl font-bold tabular-nums" style={{ color }}>{Math.round(score)}</div>
        <div className="text-xs font-semibold uppercase tracking-wide mt-0.5" style={{ color }}>{tier} exposure</div>
      </div>
    </div>
  )
}

export function KPITile({ label, value, icon: Icon, trend, color }: {
  label: string; value: string | number; icon: ElementType
  trend?: { value: number; goodWhenDown?: boolean }; color?: string
}) {
  return (
    <div className="card p-4">
      <div className="text-xs text-text-muted flex items-center gap-1">
        <Icon className="w-3 h-3" /> {label}
      </div>
      <div className="flex items-end justify-between mt-1">
        <div className={clsx('text-2xl font-bold tabular-nums', color)}>{value}</div>
        {trend !== undefined && trend.value !== 0 && (
          <div className={clsx(
            'flex items-center gap-0.5 text-xs font-medium pb-1',
            (trend.value > 0) === !!trend.goodWhenDown ? 'text-accent-red' : 'text-accent-green'
          )}>
            {trend.value > 0 ? <TrendingUp className="w-3 h-3" /> : <TrendingDown className="w-3 h-3" />}
            {Math.abs(trend.value)}
          </div>
        )}
      </div>
    </div>
  )
}

export const PERIODS: { label: string; value: string }[] = [
  { label: 'Daily', value: 'daily' },
  { label: 'Weekly', value: 'weekly' },
  { label: 'Monthly', value: 'monthly' },
  { label: 'Quarterly', value: 'quarterly' },
]

export const EXPOSURE_LEVEL_COLOR: Record<string, string> = {
  critical: 'text-accent-red', high: 'text-accent-orange', medium: 'text-accent-blue',
  low: 'text-accent-green', informational: 'text-text-muted',
}

const EXPOSURE_LEVEL_BADGE: Record<string, string> = {
  critical: 'badge-red', high: 'bg-accent-orange/15 text-accent-orange border border-accent-orange/20',
  medium: 'badge-blue', low: 'badge-green', informational: 'badge-gray',
}

export function exposureAssetLink(a: ExposureAssetRow): string | null {
  if (a.asset_type === 'host') return `/hosts/${a.asset_id}`
  if (a.asset_type === 'domain') return `/domains/${a.asset_id}`
  return null
}

export function ExposureLevelBadge({ level }: { level: string }) {
  return <span className={clsx('badge text-xs capitalize', EXPOSURE_LEVEL_BADGE[level] ?? 'badge-blue')}>{level}</span>
}

export function ExposureAssetTable({ rows, emptyLabel }: { rows: ExposureAssetRow[]; emptyLabel: string }) {
  if (rows.length === 0) return <Empty label={emptyLabel} />
  return (
    <TableCard>
      <thead><tr><th>Asset</th><th>Type</th><th>Exposure</th><th>Risk</th><th>Level</th><th>Findings</th><th>Paths</th></tr></thead>
      <tbody>
        {rows.map(a => {
          const link = exposureAssetLink(a)
          return (
            <tr key={a.id}>
              <td>
                {link ? (
                  <Link to={link} className="font-mono text-sm text-accent-cyan hover:underline">{a.label}</Link>
                ) : (
                  <span className="font-mono text-sm text-text-primary">{a.label}</span>
                )}
              </td>
              <td><span className="badge-gray text-xs">{a.asset_type}</span></td>
              <td><span className={clsx('text-sm font-semibold tabular-nums', EXPOSURE_LEVEL_COLOR[a.exposure_level])}>{a.exposure_score.toFixed(1)}</span></td>
              <td><span className="text-sm text-text-muted tabular-nums">{a.risk_score.toFixed(1)}</span></td>
              <td><ExposureLevelBadge level={a.exposure_level} /></td>
              <td><span className="text-sm text-text-secondary tabular-nums">{a.critical_findings}</span></td>
              <td><span className="text-sm text-text-secondary tabular-nums">{a.attack_path_count}</span></td>
            </tr>
          )
        })}
      </tbody>
    </TableCard>
  )
}
