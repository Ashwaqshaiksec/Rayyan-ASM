import type { AttackPath, AttackPathHop } from '@/types'

export interface FlowNode {
  type: string
  label: string
  score: number | null
  kind: 'entry' | 'hop' | 'target'
  relationFromPrev?: string
}

export const NODE_W = 132
export const NODE_H = 52
export const GAP = 56
export const ROW_H = 108

export function scoreColor(score: number | null): string {
  if (score == null) return '#565D6D' // neutral for entry/target with no own score
  if (score >= 75) return '#C81E3A'
  if (score >= 50) return '#A75709'
  if (score >= 25) return '#8D6608'
  return '#147D3B'
}

export function buildNodes(path: AttackPath): FlowNode[] {
  const hops: AttackPathHop[] = path.hops?.hops ?? []
  const nodes: FlowNode[] = [
    { type: path.entry_type, label: path.entry_label, score: null, kind: 'entry' },
    ...hops.map((h): FlowNode => ({
      type: h.type, label: h.label, score: h.risk_score, kind: 'hop', relationFromPrev: h.relation_type,
    })),
  ]
  // Only append a distinct target node if it isn't already the last hop —
  // some paths' final hop IS the target, and duplicating it would draw a
  // confusing self-loop-looking pair of identical nodes at the end.
  const last = hops[hops.length - 1]
  if (!last || last.id !== path.target_id) {
    nodes.push({ type: path.target_type, label: path.target_label, score: null, kind: 'target' })
  }
  return nodes
}
