import { describe, it, expect } from 'vitest'
import { buildNodes } from './attackPathFlow.utils'
import type { AttackPath } from '@/types'

function makePath(overrides: Partial<AttackPath> = {}): AttackPath {
  return {
    id: 'p1', org_id: 'o1',
    entry_type: 'host', entry_id: 'e1', entry_label: '1.2.3.4',
    target_type: 'service', target_id: 't1', target_label: '1.2.3.4:5432',
    weakest_score: 80, weakest_type: 'service', weakest_id: 'w1', weakest_label: 'postgres',
    hop_count: 2,
    hops: { hops: [
      { type: 'service', id: 'h1', label: 'ssh:22', relation_type: 'exposes', risk_score: 40 },
      { type: 'finding', id: 'h2', label: 'weak creds', relation_type: 'vulnerable_to', risk_score: 80 },
    ] },
    computed_at: '2026-01-01T00:00:00Z',
    ...overrides,
  }
}

describe('buildNodes', () => {
  it('produces entry, each hop, then a distinct target node', () => {
    const nodes = buildNodes(makePath())
    expect(nodes.map(n => n.kind)).toEqual(['entry', 'hop', 'hop', 'target'])
    expect(nodes[0].label).toBe('1.2.3.4')
    expect(nodes[3].label).toBe('1.2.3.4:5432')
  })

  it('carries each hop\'s own risk score, not the path-level weakest score', () => {
    const nodes = buildNodes(makePath())
    const hopNodes = nodes.filter(n => n.kind === 'hop')
    expect(hopNodes[0].score).toBe(40)
    expect(hopNodes[1].score).toBe(80)
  })

  it('entry and target nodes have no own score (they are not scored hops)', () => {
    const nodes = buildNodes(makePath())
    expect(nodes[0].score).toBeNull()
    expect(nodes[nodes.length - 1].score).toBeNull()
  })

  it('does not duplicate the target when the last hop IS the target', () => {
    const path = makePath({
      target_id: 'h2',
      hops: { hops: [
        { type: 'service', id: 'h1', label: 'ssh:22', relation_type: 'exposes', risk_score: 40 },
        { type: 'finding', id: 'h2', label: 'weak creds', relation_type: 'vulnerable_to', risk_score: 80 },
      ] },
    })
    const nodes = buildNodes(path)
    // Previously this would append a second, redundant target node
    // identical to the last hop, drawing a confusing extra box.
    expect(nodes).toHaveLength(3)
    expect(nodes[nodes.length - 1].kind).toBe('hop')
  })

  it('handles a path with no hops (direct entry-to-target)', () => {
    const path = makePath({ hop_count: 0, hops: { hops: [] } })
    const nodes = buildNodes(path)
    expect(nodes.map(n => n.kind)).toEqual(['entry', 'target'])
  })

  it('carries the relation type onto the node that follows it', () => {
    const nodes = buildNodes(makePath())
    expect(nodes[1].relationFromPrev).toBe('exposes')
    expect(nodes[2].relationFromPrev).toBe('vulnerable_to')
    expect(nodes[0].relationFromPrev).toBeUndefined()
  })
})
