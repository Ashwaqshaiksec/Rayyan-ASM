import { describe, it, expect } from 'vitest'
import { renderHook, act } from '@testing-library/react'
import { MemoryRouter } from 'react-router-dom'
import type { ReactNode } from 'react'
import { useFacetFilters, countBy } from './useFacetFilters'

const wrapper = ({ children }: { children: ReactNode }) => <MemoryRouter>{children}</MemoryRouter>

describe('useFacetFilters', () => {
  it('starts with no active values', () => {
    const { result } = renderHook(() => useFacetFilters(['severity', 'status'] as const), { wrapper })
    expect(result.current.values.severity).toEqual([])
    expect(result.current.values.status).toEqual([])
    expect(result.current.activeCount).toBe(0)
  })

  it('toggle adds and then removes a value from a facet', () => {
    const { result } = renderHook(() => useFacetFilters(['severity'] as const), { wrapper })

    act(() => result.current.toggle('severity', 'critical'))
    expect(result.current.values.severity).toEqual(['critical'])
    expect(result.current.isActive('severity', 'critical')).toBe(true)
    expect(result.current.activeCount).toBe(1)

    act(() => result.current.toggle('severity', 'critical'))
    expect(result.current.values.severity).toEqual([])
    expect(result.current.activeCount).toBe(0)
  })

  it('supports multiple values selected within one facet (OR)', () => {
    const { result } = renderHook(() => useFacetFilters(['severity'] as const), { wrapper })

    act(() => result.current.toggle('severity', 'critical'))
    act(() => result.current.toggle('severity', 'high'))
    expect(result.current.values.severity.sort()).toEqual(['critical', 'high'])
    expect(result.current.activeCount).toBe(2)
  })

  it('keeps facets independent (AND across facets)', () => {
    const { result } = renderHook(() => useFacetFilters(['severity', 'status'] as const), { wrapper })

    act(() => result.current.toggle('severity', 'critical'))
    act(() => result.current.toggle('status', 'open'))
    expect(result.current.values.severity).toEqual(['critical'])
    expect(result.current.values.status).toEqual(['open'])
    expect(result.current.activeCount).toBe(2)
  })

  it('clear(facet) only clears that facet', () => {
    const { result } = renderHook(() => useFacetFilters(['severity', 'status'] as const), { wrapper })

    act(() => result.current.toggle('severity', 'critical'))
    act(() => result.current.toggle('status', 'open'))
    act(() => result.current.clear('severity'))

    expect(result.current.values.severity).toEqual([])
    expect(result.current.values.status).toEqual(['open'])
  })

  it('clear() with no argument clears every facet', () => {
    const { result } = renderHook(() => useFacetFilters(['severity', 'status'] as const), { wrapper })

    act(() => result.current.toggle('severity', 'critical'))
    act(() => result.current.toggle('status', 'open'))
    act(() => result.current.clear())

    expect(result.current.values.severity).toEqual([])
    expect(result.current.values.status).toEqual([])
    expect(result.current.activeCount).toBe(0)
  })
})

describe('countBy', () => {
  it('tallies occurrences and sorts by count descending', () => {
    const items = [
      { protocol: 'tcp' }, { protocol: 'tcp' }, { protocol: 'udp' }, { protocol: 'tcp' },
    ]
    const result = countBy(items, i => i.protocol)
    expect(result).toEqual([
      { value: 'tcp', count: 3 },
      { value: 'udp', count: 1 },
    ])
  })

  it('skips null/undefined/empty values', () => {
    const items = [{ x: 'a' }, { x: '' }, { x: null }, { x: undefined }, { x: 'a' }]
    const result = countBy(items, i => i.x)
    expect(result).toEqual([{ value: 'a', count: 2 }])
  })
})
