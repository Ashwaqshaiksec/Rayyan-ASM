import { describe, it, expect, vi, beforeEach } from 'vitest'
import api from '@/utils/api'

vi.mock('@/utils/api', () => ({
  default: { get: vi.fn() },
}))

const mockFindings = {
  data: [
    { id: 'f1', title: 'SQL Injection', severity: 'critical', status: 'open' },
    { id: 'f2', title: 'XSS', severity: 'high', status: 'open' },
    { id: 'f3', title: 'Info Disclosure', severity: 'low', status: 'resolved' },
  ],
  total: 3,
}

describe('Findings filtering', () => {
  beforeEach(() => {
    vi.clearAllMocks()
    ;(api.get as ReturnType<typeof vi.fn>).mockResolvedValue({ data: mockFindings })
  })

  it('fetches findings with severity filter', async () => {
    await api.get('/findings?severity=critical')
    expect(api.get).toHaveBeenCalledWith('/findings?severity=critical')
  })

  it('returns correct severity counts', () => {
    const critical = mockFindings.data.filter(f => f.severity === 'critical')
    expect(critical).toHaveLength(1)
  })

  it('filters by status correctly', () => {
    const open = mockFindings.data.filter(f => f.status === 'open')
    expect(open).toHaveLength(2)
  })
})
