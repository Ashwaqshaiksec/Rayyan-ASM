import { describe, it, expect, vi, beforeEach } from 'vitest'
import api from '@/utils/api'

vi.mock('@/utils/api', () => ({
  default: {
    get: vi.fn(),
    post: vi.fn(),
    delete: vi.fn(),
  },
}))

const mockScans = {
  data: [
    {
      id: 'scan-1',
      type: 'subdomain',
      status: 'completed',
      progress: 100,
      created_at: '2024-01-01T00:00:00Z',
    },
    {
      id: 'scan-2',
      type: 'network',
      status: 'running',
      progress: 45,
      created_at: '2024-01-02T00:00:00Z',
    },
  ],
  total: 2,
}

describe('Scans API integration', () => {
  beforeEach(() => {
    vi.clearAllMocks()
    ;(api.get as ReturnType<typeof vi.fn>).mockResolvedValue({ data: mockScans })
    ;(api.post as ReturnType<typeof vi.fn>).mockResolvedValue({ data: { id: 'new-scan', status: 'pending' } })
    ;(api.delete as ReturnType<typeof vi.fn>).mockResolvedValue({ data: { message: 'scan cancelled', goroutine_signalled: true } })
  })

  it('fetches scan list', async () => {
    await api.get('/scans')
    expect(api.get).toHaveBeenCalledWith('/scans')
  })

  it('creates a scan job', async () => {
    const payload = { type: 'subdomain', targets: { targets: ['example.com'] } }
    const res = await api.post('/scans', payload)
    expect(res.data.status).toBe('pending')
  })

  it('cancels a running scan', async () => {
    const res = await api.delete('/scans/scan-2')
    expect(res.data.goroutine_signalled).toBe(true)
  })
})
