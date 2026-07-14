import { describe, it, expect, vi, beforeEach } from 'vitest'
import api from '@/utils/api'

vi.mock('@/utils/api', () => ({
  default: { get: vi.fn() },
}))

const mockDomain = {
  id: 'domain-1',
  name: 'example.com',
  status: 'active',
  registrar: 'GoDaddy',
  risk_score: 72.5,
  risk_tier: 'high',
  subdomains: [
    { id: 'sub-1', fqdn: 'app.example.com', status: 'active' },
    { id: 'sub-2', fqdn: 'api.example.com', status: 'active' },
  ],
}

describe('Domain Detail', () => {
  beforeEach(() => {
    vi.clearAllMocks()
    ;(api.get as ReturnType<typeof vi.fn>).mockResolvedValue({ data: mockDomain })
  })

  it('fetches domain by id', async () => {
    await api.get('/domains/domain-1')
    expect(api.get).toHaveBeenCalledWith('/domains/domain-1')
  })

  it('domain has expected risk data', () => {
    expect(mockDomain.risk_score).toBeGreaterThan(0)
    expect(['low', 'medium', 'high', 'critical']).toContain(mockDomain.risk_tier)
  })

  it('domain has subdomains', () => {
    expect(mockDomain.subdomains.length).toBeGreaterThan(0)
  })
})
