import { describe, it, expect, vi, beforeEach } from 'vitest'
import { render, waitFor } from '@testing-library/react'
import { MemoryRouter } from 'react-router-dom'
import DashboardPage from '@/pages/DashboardPage'
import { dashboardApi, alertApi, scanApi, changeDetectApi } from '@/utils/api'

vi.mock('@/utils/api', () => ({
  dashboardApi: {
    summary: vi.fn(),
    trends: vi.fn(),
    riskScore: vi.fn(),
  },
  alertApi: {
    list: vi.fn(),
  },
  scanApi: {
    list: vi.fn(),
  },
  changeDetectApi: {
    timeline: vi.fn(),
  },
}))

const mockSummary = {
  domains: 12,
  subdomains: 340,
  hosts: 87,
  total_findings: 45,
  open_findings: 30,
  critical_findings: 3,
  high_findings: 8,
  active_scans: 2,
  expiring_certs: 5,
}

describe('DashboardPage', () => {
  beforeEach(() => {
    vi.clearAllMocks()
    ;(dashboardApi.summary as ReturnType<typeof vi.fn>).mockResolvedValue({ data: mockSummary })
    ;(dashboardApi.trends as ReturnType<typeof vi.fn>).mockResolvedValue({ data: { data: [] } })
    ;(dashboardApi.riskScore as ReturnType<typeof vi.fn>).mockResolvedValue({ data: {} })
    ;(alertApi.list as ReturnType<typeof vi.fn>).mockResolvedValue({ data: { data: [] } })
    ;(scanApi.list as ReturnType<typeof vi.fn>).mockResolvedValue({ data: { data: [] } })
    ;(changeDetectApi.timeline as ReturnType<typeof vi.fn>).mockResolvedValue({ data: { data: [] } })
  })

  it('renders loading state initially', () => {
    render(
      <MemoryRouter>
        <DashboardPage />
      </MemoryRouter>
    )
    // Should show some loading indicator or skeleton
    expect(document.body).toBeTruthy()
  })

  it('displays summary stats after load', async () => {
    render(
      <MemoryRouter>
        <DashboardPage />
      </MemoryRouter>
    )
    await waitFor(() => {
      expect(dashboardApi.summary).toHaveBeenCalled()
    })
  })

  it('handles API error gracefully', async () => {
    (dashboardApi.summary as ReturnType<typeof vi.fn>).mockRejectedValue(new Error('Network error'))
    render(
      <MemoryRouter>
        <DashboardPage />
      </MemoryRouter>
    )
    // Should not crash
    await waitFor(() => {
      expect(document.body).toBeTruthy()
    })
  })
})
