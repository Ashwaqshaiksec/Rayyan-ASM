import { describe, it, expect, vi, beforeEach } from 'vitest'
import { render, screen, fireEvent, waitFor, within } from '@testing-library/react'
import { AlertsPage } from '@/pages/AlertsPage'
import { alertApi } from '@/utils/api'
import type { Alert } from '@/types'

vi.mock('@/utils/api', () => ({
  alertApi: {
    list: vi.fn(),
    acknowledge: vi.fn(),
    resolve: vi.fn(),
  },
}))

function makeAlert(overrides: Partial<Alert> = {}): Alert {
  return {
    id: 'a1',
    org_id: 'org1',
    type: 'sla_breach',
    severity: 'high',
    title: 'SLA Breached: Test finding',
    message: 'Finding exceeded its SLA deadline.',
    asset_id: null,
    asset_type: '',
    status: 'open',
    acked_by: null,
    acked_at: null,
    resolved_at: null,
    created_at: '2026-06-01T00:00:00Z',
    ...overrides,
  }
}

describe('AlertsPage', () => {
  beforeEach(() => {
    vi.clearAllMocks()
    vi.mocked(alertApi.list).mockResolvedValue({
      data: { data: [] },
      status: 200, statusText: 'OK', headers: {}, config: {} as never,
    })
  })

  it('renders the page heading', async () => {
    render(<AlertsPage />)
    expect(screen.getByRole('heading', { name: /alerts/i })).toBeInTheDocument()
    await waitFor(() => expect(alertApi.list).toHaveBeenCalled())
  })

  it('renders one row per alert and computes summary counts', async () => {
    const alerts = [
      makeAlert({ id: 'a1', severity: 'critical', status: 'open', title: 'Critical issue' }),
      makeAlert({ id: 'a2', severity: 'high', status: 'open', title: 'High issue' }),
      makeAlert({ id: 'a3', severity: 'medium', status: 'acknowledged', title: 'Medium issue' }),
    ]
    vi.mocked(alertApi.list).mockResolvedValue({
      data: { data: alerts },
      status: 200, statusText: 'OK', headers: {}, config: {} as never,
    })

    render(<AlertsPage />)

    await waitFor(() => {
      expect(screen.getByText('Critical issue')).toBeInTheDocument()
    })
    expect(screen.getByText('High issue')).toBeInTheDocument()
    expect(screen.getByText('Medium issue')).toBeInTheDocument()

    const rows = screen.getAllByRole('row')
    // header + 3 data rows
    expect(rows).toHaveLength(4)
  })

  it('shows the correct open/critical/high counts in the summary cards', async () => {
    const alerts = [
      makeAlert({ id: 'a1', severity: 'critical', status: 'open' }),
      makeAlert({ id: 'a2', severity: 'high', status: 'open' }),
      makeAlert({ id: 'a3', severity: 'high', status: 'open' }),
      makeAlert({ id: 'a4', severity: 'medium', status: 'acknowledged' }),
    ]
    vi.mocked(alertApi.list).mockResolvedValue({
      data: { data: alerts },
      status: 200, statusText: 'OK', headers: {}, config: {} as never,
    })

    render(<AlertsPage />)

    await waitFor(() => expect(screen.getByText('Open')).toBeInTheDocument())

    const openCard = screen.getByText('Open').closest('div.card') as HTMLElement
    expect(within(openCard).getByText('3')).toBeInTheDocument()

    const criticalCard = screen.getByText('Critical').closest('div.card') as HTMLElement
    expect(within(criticalCard).getByText('1')).toBeInTheDocument()

    const highCard = screen.getByText('High').closest('div.card') as HTMLElement
    expect(within(highCard).getByText('2')).toBeInTheDocument()
  })

  it('filters alerts by severity', async () => {
    const alerts = [
      makeAlert({ id: 'a1', severity: 'critical', title: 'Critical issue' }),
      makeAlert({ id: 'a2', severity: 'low', title: 'Low issue' }),
    ]
    vi.mocked(alertApi.list).mockResolvedValue({
      data: { data: alerts },
      status: 200, statusText: 'OK', headers: {}, config: {} as never,
    })

    render(<AlertsPage />)
    await waitFor(() => expect(screen.getByText('Critical issue')).toBeInTheDocument())

    const selects = screen.getAllByRole('combobox')
    fireEvent.change(selects[0], { target: { value: 'critical' } })

    expect(screen.getByText('Critical issue')).toBeInTheDocument()
    expect(screen.queryByText('Low issue')).not.toBeInTheDocument()
  })

  it('filters alerts by type', async () => {
    const alerts = [
      makeAlert({ id: 'a1', type: 'sla_breach', title: 'SLA issue' }),
      makeAlert({ id: 'a2', type: 'cert_expiry', title: 'Cert issue' }),
    ]
    vi.mocked(alertApi.list).mockResolvedValue({
      data: { data: alerts },
      status: 200, statusText: 'OK', headers: {}, config: {} as never,
    })

    render(<AlertsPage />)
    await waitFor(() => expect(screen.getByText('SLA issue')).toBeInTheDocument())

    const selects = screen.getAllByRole('combobox')
    fireEvent.change(selects[1], { target: { value: 'cert_expiry' } })

    expect(screen.queryByText('SLA issue')).not.toBeInTheDocument()
    expect(screen.getByText('Cert issue')).toBeInTheDocument()
  })

  it('calls alertApi.acknowledge and reloads when acknowledging an open alert', async () => {
    const openAlert = makeAlert({ id: 'a1', status: 'open', title: 'Needs ack' })
    vi.mocked(alertApi.list)
      .mockResolvedValueOnce({
        data: { data: [openAlert] },
        status: 200, statusText: 'OK', headers: {}, config: {} as never,
      })
      .mockResolvedValueOnce({
        data: { data: [{ ...openAlert, status: 'acknowledged' }] },
        status: 200, statusText: 'OK', headers: {}, config: {} as never,
      })
    vi.mocked(alertApi.acknowledge).mockResolvedValue({
      data: {}, status: 200, statusText: 'OK', headers: {}, config: {} as never,
    })

    render(<AlertsPage />)
    await waitFor(() => expect(screen.getByText('Needs ack')).toBeInTheDocument())

    const row = screen.getByText('Needs ack').closest('tr')!
    fireEvent.click(within(row).getByTitle('Acknowledge'))

    await waitFor(() => {
      expect(alertApi.acknowledge).toHaveBeenCalledWith('a1')
    })
    await waitFor(() => {
      expect(alertApi.list).toHaveBeenCalledTimes(2)
    })
  })

  it('calls alertApi.resolve and reloads when resolving an open alert', async () => {
    const openAlert = makeAlert({ id: 'a1', status: 'open', title: 'Needs resolve' })
    vi.mocked(alertApi.list)
      .mockResolvedValueOnce({
        data: { data: [openAlert] },
        status: 200, statusText: 'OK', headers: {}, config: {} as never,
      })
      .mockResolvedValueOnce({
        data: { data: [] },
        status: 200, statusText: 'OK', headers: {}, config: {} as never,
      })
    vi.mocked(alertApi.resolve).mockResolvedValue({
      data: {}, status: 200, statusText: 'OK', headers: {}, config: {} as never,
    })

    render(<AlertsPage />)
    await waitFor(() => expect(screen.getByText('Needs resolve')).toBeInTheDocument())

    const row = screen.getByText('Needs resolve').closest('tr')!
    fireEvent.click(within(row).getByTitle('Resolve'))

    await waitFor(() => {
      expect(alertApi.resolve).toHaveBeenCalledWith('a1')
    })
    await waitFor(() => {
      expect(alertApi.list).toHaveBeenCalledTimes(2)
    })
  })

  it('does not show acknowledge/resolve actions for non-open alerts', async () => {
    const acked = makeAlert({ id: 'a1', status: 'acknowledged', title: 'Already acked' })
    vi.mocked(alertApi.list).mockResolvedValue({
      data: { data: [acked] },
      status: 200, statusText: 'OK', headers: {}, config: {} as never,
    })

    render(<AlertsPage />)
    await waitFor(() => expect(screen.getByText('Already acked')).toBeInTheDocument())

    const row = screen.getByText('Already acked').closest('tr')!
    expect(within(row).queryByTitle('Acknowledge')).not.toBeInTheDocument()
    expect(within(row).queryByTitle('Resolve')).not.toBeInTheDocument()
  })
})
