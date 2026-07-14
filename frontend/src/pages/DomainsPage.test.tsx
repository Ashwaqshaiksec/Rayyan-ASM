import { describe, it, expect, vi, beforeEach } from 'vitest'
import { render, screen, fireEvent, waitFor, within } from '@testing-library/react'
import { MemoryRouter } from 'react-router-dom'
import DomainsPage from '@/pages/DomainsPage'
import { domainApi, scanApi } from '@/utils/api'
import type { Domain } from '@/types'

vi.mock('@/utils/api', () => ({
  domainApi: {
    list: vi.fn(),
    create: vi.fn(),
    delete: vi.fn(),
  },
  scanApi: {
    create: vi.fn(),
  },
}))

function makeDomain(overrides: Partial<Domain> = {}): Domain {
  return {
    id: 'd1',
    org_id: 'org1',
    name: 'example.com',
    registrar: '',
    registration_date: null,
    expiry_date: null,
    nameservers: [],
    status: 'active',
    tags: ['external'],
    notes: '',
    owner: 'security-team',
    business_unit: '',
    environment: 'production',
    monitored: true,
    last_scanned_at: null,
    created_at: '2026-01-01T00:00:00Z',
    updated_at: '2026-01-01T00:00:00Z',
    ...overrides,
  }
}

function renderDomains() {
  return render(
    <MemoryRouter>
      <DomainsPage />
    </MemoryRouter>
  )
}

describe('DomainsPage', () => {
  beforeEach(() => {
    vi.clearAllMocks()
    vi.mocked(domainApi.list).mockResolvedValue({
      data: { data: [], total: 0 },
      status: 200, statusText: 'OK', headers: {}, config: {} as never,
    })
  })

  it('renders the page heading', async () => {
    renderDomains()
    expect(screen.getByRole('heading', { name: /domains/i })).toBeInTheDocument()
    await waitFor(() => expect(domainApi.list).toHaveBeenCalled())
  })

  it('shows a loading state before data resolves', async () => {
    renderDomains()
    expect(screen.getByText(/loading/i)).toBeInTheDocument()
    await waitFor(() => expect(domainApi.list).toHaveBeenCalled())
  })

  it('renders one row per domain returned by the API and the correct total count', async () => {
    const domains = [
      makeDomain({ id: 'd1', name: 'example.com' }),
      makeDomain({ id: 'd2', name: 'app.example.com', status: 'inactive', environment: 'staging' }),
      makeDomain({ id: 'd3', name: 'api.example.com' }),
    ]
    vi.mocked(domainApi.list).mockResolvedValue({
      data: { data: domains, total: 3 },
      status: 200, statusText: 'OK', headers: {}, config: {} as never,
    })

    renderDomains()

    await waitFor(() => {
      expect(screen.getByText('example.com')).toBeInTheDocument()
    })
    expect(screen.getByText('app.example.com')).toBeInTheDocument()
    expect(screen.getByText('api.example.com')).toBeInTheDocument()

    const rows = screen.getAllByRole('row')
    // header row + 3 data rows
    expect(rows).toHaveLength(4)
    expect(screen.getByText('3 domains tracked')).toBeInTheDocument()
  })

  it('shows an empty state when no domains are returned', async () => {
    renderDomains()
    await waitFor(() => {
      expect(screen.getByText(/no domains yet/i)).toBeInTheDocument()
    })
  })

  it('passes the search term through to domainApi.list', async () => {
    vi.mocked(domainApi.list).mockResolvedValue({
      data: { data: [makeDomain()], total: 1 },
      status: 200, statusText: 'OK', headers: {}, config: {} as never,
    })
    renderDomains()
    await waitFor(() => expect(domainApi.list).toHaveBeenCalled())

    fireEvent.change(screen.getByPlaceholderText(/filter domains/i), { target: { value: 'example' } })

    await waitFor(() => {
      expect(domainApi.list).toHaveBeenCalledWith(
        expect.objectContaining({ search: 'example' })
      )
    })
  })

  it('opens the add-domain modal and submits a new domain', async () => {
    vi.mocked(domainApi.create).mockResolvedValue({
      data: makeDomain({ id: 'new-id', name: 'newsite.com' }),
      status: 201, statusText: 'Created', headers: {}, config: {} as never,
    })
    renderDomains()
    await waitFor(() => expect(domainApi.list).toHaveBeenCalled())

    fireEvent.click(screen.getByRole('button', { name: /add domain/i }))
    const dialog = screen.getByPlaceholderText('example.com')
    fireEvent.change(dialog, { target: { value: 'newsite.com' } })

    const submitButtons = screen.getAllByRole('button', { name: /add domain/i })
    fireEvent.click(submitButtons[submitButtons.length - 1])

    await waitFor(() => {
      expect(domainApi.create).toHaveBeenCalledWith(
        expect.objectContaining({ name: 'newsite.com', monitored: true })
      )
    })
  })

  it('does not submit when the domain name is blank', async () => {
    renderDomains()
    await waitFor(() => expect(domainApi.list).toHaveBeenCalled())

    fireEvent.click(screen.getByRole('button', { name: /add domain/i }))
    const submitButtons = screen.getAllByRole('button', { name: /add domain/i })
    fireEvent.click(submitButtons[submitButtons.length - 1])

    expect(domainApi.create).not.toHaveBeenCalled()
  })

  it('starts a scan for a domain row', async () => {
    vi.mocked(domainApi.list).mockResolvedValue({
      data: { data: [makeDomain({ id: 'd1', name: 'example.com' })], total: 1 },
      status: 200, statusText: 'OK', headers: {}, config: {} as never,
    })
    vi.mocked(scanApi.create).mockResolvedValue({
      data: {}, status: 201, statusText: 'Created', headers: {}, config: {} as never,
    })
    renderDomains()

    await waitFor(() => expect(screen.getByText('example.com')).toBeInTheDocument())

    const row = screen.getByText('example.com').closest('tr')!
    fireEvent.click(within(row).getByText('Scan'))

    await waitFor(() => {
      expect(scanApi.create).toHaveBeenCalledWith(
        expect.objectContaining({ type: 'subdomain', targets: { targets: ['example.com'] } })
      )
    })
  })
})
