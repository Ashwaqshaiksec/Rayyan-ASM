import { describe, it, expect, vi, beforeEach } from 'vitest'
import { render, screen, fireEvent, waitFor } from '@testing-library/react'
import { MemoryRouter } from 'react-router-dom'
import CommandPalette from './CommandPalette'
import { searchApi, savedSearchApi } from '@/utils/api'
import { clearRecentSearches, saveRecentSearch } from '@/utils/recentSearches'

vi.mock('@/utils/api', () => ({
  searchApi: {
    search: vi.fn(),
    suggestions: vi.fn(),
  },
  savedSearchApi: {
    list: vi.fn(),
    create: vi.fn(),
    use: vi.fn(),
    delete: vi.fn(),
  },
}))

const mockNavigate = vi.fn()
vi.mock('react-router-dom', async () => {
  const actual = await vi.importActual('react-router-dom')
  return { ...actual, useNavigate: () => mockNavigate }
})

function renderPalette(open = true) {
  const onClose = vi.fn()
  render(
    <MemoryRouter>
      <CommandPalette open={open} onClose={onClose} />
    </MemoryRouter>,
  )
  return { onClose }
}

describe('CommandPalette', () => {
  beforeEach(() => {
    vi.clearAllMocks()
    clearRecentSearches()
    ;(savedSearchApi.list as ReturnType<typeof vi.fn>).mockResolvedValue({ data: { data: [] } })
    ;(searchApi.suggestions as ReturnType<typeof vi.fn>).mockResolvedValue({ data: { suggestions: [] } })
  })

  it('renders nothing when closed', () => {
    render(
      <MemoryRouter>
        <CommandPalette open={false} onClose={vi.fn()} />
      </MemoryRouter>,
    )
    expect(screen.queryByPlaceholderText(/Search domains/i)).not.toBeInTheDocument()
  })

  it('shows top-level nav destinations as "Go to" shortcuts when open with an empty query', async () => {
    renderPalette()
    await waitFor(() => expect(screen.getAllByText('Go to').length).toBeGreaterThan(0))
    // Dashboard is always the first nav item in the shared registry.
    expect(screen.getAllByText('Dashboard').length).toBeGreaterThan(0)
  })

  it('shows recent searches from shared storage when the query is empty', async () => {
    saveRecentSearch('mydomain.com')
    renderPalette()
    await waitFor(() => expect(screen.getByText('Recent searches')).toBeInTheDocument())
    expect(screen.getByText('mydomain.com')).toBeInTheDocument()
  })

  it('calls onClose on Escape', async () => {
    const { onClose } = renderPalette()
    const input = screen.getByPlaceholderText(/Search domains/i)
    await waitFor(() => expect(savedSearchApi.list).toHaveBeenCalled())
    fireEvent.keyDown(input, { key: 'Escape' })
    expect(onClose).toHaveBeenCalled()
  })

  it('debounces typing and renders live results grouped by category', async () => {
    (searchApi.search as ReturnType<typeof vi.fn>).mockResolvedValue({
      data: {
        domains: [{ id: 'd1', name: 'example.com' }],
        hosts: [], subdomains: [], services: [], technologies: [], findings: [], cloud_assets: [],
      },
    })

    renderPalette()
    const input = screen.getByPlaceholderText(/Search domains/i)
    fireEvent.change(input, { target: { value: 'example' } })

    await waitFor(() => expect(searchApi.search).toHaveBeenCalledWith('example'), { timeout: 1000 })
    await waitFor(() => expect(screen.getByText('example.com')).toBeInTheDocument())
    expect(screen.getByText('Domains')).toBeInTheDocument()
  })

  it('navigates to the asset page when a result row is clicked', async () => {
    (searchApi.search as ReturnType<typeof vi.fn>).mockResolvedValue({
      data: {
        domains: [{ id: 'd1', name: 'example.com' }],
        hosts: [], subdomains: [], services: [], technologies: [], findings: [], cloud_assets: [],
      },
    })

    const { onClose } = renderPalette()
    const input = screen.getByPlaceholderText(/Search domains/i)
    fireEvent.change(input, { target: { value: 'example' } })

    await waitFor(() => screen.getByText('example.com'))
    fireEvent.click(screen.getByText('example.com'))

    expect(mockNavigate).toHaveBeenCalledWith('/domains/d1')
    expect(onClose).toHaveBeenCalled()
  })

  it('shows a "no results" message when a search comes back empty', async () => {
    (searchApi.search as ReturnType<typeof vi.fn>).mockResolvedValue({
      data: { domains: [], hosts: [], subdomains: [], services: [], technologies: [], findings: [], cloud_assets: [] },
    })

    renderPalette()
    const input = screen.getByPlaceholderText(/Search domains/i)
    fireEvent.change(input, { target: { value: 'nomatch' } })

    await waitFor(() => expect(screen.getByText(/No results for/)).toBeInTheDocument(), { timeout: 1000 })
  })

  it('does not crash if the backend sends null instead of [] for an empty category', async () => {
    // Regression guard: a Go nil slice marshals as JSON null, not []. The
    // backend has been fixed to always send real arrays, but the palette
    // should degrade gracefully rather than throw if that ever regresses.
    (searchApi.search as ReturnType<typeof vi.fn>).mockResolvedValue({
      data: {
        domains: [{ id: 'd1', name: 'example.com' }],
        hosts: null, subdomains: null, services: null, technologies: null, findings: null, cloud_assets: null,
      },
    })

    renderPalette()
    const input = screen.getByPlaceholderText(/Search domains/i)
    fireEvent.change(input, { target: { value: 'severity:critical' } })

    await waitFor(() => expect(screen.getByText('example.com')).toBeInTheDocument(), { timeout: 1000 })
  })
})
