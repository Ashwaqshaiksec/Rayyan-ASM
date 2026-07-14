import { describe, it, expect, vi, beforeEach } from 'vitest'
import { render, screen, fireEvent, waitFor } from '@testing-library/react'
import { MemoryRouter } from 'react-router-dom'
import LoginPage from '@/pages/LoginPage'
import { authApi } from '@/utils/api'

vi.mock('@/utils/api', () => ({
  authApi: { login: vi.fn() },
  default: {},
}))

const mockNavigate = vi.fn()
vi.mock('react-router-dom', async (importOriginal) => {
  const actual = await importOriginal<typeof import('react-router-dom')>()
  return { ...actual, useNavigate: () => mockNavigate }
})

function renderLogin() {
  return render(
    <MemoryRouter>
      <LoginPage />
    </MemoryRouter>
  )
}

describe('LoginPage', () => {
  beforeEach(() => {
    vi.clearAllMocks()
  })

  it('renders email and password fields', () => {
    renderLogin()
    expect(screen.getByLabelText(/email address/i)).toBeInTheDocument()
    expect(screen.getByLabelText(/password/i)).toBeInTheDocument()
  })

  it('renders a submit button', () => {
    renderLogin()
    expect(screen.getByRole('button', { name: /sign in/i })).toBeInTheDocument()
  })

  it('shows error message on failed login', async () => {
    vi.mocked(authApi.login).mockRejectedValueOnce({
      response: { data: { error: 'invalid credentials' } },
    })

    renderLogin()
    fireEvent.change(screen.getByLabelText(/email address/i), { target: { value: 'bad@bad.com' } })
    fireEvent.change(screen.getByLabelText(/password/i), { target: { value: 'wrong' } })
    fireEvent.click(screen.getByRole('button', { name: /sign in/i }))

    await waitFor(() => {
      expect(screen.getByText('invalid credentials')).toBeInTheDocument()
    })
  })

  it('navigates to /dashboard on successful login', async () => {
    vi.mocked(authApi.login).mockResolvedValueOnce({
      data: {
        access_token: 'tok',
        refresh_token: 'ref',
        user: {
          id: 'u1', email: 'a@b.com', username: 'u', role: 'admin',
          org_id: 'o1', first_name: 'Test', last_name: 'User',
          mfa_enabled: false, active: true, created_at: '', updated_at: '',
          last_login_at: null, avatar_url: '',
        },
      },
      status: 200, statusText: 'OK', headers: {}, config: {} as never,
    })

    renderLogin()
    fireEvent.change(screen.getByLabelText(/email address/i), { target: { value: 'a@b.com' } })
    fireEvent.change(screen.getByLabelText(/password/i), { target: { value: 'correct' } })
    fireEvent.click(screen.getByRole('button', { name: /sign in/i }))

    await waitFor(() => {
      expect(mockNavigate).toHaveBeenCalledWith('/dashboard')
    })
  })
})
