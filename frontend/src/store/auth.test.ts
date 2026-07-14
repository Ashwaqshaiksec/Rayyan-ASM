import { describe, it, expect, beforeEach } from 'vitest'
import { useAuthStore } from '@/store/auth'

describe('useAuthStore', () => {
  beforeEach(() => {
    useAuthStore.getState().logout()
  })

  it('initial state is unauthenticated', () => {
    const state = useAuthStore.getState()
    expect(state.user).toBeNull()
    expect(state.accessToken).toBeNull()
    expect(state.isAuthenticated).toBe(false)
  })

  it('setAuth marks user as authenticated', () => {
    const fakeUser = {
      id: 'u1',
      email: 'a@b.com',
      username: 'tester',
      role: 'admin' as const,
      org_id: 'org1',
      first_name: 'Test',
      last_name: 'User',
      mfa_enabled: false,
      active: true,
      created_at: new Date().toISOString(),
      updated_at: new Date().toISOString(),
      last_login_at: null,
      avatar_url: '',
    }

    useAuthStore.getState().setAuth(fakeUser, 'tok', 'ref')

    const state = useAuthStore.getState()
    expect(state.isAuthenticated).toBe(true)
    expect(state.accessToken).toBe('tok')
    expect(state.refreshToken).toBe('ref')
    expect(state.user?.email).toBe('a@b.com')
  })

  it('setUser updates the user without affecting tokens or auth status', () => {
    const fakeUser = {
      id: 'u3', email: 'c@b.com', username: 'u3', role: 'analyst' as const,
      org_id: 'org1', first_name: 'First', last_name: 'Last', mfa_enabled: false,
      active: true, created_at: '', updated_at: '', last_login_at: null, avatar_url: '',
    }
    useAuthStore.getState().setAuth(fakeUser, 'tok', 'ref')

    const updatedUser = { ...fakeUser, first_name: 'Updated' }
    useAuthStore.getState().setUser(updatedUser)

    const state = useAuthStore.getState()
    expect(state.user?.first_name).toBe('Updated')
    expect(state.accessToken).toBe('tok')
    expect(state.refreshToken).toBe('ref')
    expect(state.isAuthenticated).toBe(true)
  })

  it('logout clears all auth state', () => {
    const fakeUser = {
      id: 'u2', email: 'b@b.com', username: 'u2', role: 'viewer' as const,
      org_id: 'org1', first_name: '', last_name: '', mfa_enabled: false,
      active: true, created_at: '', updated_at: '', last_login_at: null, avatar_url: '',
    }
    useAuthStore.getState().setAuth(fakeUser, 'tok', 'ref')
    useAuthStore.getState().logout()

    const state = useAuthStore.getState()
    expect(state.user).toBeNull()
    expect(state.accessToken).toBeNull()
    expect(state.refreshToken).toBeNull()
    expect(state.isAuthenticated).toBe(false)
  })
})
