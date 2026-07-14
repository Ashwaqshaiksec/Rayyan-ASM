import { useState } from 'react'
import { Link, useNavigate } from 'react-router-dom'
import { Radar, Eye, EyeOff, AlertCircle } from 'lucide-react'
import { authApi } from '@/utils/api'
import { useAuthStore } from '@/store/auth'
import type { LoginResponse } from '@/types'
import toast from 'react-hot-toast'

const FEED = [
  { host: 'api.ashwaq.io',        kind: 'subdomain', detail: 'new TLS cert · 87 days left' },
  { host: '203.0.113.41',         kind: 'host',       detail: '22, 443, 8443 open' },
  { host: 'staging.ashwaq.io',    kind: 'subdomain', detail: 'first seen 4m ago' },
  { host: 'vpn.ashwaq.io',        kind: 'host',       detail: 'cert expires in 9 days' },
]

export default function LoginPage() {
  const [email, setEmail] = useState('')
  const [password, setPassword] = useState('')
  const [showPwd, setShowPwd] = useState(false)
  const [loading, setLoading] = useState(false)
  const [error, setError] = useState('')
  const navigate = useNavigate()
  const setAuth = useAuthStore((s) => s.setAuth)

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault()
    setError('')
    setLoading(true)
    try {
      const { data } = await authApi.login(email, password)
      const resp = data as LoginResponse
      setAuth(resp.user, resp.access_token, resp.refresh_token)
      toast.success('Welcome back, ' + resp.user.first_name)
      navigate('/dashboard')
    } catch (err: unknown) {
      const msg = (err as { response?: { data?: { error?: string } } })?.response?.data?.error ?? 'Login failed'
      setError(msg)
    } finally {
      setLoading(false)
    }
  }

  return (
    <div className="min-h-screen flex bg-surface-0">
      {/* Left panel — a quiet, real piece of the product instead of an abstract hero */}
      <div className="hidden lg:flex lg:w-[46%] relative flex-col justify-between p-10 overflow-hidden border-r border-border"
        style={{ background: 'linear-gradient(180deg, var(--surface-2) 0%, var(--surface-0) 100%)' }}>

        <div className="relative z-10 reticle w-fit flex items-center gap-2.5 py-1 px-1">
          <Radar className="w-4 h-4 text-accent-cyan" />
          <span className="text-text-primary text-sm font-mono font-medium tracking-tight">RAYYAN_ASM</span>
        </div>

        {/* A small, believable slice of the actual product: a live discovery feed */}
        <div className="relative z-10 -mx-1">
          <div className="rounded-lg border border-border bg-surface-1/60 overflow-hidden">
            <div className="flex items-center gap-2 px-3.5 py-2.5 border-b border-border-muted">
              <span className="w-1.5 h-1.5 rounded-full bg-accent-green animate-pulse-slow" />
              <span className="text-[11px] font-mono text-text-secondary tracking-wide uppercase">Live discovery — ashwaq.io</span>
            </div>
            <div className="divide-y divide-border-muted">
              {FEED.map((row) => (
                <div key={row.host} className="flex items-center gap-3 px-3.5 py-2.5">
                  <span className={
                    row.kind === 'host'
                      ? 'text-[10px] font-mono px-1.5 py-0.5 rounded-sm bg-accent-cyan/10 text-accent-cyan flex-shrink-0'
                      : 'text-[10px] font-mono px-1.5 py-0.5 rounded-sm bg-accent-purple/10 text-accent-purple flex-shrink-0'
                  }>
                    {row.kind}
                  </span>
                  <span className="text-xs text-text-primary font-mono truncate">{row.host}</span>
                  <span className="text-[11px] text-text-muted ml-auto flex-shrink-0">{row.detail}</span>
                </div>
              ))}
            </div>
          </div>
          <p className="text-[11px] text-text-muted mt-3 pl-1">
            Sample feed — your workspace fills in once you're signed in.
          </p>
        </div>

        <div className="relative z-10 max-w-sm">
          <p className="text-[13px] text-text-secondary leading-relaxed">
            Rayyan watches your domains, hosts, and certificates continuously,
            so the first time you hear about a new subdomain isn't from someone else.
          </p>
        </div>
      </div>

      {/* Right form panel */}
      <div className="flex-1 flex items-center justify-center p-4 sm:p-8">
        <div className="w-full max-w-sm">
          <div className="flex flex-col items-center mb-8 lg:hidden">
            <div className="w-12 h-12 rounded-xl bg-accent-cyan/10 border border-accent-cyan/30 flex items-center justify-center mb-3">
              <Radar className="w-6 h-6 text-accent-cyan" />
            </div>
            <h1 className="text-xl font-semibold text-text-primary">Rayyan ASM</h1>
            <p className="text-sm text-text-muted mt-1">Attack Surface Management Platform</p>
          </div>

          <div className="mb-7 hidden lg:block">
            <h2 className="text-xl font-semibold text-text-primary">Sign in</h2>
            <p className="text-sm text-text-muted mt-1">Use your workspace email and password.</p>
          </div>

          <div className="card p-6 lg:p-0 lg:border-0 lg:shadow-none lg:bg-transparent">
            {error && (
              <div className="flex items-center gap-2 p-3 mb-4 bg-accent-red/10 border border-accent-red/20 rounded-md text-sm text-accent-red">
                <AlertCircle className="w-4 h-4 flex-shrink-0" />
                {error}
              </div>
            )}

            <form onSubmit={handleSubmit} className="space-y-4">
              <div>
                <label htmlFor="login-email" className="block text-xs font-medium text-text-secondary mb-1.5">Email address</label>
                <input
                  id="login-email"
                  type="email"
                  value={email}
                  onChange={(e) => setEmail(e.target.value)}
                  className="input"
                  placeholder="you@company.com"
                  required
                  autoFocus
                />
              </div>

              <div>
                <label htmlFor="login-password" className="block text-xs font-medium text-text-secondary mb-1.5">Password</label>
                <div className="relative">
                  <input
                    id="login-password"
                    type={showPwd ? 'text' : 'password'}
                    value={password}
                    onChange={(e) => setPassword(e.target.value)}
                    className="input pr-10"
                    placeholder="••••••••"
                    required
                  />
                  <button
                    type="button"
                    onClick={() => setShowPwd(!showPwd)}
                    className="absolute right-3 top-1/2 -translate-y-1/2 text-text-muted hover:text-text-secondary"
                  >
                    {showPwd ? <EyeOff className="w-4 h-4" /> : <Eye className="w-4 h-4" />}
                  </button>
                </div>
              </div>

              <button
                type="submit"
                disabled={loading}
                className="w-full py-2.5 px-4 bg-accent-cyan text-white hover:bg-accent-cyan/90 rounded text-sm font-semibold transition-all disabled:opacity-50 disabled:cursor-not-allowed flex items-center justify-center gap-2 shadow-sm"
              >
                {loading ? (
                  <>
                    <span className="w-4 h-4 border-2 border-white/30 border-t-white rounded-full animate-spin" />
                    Signing in…
                  </>
                ) : 'Sign in'}
              </button>
            </form>

            <p className="mt-5 text-center text-xs text-text-muted">
              New organization?{' '}
              <Link to="/register" className="text-accent-cyan font-medium hover:underline">Create account</Link>
            </p>
          </div>
        </div>
      </div>
    </div>
  )
}
