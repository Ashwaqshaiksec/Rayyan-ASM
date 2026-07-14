import { useState } from 'react'
import { Link, useNavigate } from 'react-router-dom'
import { Radar, ShieldCheck, Globe2, Activity } from 'lucide-react'
import { authApi } from '@/utils/api'
import toast from 'react-hot-toast'
import { isAxiosError } from 'axios'

export default function RegisterPage() {
  const [form, setForm] = useState({ org_name: '', first_name: '', last_name: '', email: '', username: '', password: '' })
  const [loading, setLoading] = useState(false)
  const navigate = useNavigate()

  const set = (k: string) => (e: React.ChangeEvent<HTMLInputElement>) => setForm(f => ({ ...f, [k]: e.target.value }))

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault()
    setLoading(true)
    try {
      await authApi.register(form)
      toast.success('Organization created! Check your email to verify your account.')
      navigate('/check-email', { state: { email: form.email } })
    } catch (err) {
      const message = isAxiosError<{ error: string }>(err)
        ? err.response?.data?.error
        : undefined
      toast.error(message ?? 'Registration failed')
    }
    setLoading(false)
  }

  return (
    <div className="min-h-screen flex bg-surface-0">
      {/* Left brand panel */}
      <div className="hidden lg:flex lg:w-[40%] relative flex-col justify-between p-12 overflow-hidden"
        style={{ background: 'linear-gradient(160deg, var(--surface-2) 0%, var(--surface-0) 70%)' }}>

        <div className="absolute inset-0 opacity-[0.06]"
          style={{
            backgroundImage: 'radial-gradient(circle, #12151C 1px, transparent 1px)',
            backgroundSize: '28px 28px',
          }} />
        <div className="absolute -right-24 -top-24 w-96 h-96 rounded-full opacity-[0.10] blur-3xl"
          style={{ background: 'radial-gradient(circle, rgb(var(--accent-cyan)) 0%, transparent 70%)' }} />
        <div className="absolute -left-16 bottom-12 w-72 h-72 rounded-full opacity-[0.06] blur-3xl"
          style={{ background: 'radial-gradient(circle, rgb(var(--accent-cyan)) 0%, transparent 70%)' }} />

        <div className="relative z-10">
          <div className="flex items-center gap-3 mb-16">
            <div className="reticle w-10 h-10 m-1 bg-surface-2 border border-border flex items-center justify-center">
              <Radar className="w-5 h-5 text-accent-cyan" />
            </div>
            <span className="text-text-primary font-mono font-semibold text-lg tracking-tight">RAYYAN_ASM</span>
          </div>

          <h1 className="text-3xl font-semibold text-text-primary leading-tight mb-4 max-w-md">
            Set up your organization in minutes.
          </h1>
          <p className="text-sm text-text-secondary max-w-sm leading-relaxed">
            Bring your whole security team onto one platform for attack surface discovery,
            scanning, and reporting.
          </p>
        </div>

        <div className="relative z-10 grid grid-cols-1 gap-4">
          <div className="flex items-center gap-3 text-text-secondary">
            <Globe2 className="w-4 h-4 text-accent-cyan flex-shrink-0" />
            <span className="text-xs">Automated subdomain &amp; asset discovery</span>
          </div>
          <div className="flex items-center gap-3 text-text-secondary">
            <Activity className="w-4 h-4 text-accent-cyan flex-shrink-0" />
            <span className="text-xs">Real-time scan orchestration and alerting</span>
          </div>
          <div className="flex items-center gap-3 text-text-secondary">
            <ShieldCheck className="w-4 h-4 text-accent-cyan flex-shrink-0" />
            <span className="text-xs">Role-based access for security teams</span>
          </div>
        </div>
      </div>

      {/* Right form panel */}
      <div className="flex-1 flex items-center justify-center p-4 sm:p-8">
        <div className="w-full max-w-md">
          <div className="flex flex-col items-center mb-8 lg:hidden">
            <div className="w-12 h-12 rounded-xl bg-accent-cyan/10 border border-accent-cyan/30 flex items-center justify-center mb-3">
              <Radar className="w-6 h-6 text-accent-cyan" />
            </div>
            <h1 className="text-xl font-semibold text-text-primary">Rayyan ASM</h1>
            <p className="text-sm text-text-muted">Create a new organization</p>
          </div>

          <div className="mb-6 hidden lg:block">
            <h2 className="text-xl font-semibold text-text-primary">Create your organization</h2>
            <p className="text-sm text-text-muted mt-1">Set up your workspace and admin account</p>
          </div>

          <div className="card p-6">
            <form onSubmit={handleSubmit} className="space-y-4">
              <div>
                <label className="block text-xs font-medium text-text-secondary mb-1.5">Organization name</label>
                <input className="input" value={form.org_name} onChange={set('org_name')} placeholder="Acme Security" required />
              </div>
              <div className="grid grid-cols-2 gap-3">
                <div>
                  <label className="block text-xs font-medium text-text-secondary mb-1.5">First name</label>
                  <input className="input" value={form.first_name} onChange={set('first_name')} placeholder="Jane" required />
                </div>
                <div>
                  <label className="block text-xs font-medium text-text-secondary mb-1.5">Last name</label>
                  <input className="input" value={form.last_name} onChange={set('last_name')} placeholder="Doe" required />
                </div>
              </div>
              <div>
                <label className="block text-xs font-medium text-text-secondary mb-1.5">Email</label>
                <input type="email" className="input" value={form.email} onChange={set('email')} placeholder="jane@example.com" required />
              </div>
              <div>
                <label className="block text-xs font-medium text-text-secondary mb-1.5">Username</label>
                <input className="input" value={form.username} onChange={set('username')} placeholder="janedoe" required />
              </div>
              <div>
                <label className="block text-xs font-medium text-text-secondary mb-1.5">Password</label>
                <input type="password" className="input" value={form.password} onChange={set('password')} placeholder="Min 8 characters" required minLength={8} />
              </div>
              <button type="submit" disabled={loading}
                className="w-full py-2.5 bg-accent-cyan text-white hover:bg-accent-cyan/90 rounded text-sm font-semibold transition-all disabled:opacity-50 shadow-sm">
                {loading ? 'Creating…' : 'Create organization'}
              </button>
            </form>
            <p className="mt-4 text-center text-xs text-text-muted">
              Already have an account? <Link to="/login" className="text-accent-cyan font-medium hover:underline">Sign in</Link>
            </p>
          </div>
        </div>
      </div>
    </div>
  )
}

