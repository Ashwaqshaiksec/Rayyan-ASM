import { useState } from 'react'
import { authApi } from '@/utils/api'

export default function ResendVerificationPage() {
  const [email, setEmail] = useState('')
  const [submitted, setSubmitted] = useState(false)
  const [loading, setLoading] = useState(false)

  async function handleSubmit(e: React.FormEvent) {
    e.preventDefault()
    setLoading(true)
    try {
      await authApi.resendVerification(email)
    } catch {
      // Always show the same message regardless — prevents email enumeration
    } finally {
      setLoading(false)
      setSubmitted(true)
    }
  }

  return (
    <div className="min-h-screen flex items-center justify-center bg-bg-primary">
      <div className="card p-8 max-w-md w-full space-y-4">
        <h1 className="text-xl font-semibold text-text-primary">Resend Verification Email</h1>
        {submitted ? (
          <p className="text-text-muted text-sm">
            If an unverified account exists for that email, a new link has been sent.
            Check your inbox and spam folder.
          </p>
        ) : (
          <form onSubmit={handleSubmit} className="space-y-4">
            <div>
              <label className="label">Email address</label>
              <input
                type="email"
                className="input w-full"
                value={email}
                onChange={e => setEmail(e.target.value)}
                required
                autoFocus
              />
            </div>
            <button type="submit" disabled={loading} className="btn-primary w-full">
              {loading ? 'Sending…' : 'Send verification link'}
            </button>
            <p className="text-center text-sm text-text-muted">
              <a href="/login" className="text-accent-blue hover:underline">Back to login</a>
            </p>
          </form>
        )}
      </div>
    </div>
  )
}
