import { useEffect, useState } from 'react'
import { useSearchParams, useNavigate } from 'react-router-dom'
import { authApi } from '@/utils/api'

export default function VerifyEmailPage() {
  const [params] = useSearchParams()
  const navigate = useNavigate()
  const [status, setStatus] = useState<'pending' | 'success' | 'error'>('pending')
  const [message, setMessage] = useState('')

  useEffect(() => {
    const token = params.get('token')
    if (!token) {
      setStatus('error')
      setMessage('No verification token provided.')
      return
    }
    authApi.verifyEmail(token)
      .then(() => {
        setStatus('success')
        setMessage('Your email has been verified. You can now log in.')
        setTimeout(() => navigate('/login'), 3000)
      })
      .catch((err: { response?: { data?: { error?: string } } }) => {
        setStatus('error')
        setMessage(err?.response?.data?.error ?? 'Invalid or expired verification link.')
      })
  }, []) // eslint-disable-line react-hooks/exhaustive-deps

  return (
    <div className="min-h-screen flex items-center justify-center bg-bg-primary">
      <div className="card p-8 max-w-md w-full text-center space-y-4">
        <h1 className="text-xl font-semibold text-text-primary">Email Verification</h1>
        {status === 'pending' && (
          <p className="text-text-muted">Verifying your email…</p>
        )}
        {status === 'success' && (
          <>
            <p className="text-accent-green">{message}</p>
            <p className="text-text-muted text-sm">Redirecting to login…</p>
          </>
        )}
        {status === 'error' && (
          <>
            <p className="text-accent-red">{message}</p>
            <a href="/resend-verification" className="btn-primary text-sm inline-block">
              Resend verification email
            </a>
          </>
        )}
      </div>
    </div>
  )
}
