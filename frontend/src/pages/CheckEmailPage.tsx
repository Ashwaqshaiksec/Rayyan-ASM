import { useLocation } from 'react-router-dom'

export default function CheckEmailPage() {
  const { state } = useLocation() as { state?: { email?: string } }

  return (
    <div className="min-h-screen flex items-center justify-center bg-bg-primary">
      <div className="card p-8 max-w-md w-full text-center space-y-4">
        <h1 className="text-xl font-semibold text-text-primary">Check your email</h1>
        <p className="text-text-muted text-sm">
          We sent a verification link to{' '}
          {state?.email ? (
            <span className="text-text-primary font-medium">{state.email}</span>
          ) : (
            'your email address'
          )}
          . Click it to activate your account.
        </p>
        <p className="text-text-muted text-xs">
          Didn't get it?{' '}
          <a href="/resend-verification" className="text-accent-blue hover:underline">
            Resend verification email
          </a>
        </p>
        <a href="/login" className="btn-ghost text-sm inline-block">
          Back to login
        </a>
      </div>
    </div>
  )
}
