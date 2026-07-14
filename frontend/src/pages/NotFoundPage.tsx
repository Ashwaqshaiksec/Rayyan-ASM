import { Link } from 'react-router-dom'
import { Radar, ArrowLeft } from 'lucide-react'

export function NotFoundPage() {
  return (
    <div className="flex flex-col items-center justify-center min-h-[70vh] gap-5 text-center px-6">
      <div className="w-14 h-14 rounded-full bg-surface-2 flex items-center justify-center">
        <Radar className="w-7 h-7 text-text-muted" />
      </div>
      <div>
        <div className="text-5xl font-bold font-mono text-text-primary tracking-tight">404</div>
        <p className="text-sm text-text-muted mt-2 max-w-sm">
          This page doesn't exist — it may have moved, or the link might be out of date.
        </p>
      </div>
      <Link to="/dashboard" className="btn-primary text-sm flex items-center gap-2">
        <ArrowLeft className="w-3.5 h-3.5" />
        Back to Dashboard
      </Link>
    </div>
  )
}

export default NotFoundPage
