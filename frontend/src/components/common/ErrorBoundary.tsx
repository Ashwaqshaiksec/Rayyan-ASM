import { Component, type ErrorInfo, type ReactNode } from 'react'
import { AlertTriangle, RefreshCw } from 'lucide-react'

interface Props {
  children: ReactNode
  fallback?: ReactNode
}

interface State {
  hasError: boolean
  error: Error | null
}

export default class ErrorBoundary extends Component<Props, State> {
  state: State = { hasError: false, error: null }

  static getDerivedStateFromError(error: Error): State {
    return { hasError: true, error }
  }

  componentDidCatch(error: Error, info: ErrorInfo) {
    console.error('[ErrorBoundary]', error, info.componentStack)
  }

  handleReset = () => {
    this.setState({ hasError: false, error: null })
  }

  render() {
    if (!this.state.hasError) return this.props.children

    if (this.props.fallback) return this.props.fallback

    return (
      <div className="flex flex-col items-center justify-center min-h-[400px] gap-4 p-8 text-center">
        <div className="w-12 h-12 rounded-full bg-accent-red/10 flex items-center justify-center">
          <AlertTriangle className="w-6 h-6 text-accent-red" />
        </div>
        <div>
          <p className="text-sm font-medium text-text-primary mb-1">
            Something went wrong
          </p>
          <p className="text-xs text-text-muted max-w-sm">
            {this.state.error?.message ?? 'An unexpected error occurred in this page.'}
          </p>
        </div>
        <button
          onClick={this.handleReset}
          className="flex items-center gap-2 px-3 py-1.5 text-xs rounded-md bg-surface-2 hover:bg-surface-3 transition-colors"
        >
          <RefreshCw className="w-3.5 h-3.5" />
          Try again
        </button>
      </div>
    )
  }
}
