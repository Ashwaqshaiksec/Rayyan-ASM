import React from 'react'
import ReactDOM from 'react-dom/client'
import { BrowserRouter } from 'react-router-dom'
import { Toaster } from 'react-hot-toast'
import App from './App'
import './index.css'
import ErrorBoundary from '@/components/common/ErrorBoundary'
import { initTheme } from '@/utils/theme'

// Apply the last-known theme immediately, before React ever mounts —
// previously nothing set the theme class until the Settings page happened
// to load, so every other page (and every fresh reload) silently ignored
// the saved preference.
initTheme()

ReactDOM.createRoot(document.getElementById('root')!).render(
  <React.StrictMode>
    <ErrorBoundary>
      <BrowserRouter>
      <App />
      <Toaster
        position="bottom-right"
        toastOptions={{
          style: {
            background: 'rgb(var(--surface-1))',
            color: 'rgb(var(--text-primary))',
            border: '1px solid rgb(var(--border))',
            borderRadius: '10px',
            fontSize: '13px',
            fontWeight: 500,
            padding: '10px 14px',
            boxShadow: '0 8px 24px -4px rgba(15, 27, 45, 0.14), 0 4px 8px -4px rgba(15, 27, 45, 0.08)',
          },
          success: { iconTheme: { primary: 'rgb(var(--accent-green))', secondary: 'rgb(var(--surface-1))' } },
          error:   { iconTheme: { primary: 'rgb(var(--accent-red))', secondary: 'rgb(var(--surface-1))' } },
        }}
      />
    </BrowserRouter>
    </ErrorBoundary>
  </React.StrictMode>
)
