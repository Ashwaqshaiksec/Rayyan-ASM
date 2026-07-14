import { useEffect, useRef, useCallback } from 'react'
import { useAuthStore } from '@/store/auth'
import api from '@/utils/api'

type MessageHandler = (data: unknown) => void

interface UseWebSocketOptions {
  onMessage?: MessageHandler
  enabled?: boolean
}

/**
 * Fetch a one-time WebSocket ticket from the backend, then open the WS connection.
 * This avoids putting the JWT in the URL (which would appear in server logs,
 * browser history, and nginx access logs).
 */
async function fetchWSTicket(): Promise<string> {
  const res = await api.post<{ ticket: string }>('/ws/ticket')
  return res.data.ticket
}

export function useWebSocket({ onMessage, enabled = true }: UseWebSocketOptions = {}) {
  const wsRef = useRef<WebSocket | null>(null)
  const reconnectTimer = useRef<ReturnType<typeof setTimeout> | null>(null)
  const token = useAuthStore((s) => s.accessToken)

  const connect = useCallback(async () => {
    if (!enabled) return
    if (wsRef.current?.readyState === WebSocket.OPEN) return
    if (!token) return

    try {
      const ticket = await fetchWSTicket()
      const proto = window.location.protocol === 'https:' ? 'wss' : 'ws'
      // Use ?ticket= instead of ?token= so the JWT never appears in URLs or logs.
      const url = `${proto}://${window.location.host}/ws?ticket=${encodeURIComponent(ticket)}`

      const ws = new WebSocket(url)
      wsRef.current = ws

      ws.onmessage = (ev) => {
        if (!onMessage) return
        try {
          const parsed = JSON.parse(ev.data as string)
          onMessage(parsed)
        } catch {
          // ignore non-JSON frames
        }
      }

      ws.onclose = () => {
        // Reconnect after 3 seconds on unexpected close.
        reconnectTimer.current = setTimeout(() => { void connect() }, 3000)
      }

      ws.onerror = () => {
        ws.close()
      }
    } catch {
      // Ticket fetch failed (e.g. not logged in); retry after delay.
      reconnectTimer.current = setTimeout(() => { void connect() }, 5000)
    }
  }, [enabled, onMessage, token])

  useEffect(() => {
    void connect()
    return () => {
      if (reconnectTimer.current) clearTimeout(reconnectTimer.current)
      wsRef.current?.close()
      wsRef.current = null
    }
  }, [connect])

  const send = useCallback((data: unknown) => {
    if (wsRef.current?.readyState === WebSocket.OPEN) {
      wsRef.current.send(JSON.stringify(data))
    }
  }, [])

  return { send }
}
