import { useState, useCallback } from 'react'
import { useTauriEvents } from './useTauriEvents'
import type { LogEntry, LogEntryPayload, StreamResetPayload } from '../types/hollow'

const MAX_ENTRIES = 10_000

export function useLogBuffer() {
  const [entries, setEntries] = useState<LogEntry[]>([])

  const appendEntries = useCallback((incoming: LogEntryPayload) => {
    if (!incoming.length) return
    setEntries(prev => {
      const next = [...prev, ...incoming]
      return next.length > MAX_ENTRIES ? next.slice(next.length - MAX_ENTRIES) : next
    })
  }, [])

  useTauriEvents<LogEntryPayload>('log_entry', appendEntries)

  // Bumped whenever the stream restarts, so views can drop per-session UI state
  // (entry ids restart at 1 for each new file)
  const [session, setSession] = useState(0)
  const clear = useCallback(() => {
    setEntries([])
    setSession(s => s + 1)
  }, [])

  useTauriEvents<StreamResetPayload>('stream_reset', clear)

  return { entries, clear, session }
}
