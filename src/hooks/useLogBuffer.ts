import { useState, useCallback } from 'react'
import { useTauriEvents } from './useTauriEvents'
import type { LogEntry, LogEntryPayload } from '../types/hollow'

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

  const clear = useCallback(() => setEntries([]), [])

  return { entries, clear }
}
