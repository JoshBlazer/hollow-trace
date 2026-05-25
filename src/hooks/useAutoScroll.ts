import { useRef, useState, useEffect, useCallback } from 'react'
import type { VariableSizeList } from 'react-window'

export function useAutoScroll(entryCount: number) {
  const listRef = useRef<VariableSizeList>(null)
  const [isPaused, setIsPaused] = useState(false)

  // Refs let us read current values inside stable callbacks without stale closures
  const isPausedRef = useRef(false)
  const entryCountRef = useRef(entryCount)
  entryCountRef.current = entryCount

  // Auto-scroll whenever new entries arrive and we're not paused
  useEffect(() => {
    if (!isPausedRef.current && entryCount > 0) {
      listRef.current?.scrollToItem(entryCount - 1, 'end')
    }
  }, [entryCount])

  const togglePause = useCallback(() => {
    const next = !isPausedRef.current
    isPausedRef.current = next
    setIsPaused(next)
    if (!next) {
      // Unpausing: jump to bottom immediately
      requestAnimationFrame(() => {
        listRef.current?.scrollToItem(entryCountRef.current - 1, 'end')
      })
    }
  }, [])

  return { listRef, isPaused, togglePause }
}
