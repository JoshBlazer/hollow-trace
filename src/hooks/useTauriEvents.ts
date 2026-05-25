import { useEffect, useRef } from 'react'
import { listen } from '@tauri-apps/api/event'

/**
 * Subscribe to a Tauri backend event. Calls handler whenever the event fires.
 * Unsubscribes automatically on unmount or when the event name changes.
 * Uses a ref so the latest handler is always called without re-subscribing.
 */
export function useTauriEvents<T>(
  event: string,
  handler: (payload: T) => void,
): void {
  const handlerRef = useRef(handler)
  handlerRef.current = handler

  useEffect(() => {
    let unlisten: (() => void) | null = null

    listen<T>(event, (e) => handlerRef.current(e.payload)).then((fn) => {
      unlisten = fn
    })

    return () => {
      unlisten?.()
    }
  }, [event])
}
