import { StrictMode } from 'react'
import { describe, expect, it, vi } from 'vitest'
import { act, render } from '@testing-library/react'

// listen() resolves asynchronously, like the real IPC call
type Cb = (e: { payload: unknown }) => void
const live = new Set<Cb>()
let pendingResolves: Array<() => void> = []
vi.mock('@tauri-apps/api/event', () => ({
  listen: (_event: string, cb: Cb) =>
    new Promise<() => void>(resolve => {
      pendingResolves.push(() => {
        live.add(cb)
        resolve(() => live.delete(cb))
      })
    }),
}))

import { useTauriEvents } from './useTauriEvents'

function Probe({ onEvent }: { onEvent: (p: unknown) => void }) {
  useTauriEvents('log_entry', onEvent)
  return null
}

describe('useTauriEvents', () => {
  it('does not leak a listener when cleanup runs before listen() resolves (StrictMode)', async () => {
    const onEvent = vi.fn()
    const { unmount } = render(<StrictMode><Probe onEvent={onEvent} /></StrictMode>)

    // StrictMode mounted, cleaned up and re-mounted before any listen() resolved
    await act(async () => {
      pendingResolves.forEach(r => r())
      pendingResolves = []
    })
    expect(live.size).toBe(1)

    live.forEach(cb => cb({ payload: 'x' }))
    expect(onEvent).toHaveBeenCalledTimes(1)

    unmount()
    expect(live.size).toBe(0)
  })
})
