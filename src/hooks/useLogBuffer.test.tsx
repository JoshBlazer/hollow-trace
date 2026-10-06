import { describe, expect, it, vi } from 'vitest'
import { act, renderHook } from '@testing-library/react'
import type { LogEntry } from '../types/hollow'

// Route mocked Tauri events by name, like the real event bus
const handlers = new Map<string, (e: { payload: unknown }) => void>()
const emit = (event: string, payload: unknown) => handlers.get(event)?.({ payload })
vi.mock('@tauri-apps/api/event', () => ({
  listen: (event: string, cb: (e: { payload: unknown }) => void) => {
    handlers.set(event, cb)
    return Promise.resolve(() => handlers.delete(event))
  },
}))

import { useLogBuffer } from './useLogBuffer'

const entry = (id: number) => ({ id }) as LogEntry

describe('useLogBuffer', () => {
  it('appends batches and caps at 10,000 entries, keeping the newest', async () => {
    const { result } = renderHook(() => useLogBuffer())
    await act(async () => {})

    act(() => emit('log_entry', Array.from({ length: 6_000 }, (_, i) => entry(i))))
    act(() => emit('log_entry', Array.from({ length: 6_000 }, (_, i) => entry(6_000 + i))))

    expect(result.current.entries).toHaveLength(10_000)
    expect(result.current.entries[0].id).toBe(2_000)
    expect(result.current.entries[result.current.entries.length - 1].id).toBe(11_999)
  })

  it('drops the previous stream on stream_reset and bumps the session', async () => {
    const { result } = renderHook(() => useLogBuffer())
    await act(async () => {})

    act(() => emit('log_entry', [entry(1), entry(2), entry(3)]))
    const before = result.current.session

    // A smaller second file must not be mixed with the first one's lines
    act(() => emit('stream_reset', null))
    act(() => emit('log_entry', [entry(1)]))

    expect(result.current.entries.map(e => e.id)).toEqual([1])
    expect(result.current.session).toBe(before + 1)

    act(() => result.current.clear())
    expect(result.current.entries).toHaveLength(0)
  })
})
