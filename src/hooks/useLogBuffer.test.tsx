import { describe, expect, it, vi } from 'vitest'
import { act, renderHook } from '@testing-library/react'
import type { LogEntry } from '../types/hollow'

let emit: (payload: LogEntry[]) => void = () => {}
vi.mock('@tauri-apps/api/event', () => ({
  listen: (_e: string, cb: (e: { payload: LogEntry[] }) => void) => {
    emit = p => cb({ payload: p })
    return Promise.resolve(() => {})
  },
}))

import { useLogBuffer } from './useLogBuffer'

const entry = (id: number) => ({ id }) as LogEntry

describe('useLogBuffer', () => {
  it('appends batches and caps at 10,000 entries, keeping the newest', async () => {
    const { result } = renderHook(() => useLogBuffer())
    await act(async () => {})

    act(() => emit(Array.from({ length: 6_000 }, (_, i) => entry(i))))
    act(() => emit(Array.from({ length: 6_000 }, (_, i) => entry(6_000 + i))))

    expect(result.current.entries).toHaveLength(10_000)
    expect(result.current.entries[0].id).toBe(2_000)
    expect(result.current.entries[result.current.entries.length - 1].id).toBe(11_999)

    act(() => result.current.clear())
    expect(result.current.entries).toHaveLength(0)
  })
})
