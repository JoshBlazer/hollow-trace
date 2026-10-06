import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'
import { act, renderHook } from '@testing-library/react'
import type { EntryFilter, EntryQueryResult } from '../types/hollow'

const queryEntries = vi.fn<(f: EntryFilter) => Promise<EntryQueryResult>>()
vi.mock('../lib/tauri-commands', () => ({ queryEntries: (f: EntryFilter) => queryEntries(f) }))
vi.mock('../lib/notify', () => ({ reportError: vi.fn() }))

import { useEntryQuery } from './useEntryQuery'

const result = (n: number): EntryQueryResult => ({ entries: [], matched: n, scanned: 100 })

describe('useEntryQuery', () => {
  beforeEach(() => {
    vi.useFakeTimers()
    queryEntries.mockReset().mockImplementation(async () => result(1))
  })
  afterEach(() => vi.useRealTimers())

  it('does nothing for an inactive filter', async () => {
    const { result: r } = renderHook(() => useEntryQuery({}, 0))
    await act(async () => { vi.advanceTimersByTime(500) })
    expect(queryEntries).not.toHaveBeenCalled()
    expect(r.current).toBeNull()
  })

  it('debounces typing into a single query', async () => {
    const { rerender, result: r } = renderHook(({ text }) => useEntryQuery({ text }, 0), {
      initialProps: { text: 'u' },
    })
    rerender({ text: 'un' })
    rerender({ text: 'union' })
    await act(async () => { vi.advanceTimersByTime(250) })
    expect(queryEntries).toHaveBeenCalledTimes(1)
    expect(queryEntries).toHaveBeenCalledWith({ text: 'union' })
    expect(r.current?.matched).toBe(1)
  })

  it('refreshes on new data, but not for jump-to-line context', async () => {
    const { rerender } = renderHook(({ f, k }) => useEntryQuery(f, k), {
      initialProps: { f: { text: 'x' } as EntryFilter, k: 1 },
    })
    await act(async () => { vi.advanceTimersByTime(250) })
    rerender({ f: { text: 'x' }, k: 2 })
    await act(async () => { vi.advanceTimersByTime(250) })
    expect(queryEntries).toHaveBeenCalledTimes(2)

    rerender({ f: { around: 5 }, k: 2 })
    await act(async () => { vi.advanceTimersByTime(250) })
    rerender({ f: { around: 5 }, k: 3 })
    await act(async () => { vi.advanceTimersByTime(250) })
    expect(queryEntries).toHaveBeenCalledTimes(3)
  })
})
