import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'

const logError = vi.fn((_message: string) => Promise.resolve())
vi.mock('@tauri-apps/plugin-log', () => ({ error: (m: string) => logError(m) }))

import { _resetForTests, dismiss, errorMessage, getToasts, notify, reportError, subscribe } from './notify'

describe('notify', () => {
  beforeEach(() => {
    _resetForTests()
    logError.mockClear()
    vi.useFakeTimers()
  })
  afterEach(() => vi.useRealTimers())

  it('publishes toasts to subscribers and auto-dismisses non-sticky ones', () => {
    const listener = vi.fn()
    subscribe(listener)
    notify('success', 'saved')
    const sticky = notify('info', 'update available', { sticky: true })
    expect(getToasts().map(t => t.message)).toEqual(['saved', 'update available'])
    expect(listener).toHaveBeenCalledTimes(2)

    vi.advanceTimersByTime(60_000)
    expect(getToasts().map(t => t.id)).toEqual([sticky])
    dismiss(sticky)
    expect(getToasts()).toEqual([])
  })

  it('keeps at most four toasts', () => {
    for (let i = 0; i < 6; i++) notify('info', `m${i}`, { sticky: true })
    expect(getToasts().map(t => t.message)).toEqual(['m2', 'm3', 'm4', 'm5'])
  })

  it('reportError logs to file and optionally skips the toast', () => {
    reportError('Open file failed', new Error('Cannot open x'))
    expect(logError).toHaveBeenCalledWith('Open file failed: Cannot open x')
    expect(getToasts()[0]).toMatchObject({ kind: 'error', message: 'Open file failed: Cannot open x' })

    reportError('Export', 'disk full', { toast: false })
    expect(logError).toHaveBeenCalledWith('Export: disk full')
    expect(getToasts()).toHaveLength(1)
  })

  it('formats unknown errors', () => {
    expect(errorMessage('plain')).toBe('plain')
    expect(errorMessage({ code: 5 })).toBe('{"code":5}')
  })
})
