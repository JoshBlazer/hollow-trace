import { describe, expect, it } from 'vitest'
import { formatBytes, formatParseRate, formatTimestamp } from './format'

describe('format', () => {
  it('formats timestamps in UTC', () => {
    expect(formatTimestamp(1_777_630_830_000)).toBe('2026-05-01 10:20:30 UTC')
  })
  it('formats bytes and rates', () => {
    expect(formatBytes(null)).toBe('-')
    expect(formatBytes(512)).toBe('512B')
    expect(formatBytes(59_831)).toBe('58.4KB')
    expect(formatParseRate(9_100)).toBe('9.1K/s')
    expect(formatParseRate(42.4)).toBe('42/s')
  })
})
