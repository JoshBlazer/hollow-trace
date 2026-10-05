import { describe, expect, it } from 'vitest'
import { fromForm, parseAllowlist, toForm } from './settings-form'

const defaults = { rateThreshold: 50, rateWindowSecs: 10, baselineSigma: 3, allowlist: ['10.0.0.0/8'] }

describe('settings form', () => {
  it('round-trips settings', () => {
    expect(fromForm(toForm(defaults))).toEqual(defaults)
  })

  it('parses the allowlist, ignoring blanks and comments', () => {
    expect(parseAllowlist('10.0.0.0/8\r\n\n  203.0.113.5   # office VPN\n# whole-line comment\n')).toEqual([
      '10.0.0.0/8',
      '203.0.113.5',
    ])
  })

  it('rejects out-of-range or non-integer values with readable messages', () => {
    const form = toForm(defaults)
    expect(() => fromForm({ ...form, rateThreshold: '1' })).toThrow(/Rate threshold/)
    expect(() => fromForm({ ...form, rateThreshold: '2.5' })).toThrow(/whole number/)
    expect(() => fromForm({ ...form, rateWindowSecs: 'abc' })).toThrow(/Rate window/)
    expect(() => fromForm({ ...form, baselineSigma: '0.5' })).toThrow(/sigma/)
    expect(fromForm({ ...form, baselineSigma: ' 2.5 ' }).baselineSigma).toBe(2.5)
  })
})
