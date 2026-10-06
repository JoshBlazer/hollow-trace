import { describe, expect, it } from 'vitest'
import { EMPTY_FORM, isFilterActive, isFormEmpty, toEntryFilter } from './entry-filter'

describe('entry filter', () => {
  it('maps an empty or whitespace-only form to no filter', () => {
    expect(toEntryFilter(EMPTY_FORM)).toEqual({})
    expect(isFormEmpty({ ...EMPTY_FORM, text: '   ', ip: ' ' })).toBe(true)
  })

  it('maps every field', () => {
    expect(toEntryFilter({ text: ' union ', ip: '10.0.0.0/8 ', severity: 'high', status: '4' })).toEqual({
      text: 'union',
      ip: '10.0.0.0/8',
      minSeverity: 'high',
      statusClass: 4,
    })
    expect(toEntryFilter({ ...EMPTY_FORM, severity: 'anomalies' })).toEqual({ anomaliesOnly: true })
  })

  it('treats jump-to-line as active even with no other criteria', () => {
    expect(isFilterActive({})).toBe(false)
    expect(isFilterActive({ around: 0 })).toBe(true)
  })
})
