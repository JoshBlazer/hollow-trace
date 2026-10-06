import { describe, expect, it, vi } from 'vitest'
vi.mock('../../lib/tauri-commands', () => ({}))
vi.mock('../../lib/notify', () => ({ reportError: vi.fn() }))
import { categoryLabel, sortGroups } from './AnomalyTable'
import type { AnomalyGroup } from '../../types/hollow'

const g = (key: string, count: number, maxSeverity: AnomalyGroup['maxSeverity'], lastSeen = 0): AnomalyGroup =>
  ({ key, count, maxSeverity, firstSeen: 0, lastSeen, distinct: 1 })

describe('anomaly groups', () => {
  const groups = [g('10.0.0.2', 50, 'high', 3), g('10.0.0.10', 2, 'critical', 1), g('10.0.0.1', 50, 'medium', 2)]

  it('sorts by severity, then count', () => {
    expect(sortGroups(groups, 'severity').map(x => x.key)).toEqual(['10.0.0.10', '10.0.0.2', '10.0.0.1'])
  })
  it('sorts by count, then severity', () => {
    expect(sortGroups(groups, 'count').map(x => x.key)).toEqual(['10.0.0.2', '10.0.0.1', '10.0.0.10'])
  })
  it('sorts keys naturally and by recency', () => {
    expect(sortGroups(groups, 'key').map(x => x.key)).toEqual(['10.0.0.1', '10.0.0.2', '10.0.0.10'])
    expect(sortGroups(groups, 'lastSeen')[0].key).toBe('10.0.0.2')
  })
  it('labels categories', () => {
    expect(categoryLabel('rate_burst')).toBe('Rate burst')
    expect(categoryLabel('something_new')).toBe('something_new')
  })
})
