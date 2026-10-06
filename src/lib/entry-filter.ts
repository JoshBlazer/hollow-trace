// Search-bar state and its mapping to the backend EntryFilter.
import type { EntryFilter, Severity } from '../types/hollow'

/** "any" | "anomalies" | a minimum severity */
export type SeverityChoice = 'any' | 'anomalies' | Exclude<Severity, 'low'>

export interface FilterForm {
  text: string
  ip: string
  severity: SeverityChoice
  status: '' | '2' | '3' | '4' | '5'
}

export const EMPTY_FORM: FilterForm = { text: '', ip: '', severity: 'any', status: '' }

export function toEntryFilter(f: FilterForm): EntryFilter {
  const filter: EntryFilter = {}
  if (f.text.trim()) filter.text = f.text.trim()
  if (f.ip.trim()) filter.ip = f.ip.trim()
  if (f.severity === 'anomalies') filter.anomaliesOnly = true
  else if (f.severity !== 'any') filter.minSeverity = f.severity
  if (f.status) filter.statusClass = Number(f.status) as 2 | 3 | 4 | 5
  return filter
}

/** True if the filter narrows anything (or is a jump-to-line request). */
export function isFilterActive(filter: EntryFilter): boolean {
  return Boolean(
    filter.around !== undefined ||
      filter.text?.trim() ||
      filter.ip?.trim() ||
      filter.minSeverity ||
      filter.anomaliesOnly ||
      filter.statusClass,
  )
}

export function isFormEmpty(f: FilterForm): boolean {
  return !isFilterActive(toEntryFilter(f))
}
