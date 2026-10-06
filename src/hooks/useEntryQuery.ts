import { useEffect, useState } from 'react'
import { queryEntries } from '../lib/tauri-commands'
import { isFilterActive } from '../lib/entry-filter'
import { reportError } from '../lib/notify'
import type { EntryFilter, EntryQueryResult } from '../types/hollow'

const DEBOUNCE_MS = 200

/**
 * Runs `filter` against the backend buffer. Returns null when the filter is inactive
 * (callers show the live stream instead). Re-runs when `refreshKey` changes, e.g. as
 * lines arrive during a live tail — except for jump-to-line context, which is fixed.
 */
export function useEntryQuery(filter: EntryFilter, refreshKey: number): EntryQueryResult | null {
  const [result, setResult] = useState<EntryQueryResult | null>(null)
  const active = isFilterActive(filter)
  const filterKey = JSON.stringify(filter)
  const refresh = filter.around === undefined ? refreshKey : 0

  useEffect(() => {
    if (!active) {
      setResult(null)
      return
    }
    let cancelled = false
    const timer = setTimeout(() => {
      queryEntries(JSON.parse(filterKey) as EntryFilter)
        .then(r => { if (!cancelled) setResult(r) })
        .catch(err => { if (!cancelled) reportError('Search failed', err) })
    }, DEBOUNCE_MS)
    return () => {
      cancelled = true
      clearTimeout(timer)
    }
  }, [active, filterKey, refresh])

  return active ? result : null
}
