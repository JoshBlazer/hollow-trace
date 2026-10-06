import { useEffect, useMemo, useRef, useState } from 'react'
import LogStreamPanel from '../log-stream/LogStreamPanel'
import AnomalyTable from '../anomalies/AnomalyTable'
import FilterBar from './FilterBar'
import { useEntryQuery } from '../../hooks/useEntryQuery'
import { EMPTY_FORM, isFormEmpty, toEntryFilter, type FilterForm } from '../../lib/entry-filter'
import type { AppStats, EntryFilter, LogEntry, MainView } from '../../types/hollow'

export interface JumpRequest {
  entryId: number
  /** Distinguishes repeated jumps to the same line */
  nonce: number
}

interface Props {
  entries: LogEntry[]
  session: number
  stats: AppStats
  onClear: () => void
  jumpRequest: JumpRequest | null
  onJump: (entryId: number) => void
}

function Tab({ active, onClick, children }: { active: boolean; onClick: () => void; children: React.ReactNode }) {
  return (
    <button
      onClick={onClick}
      className={`px-3 h-8 text-[10px] tracking-[0.3em] border-b-2 ${active ? 'border-neon text-neon' : 'border-transparent text-neon/40 hover:text-neon/70'}`}
    >
      {children}
    </button>
  )
}

/** Log stream (live, searched, or jump context) and the grouped anomaly view. */
export default function MainPanel({ entries, session, stats, onClear, jumpRequest, onJump }: Props) {
  const [view, setView] = useState<MainView>('stream')
  const [form, setForm] = useState<FilterForm>(EMPTY_FORM)
  const [jumpId, setJumpId] = useState<number | null>(null)
  const searchRef = useRef<HTMLInputElement>(null)

  // A new file starts fresh
  useEffect(() => {
    setForm(EMPTY_FORM)
    setJumpId(null)
  }, [session])

  useEffect(() => {
    if (!jumpRequest) return
    setView('stream')
    setJumpId(jumpRequest.entryId)
  }, [jumpRequest])

  // Ctrl/Cmd+F focuses the search box
  useEffect(() => {
    function onKeyDown(e: KeyboardEvent) {
      if ((e.ctrlKey || e.metaKey) && e.key.toLowerCase() === 'f') {
        e.preventDefault()
        setView('stream')
        requestAnimationFrame(() => searchRef.current?.focus())
      }
    }
    window.addEventListener('keydown', onKeyDown)
    return () => window.removeEventListener('keydown', onKeyDown)
  }, [])

  const filter: EntryFilter = useMemo(
    () => (jumpId !== null ? { around: jumpId } : toEntryFilter(form)),
    [jumpId, form],
  )
  const result = useEntryQuery(filter, stats.totalLines)
  const searching = jumpId !== null || !isFormEmpty(form)
  const shown = searching ? result?.entries ?? [] : entries

  function changeForm(next: FilterForm) {
    setJumpId(null) // editing the search leaves jump mode
    setForm(next)
  }

  let status: React.ReactNode = null
  if (jumpId !== null) {
    status = (
      <>
        <span>CONTEXT AROUND LINE {jumpId.toLocaleString()}</span>
        <button onClick={() => setJumpId(null)} className="ml-auto text-neon/70 hover:text-neon">
          ← BACK TO {isFormEmpty(form) ? 'LIVE STREAM' : 'SEARCH'}
        </button>
      </>
    )
  } else if (searching) {
    status = !result ? (
      <span className="animate-blink">SEARCHING…</span>
    ) : (
      <>
        <span>
          <span className="text-neon">{result.matched.toLocaleString()}</span> MATCHES IN{' '}
          {result.scanned.toLocaleString()} LINES
        </span>
        {result.matched > result.entries.length && (
          <span className="text-neon/40">· SHOWING NEWEST {result.entries.length.toLocaleString()}</span>
        )}
      </>
    )
  }

  return (
    <div className="flex flex-col h-full min-h-0">
      <div className="flex items-center border-b border-neon/20 shrink-0">
        <Tab active={view === 'stream'} onClick={() => setView('stream')}>STREAM</Tab>
        <Tab active={view === 'anomalies'} onClick={() => setView('anomalies')}>
          ANOMALIES{stats.anomalyCount > 0 && <span className="text-alert ml-2">{stats.anomalyCount.toLocaleString()}</span>}
        </Tab>
      </div>

      {view === 'stream' ? (
        <>
          <FilterBar ref={searchRef} form={form} onChange={changeForm} />
          {status && (
            <div className="flex items-center gap-2 px-3 h-6 text-[10px] tracking-widest text-neon/60 border-b border-neon/10 shrink-0">
              {status}
            </div>
          )}
          <div className="flex-1 min-h-0 relative">
            {searching && result && result.entries.length === 0 ? (
              <div className="absolute inset-0 flex items-center justify-center text-neon/25 text-xs tracking-[0.3em]">
                NO MATCHING LINES
              </div>
            ) : (
              <LogStreamPanel
                entries={shown}
                session={session}
                onClear={onClear}
                live={!searching}
                focusId={jumpId}
              />
            )}
          </div>
        </>
      ) : (
        <div className="flex-1 min-h-0">
          <AnomalyTable refreshKey={stats.anomalyCount + session * 1e9} onJump={onJump} />
        </div>
      )}
    </div>
  )
}
