import { useState, useCallback, useRef, useEffect, useMemo } from 'react'
import { VariableSizeList } from 'react-window'
import type { ListChildComponentProps } from 'react-window'
import { useAutoScroll } from '../../hooks/useAutoScroll'
import type { LogEntry } from '../../types/hollow'
import LogRow from './LogRow'

const NORMAL_ROW_HEIGHT = 28
const EXPANDED_HEIGHT = 168

interface ItemData {
  entries: LogEntry[]
  expandedId: number | null
  onToggle: (id: number) => void
  onSizeChange: (id: number) => void
}

function Row({ index, style, data }: ListChildComponentProps<ItemData>) {
  const { entries, expandedId, onToggle, onSizeChange } = data
  const entry = entries[index]
  return (
    <LogRow
      entry={entry}
      style={style}
      isExpanded={entry.id === expandedId}
      onToggle={onToggle}
      onSizeChange={onSizeChange}
    />
  )
}

interface Props {
  entries: LogEntry[]
  onClear: () => void
}

export default function LogStreamPanel({ entries, onClear }: Props) {
  const { listRef, isPaused, togglePause } = useAutoScroll(entries.length)

  const [expandedId, setExpandedId] = useState<number | null>(null)

  // Container ref for ResizeObserver
  const containerRef = useRef<HTMLDivElement>(null)
  const [dimensions, setDimensions] = useState({ width: 0, height: 0 })

  useEffect(() => {
    const el = containerRef.current
    if (!el) return
    const ro = new ResizeObserver(([entry]) => {
      const { width, height } = entry.contentRect
      setDimensions({ width, height })
    })
    ro.observe(el)
    return () => ro.disconnect()
  }, [])

  const getItemSize = useCallback(
    (index: number) => {
      const entry = entries[index]
      return entry && entry.id === expandedId ? EXPANDED_HEIGHT : NORMAL_ROW_HEIGHT
    },
    [entries, expandedId],
  )

  const onToggle = useCallback((id: number) => {
    setExpandedId(prev => (prev === id ? null : id))
  }, [])

  const onSizeChange = useCallback((id: number) => {
    if (!listRef.current) return
    const entries_snapshot = listRef.current.props.itemData as ItemData
    const idx = entries_snapshot.entries.findIndex(e => e.id === id)
    if (idx !== -1) listRef.current.resetAfterIndex(idx, true)
  }, [listRef])

  const itemData = useMemo<ItemData>(
    () => ({ entries, expandedId, onToggle, onSizeChange }),
    [entries, expandedId, onToggle, onSizeChange],
  )

  return (
    <div ref={containerRef} className="relative h-full w-full">
      {/* Empty state */}
      {entries.length === 0 && (
        <div className="absolute inset-0 flex flex-col items-center justify-center gap-2 opacity-10 pointer-events-none">
          <span className="text-xs tracking-[0.4em]">LOG STREAM</span>
          <span className="animate-blink text-xs">_</span>
        </div>
      )}

      {/* Virtual list */}
      {dimensions.height > 0 && (
        <VariableSizeList
          ref={listRef}
          width={dimensions.width}
          height={dimensions.height}
          itemCount={entries.length}
          itemSize={getItemSize}
          itemData={itemData}
          overscanCount={8}
        >
          {Row}
        </VariableSizeList>
      )}

      {/* Controls — bottom-right */}
      <div className="absolute bottom-2 right-2 flex gap-2">
        <button
          onClick={togglePause}
          className={[
            'text-[10px] tracking-widest px-2 py-1 border transition-colors duration-150',
            isPaused
              ? 'border-alert text-alert hover:bg-alert/10'
              : 'border-neon/40 text-neon/40 hover:border-neon hover:text-neon',
          ].join(' ')}
        >
          {isPaused ? '▶ RESUME' : '‖ PAUSE'}
        </button>
        <button
          onClick={onClear}
          className="text-[10px] tracking-widest px-2 py-1 border border-neon/20 text-neon/30 hover:border-neon/60 hover:text-neon/60 transition-colors duration-150"
        >
          ✕ CLEAR
        </button>
      </div>
    </div>
  )
}
