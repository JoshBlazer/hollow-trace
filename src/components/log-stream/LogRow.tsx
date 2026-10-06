import React from 'react'
import type { CSSProperties } from 'react'
import type { LogEntry } from '../../types/hollow'
import { formatTimestamp, severityColor, statusColor } from '../../lib/format'
import LogRowExpanded from './LogRowExpanded'

interface Props {
  entry: LogEntry
  style: CSSProperties
  isExpanded: boolean
  onToggle: (id: number) => void
  onSizeChange: (id: number) => void
}

const LogRow = React.memo(function LogRow({
  entry,
  style,
  isExpanded,
  onToggle,
  onSizeChange,
}: Props) {
  function handleClick() {
    onToggle(entry.id)
    // Signal to the list that this row's size changed so it can recompute
    requestAnimationFrame(() => onSizeChange(entry.id))
  }

  const anomaly = entry.isAnomaly

  return (
    <div
      style={style}
      onClick={handleClick}
      className={[
        'flex flex-col cursor-pointer select-none border-b border-neon/10',
        'hover:bg-neon/5 transition-colors duration-75',
        anomaly ? 'bg-alert/5' : '',
        isExpanded ? 'bg-neon/10' : '',
      ].join(' ')}
    >
      {/* Summary line */}
      <div className="flex items-center gap-3 h-7 px-3 shrink-0 text-xs tabular-nums">
        {/* Anomaly indicator */}
        <span
          className="w-3 text-center shrink-0"
          style={{
            color: anomaly ? severityColor(entry.anomalySeverity ?? 'high') : '#00ff41',
            opacity: anomaly ? 1 : 0.25,
          }}
          title={entry.anomalySeverity ? `${entry.anomalySeverity} anomaly` : undefined}
        >
          {anomaly ? '!' : '·'}
        </span>

        {/* Timestamp */}
        <span className="text-neon/40 shrink-0 tracking-tight">
          {formatTimestamp(entry.timestamp)}
        </span>

        {/* IP */}
        {entry.ip && (
          <span className="text-neon/70 shrink-0 w-[110px] truncate">{entry.ip}</span>
        )}

        {/* Method */}
        {entry.method && (
          <span className="text-caution shrink-0 w-[40px]">{entry.method}</span>
        )}

        {/* Status code */}
        {entry.statusCode !== null && (
          <span
            className="shrink-0 w-[30px] font-bold"
            style={{ color: statusColor(entry.statusCode) }}
          >
            {entry.statusCode}
          </span>
        )}

        {/* Path / message */}
        <span className="text-neon/60 truncate flex-1 min-w-0">
          {entry.path ?? entry.message}
        </span>
      </div>

      {/* Expanded section */}
      {isExpanded && <LogRowExpanded entry={entry} />}
    </div>
  )
})

export default LogRow
