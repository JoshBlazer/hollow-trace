import type { LogEntry } from '../../types/hollow'
import { formatTimestamp, formatBytes, statusColor } from '../../lib/format'

interface Props {
  entry: LogEntry
}

export default function LogRowExpanded({ entry }: Props) {
  return (
    <div className="px-3 pb-2 text-xs leading-relaxed">
      {/* Raw line */}
      <div className="mb-2 px-2 py-1 bg-black border border-neon/20 text-neon/50 font-mono break-all">
        {entry.raw}
      </div>

      {/* Parsed fields grid */}
      <div className="grid grid-cols-3 gap-x-4 gap-y-1 mb-2">
        <Field label="TIMESTAMP" value={formatTimestamp(entry.timestamp)} />
        <Field label="FORMAT"    value={entry.format.toUpperCase()} />
        <Field label="LEVEL"     value={entry.level.toUpperCase()} />
        <Field label="IP"        value={entry.ip ?? '—'} />
        <Field
          label="STATUS"
          value={entry.statusCode?.toString() ?? '—'}
          color={statusColor(entry.statusCode)}
        />
        <Field label="BYTES"     value={formatBytes(entry.bytes)} />
        <Field label="METHOD"    value={entry.method ?? '—'} />
        <Field label="PATH"      value={entry.path ?? '—'} wide />
      </div>

      {/* Anomaly badge */}
      {entry.isAnomaly && entry.anomalyId !== null && (
        <div className="inline-flex items-center gap-2 px-2 py-0.5 border border-alert/60 text-alert text-[10px] tracking-widest">
          <span className="animate-blink">▲</span>
          <span>ANOMALY #{entry.anomalyId}</span>
        </div>
      )}
    </div>
  )
}

function Field({
  label,
  value,
  color,
  wide,
}: {
  label: string
  value: string
  color?: string
  wide?: boolean
}) {
  return (
    <div className={wide ? 'col-span-3' : ''}>
      <span className="text-neon/30 tracking-widest mr-2">{label}</span>
      <span style={color ? { color } : undefined} className="text-neon/80">
        {value}
      </span>
    </div>
  )
}
