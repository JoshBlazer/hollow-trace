import type { SeverityCounts } from '../../types/hollow'

interface Props {
  counts: SeverityCounts
}

const BANDS = [
  { key: 'critical', label: 'C', color: '#ff0055' },
  { key: 'high',     label: 'H', color: '#ff0055' },
  { key: 'medium',   label: 'M', color: '#ff6600' },
  { key: 'low',      label: 'L', color: '#ffff00' },
] as const

export default function SeverityBreakdown({ counts }: Props) {
  return (
    <div className="flex items-center gap-3 tabular-nums">
      {BANDS.map(({ key, label, color }) => {
        const n = counts[key]
        return (
          <span
            key={key}
            style={{ color: n > 0 ? color : 'rgba(0,255,65,0.2)' }}
          >
            {label}:{n}
          </span>
        )
      })}
    </div>
  )
}
