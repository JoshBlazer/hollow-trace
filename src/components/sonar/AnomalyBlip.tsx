import type { Severity } from '../../types/hollow'
import { severityColor } from '../../lib/format'

interface Props {
  cx: number
  cy: number
  severity: Severity
  isNew: boolean
}

export default function AnomalyBlip({ cx, cy, severity, isNew }: Props) {
  const color = severityColor(severity)

  return (
    <g>
      {/* Ping ring — only rendered for 1500ms after arrival */}
      {isNew && (
        <circle
          cx={cx}
          cy={cy}
          r={5}
          fill="none"
          stroke={color}
          strokeWidth="1"
          className="animate-ping"
          style={{ transformOrigin: `${cx}px ${cy}px` }}
        />
      )}
      {/* Main blip */}
      <circle cx={cx} cy={cy} r={3} fill={color} fillOpacity={0.9} />
      <circle cx={cx} cy={cy} r={3} fill="none" stroke={color} strokeWidth="0.5" strokeOpacity={0.4} />
    </g>
  )
}
