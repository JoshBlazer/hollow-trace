import type { ReactNode } from 'react'

const CX = 100
const CY = 100
const RINGS = [22, 44, 67, 90]

// Trail: 3 ghost lines (negative delays) + 1 main sweep
// 4s cycle, 10° per trail step ≈ 0.111s delay each
const TRAIL = [
  { delay: '-0.333s', opacity: 0.06 },
  { delay: '-0.222s', opacity: 0.12 },
  { delay: '-0.111s', opacity: 0.22 },
]

interface Props {
  children?: ReactNode
}

export default function RadarRing({ children }: Props) {
  return (
    <svg
      viewBox="0 0 200 200"
      width="100%"
      height="100%"
      xmlns="http://www.w3.org/2000/svg"
    >
      <defs>
        <radialGradient id="radar-bg" cx="50%" cy="50%" r="50%">
          <stop offset="0%"   stopColor="#00ff41" stopOpacity="0.04" />
          <stop offset="100%" stopColor="#000000" stopOpacity="0" />
        </radialGradient>
      </defs>

      {/* Background fill */}
      <circle cx={CX} cy={CY} r={90} fill="url(#radar-bg)" />

      {/* Concentric rings */}
      {RINGS.map(r => (
        <circle
          key={r}
          cx={CX}
          cy={CY}
          r={r}
          fill="none"
          stroke="#00ff41"
          strokeWidth="0.5"
          strokeOpacity={r === 90 ? 0.5 : 0.15}
        />
      ))}

      {/* Crosshair */}
      <line x1={CX} y1={CY - 90} x2={CX} y2={CY + 90}
        stroke="#00ff41" strokeWidth="0.5" strokeOpacity="0.15" strokeDasharray="4 4" />
      <line x1={CX - 90} y1={CY} x2={CX + 90} y2={CY}
        stroke="#00ff41" strokeWidth="0.5" strokeOpacity="0.15" strokeDasharray="4 4" />

      {/* Sweep trail lines (negative animation-delay creates offset) */}
      {TRAIL.map((t, i) => (
        <line
          key={i}
          x1={CX} y1={CY} x2={CX} y2={CY - 90}
          stroke="#00ff41"
          strokeWidth="1"
          strokeOpacity={t.opacity}
          className="animate-sweep"
          style={{ transformOrigin: `${CX}px ${CY}px`, animationDelay: t.delay }}
        />
      ))}

      {/* Main sweep line */}
      <line
        x1={CX} y1={CY} x2={CX} y2={CY - 90}
        stroke="#00ff41"
        strokeWidth="1.5"
        strokeOpacity="0.85"
        className="animate-sweep"
        style={{ transformOrigin: `${CX}px ${CY}px` }}
      />

      {/* Center dot */}
      <circle cx={CX} cy={CY} r={2} fill="#00ff41" fillOpacity="0.7" />

      {/* Blips */}
      {children}

      {/* Ring labels */}
      <text x={CX + 2} y={CY - 88} fill="#00ff41" fillOpacity="0.25" fontSize="5" fontFamily="monospace">
        100
      </text>
      <text x={CX + 2} y={CY - 65} fill="#00ff41" fillOpacity="0.2" fontSize="5" fontFamily="monospace">
        75
      </text>
      <text x={CX + 2} y={CY - 42} fill="#00ff41" fillOpacity="0.2" fontSize="5" fontFamily="monospace">
        50
      </text>
    </svg>
  )
}
