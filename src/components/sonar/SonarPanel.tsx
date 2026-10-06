import { useState } from 'react'
import { useTauriEvents } from '../../hooks/useTauriEvents'
import type { Anomaly, AnomalyPayload, Severity, StreamResetPayload } from '../../types/hollow'
import { severityColor, severityLabel, formatTimestamp } from '../../lib/format'
import RadarRing from './RadarRing'
import AnomalyBlip from './AnomalyBlip'
import ThreatScore from './ThreatScore'

const MAX_BLIPS = 50
const RECENT_LIST_COUNT = 6
// Only the newest few blips of a batch ping — pinging a whole batch smears the radar
const MAX_PINGS_PER_BATCH = 3

const CENTER = 100
const MAX_R = 90

// Radial band per severity as [inner, outer] fractions of MAX_R, aligned to RadarRing's rings
const SEVERITY_BAND: Record<Severity, [number, number]> = {
  critical: [0.76, 0.97],
  high:     [0.51, 0.73],
  medium:   [0.27, 0.48],
  low:      [0.08, 0.23],
}

// Deterministic 0..1 hash so a blip keeps its position across re-renders
function hash01(n: number): number {
  const x = Math.sin(n * 12.9898) * 43758.5453
  return x - Math.floor(x)
}

function blipPosition(anomaly: Anomaly): { cx: number; cy: number } {
  // Golden angle ~137.508° gives near-uniform angular distribution
  const angleDeg = (anomaly.id * 137.508) % 360
  const angleRad = (angleDeg * Math.PI) / 180
  // Spread across the whole band (sqrt keeps density even by area), independent of angle
  const [inner, outer] = SEVERITY_BAND[anomaly.severity]
  const t = Math.sqrt(hash01(anomaly.id + anomaly.entryId * 31))
  const r = (inner + (outer - inner) * t) * MAX_R
  return {
    cx: CENTER + r * Math.sin(angleRad),
    cy: CENTER - r * Math.cos(angleRad),
  }
}

interface Props {
  threatScore: number
  /** Show an anomaly's line in the stream */
  onJump: (entryId: number) => void
}

export default function SonarPanel({ threatScore, onJump }: Props) {
  const [anomalies, setAnomalies] = useState<Anomaly[]>([])
  const [newIds, setNewIds] = useState<Set<number>>(new Set())

  useTauriEvents<StreamResetPayload>('stream_reset', () => {
    setAnomalies([])
    setNewIds(new Set())
  })

  useTauriEvents<AnomalyPayload>('anomaly_detected', (incoming) => {
    if (!incoming.length) return

    setAnomalies(prev => {
      // Anomaly ids restart at 0 when a new file is opened — drop stale blips that
      // reuse an incoming id so React keys stay unique.
      const incomingIds = new Set(incoming.map(a => a.id))
      const next = [...prev.filter(a => !incomingIds.has(a.id)), ...incoming]
      return next.length > MAX_BLIPS ? next.slice(next.length - MAX_BLIPS) : next
    })

    const ids = incoming.slice(-MAX_PINGS_PER_BATCH).map(a => a.id)
    setNewIds(prev => new Set([...prev, ...ids]))
    setTimeout(() => {
      setNewIds(prev => {
        const next = new Set(prev)
        ids.forEach(id => next.delete(id))
        return next
      })
    }, 1500)
  })

  const recent = anomalies.slice(-RECENT_LIST_COUNT).reverse()

  return (
    <div className="flex flex-col h-full text-xs font-mono">
      {/* Header */}
      <div className="px-3 py-1.5 border-b border-neon/20 flex items-center justify-between shrink-0">
        <span className="tracking-[0.3em] text-neon/60 text-[10px]">◈ ANOMALY RADAR</span>
        <span className="text-neon/30 text-[10px]">{anomalies.length} blips</span>
      </div>

      {/* Radar */}
      <div className="w-full aspect-square shrink-0 p-2">
        <RadarRing>
          {anomalies.map(a => {
            const { cx, cy } = blipPosition(a)
            return (
              <AnomalyBlip
                key={a.id}
                cx={cx}
                cy={cy}
                severity={a.severity}
                isNew={newIds.has(a.id)}
              />
            )
          })}
        </RadarRing>
      </div>

      {/* Threat score */}
      <div className="border-t border-neon/20 shrink-0">
        <ThreatScore score={threatScore} />
      </div>

      {/* Recent anomalies */}
      <div className="flex-1 overflow-hidden border-t border-neon/20">
        <div className="px-3 py-1 text-[10px] tracking-[0.3em] text-neon/40">RECENT</div>
        <div className="flex flex-col gap-0">
          {recent.length === 0 ? (
            <div className="px-3 py-2 text-neon/15 text-[10px] tracking-widest">NO ANOMALIES</div>
          ) : (
            recent.map(a => (
              <button
                key={a.id}
                onClick={() => onJump(a.entryId)}
                title="Show this line in the stream"
                className="w-full text-left flex items-center gap-2 px-3 py-1 border-b border-neon/10 hover:bg-neon/5"
              >
                <span
                  className="shrink-0 text-[10px] font-bold"
                  style={{ color: severityColor(a.severity) }}
                >
                  {severityLabel(a.severity).slice(0, 3)}
                </span>
                <span className="flex-1 truncate text-neon/50 text-[10px]" title={a.description}>
                  {a.description}
                </span>
              </button>
            ))
          )}
        </div>
      </div>

      {/* Footer timestamp of latest anomaly */}
      {anomalies.length > 0 && (
        <div className="border-t border-neon/10 px-3 py-1 text-neon/20 text-[9px] tracking-tight shrink-0">
          LAST {formatTimestamp(anomalies[anomalies.length - 1].timestamp)}
        </div>
      )}
    </div>
  )
}
