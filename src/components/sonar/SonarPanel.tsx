import { useState } from 'react'
import { useTauriEvents } from '../../hooks/useTauriEvents'
import type { Anomaly, AnomalyPayload, Severity } from '../../types/hollow'
import { severityColor, severityLabel, formatTimestamp } from '../../lib/format'
import RadarRing from './RadarRing'
import AnomalyBlip from './AnomalyBlip'
import ThreatScore from './ThreatScore'

const MAX_BLIPS = 50
const RECENT_LIST_COUNT = 6

const CENTER = 100
const MAX_R = 88

const SEVERITY_R: Record<Severity, number> = {
  critical: 0.84,
  high:     0.66,
  medium:   0.46,
  low:      0.26,
}

function blipPosition(anomaly: Anomaly): { cx: number; cy: number } {
  // Golden angle ~137.508° gives near-uniform angular distribution
  const angleDeg = (anomaly.id * 137.508) % 360
  const angleRad = (angleDeg * Math.PI) / 180
  // Small jitter within severity band to prevent overlap
  const jitter = ((anomaly.id * 7 + anomaly.entryId * 3) % 14) - 7
  const r = Math.max(6, Math.min(MAX_R, SEVERITY_R[anomaly.severity] * MAX_R + jitter))
  return {
    cx: CENTER + r * Math.sin(angleRad),
    cy: CENTER - r * Math.cos(angleRad),
  }
}

interface Props {
  threatScore: number
}

export default function SonarPanel({ threatScore }: Props) {
  const [anomalies, setAnomalies] = useState<Anomaly[]>([])
  const [newIds, setNewIds] = useState<Set<number>>(new Set())

  useTauriEvents<AnomalyPayload>('anomaly_detected', (incoming) => {
    if (!incoming.length) return

    setAnomalies(prev => {
      const next = [...prev, ...incoming]
      return next.length > MAX_BLIPS ? next.slice(next.length - MAX_BLIPS) : next
    })

    const ids = incoming.map(a => a.id)
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
              <div
                key={a.id}
                className="flex items-center gap-2 px-3 py-1 border-b border-neon/10 hover:bg-neon/5"
              >
                <span
                  className="shrink-0 text-[10px] font-bold"
                  style={{ color: severityColor(a.severity) }}
                >
                  {severityLabel(a.severity).slice(0, 3)}
                </span>
                <span className="flex-1 truncate text-neon/50 text-[10px]">
                  {a.description}
                </span>
              </div>
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
