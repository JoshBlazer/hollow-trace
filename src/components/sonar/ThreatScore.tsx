interface Props {
  score: number
}

export default function ThreatScore({ score }: Props) {
  const color =
    score >= 75 ? '#ff0055' : score >= 40 ? '#ff6600' : '#00ff41'

  const flicker = score >= 75

  return (
    <div className="flex flex-col items-center gap-0.5 py-2">
      <span className="text-[10px] tracking-[0.4em] text-neon/40">THREAT SCORE</span>
      <span
        className={flicker ? 'animate-flicker tabular-nums' : 'tabular-nums'}
        style={{ color, fontSize: '2.5rem', fontWeight: 700, lineHeight: 1 }}
      >
        {score}
      </span>
      <div className="flex gap-1 mt-1">
        {(['low', 'medium', 'high', 'critical'] as const).map((band, i) => {
          const thresholds = [0, 25, 50, 75]
          const active = score >= thresholds[i]
          const bandColor = ['#ffff00', '#ff6600', '#ff0055', '#ff0055'][i]
          return (
            <div
              key={band}
              className="h-1 w-8 transition-colors duration-300"
              style={{ backgroundColor: active ? bandColor : 'rgba(0,255,65,0.15)' }}
            />
          )
        })}
      </div>
    </div>
  )
}
