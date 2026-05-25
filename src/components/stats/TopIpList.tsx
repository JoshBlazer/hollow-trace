import type { IpCount } from '../../types/hollow'

interface Props {
  ips: IpCount[]
}

export default function TopIpList({ ips }: Props) {
  if (ips.length === 0) return null
  const top = ips.slice(0, 2)

  return (
    <div className="flex items-center gap-2 tabular-nums">
      <span className="text-neon/40">TOP</span>
      {top.map((entry, i) => (
        <span key={entry.ip} className="flex items-center gap-1">
          <span className="text-neon/70">{entry.ip}</span>
          <span className="text-neon/30">({entry.count})</span>
          {i < top.length - 1 && <span className="text-neon/20 ml-1">·</span>}
        </span>
      ))}
    </div>
  )
}
