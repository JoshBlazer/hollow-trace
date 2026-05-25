import type { AppStats } from '../../types/hollow'
import LiveCounter from './LiveCounter'
import SeverityBreakdown from './SeverityBreakdown'
import TopIpList from './TopIpList'

interface Props {
  stats: AppStats
}

function Divider() {
  return <span className="text-neon/15 select-none">|</span>
}

export default function StatsBar({ stats }: Props) {
  const hasData = stats.totalLines > 0

  return (
    <div className="flex items-center justify-between w-full text-xs tracking-widest min-w-0">

      {/* Brand */}
      <span className="text-neon font-bold shrink-0">
        ◈ HOLLOW TRACE{' '}
        <span className="opacity-30 font-normal">v0.1.0</span>
      </span>

      {/* Center stats */}
      <div className="flex items-center gap-4 overflow-hidden">
        <LiveCounter totalLines={stats.totalLines} parseRate={stats.parseRate} />

        <Divider />

        <div className="flex items-center gap-2 tabular-nums">
          <span className="text-neon/40">ANOMALIES</span>
          <span className={stats.anomalyCount > 0 ? 'text-alert font-bold' : 'text-neon font-bold'}>
            {stats.anomalyCount}
          </span>
        </div>

        <Divider />

        <SeverityBreakdown counts={stats.severityCounts} />

        {stats.topIps.length > 0 && (
          <>
            <Divider />
            <TopIpList ips={stats.topIps} />
          </>
        )}
      </div>

      {/* Status beacon */}
      <span className="text-[10px] opacity-25 tracking-widest shrink-0">
        {hasData ? (
          <span className="animate-blink">● LIVE</span>
        ) : (
          <span className="animate-blink">■ AWAITING INPUT</span>
        )}
      </span>

    </div>
  )
}
