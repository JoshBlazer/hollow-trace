import { Fragment, useEffect, useMemo, useState } from 'react'
import { anomalyGroups, groupAnomalies } from '../../lib/tauri-commands'
import { reportError } from '../../lib/notify'
import { formatTimestamp, severityColor, severityLabel } from '../../lib/format'
import type { Anomaly, AnomalyGroup, GroupBy, Severity } from '../../types/hollow'

interface Props {
  /** Changes when anomalies are added or the stream resets; triggers a refresh */
  refreshKey: number
  onJump: (entryId: number) => void
}

type SortKey = 'severity' | 'count' | 'lastSeen' | 'key'

const SEVERITY_RANK: Record<Severity, number> = { low: 0, medium: 1, high: 2, critical: 3 }

const CATEGORY_LABELS: Record<string, string> = {
  sql_injection: 'SQL injection',
  shell_injection: 'Shell injection',
  xxe_ssrf: 'SSRF/XXE',
  path_traversal: 'Path traversal',
  xss_attempt: 'XSS',
  scanner_detected: 'Scanner',
  auth_failure: 'Auth failure',
  rate_burst: 'Rate burst',
  response_size: 'Unusual response size',
}

export const categoryLabel = (key: string) => CATEGORY_LABELS[key] ?? key

export function sortGroups(groups: AnomalyGroup[], key: SortKey): AnomalyGroup[] {
  const by: Record<SortKey, (a: AnomalyGroup, b: AnomalyGroup) => number> = {
    severity: (a, b) => SEVERITY_RANK[b.maxSeverity] - SEVERITY_RANK[a.maxSeverity] || b.count - a.count,
    count: (a, b) => b.count - a.count || SEVERITY_RANK[b.maxSeverity] - SEVERITY_RANK[a.maxSeverity],
    lastSeen: (a, b) => b.lastSeen - a.lastSeen,
    key: (a, b) => a.key.localeCompare(b.key, undefined, { numeric: true }),
  }
  return [...groups].sort(by[key])
}

function Members({ groupBy, groupKey, onJump }: { groupBy: GroupBy; groupKey: string; onJump: (id: number) => void }) {
  const [members, setMembers] = useState<Anomaly[] | null>(null)

  useEffect(() => {
    groupAnomalies(groupBy, groupKey).then(setMembers).catch(err => reportError('Could not load anomalies', err))
  }, [groupBy, groupKey])

  if (!members) return <div className="px-6 py-2 text-neon/30 text-[10px] tracking-widest">LOADING…</div>
  return (
    <div className="bg-neon/[0.03] border-y border-neon/10 max-h-[280px] overflow-y-auto">
      {members.map(a => (
        <button
          key={a.id}
          onClick={() => onJump(a.entryId)}
          title="Show this line in the stream"
          className="w-full flex items-center gap-3 px-6 py-1 text-left text-[11px] hover:bg-neon/10 border-b border-neon/5"
        >
          <span className="shrink-0 font-bold w-8" style={{ color: severityColor(a.severity) }}>
            {severityLabel(a.severity).slice(0, 3)}
          </span>
          <span className="shrink-0 text-neon/40">{formatTimestamp(a.timestamp)}</span>
          <span className="flex-1 truncate text-neon/70">{a.description}</span>
          <span className="shrink-0 text-neon/30">LINE {a.entryId.toLocaleString()} ↗</span>
        </button>
      ))}
      {members.length === 500 && (
        <div className="px-6 py-1 text-[10px] text-neon/30 tracking-wide">Showing the newest 500. Narrow the stream search to see more.</div>
      )}
    </div>
  )
}

/** Anomalies grouped by source IP or attack type, with drill-down to individual lines. */
export default function AnomalyTable({ refreshKey, onJump }: Props) {
  const [groupBy, setGroupBy] = useState<GroupBy>('sourceIp')
  const [groups, setGroups] = useState<AnomalyGroup[] | null>(null)
  const [sortKey, setSortKey] = useState<SortKey>('severity')
  const [open, setOpen] = useState<string | null>(null)

  useEffect(() => {
    let cancelled = false
    anomalyGroups(groupBy)
      .then(g => { if (!cancelled) setGroups(g) })
      .catch(err => reportError('Could not load anomaly groups', err))
    return () => { cancelled = true }
  }, [groupBy, refreshKey])

  useEffect(() => setOpen(null), [groupBy])

  const sorted = useMemo(() => sortGroups(groups ?? [], sortKey), [groups, sortKey])

  const header = (label: string, key: SortKey, align = 'text-left') => (
    <button
      onClick={() => setSortKey(key)}
      className={`${align} tracking-[0.2em] ${sortKey === key ? 'text-neon' : 'text-neon/40 hover:text-neon/70'}`}
    >
      {label}{sortKey === key ? ' ▾' : ''}
    </button>
  )

  return (
    <div className="flex flex-col h-full min-h-0 text-xs">
      <div className="flex items-center gap-3 px-3 py-1.5 border-b border-neon/20 shrink-0">
        <span className="text-[10px] tracking-[0.25em] text-neon/40">GROUP BY</span>
        {(['sourceIp', 'category'] as GroupBy[]).map(g => (
          <button
            key={g}
            onClick={() => setGroupBy(g)}
            className={`text-[10px] tracking-widest px-2 h-6 border ${groupBy === g ? 'border-neon text-neon bg-neon/10' : 'border-neon/20 text-neon/40 hover:text-neon/70'}`}
          >
            {g === 'sourceIp' ? 'SOURCE IP' : 'ATTACK TYPE'}
          </button>
        ))}
        <span className="ml-auto text-[10px] text-neon/30 tracking-widest">
          {groups ? `${groups.length} GROUPS` : ''}
        </span>
      </div>

      <div className="grid grid-cols-[1fr_80px_80px_90px_170px] gap-3 px-3 py-1 border-b border-neon/15 text-[10px] shrink-0">
        {header(groupBy === 'sourceIp' ? 'SOURCE IP' : 'ATTACK TYPE', 'key')}
        {header('COUNT', 'count', 'text-right')}
        {header('WORST', 'severity')}
        <span className="text-neon/40 tracking-[0.2em] text-right">{groupBy === 'sourceIp' ? 'TYPES' : 'SOURCES'}</span>
        {header('LAST SEEN', 'lastSeen')}
      </div>

      <div className="flex-1 overflow-y-auto min-h-0">
        {groups && groups.length === 0 && (
          <div className="px-3 py-8 text-center text-neon/25 text-[10px] tracking-widest">NO ANOMALIES</div>
        )}
        {sorted.map(g => (
          <Fragment key={g.key}>
            <button
              onClick={() => setOpen(o => (o === g.key ? null : g.key))}
              className={`w-full grid grid-cols-[1fr_80px_80px_90px_170px] gap-3 px-3 py-1.5 text-left border-b border-neon/10 hover:bg-neon/5 ${open === g.key ? 'bg-neon/10' : ''}`}
            >
              <span className="truncate text-neon/80">
                <span className="text-neon/30 mr-2">{open === g.key ? '▾' : '▸'}</span>
                {groupBy === 'category' ? categoryLabel(g.key) : g.key}
              </span>
              <span className="text-right tabular-nums text-neon">{g.count.toLocaleString()}</span>
              <span className="font-bold" style={{ color: severityColor(g.maxSeverity) }}>{severityLabel(g.maxSeverity)}</span>
              <span className="text-right tabular-nums text-neon/50">{g.distinct}</span>
              <span className="text-neon/40 truncate">{formatTimestamp(g.lastSeen)}</span>
            </button>
            {open === g.key && <Members groupBy={groupBy} groupKey={g.key} onJump={onJump} />}
          </Fragment>
        ))}
      </div>
    </div>
  )
}
