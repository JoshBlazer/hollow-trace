import { formatParseRate } from '../../lib/format'

interface Props {
  totalLines: number
  parseRate: number
}

export default function LiveCounter({ totalLines, parseRate }: Props) {
  return (
    <div className="flex items-center gap-2 tabular-nums">
      <span className="text-neon/40">LINES</span>
      <span className="text-neon font-bold">{totalLines.toLocaleString()}</span>
      {parseRate > 0 && (
        <>
          <span className="text-neon/20">@</span>
          <span className="text-neon/60">{formatParseRate(parseRate)}</span>
        </>
      )}
    </div>
  )
}
