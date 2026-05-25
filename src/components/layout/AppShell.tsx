import type { ReactNode } from 'react'

interface Props {
  statsBar: ReactNode
  logStream: ReactNode
  sonar: ReactNode
}

/**
 * Root layout: stats bar across the top, log stream left, sonar right.
 * All panels share the neon border treatment. A 4px black gap between
 * panels lets the #000 background show through, giving the terminal grid look.
 */
export default function AppShell({ statsBar, logStream, sonar }: Props) {
  return (
    <div className="flex flex-col h-full w-full bg-black text-neon font-mono p-1 gap-1 select-none overflow-hidden">

      {/* ── Stats bar ─────────────────────────────────────────────── */}
      <header className="ht-border flex-none h-12 flex items-center px-4 gap-8 overflow-hidden shrink-0">
        {statsBar}
      </header>

      {/* ── Main content ──────────────────────────────────────────── */}
      <div className="flex flex-1 gap-1 min-h-0">

        {/* Log stream — fills all remaining width */}
        <section className="ht-border flex-1 min-w-0 overflow-hidden relative">
          {logStream}
        </section>

        {/* Sonar — fixed 300px wide */}
        <aside className="ht-border flex-none w-[300px] overflow-hidden relative flex flex-col">
          {sonar}
        </aside>

      </div>
    </div>
  )
}
