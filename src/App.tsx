import { useState, useCallback } from 'react'
import './App.css'

import AppShell from './components/layout/AppShell'
import ErrorBoundary from './components/ErrorBoundary'
import LogStreamPanel from './components/log-stream/LogStreamPanel'
import SonarPanel from './components/sonar/SonarPanel'
import StatsBar from './components/stats/StatsBar'
import CommandPalette from './components/command-palette/CommandPalette'
import { useTauriEvents } from './hooks/useTauriEvents'
import { useLogBuffer } from './hooks/useLogBuffer'
import { useCommandPalette } from './hooks/useCommandPalette'
import { clearStream } from './lib/tauri-commands'
import { DEFAULT_STATS } from './types/hollow'
import type { AppStats } from './types/hollow'

export default function App() {
  const [stats, setStats] = useState<AppStats>(DEFAULT_STATS)
  const { entries, clear: clearBuffer } = useLogBuffer()
  const { isOpen, close } = useCommandPalette()

  useTauriEvents<AppStats>('stats_update', setStats)

  const handleClearAll = useCallback(async () => {
    await clearStream()
    clearBuffer()
  }, [clearBuffer])

  const handleClearFrontend = useCallback(() => {
    clearBuffer()
  }, [clearBuffer])

  return (
    <ErrorBoundary label="APP">
      <AppShell
        statsBar={
          <ErrorBoundary label="STATS">
            <StatsBar stats={stats} />
          </ErrorBoundary>
        }
        logStream={
          <ErrorBoundary label="LOG STREAM">
            <LogStreamPanel entries={entries} onClear={handleClearAll} />
          </ErrorBoundary>
        }
        sonar={
          <ErrorBoundary label="SONAR">
            <SonarPanel threatScore={stats.threatScore} />
          </ErrorBoundary>
        }
      />
      {isOpen && (
        <CommandPalette onClose={close} onClearFrontend={handleClearFrontend} />
      )}
    </ErrorBoundary>
  )
}
