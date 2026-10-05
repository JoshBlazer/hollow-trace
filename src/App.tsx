import { useState, useCallback, useEffect } from 'react'
import './App.css'

import AppShell from './components/layout/AppShell'
import ErrorBoundary from './components/ErrorBoundary'
import LogStreamPanel from './components/log-stream/LogStreamPanel'
import SonarPanel from './components/sonar/SonarPanel'
import StatsBar from './components/stats/StatsBar'
import CommandPalette from './components/command-palette/CommandPalette'
import SettingsPanel from './components/settings/SettingsPanel'
import Toasts from './components/toasts/Toasts'
import { useTauriEvents } from './hooks/useTauriEvents'
import { useLogBuffer } from './hooks/useLogBuffer'
import { useCommandPalette } from './hooks/useCommandPalette'
import { clearStream } from './lib/tauri-commands'
import { checkForUpdates } from './lib/updater'
import { DEFAULT_STATS } from './types/hollow'
import type { AppStats } from './types/hollow'

export default function App() {
  const [stats, setStats] = useState<AppStats>(DEFAULT_STATS)
  const { entries, clear: clearBuffer } = useLogBuffer()
  const { isOpen, close } = useCommandPalette()

  const [settingsOpen, setSettingsOpen] = useState(false)
  const openSettings = useCallback(() => setSettingsOpen(true), [])
  const closeSettings = useCallback(() => setSettingsOpen(false), [])

  useTauriEvents<AppStats>('stats_update', setStats)

  useEffect(() => {
    void checkForUpdates()
  }, [])

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
        <CommandPalette onClose={close} onClearFrontend={handleClearFrontend} onOpenSettings={openSettings} />
      )}
      {settingsOpen && <SettingsPanel onClose={closeSettings} />}
      <Toasts />
    </ErrorBoundary>
  )
}
