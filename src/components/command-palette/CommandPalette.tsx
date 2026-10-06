import { useState, useEffect, useRef, useMemo } from 'react'
import { save as dialogSave } from '@tauri-apps/plugin-dialog'
import {
  stopWatching,
  exportAnomalies,
  exportReport,
  clearStream,
} from '../../lib/tauri-commands'
import { pickAndOpenFile, pickAndWatchFile } from '../../lib/file-actions'
import { errorMessage, notify, reportError } from '../../lib/notify'
import CommandItem from './CommandItem'

interface Command {
  id: string
  label: string
  description: string
  shortcut?: string
  action: () => Promise<void>
}

interface Props {
  onClose: () => void
  onClearFrontend: () => void
  onOpenSettings: () => void
}

export default function CommandPalette({ onClose, onClearFrontend, onOpenSettings }: Props) {
  const [query, setQuery] = useState('')
  const [selectedIndex, setSelectedIndex] = useState(0)
  const [status, setStatus] = useState<'idle' | 'running' | string>('idle')
  const inputRef = useRef<HTMLInputElement>(null)

  const commands = useMemo<Command[]>(() => [
    {
      id: 'open-file',
      label: 'Open File',
      description: 'Parse an existing log file from start to finish',
      shortcut: 'Ctrl+O',
      action: pickAndOpenFile,
    },
    {
      id: 'watch-file',
      label: 'Watch File',
      description: 'Tail a live log file for new entries',
      action: pickAndWatchFile,
    },
    {
      id: 'export',
      label: 'Export Anomalies',
      description: 'Save detected anomalies as CSV (spreadsheets) or JSON',
      action: async () => {
        const path = await dialogSave({
          defaultPath: 'anomalies.csv',
          filters: [
            { name: 'CSV', extensions: ['csv'] },
            { name: 'JSON', extensions: ['json'] },
          ],
        })
        if (!path || typeof path !== 'string') return
        const count = await exportAnomalies(path)
        notify('success', `Exported ${count} ${count === 1 ? 'anomaly' : 'anomalies'} to ${path}`)
      },
    },
    {
      id: 'report',
      label: 'Export Report',
      description: 'Incident summary (Markdown): top sources, attack types, timeline',
      action: async () => {
        const path = await dialogSave({
          defaultPath: 'incident-report.md',
          filters: [{ name: 'Markdown', extensions: ['md'] }],
        })
        if (!path || typeof path !== 'string') return
        await exportReport(path)
        notify('success', `Report saved to ${path}`)
      },
    },
    {
      id: 'stop',
      label: 'Stop Watching',
      description: 'Detach the file watcher',
      action: async () => {
        await stopWatching()
      },
    },
    {
      id: 'clear',
      label: 'Clear Stream',
      description: 'Flush the log buffer and reset stats',
      action: async () => {
        await clearStream()
        onClearFrontend()
      },
    },
    {
      id: 'settings',
      label: 'Detection Settings',
      description: 'Thresholds and IP allowlist',
      action: async () => {
        onOpenSettings()
      },
    },
  ], [onClearFrontend, onOpenSettings])

  const filtered = useMemo(
    () =>
      query.trim() === ''
        ? commands
        : commands.filter(c =>
            c.label.toLowerCase().includes(query.toLowerCase()) ||
            c.description.toLowerCase().includes(query.toLowerCase()),
          ),
    [commands, query],
  )

  // Clamp selectedIndex when filter changes
  useEffect(() => {
    setSelectedIndex(i => Math.min(i, Math.max(0, filtered.length - 1)))
  }, [filtered.length])

  // Auto-focus input
  useEffect(() => {
    inputRef.current?.focus()
  }, [])

  // Keyboard navigation
  useEffect(() => {
    function onKeyDown(e: KeyboardEvent) {
      if (e.key === 'Escape') {
        onClose()
      } else if (e.key === 'ArrowDown') {
        e.preventDefault()
        setSelectedIndex(i => Math.min(i + 1, filtered.length - 1))
      } else if (e.key === 'ArrowUp') {
        e.preventDefault()
        setSelectedIndex(i => Math.max(i - 1, 0))
      } else if (e.key === 'Enter') {
        e.preventDefault()
        void runCommand(filtered[selectedIndex])
      }
    }
    window.addEventListener('keydown', onKeyDown)
    return () => window.removeEventListener('keydown', onKeyDown)
  }, [filtered, selectedIndex, onClose])

  async function runCommand(cmd: Command | undefined) {
    if (!cmd || status === 'running') return
    setStatus('running')
    try {
      await cmd.action()
      onClose()
    } catch (err) {
      // Shown inline below; also written to the log file
      reportError(cmd.label, err, { toast: false })
      setStatus(errorMessage(err))
    }
  }

  return (
    /* Backdrop */
    <div
      className="fixed inset-0 z-50 flex items-start justify-center pt-[15vh] bg-black/60"
      style={{ backdropFilter: 'blur(2px)' }}
      onClick={onClose}
    >
      {/* Modal */}
      <div
        className="w-[480px] max-w-[90vw] border border-neon bg-black flex flex-col overflow-hidden"
        style={{ boxShadow: '0 0 8px #00ff41, 0 0 24px rgba(0,255,65,0.25)' }}
        onClick={e => e.stopPropagation()}
      >
        {/* Header */}
        <div className="flex items-center gap-3 px-4 border-b border-neon/30 h-10 shrink-0">
          <span className="text-neon/50 text-xs tracking-widest">⌘</span>
          <input
            ref={inputRef}
            value={query}
            onChange={e => { setQuery(e.target.value); setSelectedIndex(0) }}
            placeholder="TYPE A COMMAND..."
            className="flex-1 bg-transparent text-neon text-xs tracking-widest placeholder:text-neon/25 outline-none caret-neon"
          />
          <span className="text-neon/25 text-[10px] tracking-widest">ESC</span>
        </div>

        {/* Command list */}
        <div className="flex flex-col">
          {filtered.length === 0 ? (
            <div className="px-4 py-6 text-center text-neon/25 text-xs tracking-widest">
              NO COMMANDS MATCH
            </div>
          ) : (
            filtered.map((cmd, i) => (
              <CommandItem
                key={cmd.id}
                label={cmd.label}
                description={cmd.description}
                shortcut={cmd.shortcut}
                isSelected={i === selectedIndex}
                onClick={() => void runCommand(cmd)}
              />
            ))
          )}
        </div>

        {/* Status / footer */}
        <div className="border-t border-neon/15 px-4 py-1.5 flex items-center justify-between">
          {status === 'idle' && (
            <span className="text-[10px] text-neon/20 tracking-widest">
              ↑↓ NAVIGATE · ENTER SELECT
            </span>
          )}
          {status === 'running' && (
            <span className="text-[10px] text-neon/60 tracking-widest animate-blink">
              ● RUNNING...
            </span>
          )}
          {status !== 'idle' && status !== 'running' && (
            <span className="text-[10px] text-alert tracking-widest">
              ▲ {status}
            </span>
          )}
          <span className="text-[10px] text-neon/15 tracking-widest">CTRL+K</span>
        </div>
      </div>
    </div>
  )
}
