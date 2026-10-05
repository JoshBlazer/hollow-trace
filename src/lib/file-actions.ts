// File-picking actions shared by the command palette and global shortcuts.
import { open as dialogOpen } from '@tauri-apps/plugin-dialog'
import { openFile, startWatching } from './tauri-commands'

const LOG_FILE_FILTERS = [
  { name: 'Log Files', extensions: ['log', 'txt', 'json', 'gz', 'out'] },
  { name: 'All Files', extensions: ['*'] },
]

async function pickLogFile(): Promise<string | null> {
  const path = await dialogOpen({ multiple: false, filters: LOG_FILE_FILTERS })
  return typeof path === 'string' ? path : null
}

/** Ask for a log file and parse it start to finish. Resolves without doing anything if cancelled. */
export async function pickAndOpenFile(): Promise<void> {
  const path = await pickLogFile()
  if (path) await openFile(path)
}

/** Ask for a log file and start tailing it. Resolves without doing anything if cancelled. */
export async function pickAndWatchFile(): Promise<void> {
  const path = await pickLogFile()
  if (path) await startWatching(path)
}
