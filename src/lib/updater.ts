// Checks GitHub Releases for a signed update once per launch (release builds only).
import { check } from '@tauri-apps/plugin-updater'
import { relaunch } from '@tauri-apps/plugin-process'
import { logErrorToFile, errorMessage, notify } from './notify'

let checked = false

export async function checkForUpdates(): Promise<void> {
  // Dev builds aren't installed, so there is nothing to update; StrictMode mounts twice
  if (checked || !import.meta.env.PROD) return
  checked = true
  try {
    const update = await check()
    if (!update) return
    notify('info', `Hollow Trace ${update.version} is available (you have ${update.currentVersion}).`, {
      sticky: true,
      action: {
        label: 'Install & restart',
        run: async () => {
          await update.downloadAndInstall()
          await relaunch()
        },
      },
    })
  } catch (err) {
    // Offline or GitHub unreachable: not worth interrupting an analyst for
    logErrorToFile(`Update check failed: ${errorMessage(err)}`)
  }
}
