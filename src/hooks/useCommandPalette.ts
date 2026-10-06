import { useState, useEffect, useCallback } from 'react'
import { pickAndOpenFile } from '../lib/file-actions'
import { reportError } from '../lib/notify'

// Module-level so a held/repeated Ctrl+O can't stack dialogs while one is open
let openFileInFlight = false

export function useCommandPalette() {
  const [isOpen, setIsOpen] = useState(false)

  useEffect(() => {
    function onKeyDown(e: KeyboardEvent) {
      if (!(e.ctrlKey || e.metaKey)) return
      const key = e.key.toLowerCase()
      if (key === 'k') {
        e.preventDefault()
        setIsOpen(prev => !prev)
      } else if (key === 'o') {
        e.preventDefault()
        if (openFileInFlight) return
        setIsOpen(false)
        openFileInFlight = true
        pickAndOpenFile()
          .catch(err => reportError('Open file failed', err))
          .finally(() => { openFileInFlight = false })
      }
    }
    window.addEventListener('keydown', onKeyDown)
    return () => window.removeEventListener('keydown', onKeyDown)
  }, [])

  const open  = useCallback(() => setIsOpen(true), [])
  const close = useCallback(() => setIsOpen(false), [])

  return { isOpen, open, close }
}
