import { useState, useSyncExternalStore } from 'react'
import { useTauriEvents } from '../../hooks/useTauriEvents'
import { dismiss, getToasts, notify, reportError, subscribe } from '../../lib/notify'
import type { AppErrorPayload, Toast, ToastKind } from '../../types/hollow'

const KIND_STYLE: Record<ToastKind, { border: string; text: string; glyph: string }> = {
  error:   { border: 'border-alert', text: 'text-alert', glyph: '▲' },
  info:    { border: 'border-neon',  text: 'text-neon',  glyph: '◈' },
  success: { border: 'border-neon',  text: 'text-neon',  glyph: '✓' },
}

function ToastRow({ toast }: { toast: Toast }) {
  const [busy, setBusy] = useState(false)
  const style = KIND_STYLE[toast.kind]

  async function runAction() {
    if (!toast.action || busy) return
    setBusy(true)
    try {
      await toast.action.run()
      dismiss(toast.id)
    } catch (err) {
      reportError(toast.action.label, err)
    } finally {
      setBusy(false)
    }
  }

  return (
    <div
      role={toast.kind === 'error' ? 'alert' : 'status'}
      className={`pointer-events-auto flex items-start gap-3 bg-black border ${style.border} px-3 py-2 text-[11px] tracking-wide max-w-[560px]`}
      style={{ boxShadow: toast.kind === 'error' ? '0 0 6px #ff0055' : '0 0 6px #00ff41' }}
    >
      <span className={`${style.text} shrink-0`}>{style.glyph}</span>
      <span className={`${style.text} flex-1 break-words`}>{toast.message}</span>
      {toast.action && (
        <button
          onClick={() => void runAction()}
          disabled={busy}
          className="shrink-0 border border-neon/60 text-neon px-2 py-0.5 text-[10px] tracking-widest hover:bg-neon/10 disabled:opacity-50"
        >
          {busy ? 'WORKING…' : toast.action.label.toUpperCase()}
        </button>
      )}
      <button
        onClick={() => dismiss(toast.id)}
        aria-label="Dismiss"
        className="shrink-0 text-neon/40 hover:text-neon"
      >
        ✕
      </button>
    </div>
  )
}

/** Bottom-center stack of notifications; also surfaces backend `app_error` events. */
export default function Toasts() {
  const toasts = useSyncExternalStore(subscribe, getToasts)

  // Backend already logged these to the log file
  useTauriEvents<AppErrorPayload>('app_error', message => notify('error', message))

  return (
    <div className="fixed bottom-14 left-1/2 -translate-x-1/2 z-40 flex flex-col items-center gap-2 pointer-events-none">
      {toasts.map(t => <ToastRow key={t.id} toast={t} />)}
    </div>
  )
}
