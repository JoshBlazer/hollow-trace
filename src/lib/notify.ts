// App-wide notifications (toasts) plus error logging to the app log file.
import { error as logError } from '@tauri-apps/plugin-log'
import type { Toast, ToastAction, ToastKind } from '../types/hollow'

const MAX_VISIBLE = 4
const TIMEOUT_MS: Record<ToastKind, number> = { error: 10_000, info: 6_000, success: 4_000 }

let toasts: Toast[] = []
let nextId = 1
const listeners = new Set<() => void>()

function publish(next: Toast[]) {
  toasts = next
  listeners.forEach(l => l())
}

/** For useSyncExternalStore */
export function subscribe(listener: () => void): () => void {
  listeners.add(listener)
  return () => listeners.delete(listener)
}

export function getToasts(): Toast[] {
  return toasts
}

export function dismiss(id: number) {
  publish(toasts.filter(t => t.id !== id))
}

export function notify(
  kind: ToastKind,
  message: string,
  opts: { action?: ToastAction; sticky?: boolean } = {},
): number {
  const toast: Toast = { id: nextId++, kind, message, ...opts }
  publish([...toasts, toast].slice(-MAX_VISIBLE))
  if (!opts.sticky) setTimeout(() => dismiss(toast.id), TIMEOUT_MS[kind])
  return toast.id
}

export function errorMessage(err: unknown): string {
  if (err instanceof Error) return err.message
  if (typeof err === 'string') return err
  try {
    return JSON.stringify(err)
  } catch {
    return String(err)
  }
}

/** Writes to the app log file. Never throws (logging must not break the UI). */
export function logErrorToFile(message: string) {
  try {
    void logError(message).catch(() => {})
  } catch {
    // Plugin unavailable (tests, plain browser)
  }
}

/**
 * Reports a failure: always logged to the app log file, shown as a toast unless
 * the caller already displays it (e.g. inline in the command palette).
 */
export function reportError(context: string, err: unknown, { toast = true } = {}) {
  const message = `${context}: ${errorMessage(err)}`
  logErrorToFile(message)
  if (toast) notify('error', message)
}

/** Test helper: reset module state between tests. */
export function _resetForTests() {
  toasts = []
  nextId = 1
  listeners.clear()
}
