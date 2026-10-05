import { useEffect, useRef, useState } from 'react'
import { getSettings, saveSettings } from '../../lib/tauri-commands'
import { errorMessage, notify, reportError } from '../../lib/notify'
import { fromForm, toForm, type SettingsForm } from '../../lib/settings-form'

interface Props {
  onClose: () => void
}

function Field({ label, hint, children }: { label: string; hint: string; children: React.ReactNode }) {
  return (
    <label className="flex flex-col gap-1">
      <span className="text-[10px] tracking-[0.25em] text-neon/60">{label}</span>
      {children}
      <span className="text-[10px] text-neon/30 tracking-wide">{hint}</span>
    </label>
  )
}

const INPUT =
  'bg-black border border-neon/30 focus:border-neon text-neon text-xs px-2 py-1.5 outline-none caret-neon tracking-wide'

export default function SettingsPanel({ onClose }: Props) {
  const [form, setForm] = useState<SettingsForm | null>(null)
  const [error, setError] = useState<string | null>(null)
  const [saving, setSaving] = useState(false)
  const firstInput = useRef<HTMLInputElement>(null)

  useEffect(() => {
    getSettings()
      .then(s => setForm(toForm(s)))
      .catch(err => {
        reportError('Could not load settings', err)
        onClose()
      })
  }, [onClose])

  useEffect(() => {
    if (form) firstInput.current?.focus()
  }, [form === null]) // eslint-disable-line react-hooks/exhaustive-deps

  useEffect(() => {
    function onKeyDown(e: KeyboardEvent) {
      if (e.key === 'Escape') onClose()
    }
    window.addEventListener('keydown', onKeyDown)
    return () => window.removeEventListener('keydown', onKeyDown)
  }, [onClose])

  async function save() {
    if (!form || saving) return
    setError(null)
    let settings
    try {
      settings = fromForm(form)
    } catch (err) {
      setError(errorMessage(err))
      return
    }
    setSaving(true)
    try {
      await saveSettings(settings)
      notify('success', 'Settings saved. They apply to the next Open File or Watch File.')
      onClose()
    } catch (err) {
      setError(errorMessage(err)) // backend validation message, e.g. a bad CIDR
    } finally {
      setSaving(false)
    }
  }

  const set = (key: keyof SettingsForm) => (e: React.ChangeEvent<HTMLInputElement | HTMLTextAreaElement>) =>
    setForm(f => (f ? { ...f, [key]: e.target.value } : f))

  return (
    <div
      className="fixed inset-0 z-50 flex items-start justify-center pt-[10vh] bg-black/60"
      style={{ backdropFilter: 'blur(2px)' }}
      onClick={onClose}
    >
      <div
        role="dialog"
        aria-label="Detection settings"
        className="w-[520px] max-w-[92vw] border border-neon bg-black flex flex-col"
        style={{ boxShadow: '0 0 8px #00ff41, 0 0 24px rgba(0,255,65,0.25)' }}
        onClick={e => e.stopPropagation()}
      >
        <div className="flex items-center justify-between px-4 h-10 border-b border-neon/30">
          <span className="text-xs tracking-[0.3em] text-neon/80">◈ DETECTION SETTINGS</span>
          <span className="text-neon/25 text-[10px] tracking-widest">ESC</span>
        </div>

        {!form ? (
          <div className="px-4 py-8 text-center text-neon/40 text-xs tracking-widest animate-blink">LOADING…</div>
        ) : (
          <form
            className="flex flex-col gap-4 px-4 py-4"
            onSubmit={e => { e.preventDefault(); void save() }}
          >
            <div className="grid grid-cols-2 gap-4">
              <Field label="RATE THRESHOLD" hint="Failures from one IP that trigger a burst alert">
                <input ref={firstInput} className={INPUT} inputMode="numeric" value={form.rateThreshold} onChange={set('rateThreshold')} />
              </Field>
              <Field label="RATE WINDOW (S)" hint="Time window for the threshold">
                <input className={INPUT} inputMode="numeric" value={form.rateWindowSecs} onChange={set('rateWindowSecs')} />
              </Field>
            </div>
            <Field label="BASELINE SIGMA" hint="Std. deviations from the mean response size before flagging (1–10)">
              <input className={INPUT} inputMode="decimal" value={form.baselineSigma} onChange={set('baselineSigma')} />
            </Field>
            <Field label="ALLOWLIST" hint="One IP or CIDR per line (e.g. 10.0.0.0/8). Never flagged. # starts a comment.">
              <textarea
                className={`${INPUT} h-28 resize-none`}
                spellCheck={false}
                placeholder={'10.0.0.0/8\n203.0.113.5   # office VPN'}
                value={form.allowlist}
                onChange={set('allowlist')}
              />
            </Field>

            {error && <div role="alert" className="text-alert text-[11px] tracking-wide">▲ {error}</div>}

            <div className="flex justify-end gap-2 pt-1">
              <button type="button" onClick={onClose}
                className="text-[10px] tracking-widest px-3 py-1.5 border border-neon/20 text-neon/40 hover:border-neon/60 hover:text-neon/70">
                CANCEL
              </button>
              <button type="submit" disabled={saving}
                className="text-[10px] tracking-widest px-3 py-1.5 border border-neon text-neon hover:bg-neon/10 disabled:opacity-50">
                {saving ? 'SAVING…' : 'SAVE'}
              </button>
            </div>
          </form>
        )}
      </div>
    </div>
  )
}
