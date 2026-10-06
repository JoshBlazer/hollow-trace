import { forwardRef } from 'react'
import type { FilterForm, SeverityChoice } from '../../lib/entry-filter'
import { isFormEmpty } from '../../lib/entry-filter'

interface Props {
  form: FilterForm
  onChange: (form: FilterForm) => void
}

const FIELD =
  'bg-black border border-neon/25 focus:border-neon text-neon text-[11px] px-2 h-6 outline-none caret-neon tracking-wide placeholder:text-neon/25'

const SEVERITIES: { value: SeverityChoice; label: string }[] = [
  { value: 'any', label: 'ALL LINES' },
  { value: 'anomalies', label: 'ANOMALIES' },
  { value: 'medium', label: '≥ MEDIUM' },
  { value: 'high', label: '≥ HIGH' },
  { value: 'critical', label: 'CRITICAL' },
]

/** Search controls for the log stream. The text input takes the forwarded ref (Ctrl+F). */
const FilterBar = forwardRef<HTMLInputElement, Props>(function FilterBar({ form, onChange }, ref) {
  const set = <K extends keyof FilterForm>(key: K, value: FilterForm[K]) => onChange({ ...form, [key]: value })

  return (
    <div className="flex items-center gap-2 px-3 py-1.5 border-b border-neon/20 shrink-0">
      <input
        ref={ref}
        className={`${FIELD} flex-1 min-w-0`}
        placeholder="SEARCH LINES… (CTRL+F)"
        aria-label="Search text"
        spellCheck={false}
        value={form.text}
        onChange={e => set('text', e.target.value)}
        onKeyDown={e => { if (e.key === 'Escape' && form.text) { e.stopPropagation(); set('text', '') } }}
      />
      <input
        className={`${FIELD} w-[150px]`}
        placeholder="IP OR CIDR"
        aria-label="IP or CIDR"
        spellCheck={false}
        value={form.ip}
        onChange={e => set('ip', e.target.value)}
      />
      <select
        className={`${FIELD} w-[110px]`}
        aria-label="Severity"
        value={form.severity}
        onChange={e => set('severity', e.target.value as SeverityChoice)}
      >
        {SEVERITIES.map(s => <option key={s.value} value={s.value}>{s.label}</option>)}
      </select>
      <select
        className={`${FIELD} w-[90px]`}
        aria-label="Status class"
        value={form.status}
        onChange={e => set('status', e.target.value as FilterForm['status'])}
      >
        <option value="">ANY STATUS</option>
        <option value="2">2XX</option>
        <option value="3">3XX</option>
        <option value="4">4XX</option>
        <option value="5">5XX</option>
      </select>
      {!isFormEmpty(form) && (
        <button
          onClick={() => onChange({ text: '', ip: '', severity: 'any', status: '' })}
          className="text-[10px] tracking-widest px-2 h-6 border border-neon/30 text-neon/60 hover:border-neon hover:text-neon"
        >
          ✕ CLEAR
        </button>
      )}
    </div>
  )
})

export default FilterBar
