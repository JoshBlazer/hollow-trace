// Converts between DetectionSettings and the editable form fields.
// The backend re-validates everything; these checks only give faster feedback.
import type { DetectionSettings } from '../types/hollow'

export interface SettingsForm {
  rateThreshold: string
  rateWindowSecs: string
  baselineSigma: string
  /** One IP or CIDR per line; blank lines and # comments ignored */
  allowlist: string
}

export function toForm(s: DetectionSettings): SettingsForm {
  return {
    rateThreshold: String(s.rateThreshold),
    rateWindowSecs: String(s.rateWindowSecs),
    baselineSigma: String(s.baselineSigma),
    allowlist: s.allowlist.join('\n'),
  }
}

export function parseAllowlist(text: string): string[] {
  return text
    .split(/\r?\n/)
    .map(line => line.replace(/#.*$/, '').trim())
    .filter(Boolean)
}

function intInRange(raw: string, label: string, min: number, max: number): number {
  const n = Number(raw.trim())
  if (!Number.isInteger(n) || n < min || n > max) {
    throw new Error(`${label} must be a whole number between ${min} and ${max}.`)
  }
  return n
}

/** Throws an Error with a user-readable message for invalid input. */
export function fromForm(f: SettingsForm): DetectionSettings {
  const sigma = Number(f.baselineSigma.trim())
  if (!Number.isFinite(sigma) || sigma < 1 || sigma > 10) {
    throw new Error('Baseline sigma must be a number between 1 and 10.')
  }
  return {
    rateThreshold: intInRange(f.rateThreshold, 'Rate threshold', 2, 100_000),
    rateWindowSecs: intInRange(f.rateWindowSecs, 'Rate window', 1, 3_600),
    baselineSigma: sigma,
    allowlist: parseAllowlist(f.allowlist),
  }
}
