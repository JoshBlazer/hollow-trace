import type { Severity } from '../types/hollow';

export function formatTimestamp(ms: number): string {
  const d = new Date(ms);
  return (
    d.toISOString().replace('T', ' ').slice(0, 19) + ' UTC'
  );
}

export function formatBytes(bytes: number | null): string {
  if (bytes === null) return '-';
  if (bytes < 1024) return `${bytes}B`;
  if (bytes < 1024 * 1024) return `${(bytes / 1024).toFixed(1)}KB`;
  return `${(bytes / 1024 / 1024).toFixed(1)}MB`;
}

export function formatParseRate(rate: number): string {
  if (rate >= 1_000_000) return `${(rate / 1_000_000).toFixed(1)}M/s`;
  if (rate >= 1_000) return `${(rate / 1_000).toFixed(1)}K/s`;
  return `${Math.round(rate)}/s`;
}

export function severityColor(severity: Severity): string {
  switch (severity) {
    case 'critical': return '#ff0055';
    case 'high':     return '#ff0055';
    case 'medium':   return '#ff6600';
    case 'low':      return '#ffff00';
  }
}

export function severityBgColor(severity: Severity): string {
  switch (severity) {
    case 'critical': return 'rgba(255,0,85,0.15)';
    case 'high':     return 'rgba(255,0,85,0.10)';
    case 'medium':   return 'rgba(255,102,0,0.12)';
    case 'low':      return 'rgba(255,255,0,0.08)';
  }
}

export function severityLabel(severity: Severity): string {
  return severity.toUpperCase();
}

export function statusColor(code: number | null): string {
  if (code === null) return '#00ff41';
  if (code >= 500) return '#ff0055';
  if (code >= 400) return '#ff6600';
  if (code >= 300) return '#ffff00';
  return '#00ff41';
}
