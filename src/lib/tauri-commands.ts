// Typed wrappers around Tauri invoke(). Never call invoke() directly elsewhere.
import { invoke } from '@tauri-apps/api/core';
import type { AppStats, Anomaly, DetectionSettings, LogFormat } from '../types/hollow';

export const openFile = (
  path: string,
  format?: LogFormat,
): Promise<AppStats> =>
  invoke('open_file', { path, format: format ?? null });

export const startWatching = (
  path: string,
  format?: LogFormat,
): Promise<void> =>
  invoke('start_watching', { path, format: format ?? null });

export const stopWatching = (): Promise<void> =>
  invoke('stop_watching');

export const getStats = (): Promise<AppStats> =>
  invoke('get_stats');

export const getAnomalies = (severityFilter?: string): Promise<Anomaly[]> =>
  invoke('get_anomalies', { severityFilter: severityFilter ?? null });

/** Resolves to the number of anomalies written. */
export const exportAnomalies = (
  outputPath: string,
  severityFilter?: string,
): Promise<number> =>
  invoke('export_anomalies', {
    outputPath,
    severityFilter: severityFilter ?? null,
  });

export const clearStream = (): Promise<void> =>
  invoke('clear_stream');

export const getSettings = (): Promise<DetectionSettings> =>
  invoke('get_settings');

/** Validates and persists; rejects with a user-readable message if invalid. */
export const saveSettings = (settings: DetectionSettings): Promise<void> =>
  invoke('save_settings', { settings });
