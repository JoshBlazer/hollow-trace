// Typed wrappers around Tauri invoke(). Never call invoke() directly elsewhere.
import { invoke } from '@tauri-apps/api/core';
import type {
  AppStats, Anomaly, AnomalyGroup, DetectionSettings, EntryFilter, EntryQueryResult, GroupBy, LogFormat,
} from '../types/hollow';

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

/** Resolves to the number of anomalies written. CSV if the path ends in .csv, else JSON. */
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

/** Search the backend buffer (up to 100k lines), or fetch context around a line. */
export const queryEntries = (filter: EntryFilter): Promise<EntryQueryResult> =>
  invoke('query_entries', { filter });

export const anomalyGroups = (groupBy: GroupBy): Promise<AnomalyGroup[]> =>
  invoke('anomaly_groups', { groupBy });

/** Newest anomalies in one group (max 500). */
export const groupAnomalies = (groupBy: GroupBy, key: string): Promise<Anomaly[]> =>
  invoke('group_anomalies', { groupBy, key });

/** Markdown incident report for the current file. */
export const exportReport = (outputPath: string): Promise<void> =>
  invoke('export_report', { outputPath });
