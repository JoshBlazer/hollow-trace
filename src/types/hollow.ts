// Mirror of all Rust types that cross the Tauri boundary.
// serde(rename_all = "camelCase") is applied to every Rust struct/enum.
// This file is the single source of truth — never define these types inline elsewhere.

// ── Log format & level ────────────────────────────────────────────────────────

export type LogFormat = 'apache' | 'nginx' | 'authLog' | 'syslog' | 'jsonLog';

export type LogLevel = 'info' | 'warn' | 'error' | 'debug';

// ── Log entry ─────────────────────────────────────────────────────────────────

export interface LogEntry {
  id: number;
  timestamp: number;       // Unix ms
  ip: string | null;
  method: string | null;
  path: string | null;
  statusCode: number | null;
  bytes: number | null;
  message: string;
  raw: string;
  format: LogFormat;
  level: LogLevel;
  isAnomaly: boolean;
  anomalyId: number | null;
  /** Worst severity among this line's anomalies */
  anomalySeverity: Severity | null;
}

// ── Anomaly detection ─────────────────────────────────────────────────────────

export type Severity = 'low' | 'medium' | 'high' | 'critical';

/**
 * Discriminated union matching Rust's #[serde(tag = "type", rename_all = "camelCase")]
 * on AnomalyKind.
 */
export type AnomalyKind =
  | { type: 'patternMatch'; patternName: string }
  | { type: 'rateBurst'; ip: string; count: number; windowSecs: number }
  | { type: 'statisticalDeviation'; metric: string; value: number; baseline: number; stddev: number };

export interface Anomaly {
  id: number;
  entryId: number;
  timestamp: number;       // Unix ms
  kind: AnomalyKind;
  severity: Severity;
  description: string;
  sourceIp: string | null;
}

// ── Stats ─────────────────────────────────────────────────────────────────────

export interface IpCount {
  ip: string;
  count: number;
}

export interface SeverityCounts {
  low: number;
  medium: number;
  high: number;
  critical: number;
}

export interface AppStats {
  totalLines: number;
  anomalyCount: number;
  parseRate: number;       // lines/sec
  threatScore: number;     // 0-100
  topIps: IpCount[];
  severityCounts: SeverityCounts;
  firstTimestamp: number | null;  // Unix ms
  lastTimestamp: number | null;
}

// ── Event payloads ────────────────────────────────────────────────────────────

/** Payload of the "log_entry" Tauri event */
export type LogEntryPayload = LogEntry[];

/** Payload of the "anomaly_detected" Tauri event */
export type AnomalyPayload = Anomaly[];

/** Payload of the "stats_update" Tauri event */
export type StatsPayload = AppStats;

/** Payload of the "stream_reset" Tauri event: a new Open/Watch/Clear started; drop what's shown */
export type StreamResetPayload = null;

/** Payload of the "app_error" Tauri event: a background failure to show the user */
export type AppErrorPayload = string;

// ── Search ────────────────────────────────────────────────────────────────────

/** Mirror of Rust EntryFilter. Empty/undefined fields don't filter. */
export interface EntryFilter {
  text?: string;
  ip?: string;             // exact IP, CIDR, or substring
  minSeverity?: Severity;
  anomaliesOnly?: boolean;
  statusClass?: 2 | 3 | 4 | 5;
  /** Jump-to-line: lines around this entry id; other fields ignored */
  around?: number;
  limit?: number;
}

export interface EntryQueryResult {
  entries: LogEntry[];
  matched: number;   // total matches, may exceed entries.length
  scanned: number;   // lines searched in the backend buffer
}

// ── Anomaly grouping ──────────────────────────────────────────────────────────

export type GroupBy = 'sourceIp' | 'category';

export interface AnomalyGroup {
  key: string;            // source IP ("unknown") or category
  count: number;
  maxSeverity: Severity;
  firstSeen: number;      // Unix ms
  lastSeen: number;
  distinct: number;       // distinct categories (IP groups) or sources (category groups)
}

/** Which main panel is showing */
export type MainView = 'stream' | 'anomalies';

// ── Settings ──────────────────────────────────────────────────────────────────

/** Mirror of Rust DetectionSettings. Applies to the next Open File / Watch File. */
export interface DetectionSettings {
  rateThreshold: number;   // failures from one IP within the window
  rateWindowSecs: number;
  baselineSigma: number;   // std devs from mean response size
  allowlist: string[];     // IPs or CIDRs never flagged
}

// ── Notifications ─────────────────────────────────────────────────────────────

export type ToastKind = 'error' | 'info' | 'success';

export interface ToastAction {
  label: string;
  run: () => Promise<void> | void;
}

export interface Toast {
  id: number;
  kind: ToastKind;
  message: string;
  action?: ToastAction;
  /** Stays until dismissed instead of timing out */
  sticky?: boolean;
}

// ── Default values ────────────────────────────────────────────────────────────

export const DEFAULT_STATS: AppStats = {
  totalLines: 0,
  anomalyCount: 0,
  parseRate: 0,
  threatScore: 0,
  topIps: [],
  severityCounts: { low: 0, medium: 0, high: 0, critical: 0 },
  firstTimestamp: null,
  lastTimestamp: null,
};
