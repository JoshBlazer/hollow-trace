use serde::{Deserialize, Serialize};
use tauri::Emitter;

use crate::{detector::types::Anomaly, parser::types::LogEntry, scorer::AppStats};

pub const BATCH_SIZE: usize = 50;
/// Batch size when parsing a whole file: the 100ms interval still bounds latency,
/// but fewer, larger events keep the webview from re-rendering hundreds of times.
pub const FILE_BATCH_SIZE: usize = 1_000;
pub const EMIT_INTERVAL_MS: u64 = 100;
pub const STATS_INTERVAL_MS: u64 = 500;

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
#[serde(rename_all = "camelCase")]
pub struct LogBatch {
    pub entries: Vec<LogEntry>,
    pub anomalies: Vec<Anomaly>,
}

pub fn emit_batch(app: &tauri::AppHandle, batch: LogBatch) {
    if !batch.entries.is_empty() {
        let _ = app.emit("log_entry", &batch.entries);
    }
    if !batch.anomalies.is_empty() {
        let _ = app.emit("anomaly_detected", &batch.anomalies);
    }
}

pub fn emit_stats(app: &tauri::AppHandle, stats: &AppStats) {
    let _ = app.emit("stats_update", stats);
}
