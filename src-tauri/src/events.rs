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

/// Where parsing results go. The app sends them to the webview; tests record them.
pub trait EventSink: Send + 'static {
    fn batch(&self, batch: LogBatch);
    fn stats(&self, stats: &AppStats);
    /// A failure the user should see (e.g. a live watch losing its file).
    fn error(&self, message: &str);
}

impl EventSink for tauri::AppHandle {
    fn batch(&self, batch: LogBatch) {
        if !batch.entries.is_empty() {
            let _ = self.emit("log_entry", &batch.entries);
        }
        if !batch.anomalies.is_empty() {
            let _ = self.emit("anomaly_detected", &batch.anomalies);
        }
    }

    fn stats(&self, stats: &AppStats) {
        let _ = self.emit("stats_update", stats);
    }

    fn error(&self, message: &str) {
        log::error!("{message}");
        let _ = self.emit("app_error", message);
    }
}

#[cfg(test)]
pub mod test_sink {
    use std::sync::{Arc, Mutex};

    use super::*;

    /// Records everything a LineProcessor emits.
    #[derive(Clone, Default)]
    pub struct RecordingSink(pub Arc<Mutex<Recorded>>);

    #[derive(Default)]
    pub struct Recorded {
        pub batches: Vec<LogBatch>,
        pub stats: Vec<AppStats>,
        pub errors: Vec<String>,
    }

    impl RecordingSink {
        pub fn entries(&self) -> Vec<LogEntry> {
            self.0.lock().unwrap().batches.iter().flat_map(|b| b.entries.clone()).collect()
        }
        pub fn anomalies(&self) -> Vec<Anomaly> {
            self.0.lock().unwrap().batches.iter().flat_map(|b| b.anomalies.clone()).collect()
        }
        pub fn errors(&self) -> Vec<String> {
            self.0.lock().unwrap().errors.clone()
        }
    }

    impl EventSink for RecordingSink {
        fn batch(&self, batch: LogBatch) {
            self.0.lock().unwrap().batches.push(batch);
        }
        fn stats(&self, stats: &AppStats) {
            self.0.lock().unwrap().stats.push(stats.clone());
        }
        fn error(&self, message: &str) {
            self.0.lock().unwrap().errors.push(message.to_string());
        }
    }
}
