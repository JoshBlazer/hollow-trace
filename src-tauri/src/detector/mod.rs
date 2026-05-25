pub mod baseline;
pub mod patterns;
pub mod rate;
pub mod types;

pub use types::{Anomaly, AnomalyKind, Severity};

use baseline::BaselineDetector;
use patterns::check_patterns;
use rate::RateDetector;

use crate::parser::types::LogEntry;

/// Composes all three detection strategies.
/// Runs on the watcher thread — single-owner, no locking needed.
pub struct AnomalyDetector {
    id_seq: u64,
    rate: RateDetector,
    baseline: BaselineDetector,
}

impl AnomalyDetector {
    pub fn new(start_id: u64) -> Self {
        Self {
            id_seq: start_id,
            rate: RateDetector::new(),
            baseline: BaselineDetector::new(),
        }
    }

    /// Runs all detectors against a single entry.
    /// Multiple anomalies can fire on the same line (e.g., pattern + rate burst).
    pub fn check_all(&mut self, entry: &LogEntry) -> Vec<Anomaly> {
        let mut anomalies = Vec::new();

        if let Some(mut a) = check_patterns(entry) {
            a.id = self.mint_id();
            anomalies.push(a);
        }
        if let Some(mut a) = self.rate.check_rate(entry, 50, 10_000) {
            a.id = self.mint_id();
            anomalies.push(a);
        }
        if let Some(mut a) = self.baseline.check_bytes(entry) {
            a.id = self.mint_id();
            anomalies.push(a);
        }

        anomalies
    }

    fn mint_id(&mut self) -> u64 {
        let id = self.id_seq;
        self.id_seq += 1;
        id
    }
}
