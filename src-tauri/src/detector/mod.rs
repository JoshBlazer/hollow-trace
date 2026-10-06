pub mod baseline;
pub mod patterns;
pub mod rate;
pub mod types;

pub use types::{Anomaly, AnomalyKind, Severity};

use baseline::BaselineDetector;
use patterns::check_patterns;
use rate::RateDetector;

use std::net::IpAddr;

use crate::{
    parser::types::LogEntry,
    settings::{DetectionSettings, IpRange},
};

/// Composes all three detection strategies.
/// Runs on the watcher thread — single-owner, no locking needed.
pub struct AnomalyDetector {
    id_seq: u64,
    rate: RateDetector,
    baseline: BaselineDetector,
    rate_threshold: u32,
    rate_window_ms: i64,
    allowlist: Vec<IpRange>,
}

impl AnomalyDetector {
    pub fn new(start_id: u64, settings: &DetectionSettings) -> Self {
        Self {
            id_seq: start_id,
            rate: RateDetector::new(),
            baseline: BaselineDetector::new(settings.baseline_sigma),
            rate_threshold: settings.rate_threshold,
            rate_window_ms: settings.rate_window_secs as i64 * 1000,
            allowlist: settings.allowlist_ranges(),
        }
    }

    fn is_allowlisted(&self, entry: &LogEntry) -> bool {
        !self.allowlist.is_empty()
            && entry
                .ip
                .as_deref()
                .and_then(|s| s.parse::<IpAddr>().ok())
                .is_some_and(|ip| self.allowlist.iter().any(|r| r.contains(&ip)))
    }

    /// Runs all detectors against a single entry.
    /// Multiple anomalies can fire on the same line (e.g., pattern + rate burst).
    pub fn check_all(&mut self, entry: &LogEntry) -> Vec<Anomaly> {
        let mut anomalies = Vec::new();
        if self.is_allowlisted(entry) {
            return anomalies;
        }

        if let Some(mut a) = check_patterns(entry) {
            a.id = self.mint_id();
            anomalies.push(a);
        }
        if let Some(mut a) = self.rate.check_rate(entry, self.rate_threshold, self.rate_window_ms) {
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::parser::types::{LogFormat, LogLevel};

    fn attack(ip: &str) -> LogEntry {
        LogEntry {
            id: 1,
            timestamp: 0,
            ip: Some(ip.into()),
            method: Some("GET".into()),
            path: Some("/../../etc/passwd".into()),
            status_code: Some(403),
            bytes: Some(100),
            message: String::new(),
            raw: String::new(),
            format: LogFormat::Apache,
            level: LogLevel::Warn,
            is_anomaly: false,
            anomaly_id: None,
        }
    }

    #[test]
    fn allowlisted_sources_are_never_flagged() {
        let settings = DetectionSettings {
            allowlist: vec!["10.0.0.0/8".into(), "2001:db8::1".into()],
            ..Default::default()
        };
        let mut det = AnomalyDetector::new(0, &settings);
        assert!(det.check_all(&attack("10.1.2.3")).is_empty());
        assert!(det.check_all(&attack("2001:db8::1")).is_empty());
        assert_eq!(det.check_all(&attack("203.0.113.9")).len(), 1);
    }

    #[test]
    fn rate_settings_are_applied() {
        let settings = DetectionSettings { rate_threshold: 5, rate_window_secs: 1, ..Default::default() };
        let mut det = AnomalyDetector::new(0, &settings);
        let mut e = attack("203.0.113.9");
        e.path = Some("/login".into());
        e.status_code = Some(401);
        let bursts = (0..5)
            .flat_map(|i| { e.timestamp = i * 100; det.check_all(&e) })
            .filter(|a| matches!(a.kind, AnomalyKind::RateBurst { .. }))
            .count();
        assert_eq!(bursts, 1);
    }
}
