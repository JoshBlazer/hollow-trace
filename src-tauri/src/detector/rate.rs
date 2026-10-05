use std::collections::{HashMap, VecDeque};

use crate::{
    detector::types::{Anomaly, AnomalyKind, Severity},
    parser::types::LogEntry,
};

#[derive(Default)]
struct IpWindow {
    hits: VecDeque<i64>,
    /// Timestamp of the last alert for this IP; suppresses repeats for one window.
    last_alert: Option<i64>,
}

/// Per-IP sliding window rate detector.
/// Fires when an IP produces >= threshold 4xx responses within window_ms milliseconds,
/// then stays quiet for that IP for one full window — a sustained burst yields one
/// alert per window instead of one per line.
pub struct RateDetector {
    windows: HashMap<String, IpWindow>,
}

impl RateDetector {
    pub fn new() -> Self {
        Self {
            windows: HashMap::new(),
        }
    }

    pub fn check_rate(
        &mut self,
        entry: &LogEntry,
        threshold: u32,
        window_ms: i64,
    ) -> Option<Anomaly> {
        let ip = entry.ip.as_ref()?;
        let status = entry.status_code?;

        // Only 4xx responses indicate client-side attack patterns
        if !(400..500).contains(&status) {
            return None;
        }

        let win = self.windows.entry(ip.clone()).or_default();
        win.hits.push_back(entry.timestamp);

        // Evict timestamps outside the rolling window
        while let Some(&front) = win.hits.front() {
            if entry.timestamp - front > window_ms {
                win.hits.pop_front();
            } else {
                break;
            }
        }

        if win.hits.len() < threshold as usize {
            return None;
        }
        if matches!(win.last_alert, Some(t) if entry.timestamp - t <= window_ms) {
            return None;
        }
        win.last_alert = Some(entry.timestamp);

        let count = win.hits.len();
        Some(Anomaly {
            id: 0,
            entry_id: entry.id,
            timestamp: entry.timestamp,
            kind: AnomalyKind::RateBurst {
                ip: ip.clone(),
                count: count as u32,
                window_secs: (window_ms / 1000) as u32,
            },
            severity: Severity::High,
            description: format!(
                "Rate burst from {}: {} 4xx errors in {}s — possible brute-force or scan",
                ip,
                count,
                window_ms / 1000,
            ),
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::parser::types::{LogFormat, LogLevel};

    fn hit(ip: &str, ts: i64, status: u16) -> LogEntry {
        LogEntry {
            id: ts as u64,
            timestamp: ts,
            ip: Some(ip.into()),
            method: Some("POST".into()),
            path: Some("/login".into()),
            status_code: Some(status),
            bytes: Some(100),
            message: String::new(),
            raw: String::new(),
            format: LogFormat::Apache,
            level: LogLevel::Info,
            is_anomaly: false,
            anomaly_id: None,
        }
    }

    fn alerts(det: &mut RateDetector, ip: &str, start: i64, n: i64, step_ms: i64) -> usize {
        (0..n)
            .filter(|i| det.check_rate(&hit(ip, start + i * step_ms, 401), 50, 10_000).is_some())
            .count()
    }

    #[test]
    fn one_alert_per_burst() {
        let mut det = RateDetector::new();
        // 55 failed logins in ~5.5s — the generator's brute-force shape
        assert_eq!(alerts(&mut det, "1.2.3.4", 0, 55, 100), 1);
    }

    #[test]
    fn sustained_attack_realerts_once_per_window() {
        let mut det = RateDetector::new();
        // 300 failures over 30s at 10/s: first alert at hit 50 (t=4.9s), then one per 10s window
        assert_eq!(alerts(&mut det, "1.2.3.4", 0, 300, 100), 3);
    }

    #[test]
    fn below_threshold_and_non_4xx_never_alert() {
        let mut det = RateDetector::new();
        assert_eq!(alerts(&mut det, "1.2.3.4", 0, 49, 100), 0);
        let fired = (0..100).any(|i| det.check_rate(&hit("5.6.7.8", i * 10, 200), 50, 10_000).is_some());
        assert!(!fired);
    }

    #[test]
    fn separate_ips_alert_independently() {
        let mut det = RateDetector::new();
        assert_eq!(alerts(&mut det, "1.1.1.1", 0, 55, 100), 1);
        assert_eq!(alerts(&mut det, "2.2.2.2", 0, 55, 100), 1);
    }
}
