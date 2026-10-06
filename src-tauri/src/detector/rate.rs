use std::collections::{HashMap, VecDeque};

use crate::{
    detector::types::{Anomaly, AnomalyKind, Severity},
    parser::types::{LogEntry, LogLevel},
};

/// How often (in failure events) idle IPs are swept from memory.
const SWEEP_EVERY: u32 = 4_096;

#[derive(Default)]
struct IpWindow {
    hits: VecDeque<i64>,
    /// Timestamp of the last alert for this IP; suppresses repeats for one window.
    last_alert: Option<i64>,
}

/// Per-IP sliding window rate detector.
/// Fires when an IP produces >= threshold failures (4xx responses, or failed logins in
/// auth logs) within window_ms milliseconds, then stays quiet for that IP for one full
/// window — a sustained burst yields one alert per window instead of one per line.
/// IPs idle for longer than the window are swept periodically, so memory stays bounded
/// by the number of IPs active within one window.
pub struct RateDetector {
    windows: HashMap<String, IpWindow>,
    since_sweep: u32,
}

/// A request rejected with 4xx, or (for entries without HTTP status, e.g. auth.log) an
/// error-level event such as "Failed password".
fn is_failure(entry: &LogEntry) -> bool {
    match entry.status_code {
        Some(status) => (400..500).contains(&status),
        None => matches!(entry.level, LogLevel::Error),
    }
}

impl RateDetector {
    pub fn new() -> Self {
        Self {
            windows: HashMap::new(),
            since_sweep: 0,
        }
    }

    /// Number of IPs currently tracked.
    pub fn tracked_ips(&self) -> usize {
        self.windows.len()
    }

    fn sweep(&mut self, now: i64, window_ms: i64) {
        self.windows
            .retain(|_, w| w.hits.back().is_some_and(|&last| now - last <= window_ms));
    }

    pub fn check_rate(
        &mut self,
        entry: &LogEntry,
        threshold: u32,
        window_ms: i64,
    ) -> Option<Anomaly> {
        let ip = entry.ip.as_ref()?;
        if !is_failure(entry) {
            return None;
        }

        self.since_sweep += 1;
        if self.since_sweep >= SWEEP_EVERY {
            self.since_sweep = 0;
            self.sweep(entry.timestamp, window_ms);
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
            source_ip: None,
            description: format!(
                "Rate burst from {}: {} failures in {}s — possible brute force or scan",
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
            anomaly_severity: None,
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
    fn counts_failed_logins_without_status() {
        let mut det = RateDetector::new();
        let failed_login = |ts: i64| LogEntry {
            status_code: None,
            level: LogLevel::Error,
            ..hit("9.9.9.9", ts, 0)
        };
        let fired = (0..60).filter(|i| det.check_rate(&failed_login(i * 100), 50, 10_000).is_some()).count();
        assert_eq!(fired, 1);
    }

    #[test]
    fn idle_ips_are_swept() {
        let mut det = RateDetector::new();
        // 10k distinct IPs, one failure each, spread over 10k seconds
        for i in 0..10_000i64 {
            det.check_rate(&hit(&format!("10.{}.{}.{}", i / 65536, (i / 256) % 256, i % 256), i * 1000, 404), 50, 10_000);
        }
        assert!(det.tracked_ips() < SWEEP_EVERY as usize + 20, "tracked {}", det.tracked_ips());
    }

    #[test]
    fn separate_ips_alert_independently() {
        let mut det = RateDetector::new();
        assert_eq!(alerts(&mut det, "1.1.1.1", 0, 55, 100), 1);
        assert_eq!(alerts(&mut det, "2.2.2.2", 0, 55, 100), 1);
    }
}
