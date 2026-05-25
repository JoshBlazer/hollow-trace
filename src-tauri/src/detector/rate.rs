use std::collections::{HashMap, VecDeque};

use crate::{
    detector::types::{Anomaly, AnomalyKind, Severity},
    parser::types::LogEntry,
};

/// Per-IP sliding window rate detector.
/// Fires when an IP produces >= threshold 4xx responses within window_ms milliseconds.
pub struct RateDetector {
    windows: HashMap<String, VecDeque<i64>>,
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

        let deque = self.windows.entry(ip.clone()).or_default();
        deque.push_back(entry.timestamp);

        // Evict timestamps outside the rolling window
        while let Some(&front) = deque.front() {
            if entry.timestamp - front > window_ms {
                deque.pop_front();
            } else {
                break;
            }
        }

        if deque.len() >= threshold as usize {
            Some(Anomaly {
                id: 0,
                entry_id: entry.id,
                timestamp: entry.timestamp,
                kind: AnomalyKind::RateBurst {
                    ip: ip.clone(),
                    count: deque.len() as u32,
                    window_secs: (window_ms / 1000) as u32,
                },
                severity: Severity::High,
                description: format!(
                    "{} produced {} 4xx errors in {}s — possible brute-force or scan",
                    ip,
                    deque.len(),
                    window_ms / 1000,
                ),
            })
        } else {
            None
        }
    }
}
