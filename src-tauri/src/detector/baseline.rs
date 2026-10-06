use crate::{
    detector::types::{Anomaly, AnomalyKind, Severity},
    parser::types::LogEntry,
};

const WARMUP_SAMPLES: u64 = 1_000;

/// Welford's online algorithm for running mean and variance.
/// O(1) memory, O(1) per update — no historical values stored.
struct Welford {
    count: u64,
    mean: f64,
    m2: f64,
}

impl Welford {
    fn new() -> Self {
        Self {
            count: 0,
            mean: 0.0,
            m2: 0.0,
        }
    }

    fn update(&mut self, value: f64) {
        self.count += 1;
        let delta = value - self.mean;
        self.mean += delta / self.count as f64;
        let delta2 = value - self.mean;
        self.m2 += delta * delta2;
    }

    fn stddev(&self) -> f64 {
        if self.count < 2 {
            return 0.0;
        }
        (self.m2 / (self.count - 1) as f64).sqrt()
    }

    /// Returns true if value is more than `sigma` standard deviations from the mean.
    /// Gated on WARMUP_SAMPLES to avoid false positives during cold start.
    fn is_deviation(&self, value: f64, sigma: f64) -> bool {
        if self.count < WARMUP_SAMPLES {
            return false;
        }
        let sd = self.stddev();
        sd > 0.0 && (value - self.mean).abs() > sigma * sd
    }
}

pub struct BaselineDetector {
    bytes: Welford,
    sigma: f64,
}

impl BaselineDetector {
    pub fn new(sigma: f64) -> Self {
        Self {
            bytes: Welford::new(),
            sigma,
        }
    }

    /// Checks response body size against the running baseline.
    /// Updates the baseline after checking so the check uses the pre-update state.
    pub fn check_bytes(&mut self, entry: &LogEntry) -> Option<Anomaly> {
        let bytes = entry.bytes? as f64;

        let is_dev = self.bytes.is_deviation(bytes, self.sigma);
        let mean = self.bytes.mean;
        let stddev = self.bytes.stddev();

        self.bytes.update(bytes);

        if is_dev {
            let sigma_dist = if stddev > 0.0 {
                (bytes - mean).abs() / stddev
            } else {
                0.0
            };

            Some(Anomaly {
                id: 0,
                entry_id: entry.id,
                timestamp: entry.timestamp,
                kind: AnomalyKind::StatisticalDeviation {
                    metric: "response_bytes".to_string(),
                    value: bytes,
                    baseline: mean,
                    stddev,
                },
                severity: Severity::Medium,
                description: format!(
                    "Response size {:.0}B is {:.1}σ from baseline ({:.0}B avg)",
                    bytes, sigma_dist, mean,
                ),
            })
        } else {
            None
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::parser::types::{LogFormat, LogLevel};

    fn sized(id: u64, bytes: u64) -> LogEntry {
        LogEntry {
            id,
            timestamp: id as i64,
            ip: Some("10.0.0.1".into()),
            method: Some("GET".into()),
            path: Some("/".into()),
            status_code: Some(200),
            bytes: Some(bytes),
            message: String::new(),
            raw: String::new(),
            format: LogFormat::Apache,
            level: LogLevel::Info,
            is_anomaly: false,
            anomaly_id: None,
        }
    }

    #[test]
    fn flags_outlier_after_warmup_only() {
        let mut det = BaselineDetector::new(3.0);
        // Before warm-up even a huge response is not flagged
        assert!(det.check_bytes(&sized(0, 10_000_000)).is_none());
        // Steady ~1 KB responses with small variation
        for i in 1..=WARMUP_SAMPLES {
            assert!(det.check_bytes(&sized(i, 1_000 + (i % 50))).is_none());
        }
        let a = det.check_bytes(&sized(9_999, 50_000_000)).expect("outlier flagged");
        assert_eq!(a.severity, Severity::Medium);
        assert!(det.check_bytes(&sized(10_000, 1_010)).is_none());
    }

    #[test]
    fn sigma_is_configurable() {
        let mut strict = BaselineDetector::new(1.0);
        let mut lax = BaselineDetector::new(10.0);
        for i in 0..WARMUP_SAMPLES {
            let b = 1_000 + (i % 100) * 10; // mean ~1495, sd ~290
            strict.check_bytes(&sized(i, b));
            lax.check_bytes(&sized(i, b));
        }
        // ~3 sd above the mean: flagged at sigma 1, not at sigma 10
        assert!(strict.check_bytes(&sized(5_000, 2_400)).is_some());
        assert!(lax.check_bytes(&sized(5_000, 2_400)).is_none());
    }
}
