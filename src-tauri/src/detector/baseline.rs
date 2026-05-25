use crate::{
    detector::types::{Anomaly, AnomalyKind, Severity},
    parser::types::LogEntry,
};

const SIGMA_THRESHOLD: f64 = 3.0;
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
}

impl BaselineDetector {
    pub fn new() -> Self {
        Self {
            bytes: Welford::new(),
        }
    }

    /// Checks response body size against the running baseline.
    /// Updates the baseline after checking so the check uses the pre-update state.
    pub fn check_bytes(&mut self, entry: &LogEntry) -> Option<Anomaly> {
        let bytes = entry.bytes? as f64;

        let is_dev = self.bytes.is_deviation(bytes, SIGMA_THRESHOLD);
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
