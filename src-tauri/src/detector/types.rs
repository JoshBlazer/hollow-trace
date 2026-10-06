use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, PartialOrd, Ord)]
#[serde(rename_all = "camelCase")]
pub enum Severity {
    Low,
    Medium,
    High,
    Critical,
}

/// Serde internally-tagged: {"type": "patternMatch", "patternName": "..."}
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "camelCase")]
pub enum AnomalyKind {
    PatternMatch {
        #[serde(rename = "patternName")]
        pattern_name: String,
    },
    RateBurst {
        ip: String,
        count: u32,
        #[serde(rename = "windowSecs")]
        window_secs: u32,
    },
    StatisticalDeviation {
        metric: String,
        value: f64,
        baseline: f64,
        stddev: f64,
    },
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Anomaly {
    pub id: u64,
    pub entry_id: u64,
    pub timestamp: i64,
    pub kind: AnomalyKind,
    pub severity: Severity,
    pub description: String,
    /// IP of the offending log line, if it had one
    #[serde(default)]
    pub source_ip: Option<String>,
}

impl Anomaly {
    /// Stable attack-type key for grouping: pattern name, "rate_burst" or "response_size".
    pub fn category(&self) -> &str {
        match &self.kind {
            AnomalyKind::PatternMatch { pattern_name } => pattern_name,
            AnomalyKind::RateBurst { .. } => "rate_burst",
            AnomalyKind::StatisticalDeviation { .. } => "response_size",
        }
    }
}
