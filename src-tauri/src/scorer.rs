use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
#[serde(rename_all = "camelCase")]
pub struct IpCount {
    pub ip: String,
    pub count: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
#[serde(rename_all = "camelCase")]
pub struct SeverityCounts {
    pub low: u64,
    pub medium: u64,
    pub high: u64,
    pub critical: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
#[serde(rename_all = "camelCase")]
pub struct AppStats {
    pub total_lines: u64,
    pub anomaly_count: u64,
    pub parse_rate: f64,
    pub threat_score: u8,
    pub top_ips: Vec<IpCount>,
    pub severity_counts: SeverityCounts,
    /// Earliest / latest log timestamp seen (Unix ms)
    pub first_timestamp: Option<i64>,
    pub last_timestamp: Option<i64>,
}

pub fn calculate_threat_score(stats: &AppStats) -> u8 {
    if stats.total_lines == 0 {
        return 0;
    }
    let rate = (stats.anomaly_count as f64 / stats.total_lines as f64 * 100.0).min(50.0) as u8;
    let sc = &stats.severity_counts;
    let raw = sc.critical.saturating_mul(20)
        + sc.high.saturating_mul(10)
        + sc.medium.saturating_mul(5)
        + sc.low.saturating_mul(1);
    let severity = raw.min(50) as u8;
    rate.saturating_add(severity).min(100)
}
