use serde::{Deserialize, Serialize};

use crate::detector::types::Severity;

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub enum LogFormat {
    Apache,
    Nginx,
    AuthLog,
    Syslog,
    JsonLog,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub enum LogLevel {
    Info,
    Warn,
    Error,
    Debug,
}

impl Default for LogLevel {
    fn default() -> Self {
        LogLevel::Info
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct LogEntry {
    pub id: u64,
    pub timestamp: i64,
    pub ip: Option<String>,
    pub method: Option<String>,
    pub path: Option<String>,
    pub status_code: Option<u16>,
    pub bytes: Option<u64>,
    pub message: String,
    pub raw: String,
    pub format: LogFormat,
    pub level: LogLevel,
    pub is_anomaly: bool,
    pub anomaly_id: Option<u64>,
    /// Highest severity among this line's anomalies (None if clean)
    #[serde(default)]
    pub anomaly_severity: Option<Severity>,
}
