use chrono::DateTime;
use once_cell::sync::Lazy;
use regex::Regex;

use crate::parser::{
    types::{LogEntry, LogFormat, LogLevel},
    Parser,
};

/// Combined Log Format used by Apache and Nginx.
/// 127.0.0.1 - frank [10/Oct/2000:13:55:36 -0700] "GET /path HTTP/1.1" 200 2326 "ref" "UA"
static COMBINED_RE: Lazy<Regex> = Lazy::new(|| {
    Regex::new(
        r#"^(\S+)\s+\S+\s+\S+\s+\[([^\]]+)\]\s+"([A-Z]+)\s+(\S+)\s+\S+"\s+(\d{3})\s+(\d+|-)"#,
    )
    .unwrap()
});

pub struct ApacheParser;

impl Parser for ApacheParser {
    fn try_parse(&self, line: &str, id: u64) -> Option<LogEntry> {
        let caps = COMBINED_RE.captures(line)?;

        let ip = caps.get(1).map(|m| m.as_str().to_string());
        let ts_str = caps.get(2)?.as_str();
        let method = caps.get(3).map(|m| m.as_str().to_string());
        let path = caps.get(4).map(|m| m.as_str().to_string());
        let status_code: u16 = caps.get(5)?.as_str().parse().ok()?;
        let bytes_raw = caps.get(6)?.as_str();
        let bytes: Option<u64> = if bytes_raw == "-" {
            None
        } else {
            bytes_raw.parse().ok()
        };

        let timestamp = DateTime::parse_from_str(ts_str, "%d/%b/%Y:%H:%M:%S %z")
            .map(|dt| dt.timestamp_millis())
            .unwrap_or_else(|_| chrono::Utc::now().timestamp_millis());

        let level = match status_code {
            500..=599 => LogLevel::Error,
            400..=499 => LogLevel::Warn,
            _ => LogLevel::Info,
        };

        let message = format!(
            "{} {} {}",
            method.as_deref().unwrap_or("-"),
            path.as_deref().unwrap_or("-"),
            status_code,
        );

        Some(LogEntry {
            id,
            timestamp,
            ip,
            method,
            path,
            status_code: Some(status_code),
            bytes,
            message,
            raw: line.to_string(),
            format: LogFormat::Apache,
            level,
            is_anomaly: false,
            anomaly_id: None,
        })
    }
}
