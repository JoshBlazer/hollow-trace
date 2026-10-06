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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_combined_log_line() {
        let line = r#"203.0.113.5 - - [01/May/2026:10:20:30 +0000] "POST /login?next=%2F HTTP/1.1" 401 512 "-" "curl/8.4.0""#;
        let e = ApacheParser.try_parse(line, 3).unwrap();
        assert_eq!(e.ip.as_deref(), Some("203.0.113.5"));
        assert_eq!(e.method.as_deref(), Some("POST"));
        assert_eq!(e.path.as_deref(), Some("/login?next=%2F"));
        assert_eq!(e.status_code, Some(401));
        assert_eq!(e.bytes, Some(512));
        assert!(matches!(e.level, LogLevel::Warn));
        assert_eq!(e.timestamp, 1_777_630_830_000);
        assert_eq!(e.raw, line);
    }

    #[test]
    fn handles_dash_bytes_and_5xx() {
        let line = r#"::1 - user [01/May/2026:10:20:30 -0500] "GET / HTTP/2.0" 503 - "-" "-""#;
        let e = ApacheParser.try_parse(line, 1).unwrap();
        assert_eq!(e.ip.as_deref(), Some("::1"));
        assert_eq!(e.bytes, None);
        assert!(matches!(e.level, LogLevel::Error));
    }

    #[test]
    fn rejects_non_access_log_lines() {
        assert!(ApacheParser.try_parse("May  4 22:08:26 host sshd[1]: hello", 1).is_none());
        assert!(ApacheParser.try_parse("", 1).is_none());
    }
}
