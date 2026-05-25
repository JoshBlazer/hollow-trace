use chrono::Utc;
use serde_json::Value;

use crate::parser::{
    types::{LogEntry, LogFormat, LogLevel},
    Parser,
};

/// Newline-delimited JSON logs (ECS, Logstash, Bunyan, and ad-hoc formats).
/// Applies heuristic field-name mapping — works with any JSON object per line.
pub struct JsonLogParser;

impl Parser for JsonLogParser {
    fn try_parse(&self, line: &str, id: u64) -> Option<LogEntry> {
        let trimmed = line.trim();
        if !trimmed.starts_with('{') {
            return None;
        }
        let v: Value = serde_json::from_str(trimmed).ok()?;
        let obj = v.as_object()?;

        let timestamp = find_str(obj, &["timestamp", "time", "@timestamp", "ts"])
            .and_then(parse_ts_str)
            .or_else(|| find_num(obj, &["timestamp", "time", "ts"]).map(|n| to_ms(n)))
            .unwrap_or_else(|| Utc::now().timestamp_millis());

        let message = find_str(obj, &["message", "msg", "log", "text"])
            .unwrap_or(trimmed)
            .to_string();

        let level = find_str(obj, &["level", "severity", "lvl", "loglevel"])
            .map(|s| parse_level(s))
            .unwrap_or(LogLevel::Info);

        let ip = find_str(obj, &["ip", "remote_addr", "client", "remote_ip", "client_ip", "src"])
            .map(|s| s.to_string());

        let method =
            find_str(obj, &["method", "http_method", "request_method"]).map(|s| s.to_string());

        let path = find_str(obj, &["path", "uri", "url", "request_uri", "request"])
            .map(|s| s.to_string());

        let status_code = find_any(obj, &["status", "status_code", "http_status", "response_code"])
            .and_then(|v| match v {
                Value::Number(n) => n.as_u64().map(|n| n as u16),
                Value::String(s) => s.parse().ok(),
                _ => None,
            });

        let bytes = find_any(obj, &["bytes", "size", "content_length", "bytes_sent"])
            .and_then(|v| v.as_u64());

        Some(LogEntry {
            id,
            timestamp,
            ip,
            method,
            path,
            status_code,
            bytes,
            message,
            raw: line.to_string(),
            format: LogFormat::JsonLog,
            level,
            is_anomaly: false,
            anomaly_id: None,
        })
    }
}

// ── Helpers ───────────────────────────────────────────────────────────────────

fn find_str<'a>(obj: &'a serde_json::Map<String, Value>, keys: &[&str]) -> Option<&'a str> {
    keys.iter().find_map(|&k| obj.get(k)?.as_str())
}

fn find_num(obj: &serde_json::Map<String, Value>, keys: &[&str]) -> Option<i64> {
    keys.iter().find_map(|&k| obj.get(k)?.as_i64())
}

fn find_any<'a>(
    obj: &'a serde_json::Map<String, Value>,
    keys: &[&str],
) -> Option<&'a Value> {
    keys.iter().find_map(|&k| obj.get(k))
}

fn to_ms(n: i64) -> i64 {
    // Values > 1e12 are already milliseconds; smaller values are seconds
    if n > 1_000_000_000_000 {
        n
    } else {
        n * 1000
    }
}

fn parse_ts_str(s: &str) -> Option<i64> {
    chrono::DateTime::parse_from_rfc3339(s)
        .map(|dt| dt.timestamp_millis())
        .ok()
        .or_else(|| {
            chrono::NaiveDateTime::parse_from_str(s, "%Y-%m-%d %H:%M:%S")
                .map(|ndt| ndt.and_utc().timestamp_millis())
                .ok()
        })
        .or_else(|| {
            chrono::NaiveDateTime::parse_from_str(s, "%Y-%m-%dT%H:%M:%S")
                .map(|ndt| ndt.and_utc().timestamp_millis())
                .ok()
        })
}

fn parse_level(s: &str) -> LogLevel {
    match s.to_lowercase().as_str() {
        "error" | "err" | "fatal" | "crit" | "critical" => LogLevel::Error,
        "warn" | "warning" => LogLevel::Warn,
        "debug" | "trace" => LogLevel::Debug,
        _ => LogLevel::Info,
    }
}
