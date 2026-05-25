use chrono::{Datelike, NaiveDateTime, Utc};
use once_cell::sync::Lazy;
use regex::Regex;

use crate::parser::{
    types::{LogEntry, LogFormat, LogLevel},
    Parser,
};

/// auth.log / syslog (RFC 3164).
/// May  4 22:08:26 hostname sshd[1234]: Failed password for invalid user admin from 1.2.3.4
static AUTH_RE: Lazy<Regex> = Lazy::new(|| {
    Regex::new(r"^(\w{3})\s+(\d{1,2})\s+(\d{2}:\d{2}:\d{2})\s+\S+\s+\S+[:\s]+(.+)$").unwrap()
});

static IP_RE: Lazy<Regex> = Lazy::new(|| {
    Regex::new(r"\b(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\b").unwrap()
});

pub struct AuthParser;

impl Parser for AuthParser {
    fn try_parse(&self, line: &str, id: u64) -> Option<LogEntry> {
        let caps = AUTH_RE.captures(line)?;

        let month_str = caps.get(1)?.as_str();
        let day: u32 = caps.get(2)?.as_str().trim().parse().ok()?;
        let time_str = caps.get(3)?.as_str();
        let message = caps.get(4)?.as_str().to_string();

        let month = month_to_num(month_str)?;
        let year = Utc::now().year();
        let dt_str = format!("{}-{:02}-{:02} {}", year, month, day, time_str);

        let timestamp = NaiveDateTime::parse_from_str(&dt_str, "%Y-%m-%d %H:%M:%S")
            .map(|ndt| ndt.and_utc().timestamp_millis())
            .unwrap_or_else(|_| Utc::now().timestamp_millis());

        let ip = IP_RE
            .captures(&message)
            .and_then(|c| c.get(1))
            .map(|m| m.as_str().to_string());

        let lower = message.to_lowercase();
        let level = if lower.contains("fail")
            || lower.contains("invalid")
            || lower.contains("error")
            || lower.contains("denied")
        {
            LogLevel::Error
        } else if lower.contains("warn") || lower.contains("refused") {
            LogLevel::Warn
        } else {
            LogLevel::Info
        };

        Some(LogEntry {
            id,
            timestamp,
            ip,
            method: None,
            path: None,
            status_code: None,
            bytes: None,
            message,
            raw: line.to_string(),
            format: LogFormat::AuthLog,
            level,
            is_anomaly: false,
            anomaly_id: None,
        })
    }
}

fn month_to_num(abbr: &str) -> Option<u32> {
    match abbr {
        "Jan" => Some(1),
        "Feb" => Some(2),
        "Mar" => Some(3),
        "Apr" => Some(4),
        "May" => Some(5),
        "Jun" => Some(6),
        "Jul" => Some(7),
        "Aug" => Some(8),
        "Sep" => Some(9),
        "Oct" => Some(10),
        "Nov" => Some(11),
        "Dec" => Some(12),
        _ => None,
    }
}
