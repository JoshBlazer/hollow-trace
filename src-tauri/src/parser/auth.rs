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


pub struct AuthParser;

impl Parser for AuthParser {
    fn try_parse(&self, line: &str, id: u64) -> Option<LogEntry> {
        let caps = AUTH_RE.captures(line)?;

        let month_str = caps.get(1)?.as_str();
        let day: u32 = caps.get(2)?.as_str().trim().parse().ok()?;
        let time_str = caps.get(3)?.as_str();
        let message = caps.get(4)?.as_str().to_string();

        let month = month_to_num(month_str)?;
        let timestamp = syslog_timestamp(month, day, time_str, Utc::now().timestamp_millis());

        let ip = extract_ip(&message);

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
            anomaly_severity: None,
        })
    }
}

/// First IPv4 or IPv6 address in a syslog message: handles "from 2001:db8::1 port 22",
/// "rhost=203.0.113.5", "[2001:db8::1]:22" and "203.0.113.5:22".
fn extract_ip(message: &str) -> Option<String> {
    message
        .split(|c: char| c.is_whitespace() || c == '=' || c == ',' || c == ';')
        .find_map(|token| {
            let t = token.trim_matches(|c: char| matches!(c, '(' | ')' | '\'' | '"' | '.' | '<' | '>'));
            // [v6]:port or [v6]
            let t = match t.strip_prefix('[') {
                Some(rest) => rest.split(']').next().unwrap_or(rest),
                None => t,
            };
            if let Ok(ip) = t.parse::<std::net::IpAddr>() {
                return Some(ip.to_string());
            }
            // v4:port
            let (host, port) = t.rsplit_once(':')?;
            port.parse::<u16>().ok()?;
            host.parse::<std::net::Ipv4Addr>().ok().map(|ip| ip.to_string())
        })
}

/// RFC 3164 timestamps have no year. Assume the current year, unless that puts the line
/// more than a day in the future (e.g. a December log read in January): then use last year.
fn syslog_timestamp(month: u32, day: u32, time_str: &str, now_ms: i64) -> i64 {
    let year = chrono::DateTime::from_timestamp_millis(now_ms).map_or(1970, |d| d.year());
    let at = |y: i32| {
        NaiveDateTime::parse_from_str(&format!("{y}-{month:02}-{day:02} {time_str}"), "%Y-%m-%d %H:%M:%S")
            .ok()
            .map(|ndt| ndt.and_utc().timestamp_millis())
    };
    match at(year) {
        Some(ts) if ts > now_ms + 86_400_000 => at(year - 1).unwrap_or(ts),
        Some(ts) => ts,
        None => now_ms,
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_failed_ssh_login() {
        let line = "May  4 22:08:26 web01 sshd[1234]: Failed password for invalid user admin from 203.0.113.7 port 52314 ssh2";
        let e = AuthParser.try_parse(line, 7).unwrap();
        assert_eq!(e.id, 7);
        assert_eq!(e.ip.as_deref(), Some("203.0.113.7"));
        assert!(matches!(e.level, LogLevel::Error));
        assert!(e.message.starts_with("Failed password"));
        assert!(matches!(e.format, LogFormat::AuthLog));
        assert_eq!(e.status_code, None);
    }

    #[test]
    fn levels_and_missing_ip() {
        let ok = AuthParser.try_parse("Oct  5 09:00:01 web01 CRON[99]: session opened for user root", 1).unwrap();
        assert!(matches!(ok.level, LogLevel::Info));
        assert_eq!(ok.ip, None);
        let refused = AuthParser.try_parse("Oct  5 09:00:01 web01 sshd[2]: Connection refused by 10.0.0.9", 1).unwrap();
        assert!(matches!(refused.level, LogLevel::Warn));
    }

    #[test]
    fn extracts_ipv6_and_other_ip_forms() {
        let cases = [
            ("Failed password for root from 2001:db8::1 port 22 ssh2", Some("2001:db8::1")),
            ("pam_unix(sshd:auth): authentication failure; logname= uid=0 rhost=203.0.113.5  user=root", Some("203.0.113.5")),
            ("Connection closed by [2001:db8::42]:51000", Some("2001:db8::42")),
            ("Did not receive identification string from 198.51.100.3:4422", Some("198.51.100.3")),
            ("Accepted publickey for deploy from 10.0.0.9.", Some("10.0.0.9")),
            ("session opened for user root by (uid=0)", None),
        ];
        for (msg, want) in cases {
            assert_eq!(extract_ip(msg).as_deref(), want, "{msg}");
        }
        let line = "Oct  5 09:00:01 web01 sshd[2]: Failed password for invalid user x from 2001:db8::1 port 22 ssh2";
        assert_eq!(AuthParser.try_parse(line, 1).unwrap().ip.as_deref(), Some("2001:db8::1"));
    }

    #[test]
    fn rejects_other_formats() {
        assert!(AuthParser.try_parse(r#"{"msg":"hi"}"#, 1).is_none());
        assert!(AuthParser.try_parse("Foo  4 22:08:26 host prog: x", 1).is_none());
    }

    #[test]
    fn year_rolls_back_for_future_dates() {
        let jan_2027 = chrono::NaiveDate::from_ymd_opt(2027, 1, 2).unwrap().and_hms_opt(0, 0, 0).unwrap().and_utc().timestamp_millis();
        let ts = syslog_timestamp(12, 31, "23:59:00", jan_2027);
        assert_eq!(chrono::DateTime::from_timestamp_millis(ts).unwrap().year(), 2026);
        let ts = syslog_timestamp(1, 1, "10:00:00", jan_2027);
        assert_eq!(chrono::DateTime::from_timestamp_millis(ts).unwrap().year(), 2027);
    }
}
