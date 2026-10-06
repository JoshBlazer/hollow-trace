//! Searching the backend ring buffer (up to 100k entries), which holds far more
//! history than the frontend's 10k display buffer.

use std::net::IpAddr;

use serde::{Deserialize, Serialize};

use crate::{detector::types::Severity, parser::types::LogEntry, settings::IpRange};

/// Default and maximum entries returned per query (the frontend list's capacity).
pub const MAX_RESULTS: usize = 10_000;
/// Lines shown on each side of a jump-to-line target.
pub const CONTEXT_LINES: u64 = 200;

#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "camelCase", default)]
pub struct EntryFilter {
    /// Case-insensitive substring of the raw line
    pub text: Option<String>,
    /// Exact IP, CIDR range, or (if neither parses) substring of the entry's IP
    pub ip: Option<String>,
    /// Only lines whose worst anomaly is at least this severe
    pub min_severity: Option<Severity>,
    /// Only lines with any anomaly
    pub anomalies_only: bool,
    /// HTTP status class: 2, 3, 4 or 5
    pub status_class: Option<u16>,
    /// Jump-to-line: return the lines around this entry id; other criteria are ignored
    pub around: Option<u64>,
    /// Max entries to return (newest kept); 0 means MAX_RESULTS
    pub limit: usize,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct EntryQueryResult {
    /// Matching entries, oldest first (newest `limit` if more matched)
    pub entries: Vec<LogEntry>,
    /// Total matches in the buffer, including ones beyond `limit`
    pub matched: usize,
    /// Entries searched (the backend buffer's size)
    pub scanned: usize,
}

enum IpMatcher {
    Range(IpRange),
    Substring(String),
}

impl IpMatcher {
    fn new(s: &str) -> Self {
        IpRange::parse(s).map_or_else(|_| Self::Substring(s.to_lowercase()), Self::Range)
    }

    fn matches(&self, ip: Option<&str>) -> bool {
        let Some(ip) = ip else { return false };
        match self {
            Self::Range(r) => ip.parse::<IpAddr>().is_ok_and(|a| r.contains(&a)),
            Self::Substring(s) => ip.to_lowercase().contains(s.as_str()),
        }
    }
}

fn non_empty(s: &Option<String>) -> Option<&str> {
    s.as_deref().map(str::trim).filter(|s| !s.is_empty())
}

/// Runs `filter` over `entries` (oldest first, as stored in the ring buffer).
pub fn query<'a, I>(entries: I, filter: &EntryFilter) -> EntryQueryResult
where
    I: IntoIterator<Item = &'a LogEntry>,
{
    let limit = if filter.limit == 0 { MAX_RESULTS } else { filter.limit.min(MAX_RESULTS) };

    if let Some(target) = filter.around {
        let lo = target.saturating_sub(CONTEXT_LINES);
        let hi = target.saturating_add(CONTEXT_LINES);
        let mut scanned = 0;
        let entries: Vec<LogEntry> = entries
            .into_iter()
            .inspect(|_| scanned += 1)
            .filter(|e| (lo..=hi).contains(&e.id))
            .cloned()
            .collect();
        return EntryQueryResult { matched: entries.len(), entries, scanned };
    }

    let text = non_empty(&filter.text).map(str::to_lowercase);
    let ip = non_empty(&filter.ip).map(IpMatcher::new);

    let mut matched = Vec::new();
    let mut scanned = 0;
    for e in entries {
        scanned += 1;
        if filter.anomalies_only && !e.is_anomaly {
            continue;
        }
        if let Some(min) = filter.min_severity {
            if e.anomaly_severity.is_none_or(|s| s < min) {
                continue;
            }
        }
        if let Some(class) = filter.status_class {
            if e.status_code.is_none_or(|s| s / 100 != class) {
                continue;
            }
        }
        if let Some(m) = &ip {
            if !m.matches(e.ip.as_deref()) {
                continue;
            }
        }
        if let Some(t) = &text {
            if !e.raw.to_lowercase().contains(t.as_str()) {
                continue;
            }
        }
        matched.push(e);
    }

    let total = matched.len();
    let skip = total.saturating_sub(limit);
    EntryQueryResult {
        entries: matched.into_iter().skip(skip).cloned().collect(),
        matched: total,
        scanned,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::parser::types::{LogFormat, LogLevel};

    fn e(id: u64, ip: &str, status: u16, raw: &str, sev: Option<Severity>) -> LogEntry {
        LogEntry {
            id,
            timestamp: id as i64,
            ip: Some(ip.into()),
            method: Some("GET".into()),
            path: Some("/".into()),
            status_code: Some(status),
            bytes: None,
            message: String::new(),
            raw: raw.into(),
            format: LogFormat::Apache,
            level: LogLevel::Info,
            is_anomaly: sev.is_some(),
            anomaly_id: sev.map(|_| id),
            anomaly_severity: sev,
        }
    }

    fn data() -> Vec<LogEntry> {
        vec![
            e(1, "10.0.0.5", 200, "GET /index.html", None),
            e(2, "203.0.113.9", 403, "GET /../../etc/passwd", Some(Severity::High)),
            e(3, "203.0.113.9", 200, "GET /search?q=UNION SELECT", Some(Severity::Critical)),
            e(4, "2001:db8::7", 404, "GET /favicon.ico", None),
            e(5, "10.0.0.6", 401, "POST /login", Some(Severity::Low)),
        ]
    }

    fn ids(f: EntryFilter) -> Vec<u64> {
        query(&data(), &f).entries.iter().map(|e| e.id).collect()
    }

    #[test]
    fn empty_filter_returns_everything() {
        let r = query(&data(), &EntryFilter::default());
        assert_eq!((r.matched, r.scanned, r.entries.len()), (5, 5, 5));
    }

    #[test]
    fn text_is_case_insensitive_and_whitespace_only_is_ignored() {
        assert_eq!(ids(EntryFilter { text: Some("union select".into()), ..Default::default() }), vec![3]);
        assert_eq!(ids(EntryFilter { text: Some("   ".into()), ..Default::default() }).len(), 5);
    }

    #[test]
    fn ip_exact_cidr_v6_and_substring() {
        assert_eq!(ids(EntryFilter { ip: Some("203.0.113.9".into()), ..Default::default() }), vec![2, 3]);
        assert_eq!(ids(EntryFilter { ip: Some("10.0.0.0/8".into()), ..Default::default() }), vec![1, 5]);
        assert_eq!(ids(EntryFilter { ip: Some("2001:db8::/32".into()), ..Default::default() }), vec![4]);
        assert_eq!(ids(EntryFilter { ip: Some("203.0.".into()), ..Default::default() }), vec![2, 3]);
    }

    #[test]
    fn severity_anomalies_and_status_class() {
        assert_eq!(ids(EntryFilter { min_severity: Some(Severity::High), ..Default::default() }), vec![2, 3]);
        assert_eq!(ids(EntryFilter { anomalies_only: true, ..Default::default() }), vec![2, 3, 5]);
        assert_eq!(ids(EntryFilter { status_class: Some(4), ..Default::default() }), vec![2, 4, 5]);
        // Criteria combine with AND
        assert_eq!(
            ids(EntryFilter { status_class: Some(4), anomalies_only: true, ip: Some("10.0.0.0/8".into()), ..Default::default() }),
            vec![5]
        );
    }

    #[test]
    fn limit_keeps_newest_and_reports_total() {
        let r = query(&data(), &EntryFilter { limit: 2, ..Default::default() });
        assert_eq!(r.entries.iter().map(|e| e.id).collect::<Vec<_>>(), vec![4, 5]);
        assert_eq!(r.matched, 5);
    }

    #[test]
    fn around_returns_context_and_ignores_other_criteria() {
        let many: Vec<LogEntry> = (1..=1_000).map(|i| e(i, "10.0.0.1", 200, "x", None)).collect();
        let r = query(&many, &EntryFilter { around: Some(500), text: Some("nomatch".into()), ..Default::default() });
        assert_eq!(r.entries.first().unwrap().id, 300);
        assert_eq!(r.entries.last().unwrap().id, 700);
        let r = query(&many, &EntryFilter { around: Some(5), ..Default::default() });
        assert_eq!(r.entries.first().unwrap().id, 1, "clamped at the start");
    }
}
