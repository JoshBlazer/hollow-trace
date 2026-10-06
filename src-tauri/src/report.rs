//! Anomaly grouping, CSV export and the Markdown incident report.
//!
//! Anomaly descriptions embed attacker-controlled request text, so every output format
//! here escapes it: CSV against spreadsheet formula injection, Markdown against
//! rendering raw HTML/links when the report is pasted into a ticket or wiki.

use std::collections::{BTreeMap, HashMap};
use std::fmt::Write as _;

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

use crate::{
    detector::types::{Anomaly, Severity},
    scorer::AppStats,
};

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub enum GroupBy {
    SourceIp,
    Category,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct AnomalyGroup {
    /// Source IP ("unknown" if none) or attack category
    pub key: String,
    pub count: usize,
    pub max_severity: Severity,
    pub first_seen: i64,
    pub last_seen: i64,
    /// Distinct categories (for IP groups) or distinct source IPs (for category groups)
    pub distinct: usize,
}

const UNKNOWN_IP: &str = "unknown";

fn group_key(a: &Anomaly, by: GroupBy) -> &str {
    match by {
        GroupBy::SourceIp => a.source_ip.as_deref().unwrap_or(UNKNOWN_IP),
        GroupBy::Category => a.category(),
    }
}

fn other_key(a: &Anomaly, by: GroupBy) -> &str {
    group_key(a, if by == GroupBy::SourceIp { GroupBy::Category } else { GroupBy::SourceIp })
}

/// Groups anomalies, most severe first, then by count.
pub fn summarize(anomalies: &[Anomaly], by: GroupBy) -> Vec<AnomalyGroup> {
    let mut groups: HashMap<&str, (AnomalyGroup, std::collections::HashSet<&str>)> = HashMap::new();
    for a in anomalies {
        let key = group_key(a, by);
        let (g, others) = groups.entry(key).or_insert_with(|| {
            (
                AnomalyGroup {
                    key: key.to_string(),
                    count: 0,
                    max_severity: a.severity,
                    first_seen: a.timestamp,
                    last_seen: a.timestamp,
                    distinct: 0,
                },
                Default::default(),
            )
        });
        g.count += 1;
        g.max_severity = g.max_severity.max(a.severity);
        g.first_seen = g.first_seen.min(a.timestamp);
        g.last_seen = g.last_seen.max(a.timestamp);
        others.insert(other_key(a, by));
    }
    let mut out: Vec<AnomalyGroup> = groups
        .into_values()
        .map(|(mut g, others)| {
            g.distinct = others.len();
            g
        })
        .collect();
    out.sort_by(|a, b| {
        b.max_severity
            .cmp(&a.max_severity)
            .then(b.count.cmp(&a.count))
            .then(a.key.cmp(&b.key))
    });
    out
}

/// Anomalies in one group, newest first, at most `limit`.
pub fn group_members(anomalies: &[Anomaly], by: GroupBy, key: &str, limit: usize) -> Vec<Anomaly> {
    anomalies
        .iter()
        .rev()
        .filter(|a| group_key(a, by) == key)
        .take(limit)
        .cloned()
        .collect()
}

fn iso(ms: i64) -> String {
    DateTime::<Utc>::from_timestamp_millis(ms)
        .map(|d| d.format("%Y-%m-%d %H:%M:%S UTC").to_string())
        .unwrap_or_else(|| "-".into())
}

fn severity_name(s: Severity) -> &'static str {
    match s {
        Severity::Low => "low",
        Severity::Medium => "medium",
        Severity::High => "high",
        Severity::Critical => "critical",
    }
}

// ── CSV ───────────────────────────────────────────────────────────────────────

/// One CSV field. Quotes when needed, and neutralizes cells a spreadsheet would treat
/// as a formula (=, +, -, @, tab, CR) by prefixing a single quote (OWASP guidance).
fn csv_field(s: &str) -> String {
    let s = if s.starts_with(['=', '+', '-', '@', '\t', '\r']) { format!("'{s}") } else { s.to_string() };
    if s.contains([',', '"', '\n', '\r']) {
        format!("\"{}\"", s.replace('"', "\"\""))
    } else {
        s
    }
}

pub fn anomalies_csv(anomalies: &[Anomaly]) -> String {
    let mut out = String::from("timestamp,severity,category,source_ip,description,line,anomaly_id\r\n");
    for a in anomalies {
        let row = [
            iso(a.timestamp),
            severity_name(a.severity).to_string(),
            a.category().to_string(),
            a.source_ip.clone().unwrap_or_default(),
            a.description.clone(),
            a.entry_id.to_string(),
            a.id.to_string(),
        ];
        let fields: Vec<String> = row.iter().map(|f| csv_field(f)).collect();
        out.push_str(&fields.join(","));
        out.push_str("\r\n");
    }
    out
}

// ── Markdown report ───────────────────────────────────────────────────────────

/// Escapes text for Markdown (including table cells): HTML is entity-encoded so it
/// can't render, and Markdown syntax characters are backslash-escaped.
pub fn md_escape(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for c in s.chars() {
        match c {
            '<' => out.push_str("&lt;"),
            '>' => out.push_str("&gt;"),
            '&' => out.push_str("&amp;"),
            '\n' | '\r' => out.push(' '),
            '\\' | '`' | '*' | '_' | '[' | ']' | '(' | ')' | '#' | '|' | '!' | '~' => {
                out.push('\\');
                out.push(c);
            }
            _ => out.push(c),
        }
    }
    out
}

fn category_label(cat: &str) -> String {
    match cat {
        "sql_injection" => "SQL injection".into(),
        "shell_injection" => "Shell injection".into(),
        "xxe_ssrf" => "SSRF/XXE".into(),
        "path_traversal" => "Path traversal".into(),
        "xss_attempt" => "XSS".into(),
        "scanner_detected" => "Scanner".into(),
        "auth_failure" => "Auth failure".into(),
        "rate_burst" => "Rate burst (brute force / scan)".into(),
        "response_size" => "Unusual response size".into(),
        other => other.to_string(),
    }
}

/// Anomaly counts per hour (or per day for spans over 3 days), oldest first.
fn timeline(anomalies: &[Anomaly]) -> (&'static str, Vec<(String, usize)>) {
    let (Some(min), Some(max)) = (
        anomalies.iter().map(|a| a.timestamp).min(),
        anomalies.iter().map(|a| a.timestamp).max(),
    ) else {
        return ("hour", Vec::new());
    };
    let daily = max - min > 3 * 86_400_000;
    let (unit, bucket_ms, fmt) = if daily {
        ("day", 86_400_000, "%Y-%m-%d")
    } else {
        ("hour", 3_600_000, "%Y-%m-%d %H:00")
    };
    let mut buckets: BTreeMap<i64, usize> = BTreeMap::new();
    for a in anomalies {
        *buckets.entry(a.timestamp.div_euclid(bucket_ms)).or_default() += 1;
    }
    let rows = buckets
        .into_iter()
        .map(|(b, n)| {
            let label = DateTime::<Utc>::from_timestamp_millis(b * bucket_ms)
                .map(|d| d.format(fmt).to_string())
                .unwrap_or_default();
            (label, n)
        })
        .collect();
    (unit, rows)
}

pub struct ReportInput<'a> {
    pub source: Option<&'a str>,
    pub stats: &'a AppStats,
    pub anomalies: &'a [Anomaly],
    pub generated_at: i64,
    pub app_version: &'a str,
}

pub fn markdown_report(input: &ReportInput) -> String {
    let ReportInput { source, stats, anomalies, generated_at, app_version } = *input;
    let mut r = String::new();
    let source_name = source
        .map(|p| std::path::Path::new(p).file_name().and_then(|n| n.to_str()).unwrap_or(p))
        .unwrap_or("(no file)");

    let _ = writeln!(r, "# Incident report: {}\n", md_escape(source_name));
    let _ = writeln!(r, "Generated {} by Hollow Trace {}.\n", iso(generated_at), md_escape(app_version));

    // Summary
    let _ = writeln!(r, "## Summary\n");
    let _ = writeln!(r, "| | |\n|---|---|");
    if let Some(p) = source {
        let _ = writeln!(r, "| Source | {} |", md_escape(p));
    }
    if let (Some(a), Some(b)) = (stats.first_timestamp, stats.last_timestamp) {
        let _ = writeln!(r, "| Time range | {} → {} |", iso(a), iso(b));
    }
    let _ = writeln!(r, "| Lines analysed | {} |", stats.total_lines);
    let _ = writeln!(r, "| Anomalies | {} |", stats.anomaly_count);
    let sc = &stats.severity_counts;
    let _ = writeln!(
        r,
        "| By severity | Critical {} · High {} · Medium {} · Low {} |",
        sc.critical, sc.high, sc.medium, sc.low
    );
    let _ = writeln!(r, "| Threat score | {} / 100 |", stats.threat_score);
    if (stats.anomaly_count as usize) > anomalies.len() {
        let _ = writeln!(
            r,
            "\n> Details below cover the most recent {} anomalies (older ones were dropped from memory during a long session).",
            anomalies.len()
        );
    }

    if anomalies.is_empty() {
        let _ = writeln!(r, "\nNo anomalies were detected.");
        return r;
    }

    // Top sources
    let _ = writeln!(r, "\n## Top sources\n");
    let _ = writeln!(r, "| Source IP | Anomalies | Worst severity | Attack types | First seen | Last seen |");
    let _ = writeln!(r, "|---|---:|---|---|---|---|");
    for g in summarize(anomalies, GroupBy::SourceIp).iter().take(15) {
        let mut cats: Vec<String> = anomalies
            .iter()
            .filter(|a| a.source_ip.as_deref().unwrap_or(UNKNOWN_IP) == g.key)
            .map(|a| category_label(a.category()))
            .collect();
        cats.sort();
        cats.dedup();
        let _ = writeln!(
            r,
            "| {} | {} | {} | {} | {} | {} |",
            md_escape(&g.key),
            g.count,
            severity_name(g.max_severity),
            md_escape(&cats.join(", ")),
            iso(g.first_seen),
            iso(g.last_seen)
        );
    }

    // Attack types
    let _ = writeln!(r, "\n## Attack types\n");
    let _ = writeln!(r, "| Type | Anomalies | Worst severity | Distinct sources |");
    let _ = writeln!(r, "|---|---:|---|---:|");
    for g in summarize(anomalies, GroupBy::Category) {
        let _ = writeln!(
            r,
            "| {} | {} | {} | {} |",
            md_escape(&category_label(&g.key)),
            g.count,
            severity_name(g.max_severity),
            g.distinct
        );
    }

    // Timeline
    let (unit, rows) = timeline(anomalies);
    let peak = rows.iter().map(|(_, n)| *n).max().unwrap_or(1).max(1);
    let _ = writeln!(r, "\n## Timeline (anomalies per {unit})\n");
    let _ = writeln!(r, "| {} | Anomalies | |", if unit == "day" { "Day" } else { "Hour (UTC)" });
    let _ = writeln!(r, "|---|---:|---|");
    for (label, n) in &rows {
        let bar = "█".repeat((n * 20).div_ceil(peak));
        let _ = writeln!(r, "| {label} | {n} | {bar} |");
    }

    // Critical examples
    let critical: Vec<&Anomaly> = anomalies.iter().filter(|a| a.severity == Severity::Critical).take(20).collect();
    if !critical.is_empty() {
        let _ = writeln!(r, "\n## Critical findings (first {})\n", critical.len());
        let _ = writeln!(r, "| Time | Line | Finding |");
        let _ = writeln!(r, "|---|---:|---|");
        for a in critical {
            let _ = writeln!(r, "| {} | {} | {} |", iso(a.timestamp), a.entry_id, md_escape(&a.description));
        }
    }

    r
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::detector::types::AnomalyKind;

    fn a(id: u64, ts: i64, ip: &str, cat: &str, sev: Severity, desc: &str) -> Anomaly {
        let kind = if cat == "rate_burst" {
            AnomalyKind::RateBurst { ip: ip.into(), count: 50, window_secs: 10 }
        } else {
            AnomalyKind::PatternMatch { pattern_name: cat.into() }
        };
        Anomaly { id, entry_id: id * 10, timestamp: ts, kind, severity: sev, description: desc.into(), source_ip: Some(ip.into()) }
    }

    fn sample() -> Vec<Anomaly> {
        vec![
            a(1, 1_000, "203.0.113.9", "sql_injection", Severity::Critical, "SQL injection from 203.0.113.9: GET /x"),
            a(2, 2_000, "203.0.113.9", "xss_attempt", Severity::High, "XSS from 203.0.113.9: GET /?q=<script>alert(1)</script>"),
            a(3, 3_000, "198.51.100.7", "rate_burst", Severity::High, "Rate burst from 198.51.100.7"),
            a(4, 4_000, "198.51.100.7", "rate_burst", Severity::High, "Rate burst from 198.51.100.7"),
            a(5, 5_000, "198.51.100.7", "rate_burst", Severity::High, "Rate burst from 198.51.100.7"),
        ]
    }

    #[test]
    fn groups_by_ip_and_category() {
        let by_ip = summarize(&sample(), GroupBy::SourceIp);
        assert_eq!(by_ip[0].key, "203.0.113.9", "critical outranks a larger high-only group");
        assert_eq!((by_ip[0].count, by_ip[0].distinct, by_ip[0].max_severity), (2, 2, Severity::Critical));
        assert_eq!((by_ip[1].count, by_ip[1].first_seen, by_ip[1].last_seen), (3, 3_000, 5_000));

        let by_cat = summarize(&sample(), GroupBy::Category);
        assert_eq!(by_cat.iter().map(|g| g.key.as_str()).collect::<Vec<_>>(), vec!["sql_injection", "rate_burst", "xss_attempt"]);

        let members = group_members(&sample(), GroupBy::Category, "rate_burst", 2);
        assert_eq!(members.iter().map(|a| a.id).collect::<Vec<_>>(), vec![5, 4], "newest first, limited");
    }

    #[test]
    fn csv_quotes_and_blocks_formula_injection() {
        let mut list = sample();
        list[0].description = "=HYPERLINK(\"http://evil\",\"click\")".into();
        list[1].source_ip = Some("@SUM(1+1)".into());
        let csv = anomalies_csv(&list);
        let lines: Vec<&str> = csv.split("\r\n").collect();
        assert_eq!(lines[0], "timestamp,severity,category,source_ip,description,line,anomaly_id");
        assert!(lines[1].contains(r#""'=HYPERLINK(""http://evil"",""click"")""#), "{}", lines[1]);
        assert!(lines[2].contains(",'@SUM(1+1),"), "{}", lines[2]);
        assert!(lines[1].starts_with("1970-01-01 00:00:01 UTC,critical,sql_injection,203.0.113.9,"));
    }

    #[test]
    fn markdown_escapes_attacker_text() {
        let esc = md_escape("<script>alert(1)</script> | [x](http://evil) **b**");
        assert!(!esc.contains('<') && !esc.contains("](") && !esc.contains("**"), "{esc}");
        assert!(esc.contains("&lt;script&gt;") && esc.contains("\\|"));
    }

    #[test]
    fn report_has_all_sections_and_no_raw_html() {
        let stats = AppStats {
            total_lines: 10_000,
            anomaly_count: 5,
            threat_score: 56,
            first_timestamp: Some(0),
            last_timestamp: Some(7_200_000),
            ..Default::default()
        };
        let md = markdown_report(&ReportInput {
            source: Some(r"C:\logs\access.log"),
            stats: &stats,
            anomalies: &sample(),
            generated_at: 0,
            app_version: "0.3.0",
        });
        for heading in ["# Incident report: access.log", "## Summary", "## Top sources", "## Attack types", "## Timeline", "## Critical findings"] {
            assert!(md.contains(heading), "missing {heading}\n{md}");
        }
        assert!(md.contains("| Lines analysed | 10000 |"));
        // Labels are escaped too; "\(" renders as a plain "("
        assert!(md.contains(r"Rate burst \(brute force / scan\)"));
        assert!(!md.contains("<script>"), "attacker HTML must be escaped");
    }

    #[test]
    fn report_notes_truncation_and_handles_no_anomalies() {
        let stats = AppStats { total_lines: 10, anomaly_count: 0, ..Default::default() };
        let md = markdown_report(&ReportInput { source: None, stats: &stats, anomalies: &[], generated_at: 0, app_version: "x" });
        assert!(md.contains("No anomalies were detected."));

        let stats = AppStats { anomaly_count: 100, ..Default::default() };
        let md = markdown_report(&ReportInput { source: None, stats: &stats, anomalies: &sample(), generated_at: 0, app_version: "x" });
        assert!(md.contains("most recent 5 anomalies"));
    }

    #[test]
    fn timeline_buckets_by_hour_or_day() {
        let (unit, rows) = timeline(&sample());
        assert_eq!((unit, rows.len()), ("hour", 1));
        let spread: Vec<Anomaly> = (0..5).map(|d| a(d, d as i64 * 86_400_000, "1.1.1.1", "xss_attempt", Severity::High, "x")).collect();
        let (unit, rows) = timeline(&spread);
        assert_eq!((unit, rows.len()), ("day", 5));
    }
}
