use once_cell::sync::Lazy;
use regex::Regex;

use crate::{
    detector::types::{Anomaly, AnomalyKind, Severity},
    parser::types::LogEntry,
};

struct PatternDef {
    name: &'static str,
    re: Regex,
    severity: Severity,
}

/// All patterns are compiled once on first access.
static PATTERNS: Lazy<Vec<PatternDef>> = Lazy::new(|| {
    vec![
        PatternDef {
            name: "sql_injection",
            re: Regex::new(
                r"(?i)(union\s+select|drop\s+table|insert\s+into\b|or\s+1\s*=\s*1|'\s+or\s+')",
            )
            .unwrap(),
            severity: Severity::Critical,
        },
        PatternDef {
            name: "path_traversal",
            re: Regex::new(r"(\.\./|\.\.\\|%2e%2e%2f|%2e%2e/)").unwrap(),
            severity: Severity::High,
        },
        PatternDef {
            name: "shell_injection",
            re: Regex::new(
                r"(?i)(;\s*(?:bash|sh|cmd|powershell)\b|\|\s*wget\s+|\|\s*curl\s+.*\|\s*sh|`[^`]+`)",
            )
            .unwrap(),
            severity: Severity::Critical,
        },
        PatternDef {
            name: "scanner_detected",
            re: Regex::new(
                r"(?i)(nikto|sqlmap|masscan|nmap|zgrab|dirbuster|gobuster|wfuzz)",
            )
            .unwrap(),
            severity: Severity::High,
        },
        PatternDef {
            name: "auth_failure",
            re: Regex::new(
                r"(?i)(failed\s+password|authentication\s+failure|invalid\s+user|permission\s+denied|access\s+denied)",
            )
            .unwrap(),
            severity: Severity::Medium,
        },
        PatternDef {
            name: "xxe_ssrf",
            re: Regex::new(r"(?i)(file://|dict://|gopher://|<!ENTITY|<!DOCTYPE[^>]*ENTITY)")
                .unwrap(),
            severity: Severity::Critical,
        },
        PatternDef {
            name: "xss_attempt",
            re: Regex::new(r"(?i)(<script|javascript:|onerror\s*=|onload\s*=|eval\s*\()")
                .unwrap(),
            severity: Severity::High,
        },
    ]
});

/// Checks a log entry's raw line against all patterns.
/// Returns the first match, or None.
pub fn check_patterns(entry: &LogEntry) -> Option<Anomaly> {
    PATTERNS.iter().find_map(|p| {
        if p.re.is_match(&entry.raw) {
            Some(Anomaly {
                id: 0, // assigned by AnomalyDetector::check_all
                entry_id: entry.id,
                timestamp: entry.timestamp,
                kind: AnomalyKind::PatternMatch {
                    pattern_name: p.name.to_string(),
                },
                severity: p.severity,
                description: format!("Pattern '{}' matched in log entry", p.name),
            })
        } else {
            None
        }
    })
}
