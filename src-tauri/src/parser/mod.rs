pub mod apache;
pub mod auth;
pub mod json_log;
pub mod types;

pub use types::{LogEntry, LogFormat, LogLevel};

use apache::ApacheParser;
use auth::AuthParser;
use json_log::JsonLogParser;

/// Every log format parser implements this trait.
/// Parsers are pure functions — no I/O, no side effects, independently testable.
pub trait Parser: Send + Sync {
    fn try_parse(&self, line: &str, id: u64) -> Option<LogEntry>;
}

/// Tries each parser in order, returns the first match.
pub struct ParserChain {
    parsers: Vec<Box<dyn Parser>>,
}

impl ParserChain {
    pub fn new(parsers: Vec<Box<dyn Parser>>) -> Self {
        Self { parsers }
    }

    pub fn parse(&self, line: &str, id: u64) -> Option<LogEntry> {
        self.parsers.iter().find_map(|p| p.try_parse(line, id))
    }
}

/// Samples up to 20 lines and scores each parser by success rate.
/// Returns the format with the highest score, defaulting to JsonLog.
pub fn detect_format(sample_lines: &[&str]) -> LogFormat {
    let sample = &sample_lines[..sample_lines.len().min(20)];

    let apache = ApacheParser;
    let auth = AuthParser;
    let json = JsonLogParser;

    let apache_score = sample.iter().filter(|&&l| apache.try_parse(l, 0).is_some()).count();
    let auth_score = sample.iter().filter(|&&l| auth.try_parse(l, 0).is_some()).count();
    let json_score = sample.iter().filter(|&&l| json.try_parse(l, 0).is_some()).count();

    if apache_score >= auth_score && apache_score >= json_score && apache_score > 0 {
        LogFormat::Apache
    } else if auth_score >= json_score && auth_score > 0 {
        LogFormat::AuthLog
    } else {
        LogFormat::JsonLog
    }
}

/// Build a parser chain tuned for the given format.
/// Apache and Nginx use the same combined-log parser.
/// AuthLog and Syslog use the same RFC-3164 parser.
pub fn build_chain(format: &LogFormat) -> ParserChain {
    match format {
        LogFormat::Apache | LogFormat::Nginx => {
            ParserChain::new(vec![Box::new(ApacheParser)])
        }
        LogFormat::AuthLog | LogFormat::Syslog => {
            ParserChain::new(vec![Box::new(AuthParser)])
        }
        LogFormat::JsonLog => {
            ParserChain::new(vec![Box::new(JsonLogParser)])
        }
    }
}

/// Chain that tries all parsers in order — used when auto-detecting.
pub fn build_auto_chain() -> ParserChain {
    ParserChain::new(vec![
        Box::new(ApacheParser),
        Box::new(AuthParser),
        Box::new(JsonLogParser),
    ])
}
