use std::collections::HashMap;
use std::fs::File;
use std::io::{BufRead, BufReader, Read, Seek, SeekFrom};
use std::path::{Path, PathBuf};
use std::sync::{mpsc, Arc};
use std::time::{Duration, Instant};

use flate2::read::MultiGzDecoder;
use notify::{RecommendedWatcher, RecursiveMode};
use notify_debouncer_mini::{new_debouncer, DebounceEventResult, Debouncer};
use parking_lot::RwLock;

use crate::{
    detector::{
        types::{Anomaly, Severity},
        AnomalyDetector,
    },
    events::{
        EventSink, LogBatch, BATCH_SIZE, EMIT_INTERVAL_MS, FILE_BATCH_SIZE, STATS_INTERVAL_MS,
    },
    parser::{build_chain, detect_format, types::LogFormat, ParserChain},
    ring_buffer::RingBuffer,
    scorer::{calculate_threat_score, AppStats, IpCount, SeverityCounts},
    settings::DetectionSettings,
    state::WatcherHandle,
};

const EMIT_INTERVAL: Duration = Duration::from_millis(EMIT_INTERVAL_MS);
const STATS_INTERVAL: Duration = Duration::from_millis(STATS_INTERVAL_MS);

/// Anomalies kept for get_anomalies/export. Oldest are dropped beyond this,
/// so a long live tail can't grow memory without bound.
pub const MAX_STORED_ANOMALIES: usize = 50_000;
/// Distinct IPs counted for the "top IPs" stat. When exceeded, the least-seen half is
/// dropped; heavy hitters (the ones shown) keep their counts.
pub const MAX_TRACKED_IPS: usize = 100_000;

const GZIP_MAGIC: [u8; 2] = [0x1f, 0x8b];

/// Shared state a parsing session writes into.
#[derive(Clone)]
pub struct Stores {
    pub ring: Arc<RwLock<RingBuffer>>,
    pub anomalies: Arc<RwLock<Vec<Anomaly>>>,
    pub stats: Arc<RwLock<AppStats>>,
}

// ── LineProcessor ─────────────────────────────────────────────────────────────
// Holds all mutable state for one parsing session (static or live).
// Runs on a single thread; no locking inside this struct.

struct LineProcessor<S: EventSink> {
    chain: ParserChain,
    detector: AnomalyDetector,
    line_counter: u64,
    batch: LogBatch,
    batch_size: usize,
    max_anomalies: usize,
    max_ips: usize,
    last_emit: Instant,
    last_stats: Instant,
    ip_counts: HashMap<String, u64>,
    severity_counts: SeverityCounts,
    anomaly_count: u64,
    lines_in_period: u64,
    period_start: Instant,
    first_ts: Option<i64>,
    last_ts: Option<i64>,
    stores: Stores,
    sink: S,
}

impl<S: EventSink> LineProcessor<S> {
    fn new(
        chain: ParserChain,
        batch_size: usize,
        settings: &DetectionSettings,
        stores: Stores,
        sink: S,
    ) -> Self {
        let now = Instant::now();
        Self {
            chain,
            detector: AnomalyDetector::new(0, settings),
            line_counter: 0,
            batch: LogBatch::default(),
            batch_size,
            max_anomalies: MAX_STORED_ANOMALIES,
            max_ips: MAX_TRACKED_IPS,
            last_emit: now,
            last_stats: now,
            ip_counts: HashMap::new(),
            severity_counts: SeverityCounts::default(),
            anomaly_count: 0,
            lines_in_period: 0,
            period_start: now,
            first_ts: None,
            last_ts: None,
            stores,
            sink,
        }
    }

    fn process_line(&mut self, raw: &str) {
        if raw.is_empty() {
            return;
        }

        self.line_counter += 1;
        self.lines_in_period += 1;

        let Some(mut entry) = self.chain.parse(raw, self.line_counter) else {
            return;
        };

        let anomalies = self.detector.check_all(&entry);

        self.first_ts = Some(self.first_ts.map_or(entry.timestamp, |t| t.min(entry.timestamp)));
        self.last_ts = Some(self.last_ts.map_or(entry.timestamp, |t| t.max(entry.timestamp)));

        if !anomalies.is_empty() {
            entry.is_anomaly = true;
            entry.anomaly_id = Some(anomalies[0].id);
            entry.anomaly_severity = anomalies.iter().map(|a| a.severity).max();
            self.anomaly_count += anomalies.len() as u64;

            for a in &anomalies {
                match a.severity {
                    Severity::Low => self.severity_counts.low += 1,
                    Severity::Medium => self.severity_counts.medium += 1,
                    Severity::High => self.severity_counts.high += 1,
                    Severity::Critical => self.severity_counts.critical += 1,
                }
            }
            let mut store = self.stores.anomalies.write();
            store.extend(anomalies.iter().cloned());
            // Trim in chunks (10% headroom) so the O(n) drain is amortized
            if store.len() > self.max_anomalies + self.max_anomalies / 10 {
                let excess = store.len() - self.max_anomalies;
                store.drain(..excess);
            }
        }

        if let Some(ip) = &entry.ip {
            *self.ip_counts.entry(ip.clone()).or_insert(0) += 1;
            if self.ip_counts.len() > self.max_ips {
                self.prune_ip_counts();
            }
        }

        self.stores.ring.write().push(entry.clone());
        self.batch.anomalies.extend(anomalies);
        self.batch.entries.push(entry);

        if self.batch.entries.len() >= self.batch_size || self.last_emit.elapsed() >= EMIT_INTERVAL
        {
            self.flush_batch();
        }
    }

    /// Drops the least-seen half of tracked IPs.
    fn prune_ip_counts(&mut self) {
        let mut counts: Vec<u64> = self.ip_counts.values().copied().collect();
        let mid = counts.len() / 2;
        let (_, &mut median, _) = counts.select_nth_unstable(mid);
        let mut budget = mid; // remove at most half, even if many IPs share the median
        self.ip_counts.retain(|_, &mut c| {
            if c <= median && budget > 0 {
                budget -= 1;
                false
            } else {
                true
            }
        });
    }

    fn flush_batch(&mut self) {
        if self.batch.entries.is_empty() {
            return;
        }
        self.sink.batch(std::mem::take(&mut self.batch));
        self.last_emit = Instant::now();
    }

    fn maybe_emit_stats(&mut self) {
        if self.last_stats.elapsed() >= STATS_INTERVAL {
            self.push_stats();
        }
    }

    fn top_ips(&self) -> Vec<IpCount> {
        let mut top_ips: Vec<IpCount> = self
            .ip_counts
            .iter()
            .map(|(ip, &count)| IpCount {
                ip: ip.clone(),
                count,
            })
            .collect();
        top_ips.sort_unstable_by(|a, b| b.count.cmp(&a.count));
        top_ips.truncate(5);
        top_ips
    }

    fn snapshot(&self, parse_rate: f64) -> AppStats {
        let mut g = self.stores.stats.write();
        g.total_lines = self.line_counter;
        g.anomaly_count = self.anomaly_count;
        g.parse_rate = parse_rate;
        g.top_ips = self.top_ips();
        g.severity_counts = self.severity_counts.clone();
        g.first_timestamp = self.first_ts;
        g.last_timestamp = self.last_ts;
        g.threat_score = calculate_threat_score(&g);
        g.clone()
    }

    fn push_stats(&mut self) {
        let elapsed = self.period_start.elapsed().as_secs_f64().max(0.001);
        let snapshot = self.snapshot(self.lines_in_period as f64 / elapsed);
        self.sink.stats(&snapshot);

        self.lines_in_period = 0;
        self.period_start = Instant::now();
        self.last_stats = Instant::now();
    }

    fn finalize(&mut self) -> AppStats {
        self.flush_batch();
        // Final stats snapshot — parse_rate is 0 (stream ended)
        let snapshot = self.snapshot(0.0);
        self.sink.stats(&snapshot);
        snapshot
    }
}

// ── Reading ───────────────────────────────────────────────────────────────────

fn is_gzip(path: &Path) -> Result<bool, String> {
    let mut magic = [0u8; 2];
    let mut f = File::open(path).map_err(|e| format!("Cannot open '{}': {e}", path.display()))?;
    let n = f
        .read(&mut magic)
        .map_err(|e| format!("Cannot read '{}': {e}", path.display()))?;
    Ok(n == 2 && magic == GZIP_MAGIC)
}

/// Opens a log for sequential reading, transparently decompressing gzip (by content,
/// not extension).
fn open_log(path: &Path) -> Result<Box<dyn BufRead + Send>, String> {
    let gz = is_gzip(path)?;
    let file = File::open(path).map_err(|e| format!("Cannot open '{}': {e}", path.display()))?;
    Ok(if gz {
        Box::new(BufReader::new(MultiGzDecoder::new(file)))
    } else {
        Box::new(BufReader::new(file))
    })
}

/// Reads one line, tolerating invalid UTF-8 (replaced with U+FFFD) so a single bad
/// byte can't abort a whole file. Returns Ok(None) at EOF.
fn read_line_lossy(reader: &mut dyn BufRead, buf: &mut Vec<u8>) -> std::io::Result<Option<String>> {
    buf.clear();
    if reader.read_until(b'\n', buf)? == 0 {
        return Ok(None);
    }
    Ok(Some(String::from_utf8_lossy(buf).trim_end().to_string()))
}

fn sample_format(reader: &mut dyn BufRead) -> LogFormat {
    let mut samples = Vec::new();
    let mut buf = Vec::new();
    while samples.len() < 20 {
        match read_line_lossy(reader, &mut buf) {
            Ok(Some(line)) if line.trim().is_empty() => continue,
            Ok(Some(line)) => samples.push(line.trim().to_string()),
            _ => break,
        }
    }
    let refs: Vec<&str> = samples.iter().map(String::as_str).collect();
    detect_format(&refs)
}

// ── Public API ────────────────────────────────────────────────────────────────

/// Read and parse a whole file (plain or gzip) from start to finish.
/// Emits batched events as it goes. Returns final AppStats.
pub fn process_file<S: EventSink>(
    path: &str,
    format: Option<LogFormat>,
    settings: &DetectionSettings,
    stores: Stores,
    sink: S,
) -> Result<AppStats, String> {
    let path = Path::new(path);
    let detected_format = match format {
        Some(f) => f,
        None => sample_format(&mut *open_log(path)?),
    };

    let mut reader = open_log(path)?;
    let mut proc = LineProcessor::new(
        build_chain(&detected_format),
        FILE_BATCH_SIZE,
        settings,
        stores,
        sink,
    );

    let mut buf = Vec::new();
    loop {
        match read_line_lossy(&mut *reader, &mut buf) {
            Ok(Some(line)) => proc.process_line(&line),
            Ok(None) => break,
            Err(e) => {
                // Keep what was parsed (e.g. a truncated .gz) and report the failure
                let stats = proc.finalize();
                return Err(format!(
                    "Read error after {} lines of '{}': {e}",
                    stats.total_lines,
                    path.display()
                ));
            }
        }
        proc.maybe_emit_stats();
    }

    Ok(proc.finalize())
}

/// Fails fast if `path` can't be opened for Open File, before any state is reset.
pub fn check_readable(path: &str) -> Result<(), String> {
    open_log(Path::new(path)).map(|_| ())
}

/// A live watch whose setup succeeded (file opened, format detected, OS watcher running)
/// but which hasn't started processing yet. Splitting setup from `spawn` lets callers
/// leave existing state untouched when setup fails.
pub struct PreparedWatch {
    path_buf: PathBuf,
    reader: BufReader<File>,
    pos: u64,
    chain: ParserChain,
    debouncer: Debouncer<RecommendedWatcher>,
    event_rx: mpsc::Receiver<DebounceEventResult>,
}

/// Tail a live log file on a dedicated OS thread. See [`prepare_watch`] and
/// [`PreparedWatch::spawn`]; this is both in one step.
pub fn start_watching<S: EventSink>(
    path: String,
    format: Option<LogFormat>,
    settings: &DetectionSettings,
    stores: Stores,
    sink: S,
) -> Result<WatcherHandle, String> {
    Ok(prepare_watch(path, format)?.spawn(settings, stores, sink))
}

/// Opens the file, detects its format and starts the OS watcher. Setup failures are
/// returned here; nothing has been processed yet.
pub fn prepare_watch(path: String, format: Option<LogFormat>) -> Result<PreparedWatch, String> {
    let path_buf = PathBuf::from(&path);
    if is_gzip(&path_buf)? {
        return Err("Compressed (.gz) logs can't be watched live. Use Open File instead.".into());
    }

    let file = File::open(&path_buf).map_err(|e| format!("Cannot open '{path}': {e}"))?;
    let mut reader = BufReader::new(file);
    let detected_format = match format {
        Some(f) => f,
        None => sample_format(&mut reader),
    };
    // Tail from the current end
    let pos = reader
        .seek(SeekFrom::End(0))
        .map_err(|e| format!("Seek failed: {e}"))?;

    let (event_tx, event_rx) = mpsc::channel();
    let mut debouncer = new_debouncer(Duration::from_millis(200), move |res| {
        let _ = event_tx.send(res);
    })
    .map_err(|e| format!("Cannot start file watcher: {e}"))?;
    debouncer
        .watcher()
        .watch(&path_buf, RecursiveMode::NonRecursive)
        .map_err(|e| format!("Cannot watch '{path}': {e}"))?;

    Ok(PreparedWatch {
        path_buf,
        reader,
        pos,
        chain: build_chain(&detected_format),
        debouncer,
        event_rx,
    })
}

impl PreparedWatch {
    /// Starts processing appended lines on a dedicated OS thread. Later failures are
    /// reported through `sink.error`.
    pub fn spawn<S: EventSink>(
        self,
        settings: &DetectionSettings,
        stores: Stores,
        sink: S,
    ) -> WatcherHandle {
        let PreparedWatch {
            path_buf,
            mut reader,
            mut pos,
            chain,
            debouncer,
            event_rx,
        } = self;
        let settings = settings.clone();
        let (stop_tx, stop_rx) = mpsc::channel::<()>();

        std::thread::spawn(move || {
            let _debouncer = debouncer; // keep the OS watcher alive for the thread's lifetime
            let mut proc = LineProcessor::new(chain, BATCH_SIZE, &settings, stores, sink);
            // Bytes of a line still being written (no trailing newline yet)
            let mut pending: Vec<u8> = Vec::new();
            let mut buf = Vec::new();

            loop {
                if stop_rx.try_recv().is_ok() {
                    break;
                }

                match event_rx.recv_timeout(EMIT_INTERVAL) {
                    Ok(_) => {
                        // Truncated (copytruncate) or replaced (rotation): restart from the top
                        let len = std::fs::metadata(&path_buf).map(|m| m.len()).unwrap_or(pos);
                        if len < pos {
                            match File::open(&path_buf) {
                                Ok(f) => {
                                    reader = BufReader::new(f);
                                    pos = 0;
                                    pending.clear();
                                    log::info!("[watcher] '{}' was truncated or rotated; reading from the start", path_buf.display());
                                }
                                Err(e) => {
                                    proc.sink.error(&format!(
                                        "Lost access to '{}': {e}",
                                        path_buf.display()
                                    ));
                                    break;
                                }
                            }
                        }

                        loop {
                            buf.clear();
                            match reader.read_until(b'\n', &mut buf) {
                                Ok(0) => break,
                                Ok(n) => {
                                    pos += n as u64;
                                    pending.extend_from_slice(&buf);
                                    if pending.last() == Some(&b'\n') {
                                        let line = String::from_utf8_lossy(&pending)
                                            .trim_end()
                                            .to_string();
                                        pending.clear();
                                        proc.process_line(&line);
                                    }
                                }
                                Err(e) => {
                                    proc.sink.error(&format!(
                                        "Error reading '{}': {e}",
                                        path_buf.display()
                                    ));
                                    break;
                                }
                            }
                        }
                    }
                    Err(mpsc::RecvTimeoutError::Timeout) => {}
                    Err(mpsc::RecvTimeoutError::Disconnected) => {
                        proc.sink.error(&format!(
                            "File watcher for '{}' stopped unexpectedly",
                            path_buf.display()
                        ));
                        break;
                    }
                }

                proc.flush_batch();
                proc.maybe_emit_stats();
            }

            proc.finalize();
        });

        WatcherHandle { stop_tx }
    }
}

#[cfg(test)]
mod tests {
    use std::io::Write;

    use super::*;
    use crate::events::test_sink::RecordingSink;

    fn stores() -> Stores {
        Stores {
            ring: Arc::new(RwLock::new(RingBuffer::default())),
            anomalies: Arc::new(RwLock::new(Vec::new())),
            stats: Arc::new(RwLock::new(AppStats::default())),
        }
    }

    fn temp_path(name: &str) -> PathBuf {
        std::env::temp_dir().join(format!("ht-{}-{name}", std::process::id()))
    }

    fn apache(ip: &str, path: &str, status: u16) -> String {
        format!(
            r#"{ip} - - [01/May/2026:10:00:00 +0000] "GET {path} HTTP/1.1" {status} 100 "-" "test""#
        )
    }

    fn sample_log() -> String {
        let mut s = String::new();
        for i in 0..30 {
            s += &apache(&format!("203.0.113.{}", i % 5), "/index.html", 200);
            s.push('\n');
        }
        s += &apache("198.51.100.7", "/../../etc/passwd", 403);
        s.push('\n');
        s
    }

    #[test]
    fn processes_plain_file() {
        let path = temp_path("plain.log");
        std::fs::write(&path, sample_log()).unwrap();
        let sink = RecordingSink::default();
        let st = stores();

        let stats = process_file(
            path.to_str().unwrap(),
            None,
            &DetectionSettings::default(),
            st.clone(),
            sink.clone(),
        )
        .unwrap();

        assert_eq!(stats.total_lines, 31);
        assert_eq!(stats.anomaly_count, 1);
        assert_eq!(sink.entries().len(), 31);
        assert_eq!(sink.anomalies().len(), 1);
        assert_eq!(st.anomalies.read().len(), 1);
        assert_eq!(st.ring.read().len(), 31);
        let _ = std::fs::remove_file(path);
    }

    #[test]
    fn processes_gzip_file_by_content() {
        // Named .log on purpose: detection is by magic bytes, not extension
        let path = temp_path("compressed.log");
        let mut enc = flate2::write::GzEncoder::new(
            File::create(&path).unwrap(),
            flate2::Compression::default(),
        );
        enc.write_all(sample_log().as_bytes()).unwrap();
        enc.finish().unwrap();

        let sink = RecordingSink::default();
        let stats = process_file(
            path.to_str().unwrap(),
            None,
            &DetectionSettings::default(),
            stores(),
            sink,
        )
        .unwrap();
        assert_eq!(stats.total_lines, 31);
        assert_eq!(stats.anomaly_count, 1);
        let _ = std::fs::remove_file(path);
    }

    #[test]
    fn invalid_utf8_does_not_abort() {
        let path = temp_path("binary.log");
        let mut bytes = sample_log().into_bytes();
        bytes.extend_from_slice(b"\xff\xfe garbage \xc3\x28\n");
        bytes.extend_from_slice(apache("203.0.113.1", "/after", 200).as_bytes());
        bytes.push(b'\n');
        std::fs::write(&path, bytes).unwrap();

        let sink = RecordingSink::default();
        let stats = process_file(
            path.to_str().unwrap(),
            None,
            &DetectionSettings::default(),
            stores(),
            sink.clone(),
        )
        .unwrap();
        assert_eq!(stats.total_lines, 33, "bad line counted, parsing continued");
        assert!(sink
            .entries()
            .iter()
            .any(|e| e.path.as_deref() == Some("/after")));
        let _ = std::fs::remove_file(path);
    }

    #[test]
    fn missing_file_is_an_error() {
        let err = process_file(
            "Z:/definitely/missing.log",
            None,
            &DetectionSettings::default(),
            stores(),
            RecordingSink::default(),
        )
        .unwrap_err();
        assert!(err.contains("Cannot open"), "{err}");
    }

    #[test]
    fn anomaly_store_and_ip_counts_are_capped() {
        let sink = RecordingSink::default();
        let st = stores();
        let mut proc = LineProcessor::new(
            build_chain(&LogFormat::Apache),
            50,
            &DetectionSettings::default(),
            st.clone(),
            sink,
        );
        proc.max_anomalies = 100;
        proc.max_ips = 1_000;
        for i in 0..5_000u32 {
            let ip = format!("10.{}.{}.{}", i / 65536, (i / 256) % 256, i % 256);
            proc.process_line(&apache(&ip, "/../etc/passwd", 403));
        }
        let stored = st.anomalies.read().len();
        assert!(stored <= 110, "stored {stored}");
        assert_eq!(
            st.anomalies.read().last().unwrap().entry_id,
            5_000,
            "newest anomalies kept"
        );
        assert!(proc.ip_counts.len() <= 1_000);
        assert_eq!(proc.anomaly_count, 5_000, "totals still count everything");
    }

    #[test]
    fn allowlist_applies_to_file_loads() {
        let path = temp_path("allow.log");
        std::fs::write(&path, sample_log()).unwrap();
        let settings = DetectionSettings {
            allowlist: vec!["198.51.100.0/24".into()],
            ..Default::default()
        };
        let stats = process_file(
            path.to_str().unwrap(),
            None,
            &settings,
            stores(),
            RecordingSink::default(),
        )
        .unwrap();
        assert_eq!(stats.anomaly_count, 0);
        let _ = std::fs::remove_file(path);
    }

    /// Polls until `cond` holds or the timeout passes.
    fn wait_for(timeout: Duration, mut cond: impl FnMut() -> bool) -> bool {
        let start = Instant::now();
        while start.elapsed() < timeout {
            if cond() {
                return true;
            }
            std::thread::sleep(Duration::from_millis(50));
        }
        cond()
    }

    #[test]
    fn watch_tails_new_lines_holds_partial_lines_and_handles_truncation() {
        let path = temp_path("live.log");
        std::fs::write(&path, sample_log()).unwrap();
        let sink = RecordingSink::default();
        let handle = start_watching(
            path.to_str().unwrap().into(),
            None,
            &DetectionSettings::default(),
            stores(),
            sink.clone(),
        )
        .unwrap();

        // Existing content is skipped; only appended lines are processed
        let mut f = std::fs::OpenOptions::new()
            .append(true)
            .open(&path)
            .unwrap();
        writeln!(f, "{}", apache("192.0.2.1", "/new-1", 200)).unwrap();
        // Half a line, completed later: must arrive as one entry
        let partial = apache("192.0.2.2", "/split-line", 200);
        let (head, tail) = partial.split_at(20);
        write!(f, "{head}").unwrap();
        f.flush().unwrap();
        std::thread::sleep(Duration::from_millis(600));
        writeln!(f, "{tail}").unwrap();
        f.flush().unwrap();
        drop(f);

        let paths = || {
            sink.entries()
                .iter()
                .filter_map(|e| e.path.clone())
                .collect::<Vec<_>>()
        };
        assert!(
            wait_for(Duration::from_secs(10), || paths().len() >= 2),
            "got {:?}",
            paths()
        );
        assert_eq!(
            paths(),
            vec!["/new-1".to_string(), "/split-line".to_string()]
        );

        // Truncate and write fresh content: tailing restarts from the top
        std::fs::write(
            &path,
            format!("{}\n", apache("192.0.2.3", "/after-truncate", 200)),
        )
        .unwrap();
        assert!(
            wait_for(Duration::from_secs(10), || paths()
                .contains(&"/after-truncate".to_string())),
            "got {:?}",
            paths()
        );

        handle.stop_tx.send(()).unwrap();
        assert!(sink.errors().is_empty(), "{:?}", sink.errors());
        let _ = std::fs::remove_file(path);
    }

    #[test]
    fn watch_rejects_gzip_and_missing_files() {
        let path = temp_path("live.gz");
        let mut enc = flate2::write::GzEncoder::new(
            File::create(&path).unwrap(),
            flate2::Compression::default(),
        );
        enc.write_all(b"x\n").unwrap();
        enc.finish().unwrap();
        let err = start_watching(
            path.to_str().unwrap().into(),
            None,
            &DetectionSettings::default(),
            stores(),
            RecordingSink::default(),
        )
        .err()
        .unwrap();
        assert!(err.contains("can't be watched"), "{err}");
        let err = start_watching(
            "Z:/missing.log".into(),
            None,
            &DetectionSettings::default(),
            stores(),
            RecordingSink::default(),
        )
        .err()
        .unwrap();
        assert!(err.contains("Cannot open"), "{err}");
        let _ = std::fs::remove_file(path);
    }
}
