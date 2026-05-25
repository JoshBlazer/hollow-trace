use std::collections::HashMap;
use std::fs::File;
use std::io::{BufRead, BufReader, Seek, SeekFrom};
use std::path::PathBuf;
use std::sync::{mpsc, Arc};
use std::time::{Duration, Instant};

use notify::RecursiveMode;
use notify_debouncer_mini::new_debouncer;
use parking_lot::RwLock;
use tauri::AppHandle;

use crate::{
    detector::{
        types::{Anomaly, Severity},
        AnomalyDetector,
    },
    events::{emit_batch, emit_stats, LogBatch, BATCH_SIZE, EMIT_INTERVAL_MS, STATS_INTERVAL_MS},
    parser::{build_chain, detect_format, types::LogFormat, ParserChain},
    ring_buffer::RingBuffer,
    scorer::{calculate_threat_score, AppStats, IpCount, SeverityCounts},
    state::WatcherHandle,
};

const EMIT_INTERVAL: Duration = Duration::from_millis(EMIT_INTERVAL_MS);
const STATS_INTERVAL: Duration = Duration::from_millis(STATS_INTERVAL_MS);

// ── LineProcessor ─────────────────────────────────────────────────────────────
// Holds all mutable state for one parsing session (static or live).
// Runs on a single thread; no locking inside this struct.

struct LineProcessor {
    chain: ParserChain,
    detector: AnomalyDetector,
    line_counter: u64,
    batch: LogBatch,
    last_emit: Instant,
    last_stats: Instant,
    ip_counts: HashMap<String, u64>,
    severity_counts: SeverityCounts,
    anomaly_count: u64,
    lines_in_period: u64,
    period_start: Instant,
    ring: Arc<RwLock<RingBuffer>>,
    anomalies_store: Arc<RwLock<Vec<Anomaly>>>,
    stats_store: Arc<RwLock<AppStats>>,
    app: AppHandle,
}

impl LineProcessor {
    fn new(
        chain: ParserChain,
        ring: Arc<RwLock<RingBuffer>>,
        anomalies_store: Arc<RwLock<Vec<Anomaly>>>,
        stats_store: Arc<RwLock<AppStats>>,
        app: AppHandle,
    ) -> Self {
        let now = Instant::now();
        Self {
            chain,
            detector: AnomalyDetector::new(0),
            line_counter: 0,
            batch: LogBatch::default(),
            last_emit: now,
            last_stats: now,
            ip_counts: HashMap::new(),
            severity_counts: SeverityCounts::default(),
            anomaly_count: 0,
            lines_in_period: 0,
            period_start: now,
            ring,
            anomalies_store,
            stats_store,
            app,
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

        if !anomalies.is_empty() {
            entry.is_anomaly = true;
            entry.anomaly_id = Some(anomalies[0].id);
            self.anomaly_count += anomalies.len() as u64;

            for a in &anomalies {
                match a.severity {
                    Severity::Low => self.severity_counts.low += 1,
                    Severity::Medium => self.severity_counts.medium += 1,
                    Severity::High => self.severity_counts.high += 1,
                    Severity::Critical => self.severity_counts.critical += 1,
                }
            }
            self.anomalies_store.write().extend(anomalies.iter().cloned());
        }

        if let Some(ip) = &entry.ip {
            *self.ip_counts.entry(ip.clone()).or_insert(0) += 1;
        }

        self.ring.write().push(entry.clone());
        self.batch.anomalies.extend(anomalies);
        self.batch.entries.push(entry);

        if self.batch.entries.len() >= BATCH_SIZE || self.last_emit.elapsed() >= EMIT_INTERVAL {
            self.flush_batch();
        }
    }

    fn flush_batch(&mut self) {
        if self.batch.entries.is_empty() {
            return;
        }
        emit_batch(&self.app, std::mem::take(&mut self.batch));
        self.last_emit = Instant::now();
    }

    fn maybe_emit_stats(&mut self) {
        if self.last_stats.elapsed() >= STATS_INTERVAL {
            self.push_stats();
        }
    }

    fn push_stats(&mut self) {
        let elapsed = self.period_start.elapsed().as_secs_f64().max(0.001);
        let parse_rate = self.lines_in_period as f64 / elapsed;

        let mut top_ips: Vec<IpCount> = self
            .ip_counts
            .iter()
            .map(|(ip, &count)| IpCount { ip: ip.clone(), count })
            .collect();
        top_ips.sort_unstable_by(|a, b| b.count.cmp(&a.count));
        top_ips.truncate(5);

        let snapshot = {
            let mut g = self.stats_store.write();
            g.total_lines = self.line_counter;
            g.anomaly_count = self.anomaly_count;
            g.parse_rate = parse_rate;
            g.top_ips = top_ips;
            g.severity_counts = self.severity_counts.clone();
            g.threat_score = calculate_threat_score(&g);
            g.clone()
        };

        emit_stats(&self.app, &snapshot);

        self.lines_in_period = 0;
        self.period_start = Instant::now();
        self.last_stats = Instant::now();
    }

    fn finalize(&mut self) -> AppStats {
        self.flush_batch();

        // Final stats snapshot — parse_rate is 0 (stream ended)
        let mut top_ips: Vec<IpCount> = self
            .ip_counts
            .iter()
            .map(|(ip, &count)| IpCount { ip: ip.clone(), count })
            .collect();
        top_ips.sort_unstable_by(|a, b| b.count.cmp(&a.count));
        top_ips.truncate(5);

        let snapshot = {
            let mut g = self.stats_store.write();
            g.total_lines = self.line_counter;
            g.anomaly_count = self.anomaly_count;
            g.parse_rate = 0.0;
            g.top_ips = top_ips;
            g.severity_counts = self.severity_counts.clone();
            g.threat_score = calculate_threat_score(&g);
            g.clone()
        };

        emit_stats(&self.app, &snapshot);
        snapshot
    }
}

// ── Public API ────────────────────────────────────────────────────────────────

/// Read and parse a static file from start to finish.
/// Emits batched events to the frontend as it goes. Returns final AppStats.
pub fn process_file(
    path: &str,
    format: Option<LogFormat>,
    app: &AppHandle,
    ring: Arc<RwLock<RingBuffer>>,
    anomalies_store: Arc<RwLock<Vec<Anomaly>>>,
    stats_store: Arc<RwLock<AppStats>>,
) -> Result<AppStats, String> {
    let file = File::open(path).map_err(|e| format!("Cannot open '{}': {e}", path))?;
    let mut reader = BufReader::new(file);

    let detected_format = if let Some(f) = format {
        f
    } else {
        let mut samples = Vec::new();
        let mut line = String::new();
        for _ in 0..20 {
            line.clear();
            if reader.read_line(&mut line).unwrap_or(0) == 0 {
                break;
            }
            samples.push(line.trim().to_string());
        }
        let refs: Vec<&str> = samples.iter().map(String::as_str).collect();
        let fmt = detect_format(&refs);
        reader
            .seek(SeekFrom::Start(0))
            .map_err(|e| format!("Seek failed: {e}"))?;
        fmt
    };

    let chain = build_chain(&detected_format);
    let mut proc = LineProcessor::new(chain, ring, anomalies_store, stats_store, app.clone());

    let mut line = String::new();
    loop {
        line.clear();
        match reader.read_line(&mut line) {
            Ok(0) => break,
            Ok(_) => proc.process_line(line.trim_end()),
            Err(e) => return Err(format!("Read error: {e}")),
        }
        proc.maybe_emit_stats();
    }

    Ok(proc.finalize())
}

/// Spawn a dedicated OS thread to tail a live log file.
/// New lines are parsed and emitted in real time. Returns a handle to stop it.
pub fn start_watching(
    path: String,
    format: Option<LogFormat>,
    app: AppHandle,
    ring: Arc<RwLock<RingBuffer>>,
    anomalies_store: Arc<RwLock<Vec<Anomaly>>>,
    stats_store: Arc<RwLock<AppStats>>,
) -> Result<WatcherHandle, String> {
    let (stop_tx, stop_rx) = mpsc::channel::<()>();

    std::thread::spawn(move || {
        let path_buf = PathBuf::from(&path);

        let file = match File::open(&path_buf) {
            Ok(f) => f,
            Err(e) => {
                eprintln!("[watcher] Cannot open '{}': {e}", path);
                return;
            }
        };

        let mut reader = BufReader::new(file);

        // Sample first 20 lines for format detection, then tail from EOF
        let detected_format = format.unwrap_or_else(|| {
            let mut samples = Vec::new();
            let mut line = String::new();
            for _ in 0..20 {
                line.clear();
                if reader.read_line(&mut line).unwrap_or(0) == 0 {
                    break;
                }
                samples.push(line.trim().to_string());
            }
            let refs: Vec<&str> = samples.iter().map(String::as_str).collect();
            detect_format(&refs)
        });

        if let Err(e) = reader.seek(SeekFrom::End(0)) {
            eprintln!("[watcher] Seek to end failed: {e}");
            return;
        }

        let chain = build_chain(&detected_format);

        let (event_tx, event_rx) = mpsc::channel();
        let mut debouncer = match new_debouncer(Duration::from_millis(200), move |res| {
            let _ = event_tx.send(res);
        }) {
            Ok(d) => d,
            Err(e) => {
                eprintln!("[watcher] Debouncer init failed: {e}");
                return;
            }
        };

        if let Err(e) = debouncer.watcher().watch(&path_buf, RecursiveMode::NonRecursive) {
            eprintln!("[watcher] Watch failed: {e}");
            return;
        }

        let mut proc = LineProcessor::new(chain, ring, anomalies_store, stats_store, app);

        loop {
            if stop_rx.try_recv().is_ok() {
                break;
            }

            match event_rx.recv_timeout(EMIT_INTERVAL) {
                Ok(_) => {
                    // Read all new lines since the last known position
                    let mut line = String::new();
                    loop {
                        line.clear();
                        match reader.read_line(&mut line) {
                            Ok(0) => break,
                            Ok(_) => proc.process_line(line.trim_end()),
                            Err(e) => {
                                eprintln!("[watcher] Read error: {e}");
                                break;
                            }
                        }
                    }
                }
                Err(mpsc::RecvTimeoutError::Timeout) => {}
                Err(mpsc::RecvTimeoutError::Disconnected) => break,
            }

            proc.flush_batch();
            proc.maybe_emit_stats();
        }

        proc.finalize();
    });

    Ok(WatcherHandle { stop_tx })
}
