use std::sync::{Arc, Mutex};
use parking_lot::RwLock;

use crate::{
    detector::types::Anomaly,
    parser::types::LogFormat,
    ring_buffer::RingBuffer,
    scorer::AppStats,
};

pub struct WatcherHandle {
    pub stop_tx: std::sync::mpsc::Sender<()>,
}

pub struct AppState {
    pub ring_buffer: Arc<RwLock<RingBuffer>>,
    pub stats: Arc<RwLock<AppStats>>,
    pub anomalies: Arc<RwLock<Vec<Anomaly>>>,
    pub watcher: Arc<Mutex<Option<WatcherHandle>>>,
    pub current_format: Arc<Mutex<LogFormat>>,
}

impl Default for AppState {
    fn default() -> Self {
        Self {
            ring_buffer: Arc::new(RwLock::new(RingBuffer::default())),
            stats: Arc::new(RwLock::new(AppStats::default())),
            anomalies: Arc::new(RwLock::new(Vec::new())),
            watcher: Arc::new(Mutex::new(None)),
            current_format: Arc::new(Mutex::new(LogFormat::Apache)),
        }
    }
}
