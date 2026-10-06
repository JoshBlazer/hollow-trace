use std::sync::{Arc, Mutex};
use parking_lot::RwLock;

use crate::{
    detector::types::Anomaly,
    parser::types::LogFormat,
    ring_buffer::RingBuffer,
    scorer::AppStats,
    settings::DetectionSettings,
    watcher::Stores,
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
    pub settings: Arc<RwLock<DetectionSettings>>,
}

impl AppState {
    pub fn with_settings(settings: DetectionSettings) -> Self {
        Self {
            settings: Arc::new(RwLock::new(settings)),
            ..Self::default()
        }
    }

    /// The shared stores a parsing session writes into.
    pub fn stores(&self) -> Stores {
        Stores {
            ring: Arc::clone(&self.ring_buffer),
            anomalies: Arc::clone(&self.anomalies),
            stats: Arc::clone(&self.stats),
        }
    }
}

impl Default for AppState {
    fn default() -> Self {
        Self {
            ring_buffer: Arc::new(RwLock::new(RingBuffer::default())),
            stats: Arc::new(RwLock::new(AppStats::default())),
            anomalies: Arc::new(RwLock::new(Vec::new())),
            watcher: Arc::new(Mutex::new(None)),
            current_format: Arc::new(Mutex::new(LogFormat::Apache)),
            settings: Arc::new(RwLock::new(DetectionSettings::default())),
        }
    }
}
