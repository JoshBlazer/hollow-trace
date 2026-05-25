use std::sync::Arc;

use tauri::AppHandle;

use crate::{
    detector::types::{Anomaly, Severity},
    parser::types::LogFormat,
    scorer::AppStats,
    state::{AppState, WatcherHandle},
};

// ── Helpers ───────────────────────────────────────────────────────────────────

fn stop_watcher(watcher: &Arc<std::sync::Mutex<Option<WatcherHandle>>>) {
    if let Ok(mut guard) = watcher.lock() {
        if let Some(handle) = guard.take() {
            let _ = handle.stop_tx.send(());
        }
    }
}

fn reset_state(state: &AppState) {
    state.ring_buffer.write().clear();
    state.anomalies.write().clear();
    *state.stats.write() = AppStats::default();
}

fn filter_anomalies(all: &[Anomaly], severity_filter: Option<&str>) -> Vec<Anomaly> {
    match severity_filter {
        Some("low") => all.iter().filter(|a| a.severity == Severity::Low).cloned().collect(),
        Some("medium") => all.iter().filter(|a| a.severity == Severity::Medium).cloned().collect(),
        Some("high") => all.iter().filter(|a| a.severity == Severity::High).cloned().collect(),
        Some("critical") => all.iter().filter(|a| a.severity == Severity::Critical).cloned().collect(),
        _ => all.to_vec(),
    }
}

// ── Commands ──────────────────────────────────────────────────────────────────

/// Open a static log file, parse it fully, return final stats.
/// Runs on a blocking thread so the async runtime stays free.
#[tauri::command]
pub async fn open_file(
    path: String,
    format: Option<LogFormat>,
    state: tauri::State<'_, AppState>,
    app: AppHandle,
) -> Result<AppStats, String> {
    stop_watcher(&state.watcher);
    reset_state(&state);

    let ring = Arc::clone(&state.ring_buffer);
    let anomalies_store = Arc::clone(&state.anomalies);
    let stats_store = Arc::clone(&state.stats);

    tauri::async_runtime::spawn_blocking(move || {
        crate::watcher::process_file(&path, format, &app, ring, anomalies_store, stats_store)
    })
    .await
    .map_err(|e| format!("Spawn error: {e}"))?
}

/// Start tailing a live log file. Returns immediately; parsing runs in background.
#[tauri::command]
pub fn start_watching(
    path: String,
    format: Option<LogFormat>,
    state: tauri::State<'_, AppState>,
    app: AppHandle,
) -> Result<(), String> {
    stop_watcher(&state.watcher);
    reset_state(&state);

    let ring = Arc::clone(&state.ring_buffer);
    let anomalies_store = Arc::clone(&state.anomalies);
    let stats_store = Arc::clone(&state.stats);

    let handle =
        crate::watcher::start_watching(path, format, app, ring, anomalies_store, stats_store)?;

    *state.watcher.lock().map_err(|e| format!("Lock error: {e}"))? = Some(handle);
    Ok(())
}

/// Stop the live watcher if one is running.
#[tauri::command]
pub fn stop_watching(state: tauri::State<'_, AppState>) -> Result<(), String> {
    stop_watcher(&state.watcher);
    Ok(())
}

/// Return a snapshot of current stats.
#[tauri::command]
pub fn get_stats(state: tauri::State<'_, AppState>) -> Result<AppStats, String> {
    Ok(state.stats.read().clone())
}

/// Return all anomalies, optionally filtered by severity string ("low"|"medium"|"high"|"critical").
#[tauri::command]
pub fn get_anomalies(
    severity_filter: Option<String>,
    state: tauri::State<'_, AppState>,
) -> Result<Vec<Anomaly>, String> {
    let guard = state.anomalies.read();
    Ok(filter_anomalies(&guard, severity_filter.as_deref()))
}

/// Write anomalies (optionally filtered) to a JSON file at output_path.
#[tauri::command]
pub async fn export_anomalies(
    output_path: String,
    severity_filter: Option<String>,
    state: tauri::State<'_, AppState>,
) -> Result<(), String> {
    let anomalies_store = Arc::clone(&state.anomalies);

    tauri::async_runtime::spawn_blocking(move || {
        let guard = anomalies_store.read();
        let filtered = filter_anomalies(&guard, severity_filter.as_deref());
        drop(guard);

        let json =
            serde_json::to_string_pretty(&filtered).map_err(|e| format!("Serialize error: {e}"))?;

        std::fs::write(&output_path, json).map_err(|e| format!("Write error: {e}"))?;
        Ok(())
    })
    .await
    .map_err(|e| format!("Spawn error: {e}"))?
}

/// Clear the ring buffer, anomaly list, and stats — reset to initial state.
#[tauri::command]
pub fn clear_stream(state: tauri::State<'_, AppState>) -> Result<(), String> {
    stop_watcher(&state.watcher);
    reset_state(&state);
    Ok(())
}
