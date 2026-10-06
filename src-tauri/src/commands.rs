use std::path::Path;
use std::sync::Arc;

use tauri::{AppHandle, Emitter, Manager};

use crate::{
    detector::types::{Anomaly, Severity},
    parser::types::LogFormat,
    query::{EntryFilter, EntryQueryResult},
    report::{AnomalyGroup, GroupBy, ReportInput},
    scorer::AppStats,
    settings::DetectionSettings,
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

/// Clears backend state and tells the frontend to drop what it's showing.
fn reset_state(state: &AppState, app: &AppHandle, source: Option<String>) {
    *state.source.write() = source;
    state.ring_buffer.write().clear();
    state.anomalies.write().clear();
    *state.stats.write() = AppStats::default();
    let _ = app.emit(crate::events::STREAM_RESET_EVENT, ());
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

/// Writes anomalies (optionally filtered by severity) to `output_path`: CSV if the path
/// ends in `.csv`, otherwise pretty JSON. Returns how many were written.
pub fn write_anomalies(all: &[Anomaly], severity_filter: Option<&str>, output_path: &Path) -> Result<usize, String> {
    let filtered = filter_anomalies(all, severity_filter);
    let is_csv = output_path
        .extension()
        .is_some_and(|e| e.eq_ignore_ascii_case("csv"));
    let body = if is_csv {
        crate::report::anomalies_csv(&filtered)
    } else {
        serde_json::to_string_pretty(&filtered).map_err(|e| format!("Serialize error: {e}"))?
    };
    std::fs::write(output_path, body)
        .map_err(|e| format!("Cannot write '{}': {e}", output_path.display()))?;
    Ok(filtered.len())
}

fn config_dir(app: &AppHandle) -> Result<std::path::PathBuf, String> {
    app.path().app_config_dir().map_err(|e| format!("Cannot locate config folder: {e}"))
}

// ── Commands ──────────────────────────────────────────────────────────────────

/// Open a static log file (plain or gzip), parse it fully, return final stats.
/// Runs on a blocking thread so the async runtime stays free.
#[tauri::command]
pub async fn open_file(
    path: String,
    format: Option<LogFormat>,
    state: tauri::State<'_, AppState>,
    app: AppHandle,
) -> Result<AppStats, String> {
    // Fail before touching anything, so a bad pick keeps the current view
    crate::watcher::check_readable(&path)?;
    stop_watcher(&state.watcher);
    reset_state(&state, &app, Some(path.clone()));

    let stores = state.stores();
    let settings = state.settings.read().clone();

    // Errors are returned to the UI, which logs them; successes are logged here
    let stats = tauri::async_runtime::spawn_blocking(move || {
        let stats = crate::watcher::process_file(&path, format, &settings, stores, app)?;
        log::info!("Opened '{path}': {} lines, {} anomalies", stats.total_lines, stats.anomaly_count);
        Ok::<_, String>(stats)
    })
    .await
    .map_err(|e| format!("Spawn error: {e}"))??;
    Ok(stats)
}

/// Start tailing a live log file. Setup errors (missing file, gzip, watcher failure)
/// are returned; parsing then runs in the background.
#[tauri::command]
pub fn start_watching(
    path: String,
    format: Option<LogFormat>,
    state: tauri::State<'_, AppState>,
    app: AppHandle,
) -> Result<(), String> {
    // All setup (open, gzip check, OS watcher) first: a failure keeps the current view
    let prepared = crate::watcher::prepare_watch(path.clone(), format)?;
    stop_watcher(&state.watcher);
    reset_state(&state, &app, Some(path.clone()));

    let settings = state.settings.read().clone();
    let handle = prepared.spawn(&settings, state.stores(), app);
    log::info!("Watching '{path}'");

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

/// Write anomalies (optionally filtered) to a JSON file at output_path. Returns the count written.
#[tauri::command]
pub async fn export_anomalies(
    output_path: String,
    severity_filter: Option<String>,
    state: tauri::State<'_, AppState>,
) -> Result<usize, String> {
    let anomalies_store = Arc::clone(&state.anomalies);

    tauri::async_runtime::spawn_blocking(move || {
        let snapshot = anomalies_store.read().clone();
        write_anomalies(&snapshot, severity_filter.as_deref(), Path::new(&output_path))
    })
    .await
    .map_err(|e| format!("Spawn error: {e}"))?
}

/// Clear the ring buffer, anomaly list, and stats — reset to initial state.
#[tauri::command]
pub fn clear_stream(state: tauri::State<'_, AppState>, app: AppHandle) -> Result<(), String> {
    stop_watcher(&state.watcher);
    reset_state(&state, &app, None);
    Ok(())
}

/// Current detection settings.
#[tauri::command]
pub fn get_settings(state: tauri::State<'_, AppState>) -> Result<DetectionSettings, String> {
    Ok(state.settings.read().clone())
}

/// Validate, persist and apply detection settings. They take effect on the next
/// Open File / Watch File.
#[tauri::command]
pub fn save_settings(
    settings: DetectionSettings,
    state: tauri::State<'_, AppState>,
    app: AppHandle,
) -> Result<(), String> {
    settings.save(&config_dir(&app)?)?;
    *state.settings.write() = settings;
    Ok(())
}

/// Search the backend buffer (up to 100k lines), or fetch context around a line.
#[tauri::command]
pub fn query_entries(filter: EntryFilter, state: tauri::State<'_, AppState>) -> Result<EntryQueryResult, String> {
    let ring = state.ring_buffer.read();
    Ok(crate::query::query(ring.iter(), &filter))
}

/// Anomalies grouped by source IP or attack type, most severe first.
#[tauri::command]
pub fn anomaly_groups(group_by: GroupBy, state: tauri::State<'_, AppState>) -> Result<Vec<AnomalyGroup>, String> {
    Ok(crate::report::summarize(&state.anomalies.read(), group_by))
}

/// The newest anomalies in one group (max 500).
#[tauri::command]
pub fn group_anomalies(group_by: GroupBy, key: String, state: tauri::State<'_, AppState>) -> Result<Vec<Anomaly>, String> {
    Ok(crate::report::group_members(&state.anomalies.read(), group_by, &key, 500))
}

/// Writes a Markdown incident report for the current file to `output_path`.
#[tauri::command]
pub async fn export_report(
    output_path: String,
    state: tauri::State<'_, AppState>,
    app: AppHandle,
) -> Result<(), String> {
    let anomalies = state.anomalies.read().clone();
    let stats = state.stats.read().clone();
    let source = state.source.read().clone();
    let version = app.package_info().version.to_string();

    tauri::async_runtime::spawn_blocking(move || {
        let md = crate::report::markdown_report(&ReportInput {
            source: source.as_deref(),
            stats: &stats,
            anomalies: &anomalies,
            generated_at: chrono::Utc::now().timestamp_millis(),
            app_version: &version,
        });
        std::fs::write(&output_path, md).map_err(|e| format!("Cannot write '{output_path}': {e}"))?;
        log::info!("Wrote report '{output_path}'");
        Ok(())
    })
    .await
    .map_err(|e| format!("Spawn error: {e}"))?
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::detector::types::AnomalyKind;

    fn anomaly(id: u64, severity: Severity) -> Anomaly {
        Anomaly {
            id,
            entry_id: id,
            timestamp: 0,
            kind: AnomalyKind::PatternMatch { pattern_name: "xss_attempt".into() },
            severity,
            source_ip: None,
            description: "XSS from 203.0.113.9: GET /x".into(),
        }
    }

    #[test]
    fn export_writes_filtered_json() {
        let all = vec![anomaly(1, Severity::High), anomaly(2, Severity::Critical), anomaly(3, Severity::High)];
        let path = std::env::temp_dir().join(format!("ht-export-{}.json", std::process::id()));

        assert_eq!(write_anomalies(&all, Some("high"), &path).unwrap(), 2);
        let back: Vec<Anomaly> = serde_json::from_str(&std::fs::read_to_string(&path).unwrap()).unwrap();
        assert_eq!(back.iter().map(|a| a.id).collect::<Vec<_>>(), vec![1, 3]);

        // camelCase field names and the tagged kind, as the frontend types expect
        let text = std::fs::read_to_string(&path).unwrap();
        assert!(text.contains("\"entryId\"") && text.contains("\"type\": \"patternMatch\""), "{text}");

        assert_eq!(write_anomalies(&all, None, &path).unwrap(), 3);
        let _ = std::fs::remove_file(path);
    }

    #[test]
    fn export_picks_csv_by_extension() {
        let all = vec![anomaly(1, Severity::High)];
        let path = std::env::temp_dir().join(format!("ht-export-{}.CSV", std::process::id()));
        assert_eq!(write_anomalies(&all, None, &path).unwrap(), 1);
        let text = std::fs::read_to_string(&path).unwrap();
        assert!(text.starts_with("timestamp,severity,category,source_ip"), "{text}");
        let _ = std::fs::remove_file(path);
    }

    #[test]
    fn export_to_bad_path_is_an_error() {
        let err = write_anomalies(&[], None, Path::new("Z:/no/such/dir/out.json")).unwrap_err();
        assert!(err.contains("Cannot write"), "{err}");
    }
}
