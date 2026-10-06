pub mod commands;
pub mod detector;
pub mod events;
pub mod parser;
pub mod query;
pub mod report;
pub mod ring_buffer;
pub mod scorer;
pub mod settings;
pub mod state;
pub mod watcher;

use tauri::Manager;
use tauri_plugin_log::{RotationStrategy, Target, TargetKind};

use settings::DetectionSettings;
use state::AppState;

/// The app ID was `dev.hollowtrace.app` before 0.3.0. Copy settings saved under the old
/// ID once, so pre-release testers keep them. Never overwrites existing settings.
fn migrate_legacy_settings(config_dir: &std::path::Path) {
    let new = config_dir.join(settings::SETTINGS_FILE);
    let Some(old) = config_dir
        .parent()
        .map(|p| p.join("dev.hollowtrace.app").join(settings::SETTINGS_FILE))
    else {
        return;
    };
    if new.exists() || !old.exists() {
        return;
    }
    let copied = std::fs::create_dir_all(config_dir).and_then(|_| std::fs::copy(&old, &new));
    match copied {
        Ok(_) => log::info!("Migrated settings from {}", old.display()),
        Err(e) => log::warn!("Could not migrate settings from {}: {e}", old.display()),
    }
}

#[cfg_attr(mobile, tauri::mobile_entry_point)]
pub fn run() {
    tauri::Builder::default()
        .plugin(
            // Rotating log file in the app log dir (e.g. %LOCALAPPDATA%\dev.hollowtrace.desktop\logs)
            tauri_plugin_log::Builder::new()
                .targets([
                    Target::new(TargetKind::LogDir { file_name: None }),
                    Target::new(TargetKind::Stdout),
                ])
                .level(log::LevelFilter::Info)
                .max_file_size(5_000_000)
                .rotation_strategy(RotationStrategy::KeepSome(5))
                .build(),
        )
        .plugin(tauri_plugin_dialog::init())
        .plugin(tauri_plugin_updater::Builder::new().build())
        .plugin(tauri_plugin_process::init())
        .setup(|app| {
            let config_dir = app.path().app_config_dir().ok();
            if let Some(dir) = &config_dir {
                migrate_legacy_settings(dir);
            }
            let settings = config_dir
                .map(|dir| DetectionSettings::load(&dir))
                .unwrap_or_default();
            log::info!("Hollow Trace {} starting", app.package_info().version);
            app.manage(AppState::with_settings(settings));
            Ok(())
        })
        .invoke_handler(tauri::generate_handler![
            commands::open_file,
            commands::start_watching,
            commands::stop_watching,
            commands::get_stats,
            commands::get_anomalies,
            commands::export_anomalies,
            commands::clear_stream,
            commands::get_settings,
            commands::save_settings,
            commands::query_entries,
            commands::anomaly_groups,
            commands::group_anomalies,
            commands::export_report,
        ])
        .run(tauri::generate_context!())
        .expect("error while running tauri application");
}
