pub mod commands;
pub mod detector;
pub mod events;
pub mod parser;
pub mod ring_buffer;
pub mod scorer;
pub mod settings;
pub mod state;
pub mod watcher;

use tauri::Manager;
use tauri_plugin_log::{RotationStrategy, Target, TargetKind};

use settings::DetectionSettings;
use state::AppState;

#[cfg_attr(mobile, tauri::mobile_entry_point)]
pub fn run() {
    tauri::Builder::default()
        .plugin(
            // Rotating log file in the app log dir (e.g. %LOCALAPPDATA%\dev.hollowtrace.app\logs)
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
            let settings = app
                .path()
                .app_config_dir()
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
        ])
        .run(tauri::generate_context!())
        .expect("error while running tauri application");
}
