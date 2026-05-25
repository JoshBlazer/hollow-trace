pub mod commands;
pub mod detector;
pub mod events;
pub mod parser;
pub mod ring_buffer;
pub mod scorer;
pub mod state;
pub mod watcher;

use state::AppState;

#[cfg_attr(mobile, tauri::mobile_entry_point)]
pub fn run() {
    tauri::Builder::default()
        .plugin(tauri_plugin_dialog::init())
        .plugin(tauri_plugin_fs::init())
        .manage(AppState::default())
        .invoke_handler(tauri::generate_handler![
            commands::open_file,
            commands::start_watching,
            commands::stop_watching,
            commands::get_stats,
            commands::get_anomalies,
            commands::export_anomalies,
            commands::clear_stream,
        ])
        .run(tauri::generate_context!())
        .expect("error while running tauri application");
}
