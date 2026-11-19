#![forbid(unsafe_code)]

pub mod commands;
pub mod registry;
pub mod state;

use state::AppState;
use tauri::Manager;

#[cfg_attr(mobile, tauri::mobile_entry_point)]
pub fn run() {
    tauri::Builder::default()
        .plugin(tauri_plugin_dialog::init())
        .manage(AppState::new())
        .setup(|app| {
            let handle = app.handle().clone();
            let app_state = app.state::<AppState>().inner().clone();
            state::spawn_autolock_task(handle, app_state);
            Ok(())
        })
        .invoke_handler(tauri::generate_handler![
            commands::list_vaults,
            commands::create_vault,
            commands::register_existing_vault,
            commands::remove_vault_entry,
            commands::unlock_vault,
            commands::unlock_vault_with_recovery,
            commands::reset_password_with_recovery,
            commands::change_vault_password,
            commands::lock_vault,
            commands::lock_all_vaults,
            commands::list_dir,
            commands::create_dir,
            commands::import_file,
            commands::export_file,
            commands::preview_file,
            commands::rename_entry,
            commands::move_entry,
            commands::delete_entry,
            commands::search_vault,
            commands::verify_vault,
            commands::get_settings,
            commands::update_settings,
            commands::touch_activity,
        ])
        .run(tauri::generate_context!())
        .expect("error while running Fortress CipherVaultX");
}
