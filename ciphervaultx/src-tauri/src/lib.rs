#![forbid(unsafe_code)]

pub mod commands;
pub mod gate;
pub mod registry;
pub mod state;
pub mod webdav;

use state::AppState;
use tauri::Manager;

#[cfg_attr(mobile, tauri::mobile_entry_point)]
pub fn run() {
    tauri::Builder::default()
        .plugin(tauri_plugin_dialog::init())
        .manage(AppState::new())
        .setup(|app| {
            let handle = app.handle().clone();
            #[cfg(mobile)]
            if let Ok(base) = app
                .path()
                .app_local_data_dir()
                .or_else(|_| app.path().app_data_dir())
            {
                registry::init_base_dir(base);
            }
            let app_state = app.state::<AppState>().inner().clone();
            state::spawn_autolock_task(handle, app_state);
            Ok(())
        })
        .invoke_handler(tauri::generate_handler![
            commands::get_app_gate_status,
            commands::unlock_app_gate,
            commands::lock_app_gate,
            commands::generate_access_gate_hash,
            commands::is_mobile,
            commands::default_vault_path,
            commands::default_vaults_dir,
            commands::list_discovered_vaults,
            commands::default_export_dir,
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
            commands::mount_vault,
            commands::unmount_vault,
            commands::get_mount_info,
            commands::reveal_mount,
            commands::list_dir,
            commands::create_dir,
            commands::import_file,
            commands::import_paths,
            commands::export_file,
            commands::export_dir,
            commands::preview_file,
            commands::rename_entry,
            commands::move_entry,
            commands::delete_entry,
            commands::search_vault,
            commands::verify_vault,
            commands::get_settings,
            commands::update_settings,
            commands::touch_activity,
            commands::encrypt_standalone_file,
            commands::decrypt_standalone_file,
            commands::open_cryptomator_vault,
            commands::close_cryptomator_vault,
            commands::list_cryptomator_dir,
            commands::export_cryptomator_file,
        ])
        .run(tauri::generate_context!())
        .expect("error while running Fortress CipherVaultX");
}
