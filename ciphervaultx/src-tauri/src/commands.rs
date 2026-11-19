use std::path::PathBuf;

use base64::engine::general_purpose::STANDARD;
use base64::Engine;
use cvz_core::{
    Argon2Params, CipherSuite, IntegrityReport, KdfProfile, RecoveryKey, Vault, VaultEntry,
    VaultSummary,
};
use serde::{Deserialize, Serialize};
use tauri::{AppHandle, Emitter, State};

use crate::registry::{self, AppSettings, KnownVault};
use crate::state::AppState;

const MAX_PREVIEW_BYTES: u64 = 12 * 1024 * 1024;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VaultInfo {
    pub id: String,
    pub name: String,
    pub path: String,
    pub unlocked: bool,
    pub summary: Option<VaultSummary>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CreateVaultResult {
    pub vault: VaultInfo,
    pub recovery_key: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TransferProgress {
    pub vault_id: String,
    pub operation: String,
    pub done: u64,
    pub total: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PreviewPayload {
    pub mime: String,
    pub base64: String,
    pub size: usize,
}

#[tauri::command]
pub fn list_vaults(state: State<'_, AppState>) -> Vec<VaultInfo> {
    registry::load()
        .into_iter()
        .map(|kv| {
            let unlocked = state.is_unlocked(&kv.id);
            let summary = if unlocked {
                state
                    .get_session(&kv.id)
                    .ok()
                    .and_then(|arc| arc.read().ok().map(|v| v.summary()))
            } else {
                None
            };
            VaultInfo {
                id: kv.id,
                name: kv.name,
                path: kv.path,
                unlocked,
                summary,
            }
        })
        .collect()
}

#[tauri::command]
pub async fn create_vault(
    state: State<'_, AppState>,
    name: String,
    path: String,
    suite: CipherSuite,
    kdf_profile: KdfProfile,
    password: String,
) -> Result<CreateVaultResult, String> {
    let root = PathBuf::from(&path);
    let params = Argon2Params::for_profile(kdf_profile);

    let (vault, recovery) = tauri::async_runtime::spawn_blocking(move || {
        Vault::create(&root, &password, suite, params)
    })
    .await
    .map_err(|_| "background task failed".to_string())?
    .map_err(|e| e.to_string())?;

    let summary = vault.summary();
    let display_name = if name.trim().is_empty() {
        registry::safe_folder_name(&path)
    } else {
        name.trim().to_string()
    };
    let kv = registry::add(display_name, path)?;
    state.insert_session(kv.id.clone(), vault)?;

    Ok(CreateVaultResult {
        vault: VaultInfo {
            id: kv.id,
            name: kv.name,
            path: kv.path,
            unlocked: true,
            summary: Some(summary),
        },
        recovery_key: recovery.to_display_string(),
    })
}

#[tauri::command]
pub fn register_existing_vault(name: Option<String>, path: String) -> Result<KnownVault, String> {
    let display = name
        .filter(|n| !n.trim().is_empty())
        .unwrap_or_else(|| registry::safe_folder_name(&path));
    registry::add(display, path)
}

#[tauri::command]
pub fn remove_vault_entry(state: State<'_, AppState>, vault_id: String) -> Result<bool, String> {
    state.lock(&vault_id);
    registry::remove(&vault_id)
}

#[tauri::command]
pub async fn unlock_vault(
    state: State<'_, AppState>,
    vault_id: String,
    password: String,
) -> Result<VaultInfo, String> {
    let kv = registry::find(&vault_id).ok_or_else(|| "vault not found in registry".to_string())?;
    let root = PathBuf::from(&kv.path);

    let vault =
        tauri::async_runtime::spawn_blocking(move || Vault::unlock_with_password(&root, &password))
            .await
            .map_err(|_| "background task failed".to_string())?
            .map_err(|e| e.to_string())?;

    let summary = vault.summary();
    state.insert_session(kv.id.clone(), vault)?;

    Ok(VaultInfo {
        id: kv.id,
        name: kv.name,
        path: kv.path,
        unlocked: true,
        summary: Some(summary),
    })
}

#[tauri::command]
pub async fn unlock_vault_with_recovery(
    state: State<'_, AppState>,
    vault_id: String,
    recovery_key: String,
) -> Result<VaultInfo, String> {
    let kv = registry::find(&vault_id).ok_or_else(|| "vault not found in registry".to_string())?;
    let root = PathBuf::from(&kv.path);

    let vault = tauri::async_runtime::spawn_blocking(move || {
        let parsed = RecoveryKey::parse(&recovery_key)?;
        Vault::unlock_with_recovery(&root, &parsed)
    })
    .await
    .map_err(|_| "background task failed".to_string())?
    .map_err(|e| e.to_string())?;

    let summary = vault.summary();
    state.insert_session(kv.id.clone(), vault)?;

    Ok(VaultInfo {
        id: kv.id,
        name: kv.name,
        path: kv.path,
        unlocked: true,
        summary: Some(summary),
    })
}

#[tauri::command]
pub async fn reset_password_with_recovery(
    state: State<'_, AppState>,
    vault_id: String,
    recovery_key: String,
    new_password: String,
    kdf_profile: KdfProfile,
) -> Result<VaultInfo, String> {
    let kv = registry::find(&vault_id).ok_or_else(|| "vault not found in registry".to_string())?;
    let root = PathBuf::from(&kv.path);
    let params = Argon2Params::for_profile(kdf_profile);

    let vault = tauri::async_runtime::spawn_blocking(move || {
        let parsed = RecoveryKey::parse(&recovery_key)?;
        Vault::reset_password_with_recovery(&root, &parsed, &new_password, params)
    })
    .await
    .map_err(|_| "background task failed".to_string())?
    .map_err(|e| e.to_string())?;

    let summary = vault.summary();
    state.insert_session(kv.id.clone(), vault)?;

    Ok(VaultInfo {
        id: kv.id,
        name: kv.name,
        path: kv.path,
        unlocked: true,
        summary: Some(summary),
    })
}

#[tauri::command]
pub async fn change_vault_password(
    state: State<'_, AppState>,
    vault_id: String,
    current_password: String,
    new_password: String,
    kdf_profile: KdfProfile,
) -> Result<(), String> {
    let session = state.get_session(&vault_id)?;
    let params = Argon2Params::for_profile(kdf_profile);

    tauri::async_runtime::spawn_blocking(move || {
        let mut vault = session
            .write()
            .map_err(|_| "vault lock poisoned".to_string())?;
        vault
            .change_password(&current_password, &new_password, params)
            .map_err(|e| e.to_string())
    })
    .await
    .map_err(|_| "background task failed".to_string())?
}

#[tauri::command]
pub fn lock_vault(state: State<'_, AppState>, vault_id: String) -> bool {
    state.lock(&vault_id)
}

#[tauri::command]
pub fn lock_all_vaults(state: State<'_, AppState>) -> Vec<String> {
    state.lock_all()
}

#[tauri::command]
pub async fn list_dir(
    state: State<'_, AppState>,
    vault_id: String,
    path: String,
) -> Result<Vec<VaultEntry>, String> {
    let session = state.get_session(&vault_id)?;
    tauri::async_runtime::spawn_blocking(move || {
        let vault = session
            .read()
            .map_err(|_| "vault lock poisoned".to_string())?;
        vault.list_dir(&path).map_err(|e| e.to_string())
    })
    .await
    .map_err(|_| "background task failed".to_string())?
}

#[tauri::command]
pub async fn create_dir(
    state: State<'_, AppState>,
    vault_id: String,
    path: String,
) -> Result<(), String> {
    let session = state.get_session(&vault_id)?;
    tauri::async_runtime::spawn_blocking(move || {
        let vault = session
            .read()
            .map_err(|_| "vault lock poisoned".to_string())?;
        vault.create_dir(&path).map_err(|e| e.to_string())
    })
    .await
    .map_err(|_| "background task failed".to_string())?
}

#[tauri::command]
pub async fn import_file(
    app: AppHandle,
    state: State<'_, AppState>,
    vault_id: String,
    src_path: String,
    dst_vault_path: String,
) -> Result<u64, String> {
    let session = state.get_session(&vault_id)?;
    let src = PathBuf::from(src_path);
    let vid = vault_id.clone();

    tauri::async_runtime::spawn_blocking(move || {
        let vault = session
            .read()
            .map_err(|_| "vault lock poisoned".to_string())?;
        let mut cb = |done: u64, total: u64| {
            let _ = app.emit(
                "transfer-progress",
                TransferProgress {
                    vault_id: vid.clone(),
                    operation: "import".to_string(),
                    done,
                    total,
                },
            );
        };
        vault
            .import_file(&src, &dst_vault_path, Some(&mut cb))
            .map_err(|e| e.to_string())
    })
    .await
    .map_err(|_| "background task failed".to_string())?
}

#[tauri::command]
pub async fn export_file(
    app: AppHandle,
    state: State<'_, AppState>,
    vault_id: String,
    src_vault_path: String,
    dst_path: String,
) -> Result<u64, String> {
    let session = state.get_session(&vault_id)?;
    let dst = PathBuf::from(dst_path);
    let vid = vault_id.clone();

    tauri::async_runtime::spawn_blocking(move || {
        let vault = session
            .read()
            .map_err(|_| "vault lock poisoned".to_string())?;
        let mut cb = |done: u64, total: u64| {
            let _ = app.emit(
                "transfer-progress",
                TransferProgress {
                    vault_id: vid.clone(),
                    operation: "export".to_string(),
                    done,
                    total,
                },
            );
        };
        vault
            .export_file(&src_vault_path, &dst, Some(&mut cb))
            .map_err(|e| e.to_string())
    })
    .await
    .map_err(|_| "background task failed".to_string())?
}

#[tauri::command]
pub async fn preview_file(
    state: State<'_, AppState>,
    vault_id: String,
    path: String,
) -> Result<PreviewPayload, String> {
    let session = state.get_session(&vault_id)?;
    let mime = guess_mime(&path).to_string();

    tauri::async_runtime::spawn_blocking(move || {
        let vault = session
            .read()
            .map_err(|_| "vault lock poisoned".to_string())?;
        let bytes = vault
            .read_file_bytes(&path, MAX_PREVIEW_BYTES)
            .map_err(|e| e.to_string())?;
        let size = bytes.len();
        Ok(PreviewPayload {
            mime,
            base64: STANDARD.encode(bytes),
            size,
        })
    })
    .await
    .map_err(|_| "background task failed".to_string())?
}

#[tauri::command]
pub async fn rename_entry(
    state: State<'_, AppState>,
    vault_id: String,
    path: String,
    new_name: String,
) -> Result<(), String> {
    let session = state.get_session(&vault_id)?;
    tauri::async_runtime::spawn_blocking(move || {
        let vault = session
            .read()
            .map_err(|_| "vault lock poisoned".to_string())?;
        vault
            .rename_entry(&path, &new_name)
            .map_err(|e| e.to_string())
    })
    .await
    .map_err(|_| "background task failed".to_string())?
}

#[tauri::command]
pub async fn move_entry(
    state: State<'_, AppState>,
    vault_id: String,
    src_path: String,
    dst_dir: String,
) -> Result<(), String> {
    let session = state.get_session(&vault_id)?;
    tauri::async_runtime::spawn_blocking(move || {
        let vault = session
            .read()
            .map_err(|_| "vault lock poisoned".to_string())?;
        vault
            .move_entry(&src_path, &dst_dir)
            .map_err(|e| e.to_string())
    })
    .await
    .map_err(|_| "background task failed".to_string())?
}

#[tauri::command]
pub async fn delete_entry(
    state: State<'_, AppState>,
    vault_id: String,
    path: String,
) -> Result<(), String> {
    let session = state.get_session(&vault_id)?;
    tauri::async_runtime::spawn_blocking(move || {
        let vault = session
            .read()
            .map_err(|_| "vault lock poisoned".to_string())?;
        vault.delete_entry(&path).map_err(|e| e.to_string())
    })
    .await
    .map_err(|_| "background task failed".to_string())?
}

#[tauri::command]
pub async fn search_vault(
    state: State<'_, AppState>,
    vault_id: String,
    query: String,
) -> Result<Vec<VaultEntry>, String> {
    let session = state.get_session(&vault_id)?;
    tauri::async_runtime::spawn_blocking(move || {
        let vault = session
            .read()
            .map_err(|_| "vault lock poisoned".to_string())?;
        vault.search(&query).map_err(|e| e.to_string())
    })
    .await
    .map_err(|_| "background task failed".to_string())?
}

#[tauri::command]
pub async fn verify_vault(
    state: State<'_, AppState>,
    vault_id: String,
) -> Result<IntegrityReport, String> {
    let session = state.get_session(&vault_id)?;
    tauri::async_runtime::spawn_blocking(move || {
        let vault = session
            .read()
            .map_err(|_| "vault lock poisoned".to_string())?;
        vault.verify_integrity().map_err(|e| e.to_string())
    })
    .await
    .map_err(|_| "background task failed".to_string())?
}

#[tauri::command]
pub fn get_settings() -> AppSettings {
    registry::load_settings()
}

#[tauri::command]
pub fn update_settings(settings: AppSettings) -> Result<(), String> {
    registry::save_settings(&settings)
}

#[tauri::command]
pub fn touch_activity(state: State<'_, AppState>) {
    state.touch();
}

fn guess_mime(path: &str) -> &'static str {
    let lower = path.to_lowercase();
    if lower.ends_with(".png") {
        "image/png"
    } else if lower.ends_with(".jpg") || lower.ends_with(".jpeg") {
        "image/jpeg"
    } else if lower.ends_with(".webp") {
        "image/webp"
    } else if lower.ends_with(".gif") {
        "image/gif"
    } else if lower.ends_with(".pdf") {
        "application/pdf"
    } else if lower.ends_with(".txt") || lower.ends_with(".md") || lower.ends_with(".json") {
        "text/plain"
    } else {
        "application/octet-stream"
    }
}
