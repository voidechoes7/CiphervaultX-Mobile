use std::path::PathBuf;

use base64::engine::general_purpose::STANDARD;
use base64::Engine;
use cvz_core::{
    Argon2Params, CipherSuite, IntegrityReport, KdfProfile, RecoveryKey, Vault, VaultEntry,
    VaultSummary,
};
use serde::{Deserialize, Serialize};
use tauri::{AppHandle, Emitter, State};

use crate::gate::{self, AppGateStatus};
use crate::registry::{self, AppSettings, KnownVault};
use crate::state::AppState;

const MAX_PREVIEW_BYTES: u64 = 12 * 1024 * 1024;

fn current_gate_status(state: &AppState) -> AppGateStatus {
    AppGateStatus {
        enabled: gate::is_gate_configured(),
        unlocked: state.is_gate_unlocked(),
        authorized_keys: gate::authorized_key_count(),
    }
}

fn require_gate(state: &AppState) -> Result<(), String> {
    if !state.is_gate_unlocked() {
        return Err("Private Access Gate is locked. Unlock the application first.".to_string());
    }
    Ok(())
}

#[tauri::command]
pub fn get_app_gate_status(state: State<'_, AppState>) -> AppGateStatus {
    current_gate_status(&state)
}

#[tauri::command]
pub async fn unlock_app_gate(
    state: State<'_, AppState>,
    passphrase: String,
) -> Result<AppGateStatus, String> {
    if !gate::is_gate_configured() {
        return Ok(current_gate_status(&state));
    }
    let ok = tauri::async_runtime::spawn_blocking(move || gate::verify_passphrase(&passphrase))
        .await
        .map_err(|_| "background task failed".to_string())?;
    if !ok {
        return Err("Invalid access passphrase".to_string());
    }
    state.set_gate_unlocked(true);
    Ok(current_gate_status(&state))
}

#[tauri::command]
pub fn lock_app_gate(state: State<'_, AppState>) -> AppGateStatus {
    state.lock_gate();
    current_gate_status(&state)
}

#[tauri::command]
pub async fn generate_access_gate_hash(passphrase: String) -> Result<String, String> {
    tauri::async_runtime::spawn_blocking(move || {
        cvz_core::kdf::generate_access_gate_hash(&passphrase).map_err(|e| e.to_string())
    })
    .await
    .map_err(|_| "background task failed".to_string())?
}

/// Create and return an empty, writable vault directory inside the app's
/// platform-managed storage root (essential on Android & iOS where native
/// directory pickers are unavailable).
#[tauri::command]
pub fn default_vault_path(name: Option<String>) -> Result<String, String> {
    let root = registry::default_vaults_root()?;
    let raw = name.unwrap_or_else(|| "vault".to_string());
    let sanitized: String = raw
        .trim()
        .chars()
        .map(|c| {
            if c.is_ascii_alphanumeric() || c == '-' || c == '_' {
                c
            } else {
                '_'
            }
        })
        .collect();
    let base_name = if sanitized.is_empty() {
        "vault".to_string()
    } else {
        sanitized
    };

    let mut candidate = root.join(&base_name);
    let mut suffix = 2u32;
    while candidate.exists()
        && std::fs::read_dir(&candidate)
            .map(|mut rd| rd.next().is_some())
            .unwrap_or(true)
    {
        candidate = root.join(format!("{base_name}-{suffix}"));
        suffix += 1;
    }
    std::fs::create_dir_all(&candidate).map_err(|e| e.to_string())?;
    Ok(candidate.to_string_lossy().to_string())
}

/// Return whether this binary was compiled for a mobile target (`Android` / `iOS`).
#[tauri::command]
pub fn is_mobile() -> bool {
    cfg!(mobile)
}

/// Return the app's managed root directory where local vaults are stored.
#[tauri::command]
pub fn default_vaults_dir() -> Result<String, String> {
    let root = registry::default_vaults_root()?;
    Ok(root.to_string_lossy().to_string())
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DiscoveredVault {
    pub name: String,
    pub path: String,
    pub already_registered: bool,
}

/// Scan the app's managed vaults directory for existing CVZ v1 vault folders
/// (directories containing `cvz.vault.json`) so mobile users can re-add vaults
/// without a desktop directory picker.
#[tauri::command]
pub fn list_discovered_vaults() -> Result<Vec<DiscoveredVault>, String> {
    let root = registry::default_vaults_root()?;
    let registered = registry::load();
    let mut found = Vec::new();

    if let Ok(entries) = std::fs::read_dir(&root) {
        for entry in entries.flatten() {
            let path = entry.path();
            if path.is_dir() && path.join(cvz_core::config::CONFIG_FILENAME).is_file() {
                let path_str = path.to_string_lossy().to_string();
                let already_registered = registered.iter().any(|v| v.path == path_str);
                let name = registry::safe_folder_name(&path_str);
                found.push(DiscoveredVault {
                    name,
                    path: path_str,
                    already_registered,
                });
            }
        }
    }

    found.sort_by(|a, b| a.name.to_lowercase().cmp(&b.name.to_lowercase()));
    Ok(found)
}

/// Return a writable export directory inside the app's managed storage root
/// for mobile platforms where desktop save-file dialogs are unavailable.
#[tauri::command]
pub fn default_export_dir() -> Result<String, String> {
    let root = registry::default_exports_root()?;
    Ok(root.to_string_lossy().to_string())
}

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
    if !state.is_gate_unlocked() {
        return Vec::new();
    }
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
    custom_kdf: Option<Argon2Params>,
) -> Result<CreateVaultResult, String> {
    require_gate(&state)?;
    let root = PathBuf::from(&path);
    let params = custom_kdf.unwrap_or_else(|| Argon2Params::for_profile(kdf_profile));
    params.validate().map_err(|e| e.to_string())?;

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
    let trimmed = path.trim();
    if trimmed.is_empty() {
        return Err("Vault folder path cannot be empty.".to_string());
    }
    let mut folder = PathBuf::from(trimmed);
    if folder.is_file()
        && folder
            .file_name()
            .and_then(|n| n.to_str())
            .is_some_and(|n| n == cvz_core::config::CONFIG_FILENAME)
    {
        if let Some(parent) = folder.parent() {
            folder = parent.to_path_buf();
        }
    }
    if !folder.is_dir() {
        return Err(format!("Vault folder does not exist: {}", folder.display()));
    }
    if !folder.join(cvz_core::config::CONFIG_FILENAME).is_file() {
        return Err(format!(
            "No CVZ v1 vault found in '{}' (missing {}).",
            folder.display(),
            cvz_core::config::CONFIG_FILENAME
        ));
    }
    let normalized = folder.to_string_lossy().to_string();
    let display = name
        .map(|n| n.trim().to_string())
        .filter(|n| !n.is_empty())
        .unwrap_or_else(|| registry::safe_folder_name(&normalized));
    registry::add(display, normalized)
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
pub async fn mount_vault(
    state: State<'_, AppState>,
    vault_id: String,
) -> Result<crate::webdav::MountInfo, String> {
    if let Some(existing) = state.get_mount_info(&vault_id) {
        return Ok(existing);
    }
    let session = state.get_session(&vault_id)?;
    let handle = crate::webdav::start_mount(vault_id.clone(), session).await?;
    state.insert_mount(vault_id, handle)
}

#[tauri::command]
pub fn unmount_vault(state: State<'_, AppState>, vault_id: String) -> bool {
    state.unmount(&vault_id)
}

#[tauri::command]
pub fn get_mount_info(
    state: State<'_, AppState>,
    vault_id: String,
) -> Option<crate::webdav::MountInfo> {
    state.get_mount_info(&vault_id)
}

#[tauri::command]
pub fn reveal_mount(state: State<'_, AppState>, vault_id: String) -> Result<(), String> {
    let info = state
        .get_mount_info(&vault_id)
        .ok_or_else(|| "vault is not mounted".to_string())?;
    crate::webdav::reveal_mount_point(&info.mount_point)
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
pub async fn import_paths(
    app: AppHandle,
    state: State<'_, AppState>,
    vault_id: String,
    paths: Vec<String>,
    dst_dir: String,
) -> Result<u64, String> {
    let session = state.get_session(&vault_id)?;
    let vid = vault_id.clone();

    tauri::async_runtime::spawn_blocking(move || {
        let vault = session
            .read()
            .map_err(|_| "vault lock poisoned".to_string())?;
        let base_dir = dst_dir.trim_end_matches('/');
        let mut total_imported: u64 = 0;

        fn import_one(
            vault: &Vault,
            app: &AppHandle,
            vid: &str,
            disk_path: &std::path::Path,
            vault_parent: &str,
            total_imported: &mut u64,
        ) -> Result<(), String> {
            let name = disk_path
                .file_name()
                .and_then(|s| s.to_str())
                .ok_or_else(|| "invalid source filename".to_string())?;
            let target_vpath = if vault_parent.is_empty() || vault_parent == "/" {
                format!("/{name}")
            } else {
                format!("{vault_parent}/{name}")
            };

            if disk_path.is_dir() {
                match vault.create_dir(&target_vpath) {
                    Ok(()) | Err(cvz_core::VaultError::AlreadyExists) => {}
                    Err(e) => return Err(e.to_string()),
                }
                let rd = std::fs::read_dir(disk_path).map_err(|e| e.to_string())?;
                for entry in rd {
                    let entry = entry.map_err(|e| e.to_string())?;
                    import_one(
                        vault,
                        app,
                        vid,
                        &entry.path(),
                        &target_vpath,
                        total_imported,
                    )?;
                }
            } else if disk_path.is_file() {
                let mut cb = |done: u64, total: u64| {
                    let _ = app.emit(
                        "transfer-progress",
                        TransferProgress {
                            vault_id: vid.to_string(),
                            operation: "import".to_string(),
                            done,
                            total,
                        },
                    );
                };
                let bytes = vault
                    .import_file(disk_path, &target_vpath, Some(&mut cb))
                    .map_err(|e| e.to_string())?;
                *total_imported += bytes;
            }
            Ok(())
        }

        for p in paths {
            let disk_path = PathBuf::from(p);
            import_one(
                &vault,
                &app,
                &vid,
                &disk_path,
                base_dir,
                &mut total_imported,
            )?;
        }
        Ok(total_imported)
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

/// Recursively export an entire vault directory (all nested subfolders & files)
/// into `dst_parent_dir/<folder_name>` using authenticated streaming decryption
/// and atomic writes.
#[tauri::command]
pub async fn export_dir(
    app: AppHandle,
    state: State<'_, AppState>,
    vault_id: String,
    src_vault_dir: String,
    dst_parent_dir: String,
) -> Result<u64, String> {
    let session = state.get_session(&vault_id)?;
    let dst_parent = PathBuf::from(dst_parent_dir);
    let vid = vault_id.clone();

    tauri::async_runtime::spawn_blocking(move || {
        let vault = session
            .read()
            .map_err(|_| "vault lock poisoned".to_string())?;

        fn sanitize_component(name: &str) -> Result<&str, String> {
            let trimmed = name.trim();
            if trimmed.is_empty()
                || trimmed == "."
                || trimmed == ".."
                || trimmed.contains('/')
                || trimmed.contains('\\')
                || trimmed.contains('\0')
            {
                return Err(format!("unsafe entry name rejected: {trimmed}"));
            }
            Ok(trimmed)
        }

        fn export_recursive(
            vault: &Vault,
            app: &AppHandle,
            vid: &str,
            vault_dir: &str,
            disk_dir: &std::path::Path,
            total_exported: &mut u64,
        ) -> Result<(), String> {
            std::fs::create_dir_all(disk_dir).map_err(|e| e.to_string())?;
            let entries = vault.list_dir(vault_dir).map_err(|e| e.to_string())?;
            for entry in entries {
                match entry.kind {
                    cvz_core::EntryKind::Directory => {
                        let safe = sanitize_component(&entry.name)?;
                        let child_disk = disk_dir.join(safe);
                        export_recursive(
                            vault,
                            app,
                            vid,
                            &entry.path,
                            &child_disk,
                            total_exported,
                        )?;
                    }
                    cvz_core::EntryKind::File => {
                        let safe = sanitize_component(&entry.name)?;
                        let child_disk = disk_dir.join(safe);
                        let mut cb = |done: u64, total: u64| {
                            let _ = app.emit(
                                "transfer-progress",
                                TransferProgress {
                                    vault_id: vid.to_string(),
                                    operation: "export".to_string(),
                                    done,
                                    total,
                                },
                            );
                        };
                        let bytes = vault
                            .export_file(&entry.path, &child_disk, Some(&mut cb))
                            .map_err(|e| e.to_string())?;
                        *total_exported += bytes;
                    }
                    cvz_core::EntryKind::Unreadable => {
                        return Err(format!(
                            "integrity error: unreadable entry encountered in {vault_dir}"
                        ));
                    }
                }
            }
            Ok(())
        }

        let folder_name = src_vault_dir
            .trim_end_matches('/')
            .rsplit('/')
            .next()
            .filter(|s| !s.is_empty())
            .unwrap_or("vault-export");
        let safe_root_name = sanitize_component(folder_name)?;
        let target_root = dst_parent.join(safe_root_name);
        let mut total_exported = 0u64;
        export_recursive(
            &vault,
            &app,
            &vid,
            &src_vault_dir,
            &target_root,
            &mut total_exported,
        )?;
        Ok(total_exported)
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

#[tauri::command]
pub async fn encrypt_standalone_file(
    state: State<'_, AppState>,
    src_path: String,
    dst_path: String,
    password: String,
    suite: CipherSuite,
    kdf_profile: KdfProfile,
) -> Result<u64, String> {
    require_gate(&state)?;
    let src = PathBuf::from(src_path);
    let dst = PathBuf::from(dst_path);
    let params = Argon2Params::for_profile(kdf_profile);
    tauri::async_runtime::spawn_blocking(move || {
        cvz_core::standalone::encrypt_standalone_file(&src, &dst, &password, suite, params)
            .map_err(|e| e.to_string())
    })
    .await
    .map_err(|_| "background task failed".to_string())?
}

#[tauri::command]
pub async fn decrypt_standalone_file(
    state: State<'_, AppState>,
    src_path: String,
    dst_path: String,
    password: String,
) -> Result<u64, String> {
    require_gate(&state)?;
    let src = PathBuf::from(src_path);
    let dst = PathBuf::from(dst_path);
    tauri::async_runtime::spawn_blocking(move || {
        cvz_core::standalone::decrypt_standalone_file(&src, &dst, &password)
            .map_err(|e| e.to_string())
    })
    .await
    .map_err(|_| "background task failed".to_string())?
}

#[tauri::command]
pub async fn open_cryptomator_vault(
    state: State<'_, AppState>,
    path: String,
    password: String,
) -> Result<cvz_core::cryptomator::CryptomatorVaultInfo, String> {
    require_gate(&state)?;
    let root = PathBuf::from(path);
    let cm = tauri::async_runtime::spawn_blocking(move || {
        cvz_core::cryptomator::CryptomatorVault::open(&root, &password).map_err(|e| e.to_string())
    })
    .await
    .map_err(|_| "background task failed".to_string())??;
    let info = cm.info();
    state.set_cryptomator(cm)?;
    Ok(info)
}

#[tauri::command]
pub fn close_cryptomator_vault(state: State<'_, AppState>) -> bool {
    state.close_cryptomator()
}

#[tauri::command]
pub async fn list_cryptomator_dir(
    state: State<'_, AppState>,
    path: String,
) -> Result<Vec<VaultEntry>, String> {
    let cm = state.get_cryptomator()?;
    tauri::async_runtime::spawn_blocking(move || cm.list_dir(&path).map_err(|e| e.to_string()))
        .await
        .map_err(|_| "background task failed".to_string())?
}

#[tauri::command]
pub async fn export_cryptomator_file(
    state: State<'_, AppState>,
    src_vault_path: String,
    dst_path: String,
) -> Result<u64, String> {
    let cm = state.get_cryptomator()?;
    let dst = PathBuf::from(dst_path);
    tauri::async_runtime::spawn_blocking(move || {
        cm.export_file(&src_vault_path, &dst)
            .map_err(|e| e.to_string())
    })
    .await
    .map_err(|_| "background task failed".to_string())?
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
