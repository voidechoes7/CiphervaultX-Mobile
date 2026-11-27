use std::io;
use std::path::{Path, PathBuf};

use base64::engine::general_purpose::STANDARD;
use base64::Engine;
use cvz_core::{
    Argon2Params, BackupJob, BackupMode, BackupRunReport, BackupSchedule, CipherSuite,
    IntegrityReport, KdfProfile, RecoveryKey, Vault, VaultEntry, VaultSummary,
};
use serde::{Deserialize, Serialize};
use tauri::{AppHandle, Emitter, State};
use tauri_plugin_fs::{FilePath, FsExt, OpenOptions};
use tempfile::NamedTempFile;

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

/// Return an unused or empty writable vault path inside the app's
/// platform-managed storage root (essential on Android & iOS where native
/// directory pickers are unavailable). `Vault::create` creates the directory
/// on disk when the user confirms creation.
#[tauri::command]
pub fn default_vault_path(
    state: State<'_, AppState>,
    name: Option<String>,
) -> Result<String, String> {
    require_gate(&state)?;
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
    Ok(candidate.to_string_lossy().to_string())
}

/// Return whether this binary was compiled for a mobile target (`Android` / `iOS`).
#[tauri::command]
pub fn is_mobile() -> bool {
    cfg!(mobile)
}

/// Return the app's managed root directory where local vaults are stored.
#[tauri::command]
pub fn default_vaults_dir(state: State<'_, AppState>) -> Result<String, String> {
    require_gate(&state)?;
    let root = registry::default_vaults_root()?;
    Ok(root.to_string_lossy().to_string())
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DiscoveredVault {
    pub name: String,
    pub path: String,
    pub already_registered: bool,
}

/// Scan the app's managed vaults directory (and common shared storage directories
/// when accessible) for existing CVZ v1 vault folders (`cvz.vault.json`).
#[tauri::command]
pub fn list_discovered_vaults(state: State<'_, AppState>) -> Result<Vec<DiscoveredVault>, String> {
    require_gate(&state)?;
    let root = registry::default_vaults_root()?;
    let registered = registry::load();
    let mut found = Vec::new();
    let mut seen = std::collections::HashSet::new();

    let mut scan_roots = vec![root];
    if cfg!(target_os = "android") {
        for candidate in [
            "/storage/emulated/0",
            "/storage/emulated/0/Documents",
            "/storage/emulated/0/Download",
        ] {
            let p = PathBuf::from(candidate);
            if p.is_dir() {
                scan_roots.push(p);
            }
        }
    }

    for scan_root in scan_roots {
        if let Ok(entries) = std::fs::read_dir(&scan_root) {
            for entry in entries.flatten() {
                let path = entry.path();
                if path.is_dir() && path.join(cvz_core::config::CONFIG_FILENAME).is_file() {
                    let path_str = path.to_string_lossy().to_string();
                    if seen.insert(path_str.clone()) {
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
        }
    }

    found.sort_by_key(|a| a.name.to_lowercase());
    Ok(found)
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StorageRoot {
    pub label: String,
    pub path: String,
    pub readable: bool,
    pub kind: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HostDirEntry {
    pub name: String,
    pub path: String,
    pub is_dir: bool,
    pub size: u64,
    pub is_cvz_vault: bool,
    pub is_cryptomator_vault: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HostDirListing {
    pub path: String,
    pub parent: Option<String>,
    pub is_empty: bool,
    pub is_cvz_vault: bool,
    pub is_cryptomator_vault: bool,
    pub entries: Vec<HostDirEntry>,
}

/// Return known storage roots for the in-app filesystem browser (essential on
/// Android & iOS where `tauri-plugin-dialog` does not support folder picking).
#[tauri::command]
pub fn list_storage_roots(state: State<'_, AppState>) -> Result<Vec<StorageRoot>, String> {
    require_gate(&state)?;
    let mut roots = Vec::new();
    let mut seen = std::collections::HashSet::new();

    let mut push_root = |label: &str, path: PathBuf, kind: &str| {
        let path_str = path.to_string_lossy().to_string();
        if seen.insert(path_str.clone()) {
            let readable = std::fs::read_dir(&path).is_ok();
            roots.push(StorageRoot {
                label: label.to_string(),
                path: path_str,
                readable,
                kind: kind.to_string(),
            });
        }
    };

    if let Ok(vaults_root) = registry::default_vaults_root() {
        push_root("App Vaults", vaults_root, "app-vaults");
    }
    if let Ok(exports_root) = registry::default_exports_root() {
        push_root("App Exports", exports_root, "app-exports");
    }

    if cfg!(target_os = "android") {
        let internal = PathBuf::from("/storage/emulated/0");
        push_root("Internal Storage", internal.clone(), "internal");
        for (label, rel, kind) in [
            ("Documents", "Documents", "documents"),
            ("Downloads", "Download", "downloads"),
            ("DCIM", "DCIM", "dcim"),
        ] {
            let sub = internal.join(rel);
            if sub.exists() {
                push_root(label, sub, kind);
            }
        }
        if let Ok(storage_entries) = std::fs::read_dir("/storage") {
            for entry in storage_entries.flatten() {
                let name = entry.file_name().to_string_lossy().to_string();
                if name == "emulated" || name == "self" {
                    continue;
                }
                let p = entry.path();
                if p.is_dir() {
                    push_root(&format!("SD / {name}"), p, "sdcard");
                }
            }
        }
    } else if cfg!(target_os = "ios") {
        if let Ok(base) = registry::cfg_dir() {
            push_root("On My iPhone (App)", base, "documents");
        }
    } else if !cfg!(mobile) {
        if let Some(home) = dirs::home_dir() {
            push_root("Home", home, "home");
        }
        if let Some(docs) = dirs::document_dir() {
            push_root("Documents", docs, "documents");
        }
        if let Some(dl) = dirs::download_dir() {
            push_root("Downloads", dl, "downloads");
        }
    }

    Ok(roots)
}

/// List folders and files in a host directory for the in-app device browser.
#[tauri::command]
pub fn list_host_dir(state: State<'_, AppState>, path: String) -> Result<HostDirListing, String> {
    require_gate(&state)?;
    let trimmed = path.trim();
    if trimmed.is_empty() {
        return Err("Directory path cannot be empty.".to_string());
    }
    let dir = PathBuf::from(trimmed);
    if !dir.exists() {
        return Err(format!("Directory does not exist: {}", dir.display()));
    }
    if !dir.is_dir() {
        return Err(format!("Path is not a directory: {}", dir.display()));
    }

    let read_dir = std::fs::read_dir(&dir).map_err(|e| {
        if e.kind() == std::io::ErrorKind::PermissionDenied {
            format!(
                "Permission denied for '{}'. Grant 'All files access' in Android settings to browse shared storage.",
                dir.display()
            )
        } else {
            e.to_string()
        }
    })?;

    let mut entries = Vec::new();
    let mut total_children = 0usize;
    for entry in read_dir.flatten() {
        total_children += 1;
        let entry_path = entry.path();
        let name = entry.file_name().to_string_lossy().to_string();
        let Ok(meta) = entry.metadata() else {
            continue;
        };
        let is_dir = meta.is_dir();
        let size = if is_dir { 0 } else { meta.len() };
        let is_cvz_vault = is_dir && entry_path.join(cvz_core::config::CONFIG_FILENAME).is_file();
        let is_cryptomator_vault = is_dir && entry_path.join("vault.cryptomator").is_file();
        entries.push(HostDirEntry {
            name,
            path: entry_path.to_string_lossy().to_string(),
            is_dir,
            size,
            is_cvz_vault,
            is_cryptomator_vault,
        });
    }

    entries.sort_by_key(|e| (!e.is_dir, e.name.to_lowercase()));

    let parent = dir
        .parent()
        .filter(|p| !p.as_os_str().is_empty() && *p != dir.as_path())
        .map(|p| p.to_string_lossy().to_string());
    let is_cvz_vault = dir.join(cvz_core::config::CONFIG_FILENAME).is_file();
    let is_cryptomator_vault = dir.join("vault.cryptomator").is_file();

    Ok(HostDirListing {
        path: dir.to_string_lossy().to_string(),
        parent,
        is_empty: total_children == 0,
        is_cvz_vault,
        is_cryptomator_vault,
        entries,
    })
}

/// Create a new subfolder inside `parent` from the in-app device browser.
#[tauri::command]
pub fn create_host_dir(
    state: State<'_, AppState>,
    parent: String,
    name: String,
) -> Result<String, String> {
    require_gate(&state)?;
    let clean_name = name.trim();
    if clean_name.is_empty() {
        return Err("Folder name cannot be empty.".to_string());
    }
    if clean_name == "."
        || clean_name == ".."
        || clean_name.contains('/')
        || clean_name.contains('\\')
    {
        return Err("Invalid folder name.".to_string());
    }
    let parent_path = PathBuf::from(parent.trim());
    if !parent_path.is_dir() {
        return Err(format!(
            "Parent folder does not exist: {}",
            parent_path.display()
        ));
    }
    let target = parent_path.join(clean_name);
    std::fs::create_dir_all(&target).map_err(|e| {
        if e.kind() == std::io::ErrorKind::PermissionDenied {
            format!(
                "Permission denied creating folder in '{}'. Grant 'All files access' or choose App Vaults.",
                parent_path.display()
            )
        } else {
            e.to_string()
        }
    })?;
    Ok(target.to_string_lossy().to_string())
}

/// Return a writable export directory inside the app's managed storage root
/// for mobile platforms where desktop save-file dialogs are unavailable.
#[tauri::command]
pub fn default_export_dir(state: State<'_, AppState>) -> Result<String, String> {
    require_gate(&state)?;
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
pub fn register_existing_vault(
    state: State<'_, AppState>,
    name: Option<String>,
    path: String,
) -> Result<KnownVault, String> {
    require_gate(&state)?;
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
    require_gate(&state)?;
    state.lock(&vault_id);
    registry::remove(&vault_id)
}

#[tauri::command]
pub async fn unlock_vault(
    state: State<'_, AppState>,
    vault_id: String,
    password: String,
) -> Result<VaultInfo, String> {
    require_gate(&state)?;
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
    require_gate(&state)?;
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
    require_gate(&state)?;
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
            let meta = std::fs::symlink_metadata(disk_path).map_err(|e| e.to_string())?;
            if meta.file_type().is_symlink() {
                return Ok(());
            }
            let name = disk_path
                .file_name()
                .and_then(|s| s.to_str())
                .ok_or_else(|| "invalid source filename".to_string())?;
            let target_vpath = if vault_parent.is_empty() || vault_parent == "/" {
                format!("/{name}")
            } else {
                format!("{vault_parent}/{name}")
            };

            if meta.is_dir() {
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
            } else if meta.is_file() {
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
            let local = normalize_local_path_str(&p);
            if local.is_dir() {
                import_one(&vault, &app, &vid, &local, base_dir, &mut total_imported)?;
            } else {
                let staged = StagedSource::resolve(&app, &p)?;
                let target_vpath = if base_dir.is_empty() || base_dir == "/" {
                    format!("/{}", staged.display_name)
                } else {
                    format!("{base_dir}/{}", staged.display_name)
                };
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
                    .import_file(staged.path(), &target_vpath, Some(&mut cb))
                    .map_err(|e| e.to_string())?;
                total_imported += bytes;
            }
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
pub fn update_settings(state: State<'_, AppState>, settings: AppSettings) -> Result<(), String> {
    require_gate(&state)?;
    registry::save_settings(&settings)
}

#[tauri::command]
pub fn touch_activity(state: State<'_, AppState>) {
    state.touch();
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StandaloneOpResult {
    pub path: String,
    pub bytes: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ArchiveOpResult {
    pub path: String,
    pub bytes: u64,
    pub entries: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BackupJobInput {
    pub id: Option<String>,
    pub name: String,
    pub mode: BackupMode,
    pub source_dir: String,
    pub target_vault_id: Option<String>,
    pub target_vault_dir: Option<String>,
    pub target_output_dir: Option<String>,
    pub suite: Option<CipherSuite>,
    pub kdf_params: Option<Argon2Params>,
    pub schedule: BackupSchedule,
    pub auto_run_on_unlock: bool,
    pub enabled: bool,
}

fn percent_decode_utf8(input: &str) -> String {
    let bytes = input.as_bytes();
    let mut out = Vec::with_capacity(bytes.len());
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i] == b'%' && i + 2 < bytes.len() {
            if let Ok(hex) = std::str::from_utf8(&bytes[i + 1..i + 3]) {
                if let Ok(val) = u8::from_str_radix(hex, 16) {
                    out.push(val);
                    i += 3;
                    continue;
                }
            }
        }
        out.push(bytes[i]);
        i += 1;
    }
    String::from_utf8(out).unwrap_or_else(|_| input.to_string())
}

fn normalize_local_path_str(raw: &str) -> PathBuf {
    let trimmed = raw.trim();
    if let Some(rest) = trimmed.strip_prefix("file://") {
        let stripped = rest.strip_prefix("localhost").unwrap_or(rest);
        return PathBuf::from(percent_decode_utf8(stripped));
    }
    PathBuf::from(trimmed)
}

/// Holds either a direct readable host path or an RAII temporary copy fetched via
/// `tauri-plugin-fs` (handles iOS File Provider 0-byte `file://` URLs and Android
/// `content://` URIs without leaving temporary plaintext behind on drop).
struct StagedSource {
    path: PathBuf,
    display_name: String,
    _temp: Option<NamedTempFile>,
}

impl StagedSource {
    fn resolve(app: &AppHandle, raw: &str) -> Result<Self, String> {
        let trimmed = raw.trim();
        if trimmed.is_empty() {
            return Err("Source file path cannot be empty.".to_string());
        }
        let local = normalize_local_path_str(trimmed);
        let display_name = local
            .file_name()
            .and_then(|n| n.to_str())
            .filter(|n| !n.is_empty())
            .unwrap_or("file")
            .to_string();

        let is_uri = trimmed.starts_with("file://") || trimmed.starts_with("content://");
        let direct_ok = match std::fs::metadata(&local) {
            Ok(meta) if meta.is_file() => {
                // On iOS/File Provider, uncoordinated file:// URLs can report 0 bytes
                // even for non-empty iCloud/Files items; fall back to tauri-plugin-fs.
                if is_uri && meta.len() == 0 {
                    false
                } else {
                    std::fs::File::open(&local).is_ok()
                }
            }
            _ => false,
        };

        if direct_ok {
            return Ok(Self {
                path: local,
                display_name,
                _temp: None,
            });
        }

        // Fallback via tauri-plugin-fs (handles iOS security-scoped File Provider URLs
        // and Android content:// URIs cleanly).
        let fp = trimmed
            .parse::<FilePath>()
            .unwrap_or_else(|_| FilePath::Path(local.clone()));
        let mut opts = OpenOptions::new();
        opts.read(true);
        match app.fs().open(fp, opts) {
            Ok(mut src_file) => {
                let mut tmp = NamedTempFile::new().map_err(|e| e.to_string())?;
                io::copy(&mut src_file, tmp.as_file_mut()).map_err(|e| e.to_string())?;
                tmp.as_file_mut().sync_all().map_err(|e| e.to_string())?;
                let tmp_path = tmp.path().to_path_buf();
                Ok(Self {
                    path: tmp_path,
                    display_name,
                    _temp: Some(tmp),
                })
            }
            Err(fs_err) => {
                // If it really is an empty regular local file (not a missing URI), allow it.
                if local.is_file() && std::fs::File::open(&local).is_ok() {
                    Ok(Self {
                        path: local,
                        display_name,
                        _temp: None,
                    })
                } else {
                    Err(format!(
                        "Unable to read source file '{}': {fs_err}",
                        display_name
                    ))
                }
            }
        }
    }

    fn path(&self) -> &Path {
        &self.path
    }
}

#[tauri::command]
#[allow(clippy::too_many_arguments)]
pub async fn encrypt_standalone_file(
    app: AppHandle,
    state: State<'_, AppState>,
    src_path: String,
    dst_path: Option<String>,
    password: String,
    suite: CipherSuite,
    kdf_profile: KdfProfile,
    custom_kdf: Option<Argon2Params>,
) -> Result<StandaloneOpResult, String> {
    require_gate(&state)?;
    let params = custom_kdf.unwrap_or_else(|| Argon2Params::for_profile(kdf_profile));
    params.validate().map_err(|e| e.to_string())?;

    tauri::async_runtime::spawn_blocking(move || {
        let staged = StagedSource::resolve(&app, &src_path)?;
        let dst = match dst_path
            .map(|s| s.trim().to_string())
            .filter(|s| !s.is_empty())
        {
            Some(p) => normalize_local_path_str(&p),
            None => {
                let exports = registry::default_exports_root()?;
                exports.join(format!("{}.cvxenc", staged.display_name))
            }
        };
        let bytes = cvz_core::standalone::encrypt_standalone_file(
            staged.path(),
            &dst,
            &password,
            suite,
            params,
        )
        .map_err(|e| e.to_string())?;
        Ok(StandaloneOpResult {
            path: dst.to_string_lossy().to_string(),
            bytes,
        })
    })
    .await
    .map_err(|_| "background task failed".to_string())?
}

#[tauri::command]
pub async fn decrypt_standalone_file(
    app: AppHandle,
    state: State<'_, AppState>,
    src_path: String,
    dst_path: Option<String>,
    password: String,
) -> Result<StandaloneOpResult, String> {
    require_gate(&state)?;
    tauri::async_runtime::spawn_blocking(move || {
        let staged = StagedSource::resolve(&app, &src_path)?;
        let dst = match dst_path
            .map(|s| s.trim().to_string())
            .filter(|s| !s.is_empty())
        {
            Some(p) => normalize_local_path_str(&p),
            None => {
                let exports = registry::default_exports_root()?;
                let out_name = staged
                    .display_name
                    .strip_suffix(".cvxenc")
                    .filter(|s| !s.is_empty())
                    .unwrap_or(&staged.display_name);
                exports.join(out_name)
            }
        };
        let bytes = cvz_core::standalone::decrypt_standalone_file(staged.path(), &dst, &password)
            .map_err(|e| e.to_string())?;
        Ok(StandaloneOpResult {
            path: dst.to_string_lossy().to_string(),
            bytes,
        })
    })
    .await
    .map_err(|_| "background task failed".to_string())?
}

#[tauri::command]
pub async fn compress_to_zip(
    app: AppHandle,
    state: State<'_, AppState>,
    src_paths: Vec<String>,
    dst_zip_path: Option<String>,
) -> Result<ArchiveOpResult, String> {
    require_gate(&state)?;
    if src_paths.is_empty() {
        return Err("Select at least one file or folder to compress.".to_string());
    }
    tauri::async_runtime::spawn_blocking(move || {
        let mut staged_files = Vec::new();
        let mut resolved_paths = Vec::with_capacity(src_paths.len());
        let mut first_label = "archive".to_string();

        for (idx, raw) in src_paths.iter().enumerate() {
            let local = normalize_local_path_str(raw);
            if local.is_dir() {
                if idx == 0 {
                    first_label = registry::safe_folder_name(&local.to_string_lossy());
                }
                resolved_paths.push(local);
            } else {
                let staged = StagedSource::resolve(&app, raw)?;
                if idx == 0 {
                    first_label = staged.display_name.clone();
                }
                resolved_paths.push(staged.path().to_path_buf());
                staged_files.push(staged);
            }
        }

        let dst = match dst_zip_path
            .map(|s| s.trim().to_string())
            .filter(|s| !s.is_empty())
        {
            Some(p) => {
                let mut pb = normalize_local_path_str(&p);
                if pb.is_dir() {
                    pb = pb.join(format!("{first_label}.zip"));
                }
                pb
            }
            None => {
                let exports = registry::default_exports_root()?;
                exports.join(format!("{first_label}.zip"))
            }
        };

        let report = cvz_core::archive::compress_paths_to_zip(&resolved_paths, &dst)
            .map_err(|e| e.to_string())?;
        drop(staged_files);
        Ok(ArchiveOpResult {
            path: dst.to_string_lossy().to_string(),
            bytes: report.bytes,
            entries: report.entries,
        })
    })
    .await
    .map_err(|_| "background task failed".to_string())?
}

#[tauri::command]
pub async fn extract_archive(
    app: AppHandle,
    state: State<'_, AppState>,
    src_archive_path: String,
    dst_dir: Option<String>,
) -> Result<ArchiveOpResult, String> {
    require_gate(&state)?;
    tauri::async_runtime::spawn_blocking(move || {
        let staged = StagedSource::resolve(&app, &src_archive_path)?;
        let stem = Path::new(&staged.display_name)
            .file_stem()
            .and_then(|s| s.to_str())
            .filter(|s| !s.is_empty())
            .unwrap_or("extracted");

        let dst = match dst_dir
            .map(|s| s.trim().to_string())
            .filter(|s| !s.is_empty())
        {
            Some(p) => normalize_local_path_str(&p),
            None => registry::default_exports_root()?.join(format!("{stem}-extracted")),
        };

        let report =
            cvz_core::archive::extract_archive(staged.path(), &dst).map_err(|e| e.to_string())?;
        Ok(ArchiveOpResult {
            path: dst.to_string_lossy().to_string(),
            bytes: report.bytes,
            entries: report.entries,
        })
    })
    .await
    .map_err(|_| "background task failed".to_string())?
}

#[tauri::command]
pub async fn export_dir_as_zip(
    state: State<'_, AppState>,
    vault_id: String,
    src_vault_dir: String,
    dst_zip_path: Option<String>,
) -> Result<ArchiveOpResult, String> {
    let session = state.get_session(&vault_id)?;
    tauri::async_runtime::spawn_blocking(move || {
        let vault = session
            .read()
            .map_err(|_| "vault lock poisoned".to_string())?;
        let folder_name = src_vault_dir
            .trim_end_matches('/')
            .rsplit('/')
            .next()
            .filter(|s| !s.is_empty())
            .unwrap_or("vault-export");

        let dst = match dst_zip_path
            .map(|s| s.trim().to_string())
            .filter(|s| !s.is_empty())
        {
            Some(p) => {
                let mut pb = normalize_local_path_str(&p);
                if pb.is_dir() {
                    pb = pb.join(format!("{folder_name}.zip"));
                }
                pb
            }
            None => registry::default_exports_root()?.join(format!("{folder_name}.zip")),
        };

        let report = cvz_core::archive::export_vault_folder_to_zip(&vault, &src_vault_dir, &dst)
            .map_err(|e| e.to_string())?;
        Ok(ArchiveOpResult {
            path: dst.to_string_lossy().to_string(),
            bytes: report.bytes,
            entries: report.entries,
        })
    })
    .await
    .map_err(|_| "background task failed".to_string())?
}

#[tauri::command]
pub fn list_backup_jobs(state: State<'_, AppState>) -> Result<Vec<BackupJob>, String> {
    require_gate(&state)?;
    Ok(registry::load_backup_jobs())
}

#[tauri::command]
pub fn save_backup_job(
    state: State<'_, AppState>,
    job: BackupJobInput,
) -> Result<BackupJob, String> {
    require_gate(&state)?;
    let name = job.name.trim().to_string();
    if name.is_empty() {
        return Err("Backup job name cannot be empty.".to_string());
    }
    let source_dir = job.source_dir.trim().to_string();
    if source_dir.is_empty() {
        return Err("Source folder cannot be empty.".to_string());
    }
    if let Some(params) = job.kdf_params {
        params.validate().map_err(|e| e.to_string())?;
    }
    match job.mode {
        BackupMode::VaultMirror => {
            if job
                .target_vault_id
                .as_deref()
                .map(str::trim)
                .unwrap_or("")
                .is_empty()
            {
                return Err("Select a target vault for Vault Mirror backup.".to_string());
            }
        }
        BackupMode::EncryptedSnapshot => {
            if job
                .target_output_dir
                .as_deref()
                .map(str::trim)
                .unwrap_or("")
                .is_empty()
            {
                return Err(
                    "Select a destination folder for Encrypted Snapshot backup.".to_string()
                );
            }
        }
    }

    let mut jobs = registry::load_backup_jobs();
    let existing = job
        .id
        .as_deref()
        .and_then(|id| jobs.iter().find(|j| j.id == id).cloned());

    let id = existing
        .as_ref()
        .map(|e| e.id.clone())
        .unwrap_or_else(|| uuid::Uuid::new_v4().to_string());

    let saved = BackupJob {
        id: id.clone(),
        name,
        mode: job.mode,
        source_dir,
        target_vault_id: job.target_vault_id,
        target_vault_dir: job.target_vault_dir,
        target_output_dir: job.target_output_dir,
        suite: job.suite,
        kdf_params: job.kdf_params,
        schedule: job.schedule,
        auto_run_on_unlock: job.auto_run_on_unlock,
        enabled: job.enabled,
        last_run_unix: existing.as_ref().and_then(|e| e.last_run_unix),
        last_status: existing.and_then(|e| e.last_status),
    };

    if let Some(slot) = jobs.iter_mut().find(|j| j.id == id) {
        *slot = saved.clone();
    } else {
        jobs.push(saved.clone());
    }
    registry::save_backup_jobs(&jobs)?;
    Ok(saved)
}

#[tauri::command]
pub fn delete_backup_job(state: State<'_, AppState>, job_id: String) -> Result<bool, String> {
    require_gate(&state)?;
    let mut jobs = registry::load_backup_jobs();
    let before = jobs.len();
    jobs.retain(|j| j.id != job_id);
    if jobs.len() != before {
        registry::save_backup_jobs(&jobs)?;
        registry::remove_backup_manifest(&job_id);
        return Ok(true);
    }
    Ok(false)
}

fn update_job_status(job_id: &str, completed_unix: u64, status: String) {
    let mut jobs = registry::load_backup_jobs();
    if let Some(job) = jobs.iter_mut().find(|j| j.id == job_id) {
        job.last_run_unix = Some(completed_unix);
        job.last_status = Some(status);
        let _ = registry::save_backup_jobs(&jobs);
    }
}

fn execute_single_backup_job(
    state: &AppState,
    job: &BackupJob,
    password: Option<String>,
) -> Result<BackupRunReport, String> {
    let src = normalize_local_path_str(&job.source_dir);
    match job.mode {
        BackupMode::VaultMirror => {
            let vault_id = job
                .target_vault_id
                .as_deref()
                .ok_or_else(|| "VaultMirror job is missing target_vault_id".to_string())?;
            let session = state.get_session(vault_id)?;
            let vault = session
                .read()
                .map_err(|_| "vault lock poisoned".to_string())?;
            let target_dir = job
                .target_vault_dir
                .as_deref()
                .filter(|s| !s.trim().is_empty())
                .unwrap_or("/Backups");
            let mut manifest = registry::load_backup_manifest(&job.id);
            let report = cvz_core::backup::run_vault_mirror(
                &job.id,
                &vault,
                &src,
                target_dir,
                &mut manifest,
            )
            .map_err(|e| e.to_string())?;
            registry::save_backup_manifest(&job.id, &manifest)?;
            update_job_status(
                &job.id,
                report.completed_unix,
                format!(
                    "Synced {} file(s), skipped {} unchanged",
                    report.files_synced, report.files_skipped
                ),
            );
            Ok(report)
        }
        BackupMode::EncryptedSnapshot => {
            let pw = password
                .filter(|p| !p.is_empty())
                .ok_or_else(|| "Enter a password to encrypt this snapshot.".to_string())?;
            let out_dir = match job
                .target_output_dir
                .as_deref()
                .map(str::trim)
                .filter(|s| !s.is_empty())
            {
                Some(p) => normalize_local_path_str(p),
                None => registry::default_exports_root()?,
            };
            let suite = job.suite.unwrap_or(CipherSuite::XChaCha20Poly1305);
            let kdf_params = job.kdf_params.unwrap_or_else(|| {
                if cfg!(mobile) {
                    Argon2Params::mobile()
                } else {
                    Argon2Params::desktop()
                }
            });
            let report = cvz_core::backup::run_encrypted_snapshot(
                &job.id, &job.name, &src, &out_dir, &pw, suite, kdf_params,
            )
            .map_err(|e| e.to_string())?;
            update_job_status(
                &job.id,
                report.completed_unix,
                format!("Snapshot saved ({} entries)", report.files_synced),
            );
            Ok(report)
        }
    }
}

#[tauri::command]
pub async fn run_backup_job(
    state: State<'_, AppState>,
    job_id: String,
    password: Option<String>,
) -> Result<BackupRunReport, String> {
    require_gate(&state)?;
    let job = registry::load_backup_jobs()
        .into_iter()
        .find(|j| j.id == job_id)
        .ok_or_else(|| "Backup job not found.".to_string())?;
    let app_state = state.inner().clone();
    tauri::async_runtime::spawn_blocking(move || {
        execute_single_backup_job(&app_state, &job, password)
    })
    .await
    .map_err(|_| "background task failed".to_string())?
}

/// 1-Tap Sync All: runs all enabled `VaultMirror` backup jobs whose target vault
/// is currently unlocked.
#[tauri::command]
pub async fn run_all_mirror_backups(
    state: State<'_, AppState>,
    vault_id: Option<String>,
) -> Result<Vec<BackupRunReport>, String> {
    require_gate(&state)?;
    let jobs: Vec<BackupJob> = registry::load_backup_jobs()
        .into_iter()
        .filter(|j| {
            j.enabled
                && j.mode == BackupMode::VaultMirror
                && match (&vault_id, &j.target_vault_id) {
                    (Some(req_vid), Some(job_vid)) => req_vid == job_vid,
                    (None, Some(job_vid)) => state.is_unlocked(job_vid),
                    _ => false,
                }
        })
        .collect();

    let app_state = state.inner().clone();
    tauri::async_runtime::spawn_blocking(move || {
        let mut reports = Vec::with_capacity(jobs.len());
        for job in jobs {
            let rep = execute_single_backup_job(&app_state, &job, None)?;
            reports.push(rep);
        }
        Ok(reports)
    })
    .await
    .map_err(|_| "background task failed".to_string())?
}

/// Run enabled `VaultMirror` jobs configured with `auto_run_on_unlock` (or due
/// according to their schedule) for the freshly unlocked `vault_id`.
#[tauri::command]
pub async fn run_due_unlock_backups(
    state: State<'_, AppState>,
    vault_id: String,
) -> Result<Vec<BackupRunReport>, String> {
    require_gate(&state)?;
    let now = cvz_core::backup::now_unix_secs();
    let jobs: Vec<BackupJob> = registry::load_backup_jobs()
        .into_iter()
        .filter(|j| {
            j.enabled
                && j.mode == BackupMode::VaultMirror
                && j.target_vault_id.as_deref() == Some(vault_id.as_str())
                && (j.auto_run_on_unlock || j.is_due(now))
        })
        .collect();

    if jobs.is_empty() {
        return Ok(Vec::new());
    }

    let app_state = state.inner().clone();
    tauri::async_runtime::spawn_blocking(move || {
        let mut reports = Vec::with_capacity(jobs.len());
        for job in jobs {
            if let Ok(rep) = execute_single_backup_job(&app_state, &job, None) {
                reports.push(rep);
            }
        }
        Ok(reports)
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
