//! Tauri 2 application shell (`ciphervault-app`).
//!
//! Exposes a least-privilege IPC command surface to the React + TypeScript frontend.
//! All cryptographic and filesystem operations delegate to `ciphervault-core`.
//!
//! Security properties:
//! * Unlocked `Vault` instances live only in Rust process memory (`Mutex<AppState>`);
//!   raw masterkeys never cross the IPC boundary to the WebView.
//! * Locking a vault drops the `Vault` instance, triggering `OPENSSL_cleanse` on all
//!   key material.
//! * Errors returned to the UI are sanitized `String` messages that never include
//!   passwords, keys, or plaintext.

use std::collections::BTreeMap;
use std::io::Cursor;
use std::path::PathBuf;
use std::sync::Mutex;
use std::time::{SystemTime, UNIX_EPOCH};

use ciphervault_core::{
    encoding::b64_decode_std, encoding::b64_encode_std, KdfParams, LocalMirrorAdapter, SyncEngine, Vault,
};
use serde::{Deserialize, Serialize};
use tauri::State;
use zeroize::Zeroize;

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct VaultMeta {
    pub id: String,
    pub name: String,
    pub path: String,
    pub unlocked: bool,
    pub created_at: u64,
    pub mirror_path: Option<String>,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct UiEntry {
    pub name: String,
    pub path: String,
    pub kind: String,
    pub size: Option<u64>,
    pub modified: Option<u64>,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct UiIntegrityReport {
    pub directories: u64,
    pub files: u64,
    pub bytes_verified: u64,
    pub problems: Vec<UiIntegrityProblem>,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct UiIntegrityProblem {
    pub location: String,
    pub error: String,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct UiSyncSummary {
    pub provider: String,
    pub uploaded: u64,
    pub downloaded: u64,
    pub unchanged: u64,
    pub bytes_transferred: u64,
}

pub struct AppState {
    pub metas: BTreeMap<String, VaultMeta>,
    pub unlocked: BTreeMap<String, Vault>,
    pub auto_lock_minutes: u32,
}

impl Default for AppState {
    fn default() -> Self {
        AppState { metas: BTreeMap::new(), unlocked: BTreeMap::new(), auto_lock_minutes: 5 }
    }
}

fn now_secs() -> u64 {
    SystemTime::now().duration_since(UNIX_EPOCH).map(|d| d.as_secs()).unwrap_or(0)
}

#[tauri::command]
fn list_vaults(state: State<'_, Mutex<AppState>>) -> Result<Vec<VaultMeta>, String> {
    let st = state.lock().map_err(|_| "state lock poisoned".to_string())?;
    Ok(st
        .metas
        .values()
        .cloned()
        .map(|mut m| {
            m.unlocked = st.unlocked.contains_key(&m.id);
            m
        })
        .collect())
}

#[tauri::command]
fn create_vault(
    state: State<'_, Mutex<AppState>>,
    name: String,
    path: String,
    mut password: String,
    compat_kdf: bool,
) -> Result<VaultMeta, String> {
    let params = if compat_kdf { KdfParams::COMPAT } else { KdfParams::DEFAULT };
    let root = PathBuf::from(&path);
    let vault_res = Vault::create(&root, &password, params);
    password.zeroize();
    let vault = vault_res.map_err(|e| e.to_string())?;
    let id = vault.config().jti.clone();
    let meta = VaultMeta {
        id: id.clone(),
        name,
        path,
        unlocked: true,
        created_at: now_secs(),
        mirror_path: None,
    };
    let mut st = state.lock().map_err(|_| "state lock poisoned".to_string())?;
    st.metas.insert(id.clone(), meta.clone());
    st.unlocked.insert(id, vault);
    Ok(meta)
}

#[tauri::command]
fn unlock_vault(state: State<'_, Mutex<AppState>>, id: String, mut password: String) -> Result<VaultMeta, String> {
    let path = {
        let st = state.lock().map_err(|_| "state lock poisoned".to_string())?;
        st.metas.get(&id).map(|m| PathBuf::from(&m.path)).ok_or_else(|| "vault not registered".to_string())?
    };
    let res = Vault::unlock(&path, &password);
    password.zeroize();
    let vault = res.map_err(|e| e.to_string())?;
    let mut st = state.lock().map_err(|_| "state lock poisoned".to_string())?;
    st.unlocked.insert(id.clone(), vault);
    let mut meta = st.metas.get(&id).cloned().ok_or_else(|| "vault not found".to_string())?;
    meta.unlocked = true;
    Ok(meta)
}

#[tauri::command]
fn lock_vault(state: State<'_, Mutex<AppState>>, id: String) -> Result<(), String> {
    let mut st = state.lock().map_err(|_| "state lock poisoned".to_string())?;
    // Dropping the Vault triggers OPENSSL_cleanse on all key buffers.
    st.unlocked.remove(&id);
    Ok(())
}

#[tauri::command]
fn lock_all_vaults(state: State<'_, Mutex<AppState>>) -> Result<(), String> {
    let mut st = state.lock().map_err(|_| "state lock poisoned".to_string())?;
    st.unlocked.clear();
    Ok(())
}

#[tauri::command]
fn list_entries(state: State<'_, Mutex<AppState>>, id: String, vpath: String) -> Result<Vec<UiEntry>, String> {
    let st = state.lock().map_err(|_| "state lock poisoned".to_string())?;
    let v = st.unlocked.get(&id).ok_or_else(|| "vault is locked".to_string())?;
    let entries = v.list(&vpath).map_err(|e| e.to_string())?;
    Ok(entries
        .into_iter()
        .map(|e| UiEntry {
            name: e.name,
            path: e.path,
            kind: e.kind.as_str().to_string(),
            size: e.size,
            modified: e.modified,
        })
        .collect())
}

#[tauri::command]
fn create_folder(state: State<'_, Mutex<AppState>>, id: String, vpath: String) -> Result<UiEntry, String> {
    let st = state.lock().map_err(|_| "state lock poisoned".to_string())?;
    let v = st.unlocked.get(&id).ok_or_else(|| "vault is locked".to_string())?;
    let e = v.create_dir(&vpath).map_err(|e| e.to_string())?;
    Ok(UiEntry { name: e.name, path: e.path, kind: e.kind.as_str().to_string(), size: e.size, modified: e.modified })
}

#[tauri::command]
fn write_file_base64(
    state: State<'_, Mutex<AppState>>,
    id: String,
    vpath: String,
    data_b64: String,
    overwrite: bool,
) -> Result<UiEntry, String> {
    let bytes = b64_decode_std(&data_b64).map_err(|e| e.to_string())?;
    let st = state.lock().map_err(|_| "state lock poisoned".to_string())?;
    let v = st.unlocked.get(&id).ok_or_else(|| "vault is locked".to_string())?;
    let e = v.write_file(&vpath, Cursor::new(bytes), overwrite, None).map_err(|e| e.to_string())?;
    Ok(UiEntry { name: e.name, path: e.path, kind: e.kind.as_str().to_string(), size: e.size, modified: e.modified })
}

#[tauri::command]
fn read_preview_base64(state: State<'_, Mutex<AppState>>, id: String, vpath: String) -> Result<String, String> {
    let st = state.lock().map_err(|_| "state lock poisoned".to_string())?;
    let v = st.unlocked.get(&id).ok_or_else(|| "vault is locked".to_string())?;
    // Cap preview at 2 MiB
    let bytes = v.read_to_vec(&vpath, 2 * 1024 * 1024).map_err(|e| e.to_string())?;
    Ok(b64_encode_std(&bytes))
}

#[tauri::command]
fn export_file(
    state: State<'_, Mutex<AppState>>,
    id: String,
    vpath: String,
    dest_path: String,
    overwrite: bool,
) -> Result<u64, String> {
    let st = state.lock().map_err(|_| "state lock poisoned".to_string())?;
    let v = st.unlocked.get(&id).ok_or_else(|| "vault is locked".to_string())?;
    v.export_file(&vpath, &PathBuf::from(dest_path), overwrite, None).map_err(|e| e.to_string())
}

#[tauri::command]
fn rename_entry(
    state: State<'_, Mutex<AppState>>,
    id: String,
    from_vpath: String,
    to_vpath: String,
) -> Result<UiEntry, String> {
    let st = state.lock().map_err(|_| "state lock poisoned".to_string())?;
    let v = st.unlocked.get(&id).ok_or_else(|| "vault is locked".to_string())?;
    let e = v.rename(&from_vpath, &to_vpath).map_err(|e| e.to_string())?;
    Ok(UiEntry { name: e.name, path: e.path, kind: e.kind.as_str().to_string(), size: e.size, modified: e.modified })
}

#[tauri::command]
fn delete_entry(state: State<'_, Mutex<AppState>>, id: String, vpath: String) -> Result<(), String> {
    let st = state.lock().map_err(|_| "state lock poisoned".to_string())?;
    let v = st.unlocked.get(&id).ok_or_else(|| "vault is locked".to_string())?;
    v.delete(&vpath).map_err(|e| e.to_string())
}

#[tauri::command]
fn search_vault(
    state: State<'_, Mutex<AppState>>,
    id: String,
    query: String,
    under: String,
) -> Result<Vec<UiEntry>, String> {
    let st = state.lock().map_err(|_| "state lock poisoned".to_string())?;
    let v = st.unlocked.get(&id).ok_or_else(|| "vault is locked".to_string())?;
    let entries = v.search(&query, &under, 200).map_err(|e| e.to_string())?;
    Ok(entries
        .into_iter()
        .map(|e| UiEntry {
            name: e.name,
            path: e.path,
            kind: e.kind.as_str().to_string(),
            size: e.size,
            modified: e.modified,
        })
        .collect())
}

#[tauri::command]
fn check_vault_integrity(state: State<'_, Mutex<AppState>>, id: String) -> Result<UiIntegrityReport, String> {
    let st = state.lock().map_err(|_| "state lock poisoned".to_string())?;
    let v = st.unlocked.get(&id).ok_or_else(|| "vault is locked".to_string())?;
    let rep = v.check_integrity().map_err(|e| e.to_string())?;
    Ok(UiIntegrityReport {
        directories: rep.directories,
        files: rep.files,
        bytes_verified: rep.bytes_verified,
        problems: rep
            .problems
            .into_iter()
            .map(|p| UiIntegrityProblem { location: p.location, error: p.error })
            .collect(),
    })
}

#[tauri::command]
fn sync_vault_mirror(
    state: State<'_, Mutex<AppState>>,
    id: String,
    mirror_path: String,
) -> Result<UiSyncSummary, String> {
    let vault_root = {
        let mut st = state.lock().map_err(|_| "state lock poisoned".to_string())?;
        let meta = st.metas.get_mut(&id).ok_or_else(|| "vault not found".to_string())?;
        meta.mirror_path = Some(mirror_path.clone());
        PathBuf::from(&meta.path)
    };
    let adapter = LocalMirrorAdapter::new(PathBuf::from(mirror_path)).map_err(|e| e.to_string())?;
    let s = SyncEngine::sync_bidirectional(&vault_root, &adapter).map_err(|e| e.to_string())?;
    Ok(UiSyncSummary {
        provider: s.provider,
        uploaded: s.uploaded,
        downloaded: s.downloaded,
        unchanged: s.unchanged,
        bytes_transferred: s.bytes_transferred,
    })
}

#[cfg_attr(mobile, tauri::mobile_entry_point)]
pub fn run() {
    tauri::Builder::default()
        .plugin(tauri_plugin_dialog::init())
        .manage(Mutex::new(AppState::default()))
        .invoke_handler(tauri::generate_handler![
            list_vaults,
            create_vault,
            unlock_vault,
            lock_vault,
            lock_all_vaults,
            list_entries,
            create_folder,
            write_file_base64,
            read_preview_base64,
            export_file,
            rename_entry,
            delete_entry,
            search_vault,
            check_vault_integrity,
            sync_vault_mirror,
        ])
        .run(tauri::generate_context!())
        .expect("error while running CipherVault-X Tauri application");
}
