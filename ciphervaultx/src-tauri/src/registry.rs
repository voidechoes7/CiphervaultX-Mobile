use std::fs;
use std::path::{Path, PathBuf};

use serde::de::DeserializeOwned;
use serde::{Deserialize, Serialize};

const APP_DIR_NAME: &str = "ciphervaultx";
const VAULTS_FILE: &str = "vaults.json";
const SETTINGS_FILE: &str = "settings.json";

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct KnownVault {
    pub id: String,
    pub name: String,
    pub path: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AppSettings {
    pub theme: String,
    pub auto_lock_minutes: u32,
}

impl Default for AppSettings {
    fn default() -> Self {
        Self {
            theme: "obsidian-dark".to_string(),
            auto_lock_minutes: 10,
        }
    }
}

pub fn cfg_dir() -> Result<PathBuf, String> {
    let base = dirs::config_dir().ok_or_else(|| "unable to locate config directory".to_string())?;
    let dir = base.join(APP_DIR_NAME);
    if !dir.exists() {
        fs::create_dir_all(&dir).map_err(|e| e.to_string())?;
    }
    Ok(dir)
}

pub fn read_json<T: DeserializeOwned>(path: &Path) -> Result<T, String> {
    let raw = fs::read(path).map_err(|e| e.to_string())?;
    serde_json::from_slice(&raw).map_err(|e| e.to_string())
}

pub fn write_json<T: Serialize + ?Sized>(path: &Path, value: &T) -> Result<(), String> {
    let bytes = serde_json::to_vec_pretty(value).map_err(|e| e.to_string())?;
    cvz_core::fsio::atomic_write_bytes(path, &bytes).map_err(|e| e.to_string())
}

pub fn load() -> Vec<KnownVault> {
    let Ok(dir) = cfg_dir() else {
        return Vec::new();
    };
    read_json(&dir.join(VAULTS_FILE)).unwrap_or_default()
}

pub fn save(vaults: &[KnownVault]) -> Result<(), String> {
    let dir = cfg_dir()?;
    write_json(&dir.join(VAULTS_FILE), vaults)
}

pub fn add(name: String, path: String) -> Result<KnownVault, String> {
    let mut vaults = load();
    if let Some(existing) = vaults.iter().find(|v| v.path == path) {
        return Ok(existing.clone());
    }
    let entry = KnownVault {
        id: uuid::Uuid::new_v4().to_string(),
        name,
        path,
    };
    vaults.push(entry.clone());
    save(&vaults)?;
    Ok(entry)
}

pub fn find(id: &str) -> Option<KnownVault> {
    load().into_iter().find(|v| v.id == id)
}

pub fn remove(id: &str) -> Result<bool, String> {
    let mut vaults = load();
    let before = vaults.len();
    vaults.retain(|v| v.id != id);
    if vaults.len() != before {
        save(&vaults)?;
        return Ok(true);
    }
    Ok(false)
}

pub fn safe_folder_name(path: &str) -> String {
    Path::new(path)
        .file_name()
        .and_then(|s| s.to_str())
        .filter(|s| !s.is_empty())
        .unwrap_or("Vault")
        .to_string()
}

pub fn load_settings() -> AppSettings {
    let Ok(dir) = cfg_dir() else {
        return AppSettings::default();
    };
    read_json(&dir.join(SETTINGS_FILE)).unwrap_or_default()
}

pub fn save_settings(settings: &AppSettings) -> Result<(), String> {
    let dir = cfg_dir()?;
    write_json(&dir.join(SETTINGS_FILE), settings)
}
