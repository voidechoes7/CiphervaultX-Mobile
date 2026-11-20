use std::collections::HashMap;
use std::sync::{Arc, RwLock};
use std::time::{Duration, Instant};

use cvz_core::Vault;
use tauri::{AppHandle, Emitter};

use crate::registry;
use crate::webdav::{MountHandle, MountInfo};

#[derive(Clone)]
pub struct AppState {
    sessions: Arc<RwLock<HashMap<String, Arc<RwLock<Vault>>>>>,
    mounts: Arc<RwLock<HashMap<String, MountHandle>>>,
    last_activity: Arc<RwLock<Instant>>,
}

impl Default for AppState {
    fn default() -> Self {
        Self::new()
    }
}

impl AppState {
    pub fn new() -> Self {
        Self {
            sessions: Arc::new(RwLock::new(HashMap::new())),
            mounts: Arc::new(RwLock::new(HashMap::new())),
            last_activity: Arc::new(RwLock::new(Instant::now())),
        }
    }

    pub fn touch(&self) {
        if let Ok(mut guard) = self.last_activity.write() {
            *guard = Instant::now();
        }
    }

    pub fn idle_duration(&self) -> Duration {
        self.last_activity
            .read()
            .map(|t| t.elapsed())
            .unwrap_or_default()
    }

    pub fn insert_session(&self, id: String, vault: Vault) -> Result<(), String> {
        self.touch();
        let mut map = self
            .sessions
            .write()
            .map_err(|_| "session lock poisoned".to_string())?;
        map.insert(id, Arc::new(RwLock::new(vault)));
        Ok(())
    }

    pub fn get_session(&self, id: &str) -> Result<Arc<RwLock<Vault>>, String> {
        self.touch();
        let map = self
            .sessions
            .read()
            .map_err(|_| "session lock poisoned".to_string())?;
        map.get(id)
            .cloned()
            .ok_or_else(|| "vault is locked".to_string())
    }

    pub fn is_unlocked(&self, id: &str) -> bool {
        self.sessions
            .read()
            .map(|m| m.contains_key(id))
            .unwrap_or(false)
    }

    pub fn insert_mount(&self, id: String, handle: MountHandle) -> Result<MountInfo, String> {
        let info = handle.info.clone();
        let mut map = self
            .mounts
            .write()
            .map_err(|_| "mount lock poisoned".to_string())?;
        if let Some(mut old) = map.remove(&id) {
            old.unmount();
        }
        map.insert(id, handle);
        Ok(info)
    }

    pub fn get_mount_info(&self, id: &str) -> Option<MountInfo> {
        self.mounts
            .read()
            .ok()
            .and_then(|m| m.get(id).map(|h| h.info.clone()))
    }

    pub fn unmount(&self, id: &str) -> bool {
        if let Ok(mut map) = self.mounts.write() {
            if let Some(mut handle) = map.remove(id) {
                handle.unmount();
                return true;
            }
        }
        false
    }

    pub fn lock(&self, id: &str) -> bool {
        self.unmount(id);
        self.sessions
            .write()
            .map(|mut m| m.remove(id).is_some())
            .unwrap_or(false)
    }

    pub fn lock_all(&self) -> Vec<String> {
        if let Ok(mut mounts) = self.mounts.write() {
            for (_, mut h) in mounts.drain() {
                h.unmount();
            }
        }
        self.sessions
            .write()
            .map(|mut m| m.drain().map(|(k, _)| k).collect())
            .unwrap_or_default()
    }
}

pub fn spawn_autolock_task(app: AppHandle, state: AppState) {
    tauri::async_runtime::spawn(async move {
        let mut interval = tokio::time::interval(Duration::from_secs(15));
        loop {
            interval.tick().await;
            let settings = registry::load_settings();
            if settings.auto_lock_minutes == 0 {
                continue;
            }
            let threshold = Duration::from_secs(u64::from(settings.auto_lock_minutes) * 60);
            if state.idle_duration() >= threshold {
                let locked_ids = state.lock_all();
                if !locked_ids.is_empty() {
                    let _ = app.emit("vault-auto-locked", locked_ids);
                }
            }
        }
    });
}
