use cvz_core::kdf;
use serde::{Deserialize, Serialize};

/// Optional compile-time Argon2id PHC hash list injected via GitHub Actions
/// secret `CVZ_PRIVATE_ACCESS_HASH` (or local build env).
///
/// Supports one or multiple `$argon2id$v=19$...` entries separated by `,`, `;`,
/// or newlines so the owner can authorize themselves plus trusted individuals.
/// When unset or empty (e.g. Store / open builds), the gate is disabled.
const COMPILED_GATE_HASHES: Option<&str> = option_env!("CVZ_PRIVATE_ACCESS_HASH");

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AppGateStatus {
    pub enabled: bool,
    pub unlocked: bool,
    pub authorized_keys: usize,
}

pub fn compiled_hashes() -> Vec<&'static str> {
    let Some(raw) = COMPILED_GATE_HASHES else {
        return Vec::new();
    };
    raw.split([',', ';', '\n', '\r'])
        .map(str::trim)
        .filter(|entry| entry.starts_with("$argon2id$"))
        .collect()
}

pub fn is_gate_configured() -> bool {
    !compiled_hashes().is_empty()
}

pub fn authorized_key_count() -> usize {
    compiled_hashes().len()
}

pub fn verify_passphrase(passphrase: &str) -> bool {
    let hashes = compiled_hashes();
    if hashes.is_empty() {
        return true;
    }
    kdf::verify_access_gate_any(passphrase, &hashes)
}
