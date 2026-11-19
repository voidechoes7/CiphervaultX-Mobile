use std::path::{Path, PathBuf};

use aes_siv::siv::Aes256Siv;
use aes_siv::KeyInit;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine;
use data_encoding::BASE32_NOPAD;
use hmac::{Hmac, Mac};
use sha2::Sha256;
use unicode_normalization::UnicodeNormalization;

use crate::error::{Result, VaultError};
use crate::secret::{Key32, Key64};

pub const FILE_EXT: &str = ".cvz";
pub const DIR_EXT: &str = ".cvzd";
pub const MAX_ENCODED_NAME_LEN: usize = 200;
const DIR_ID_HMAC_PREFIX: &[u8] = b"cvz-dirid-v1\0";

type HmacSha256 = Hmac<Sha256>;

/// Validate a single path component according to the portable filename policy
/// and return its Unicode NFC-normalized form.
pub fn validate_and_normalize_name(name: &str) -> Result<String> {
    if name.is_empty() || name == "." || name == ".." {
        return Err(VaultError::InvalidName);
    }
    let normalized: String = name.nfc().collect();
    if normalized.is_empty() || normalized == "." || normalized == ".." {
        return Err(VaultError::InvalidName);
    }
    if normalized.len() > 255 {
        return Err(VaultError::InvalidName);
    }
    if normalized.ends_with(' ') || normalized.ends_with('.') {
        return Err(VaultError::InvalidName);
    }
    for ch in normalized.chars() {
        if ch.is_control() || matches!(ch, '/' | '\\' | ':' | '*' | '?' | '"' | '<' | '>' | '|') {
            return Err(VaultError::InvalidName);
        }
    }
    Ok(normalized)
}

/// Encrypt a single filename or directory name deterministically with AES-SIV-CMAC-512,
/// binding the parent directory ID as associated data.
pub fn encrypt_name(
    name_siv_key: &Key64,
    parent_dir_id: &str,
    plaintext_name: &str,
    is_dir: bool,
) -> Result<String> {
    let normalized = validate_and_normalize_name(plaintext_name)?;
    let mut cipher =
        Aes256Siv::new_from_slice(name_siv_key.as_bytes()).map_err(|_| VaultError::Integrity)?;
    let ct = cipher
        .encrypt(&[parent_dir_id.as_bytes()], normalized.as_bytes())
        .map_err(|_| VaultError::Integrity)?;
    let ext = if is_dir { DIR_EXT } else { FILE_EXT };
    let encoded = format!("{}{}", URL_SAFE_NO_PAD.encode(ct), ext);
    if encoded.len() > MAX_ENCODED_NAME_LEN {
        return Err(VaultError::NameTooLong);
    }
    Ok(encoded)
}

/// Decrypt an on-disk encrypted filename (.cvz or .cvzd) bound to `parent_dir_id`.
/// Returns `(plaintext_name, is_dir)`.
pub fn decrypt_name(
    name_siv_key: &Key64,
    parent_dir_id: &str,
    encoded_name: &str,
) -> Result<(String, bool)> {
    let (stem, is_dir) = if let Some(s) = encoded_name.strip_suffix(DIR_EXT) {
        (s, true)
    } else if let Some(s) = encoded_name.strip_suffix(FILE_EXT) {
        (s, false)
    } else {
        return Err(VaultError::Integrity);
    };

    let ct = URL_SAFE_NO_PAD
        .decode(stem)
        .map_err(|_| VaultError::Integrity)?;
    let mut cipher =
        Aes256Siv::new_from_slice(name_siv_key.as_bytes()).map_err(|_| VaultError::Integrity)?;
    let plain = cipher
        .decrypt(&[parent_dir_id.as_bytes()], &ct)
        .map_err(|_| VaultError::Integrity)?;
    let name = String::from_utf8(plain).map_err(|_| VaultError::Integrity)?;
    let normalized = validate_and_normalize_name(&name).map_err(|_| VaultError::Integrity)?;
    Ok((normalized, is_dir))
}

/// Compute flat storage directory path:
/// digest = HMAC-SHA256(dirHashKey, "cvz-dirid-v1\0" || dirId)
/// enc = BASE32_NOPAD(digest[0..20])
/// path = vaultRoot / "d" / enc[0..2] / enc[2..32]
pub fn dir_storage_path(vault_root: &Path, dir_hash_key: &Key32, dir_id: &str) -> Result<PathBuf> {
    let mut mac = <HmacSha256 as Mac>::new_from_slice(dir_hash_key.as_bytes())
        .map_err(|_| VaultError::Integrity)?;
    mac.update(DIR_ID_HMAC_PREFIX);
    mac.update(dir_id.as_bytes());
    let digest = mac.finalize().into_bytes();
    let enc = BASE32_NOPAD.encode(&digest[0..20]);
    Ok(vault_root.join("d").join(&enc[0..2]).join(&enc[2..32]))
}

/// Split a virtual vault path (e.g. "/docs/report.pdf" or "docs/report.pdf") into validated components.
pub fn split_vault_path(path: &str) -> Result<Vec<String>> {
    let trimmed = path.trim();
    if trimmed.is_empty() || trimmed == "/" {
        return Ok(Vec::new());
    }
    let stripped = trimmed.trim_matches('/');
    if stripped.is_empty() {
        return Ok(Vec::new());
    }
    let mut parts = Vec::new();
    for raw in stripped.split('/') {
        parts.push(validate_and_normalize_name(raw)?);
    }
    Ok(parts)
}
