//! Zero-knowledge Cloud Synchronization Layer (Milestone 4).
//!
//! Synchronizes *only* the encrypted vault tree (`vault.cryptomator`, `masterkey.cryptomator`,
//! and `d/<2>/<30>/*.c9r` / `*.c9s`) with an untrusted remote adapter.
//!
//! Security invariants enforced by [`SyncEngine`]:
//! 1. **Plaintext & key guard**: refuses to upload any file outside the allowlisted
//!    Cryptomator ciphertext filenames (`vault.cryptomator`, `masterkey.cryptomator`,
//!    `masterkey.cryptomator.bkup`, `dir.c9r`, `dirid.c9r`, `name.c9s`, `contents.c9r`,
//!    or `<base64url>.c9r`). Any stray file (e.g. `.DS_Store`, `.cvx-tmp-*`, or an accidental
//!    plaintext file placed inside the vault directory) is rejected before touching the adapter.
//! 2. **Header verification**: every `.c9r` content file is checked to be at least 68 bytes
//!    (header nonce + AES-256-GCM encrypted content key + tag) or a valid directory/symlink pointer.
//! 3. **No masterkey in memory required**: sync operates strictly on the on-disk ciphertext tree
//!    even while the vault is locked.

use std::collections::BTreeMap;
use std::fs;
use std::path::{Path, PathBuf};

use crate::crypto::content::HEADER_LEN;
use crate::crypto::ffi::sha1_digest;
use crate::encoding::hex_encode;
use crate::error::{Result, VaultError};
use crate::fsutil::{self, TEMP_PREFIX};
use crate::vault::{CONFIG_FILE, DATA_DIR, MASTERKEY_FILE};

/// Metadata about a remote encrypted object.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RemoteObject {
    /// Relative POSIX path from the vault root (e.g. `vault.cryptomator` or `d/AB/CD.../efg.c9r`).
    pub rel_path: String,
    pub size: u64,
    /// SHA-1 hex digest of the ciphertext bytes for change detection.
    pub sha1_hex: String,
}

/// Abstract cloud storage adapter. Implementations never receive keys or plaintext.
pub trait CloudAdapter: std::fmt::Debug + Send + Sync {
    fn provider_name(&self) -> &'static str;
    fn list_objects(&self) -> Result<Vec<RemoteObject>>;
    fn get_object(&self, rel_path: &str) -> Result<Vec<u8>>;
    fn put_object(&self, rel_path: &str, ciphertext: &[u8]) -> Result<()>;
    fn delete_object(&self, rel_path: &str) -> Result<()>;
}

/// Local folder synchronization adapter (simulates a cloud mirror / WebDAV / S3 bucket on disk).
#[derive(Debug, Clone)]
pub struct LocalMirrorAdapter {
    target_root: PathBuf,
}

impl LocalMirrorAdapter {
    pub fn new(target_root: PathBuf) -> Result<Self> {
        fs::create_dir_all(&target_root)?;
        Ok(LocalMirrorAdapter { target_root })
    }

    pub fn target_root(&self) -> &Path {
        &self.target_root
    }
}

impl CloudAdapter for LocalMirrorAdapter {
    fn provider_name(&self) -> &'static str {
        "local-mirror"
    }

    fn list_objects(&self) -> Result<Vec<RemoteObject>> {
        let mut out = Vec::new();
        walk_rel(&self.target_root, &self.target_root, &mut out)?;
        out.sort_by(|a, b| a.rel_path.cmp(&b.rel_path));
        Ok(out)
    }

    fn get_object(&self, rel_path: &str) -> Result<Vec<u8>> {
        validate_rel_path(rel_path)?;
        Ok(fs::read(self.target_root.join(rel_path))?)
    }

    fn put_object(&self, rel_path: &str, ciphertext: &[u8]) -> Result<()> {
        validate_rel_path(rel_path)?;
        let dest = self.target_root.join(rel_path);
        if let Some(p) = dest.parent() {
            fs::create_dir_all(p)?;
        }
        fsutil::write_atomic(&dest, ciphertext, true)?;
        Ok(())
    }

    fn delete_object(&self, rel_path: &str) -> Result<()> {
        validate_rel_path(rel_path)?;
        let dest = self.target_root.join(rel_path);
        if dest.is_file() {
            fs::remove_file(&dest)?;
        }
        Ok(())
    }
}

fn validate_rel_path(rel: &str) -> Result<()> {
    if rel.is_empty()
        || rel.starts_with('/')
        || rel.contains('\\')
        || rel.split('/').any(|c| c.is_empty() || c == "." || c == "..")
    {
        return Err(VaultError::InvalidName(format!("invalid relative sync path: {rel}")));
    }
    Ok(())
}

/// Verify that a relative path and its payload strictly conform to Cryptomator ciphertext rules.
/// Rejects any unencrypted or unrecognized file before it can reach a cloud adapter.
pub fn verify_ciphertext_only(rel_path: &str, bytes: &[u8]) -> Result<()> {
    validate_rel_path(rel_path)?;
    let parts: Vec<&str> = rel_path.split('/').collect();
    if parts.iter().any(|p| p.starts_with(TEMP_PREFIX) || p.starts_with('.')) {
        return Err(VaultError::Unsupported(format!(
            "refusing to sync temporary or hidden file: {rel_path}"
        )));
    }
    match parts.as_slice() {
        [CONFIG_FILE] => {
            // Must be a 3-part compact JWS
            let s = std::str::from_utf8(bytes)
                .map_err(|_| VaultError::Malformed("vault.cryptomator is not UTF-8".into()))?;
            if s.trim().split('.').count() != 3 {
                return Err(VaultError::Malformed("vault.cryptomator is not a compact JWS".into()));
            }
            Ok(())
        }
        [MASTERKEY_FILE] | ["masterkey.cryptomator.bkup"] => {
            // Must be a JSON object with wrapped keys (`primaryMasterKey`, `hmacMasterKey`, `scryptSalt`)
            let m = crate::json::parse_flat_object(bytes)?;
            if !m.contains_key("primaryMasterKey") || !m.contains_key("hmacMasterKey") || !m.contains_key("scryptSalt")
            {
                return Err(VaultError::Malformed("masterkey file missing wrapped key fields".into()));
            }
            Ok(())
        }
        [DATA_DIR, l1, l2, leaf] if l1.len() == 2 && l2.len() == 30 => {
            if *leaf == "dirid.c9r" || leaf.ends_with(".c9r") {
                if bytes.len() < HEADER_LEN {
                    return Err(VaultError::Malformed(format!(
                        "ciphertext file {rel_path} shorter than 68-byte AES-GCM header"
                    )));
                }
                Ok(())
            } else {
                Err(VaultError::Unsupported(format!(
                    "refusing to sync non-ciphertext file in vault data dir: {rel_path}"
                )))
            }
        }
        [DATA_DIR, l1, l2, node, inner] if l1.len() == 2 && l2.len() == 30 => {
            if node.ends_with(".c9r") && *inner == "dir.c9r" {
                let s = std::str::from_utf8(bytes)
                    .map_err(|_| VaultError::Malformed("dir.c9r is not ASCII UUID".into()))?;
                if s.is_empty() || s.len() > 36 || !s.is_ascii() {
                    return Err(VaultError::Malformed("invalid dir.c9r content".into()));
                }
                Ok(())
            } else if node.ends_with(".c9s") && (*inner == "name.c9s" || *inner == "dir.c9r" || *inner == "contents.c9r")
            {
                if *inner == "contents.c9r" && bytes.len() < HEADER_LEN {
                    return Err(VaultError::Malformed("contents.c9r shorter than 68-byte header".into()));
                }
                Ok(())
            } else {
                Err(VaultError::Unsupported(format!(
                    "refusing to sync unrecognized node file: {rel_path}"
                )))
            }
        }
        _ => Err(VaultError::Unsupported(format!(
            "refusing to sync path outside Cryptomator ciphertext specification: {rel_path}"
        ))),
    }
}

#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub struct SyncSummary {
    pub provider: String,
    pub uploaded: u64,
    pub downloaded: u64,
    pub unchanged: u64,
    pub bytes_transferred: u64,
}

/// Synchronize a local vault directory with a [`CloudAdapter`].
#[derive(Debug)]
pub struct SyncEngine;

impl SyncEngine {
    /// Push local ciphertext changes to the remote adapter and pull remote-only ciphertext objects.
    pub fn sync_bidirectional(vault_root: &Path, adapter: &dyn CloudAdapter) -> Result<SyncSummary> {
        let mut local_objs = Vec::new();
        walk_rel(vault_root, vault_root, &mut local_objs)?;
        let remote_objs = adapter.list_objects()?;

        let local_map: BTreeMap<String, RemoteObject> =
            local_objs.into_iter().map(|o| (o.rel_path.clone(), o)).collect();
        let remote_map: BTreeMap<String, RemoteObject> =
            remote_objs.into_iter().map(|o| (o.rel_path.clone(), o)).collect();

        let mut summary = SyncSummary { provider: adapter.provider_name().into(), ..Default::default() };

        // 1. Upload new or modified local ciphertext files after verifying they are ciphertext-only.
        for (rel, loc) in &local_map {
            let bytes = fs::read(vault_root.join(rel))?;
            verify_ciphertext_only(rel, &bytes)?;
            match remote_map.get(rel) {
                Some(rem) if rem.sha1_hex == loc.sha1_hex && rem.size == loc.size => {
                    summary.unchanged += 1;
                }
                _ => {
                    adapter.put_object(rel, &bytes)?;
                    summary.uploaded += 1;
                    summary.bytes_transferred += bytes.len() as u64;
                }
            }
        }

        // 2. Download remote ciphertext files that do not exist locally yet.
        for (rel, _rem) in &remote_map {
            if !local_map.contains_key(rel) {
                let bytes = adapter.get_object(rel)?;
                verify_ciphertext_only(rel, &bytes)?;
                let dest = vault_root.join(rel);
                if let Some(p) = dest.parent() {
                    fs::create_dir_all(p)?;
                }
                fsutil::write_atomic(&dest, &bytes, true)?;
                summary.downloaded += 1;
                summary.bytes_transferred += bytes.len() as u64;
            }
        }

        Ok(summary)
    }
}

fn walk_rel(root: &Path, cur: &Path, out: &mut Vec<RemoteObject>) -> Result<()> {
    if !cur.exists() {
        return Ok(());
    }
    for e in fs::read_dir(cur)? {
        let e = e?;
        let fname = e.file_name().to_string_lossy().into_owned();
        if fname.starts_with(TEMP_PREFIX) {
            continue;
        }
        let p = e.path();
        if p.is_dir() {
            walk_rel(root, &p, out)?;
        } else if p.is_file() {
            let rel = p
                .strip_prefix(root)
                .map_err(|_| VaultError::Malformed("strip_prefix".into()))?
                .components()
                .map(|c| c.as_os_str().to_string_lossy().into_owned())
                .collect::<Vec<_>>()
                .join("/");
            let bytes = fs::read(&p)?;
            let sha1_hex = hex_encode(&sha1_digest(&bytes));
            out.push(RemoteObject { rel_path: rel, size: bytes.len() as u64, sha1_hex });
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::masterkey_file::KdfParams;
    use crate::fsutil::TempDir;
    use crate::vault::Vault;
    use std::io::Cursor;

    #[test]
    fn sync_roundtrip_and_restore_on_second_device() {
        let d = TempDir::new().unwrap();
        let vault_a = d.path().join("device_a");
        let mirror_dir = d.path().join("cloud_mirror");
        let vault_b = d.path().join("device_b");

        let v = Vault::create(&vault_a, "sync-pass", KdfParams::INSECURE_TEST).unwrap();
        v.create_dir_all("/Docs/Taxes").unwrap();
        v.write_file("/Docs/Taxes/return-2026.pdf", Cursor::new(b"synthetic-tax-pdf".to_vec()), false, None)
            .unwrap();
        drop(v);

        let adapter = LocalMirrorAdapter::new(mirror_dir).unwrap();
        let s1 = SyncEngine::sync_bidirectional(&vault_a, &adapter).unwrap();
        assert!(s1.uploaded >= 4);
        assert_eq!(s1.downloaded, 0);

        // Second sync is idempotent
        let s2 = SyncEngine::sync_bidirectional(&vault_a, &adapter).unwrap();
        assert_eq!(s2.uploaded, 0);
        assert_eq!(s2.unchanged, s1.uploaded);

        // Pull into clean device B and unlock with password
        fs::create_dir_all(&vault_b).unwrap();
        let s3 = SyncEngine::sync_bidirectional(&vault_b, &adapter).unwrap();
        assert_eq!(s3.downloaded, s1.uploaded);

        let vb = Vault::unlock(&vault_b, "sync-pass").unwrap();
        let mut buf = Vec::new();
        vb.read_file("/Docs/Taxes/return-2026.pdf", &mut buf, None).unwrap();
        assert_eq!(buf, b"synthetic-tax-pdf");
    }

    #[test]
    fn plaintext_leak_in_vault_folder_is_blocked_from_upload() {
        let d = TempDir::new().unwrap();
        let vault_a = d.path().join("vault");
        let mirror_dir = d.path().join("mirror");
        let _v = Vault::create(&vault_a, "pw", KdfParams::INSECURE_TEST).unwrap();

        // Simulate accidental plaintext file dropped into the vault root
        fs::write(vault_a.join("accidental-plaintext.txt"), b"SENSITIVE").unwrap();

        let adapter = LocalMirrorAdapter::new(mirror_dir.clone()).unwrap();
        let res = SyncEngine::sync_bidirectional(&vault_a, &adapter);
        assert!(res.is_err(), "plaintext file must be rejected by sync guard");
        assert!(!mirror_dir.join("accidental-plaintext.txt").exists());
    }
}
