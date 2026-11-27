//! Cross-platform Automated Encrypted Backup Engine (`VaultMirror` & `EncryptedSnapshot`).
//!
//! Security invariants:
//! - Zero-Knowledge incremental manifest: only SHA-256 hashes of relative paths
//!   are persisted (`SHA-256("cvz-backup-path-v1\0" || rel_path)`). Zero plaintext
//!   filenames or directory names ever appear in manifest JSON.
//! - Symlinks are strictly ignored to prevent directory escape or recursion cycles.
//! - `EncryptedSnapshot` compresses into an RAII `TempDir` and encrypts atomically
//!   as `<name>-<YYYYMMDD-HHMMSSZ>.zip.cvxenc` via `standalone::encrypt_standalone_file`.

use std::collections::{BTreeMap, HashSet};
use std::fs;
use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use tempfile::TempDir;

use crate::archive::compress_paths_to_zip;
use crate::config::CipherSuite;
use crate::error::{Result, VaultError};
use crate::kdf::Argon2Params;
use crate::standalone::encrypt_standalone_file;
use crate::vault::Vault;

const MANIFEST_PATH_DOMAIN: &[u8] = b"cvz-backup-path-v1\0";
pub const MANIFEST_VERSION: u32 = 1;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum BackupMode {
    VaultMirror,
    EncryptedSnapshot,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum BackupSchedule {
    Manual,
    Hours12,
    Hours24,
    Days7,
}

impl BackupSchedule {
    pub const fn interval_secs(self) -> Option<u64> {
        match self {
            Self::Manual => None,
            Self::Hours12 => Some(12 * 3600),
            Self::Hours24 => Some(24 * 3600),
            Self::Days7 => Some(7 * 24 * 3600),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BackupJob {
    pub id: String,
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
    pub last_run_unix: Option<u64>,
    pub last_status: Option<String>,
}

impl BackupJob {
    pub fn is_due(&self, now_unix: u64) -> bool {
        if !self.enabled {
            return false;
        }
        let Some(interval) = self.schedule.interval_secs() else {
            return false;
        };
        match self.last_run_unix {
            None => true,
            Some(last) => now_unix.saturating_sub(last) >= interval,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ManifestFingerprint {
    pub size: u64,
    pub modified_ms: u64,
}

/// Zero-Knowledge sync manifest: maps `hex(SHA-256(domain || rel_path))` -> file fingerprint.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BackupManifest {
    pub version: u32,
    pub entries: BTreeMap<String, ManifestFingerprint>,
}

impl Default for BackupManifest {
    fn default() -> Self {
        Self {
            version: MANIFEST_VERSION,
            entries: BTreeMap::new(),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BackupRunReport {
    pub job_id: String,
    pub mode: BackupMode,
    pub files_synced: u64,
    pub files_skipped: u64,
    pub bytes_processed: u64,
    pub output_path: Option<String>,
    pub completed_unix: u64,
}

/// Compute a domain-separated SHA-256 hex digest of a relative POSIX path.
/// Ensures zero plaintext filenames are persisted in the backup manifest JSON.
pub fn hash_rel_path(rel_posix: &str) -> String {
    let mut hasher = Sha256::new();
    hasher.update(MANIFEST_PATH_DOMAIN);
    hasher.update(rel_posix.as_bytes());
    let digest = hasher.finalize();
    let mut out = String::with_capacity(64);
    for byte in digest {
        use std::fmt::Write as _;
        let _ = write!(&mut out, "{byte:02x}");
    }
    out
}

pub fn now_unix_secs() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

/// Format a UTC timestamp `YYYYMMDD-HHMMSSZ` from Unix seconds (Howard Hinnant civil-from-days).
pub fn format_utc_timestamp(unix_secs: u64) -> String {
    let days = (unix_secs / 86_400) as i64;
    let secs_of_day = unix_secs % 86_400;
    let hour = secs_of_day / 3600;
    let minute = (secs_of_day % 3600) / 60;
    let second = secs_of_day % 60;

    let z = days + 719_468;
    let era = if z >= 0 { z } else { z - 146_096 } / 146_097;
    let doe = (z - era * 146_097) as u64;
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let y = yoe as i64 + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let day = doy - (153 * mp + 2) / 5 + 1;
    let month = if mp < 10 { mp + 3 } else { mp - 9 };
    let year = if month <= 2 { y + 1 } else { y };

    format!("{year:04}{month:02}{day:02}-{hour:02}{minute:02}{second:02}Z")
}

fn sanitize_snapshot_stem(name: &str) -> String {
    let cleaned: String = name
        .trim()
        .chars()
        .map(|c| {
            if c.is_ascii_alphanumeric() || c == '-' || c == '_' {
                c
            } else {
                '-'
            }
        })
        .collect();
    let trimmed = cleaned.trim_matches('-');
    if trimmed.is_empty() {
        "backup".to_string()
    } else {
        trimmed.to_string()
    }
}

fn normalize_vault_dir(raw: &str) -> String {
    let parts: Vec<&str> = raw
        .split('/')
        .map(str::trim)
        .filter(|s| !s.is_empty() && *s != "." && *s != "..")
        .collect();
    if parts.is_empty() {
        "/".to_string()
    } else {
        format!("/{}", parts.join("/"))
    }
}

fn ensure_vault_dir_chain(vault: &Vault, dir_path: &str) -> Result<()> {
    let mut cur = String::new();
    for seg in dir_path.split('/').filter(|s| !s.is_empty()) {
        cur.push('/');
        cur.push_str(seg);
        match vault.create_dir(&cur) {
            Ok(()) | Err(VaultError::AlreadyExists) => {}
            Err(e) => return Err(e),
        }
    }
    Ok(())
}

fn collect_local_files(
    base: &Path,
    cur: &Path,
    out: &mut Vec<(PathBuf, String, ManifestFingerprint)>,
) -> Result<()> {
    let mut entries: Vec<PathBuf> = fs::read_dir(cur)?
        .filter_map(|e| e.ok().map(|entry| entry.path()))
        .collect();
    entries.sort();

    for path in entries {
        let meta = match fs::symlink_metadata(&path) {
            Ok(m) => m,
            Err(_) => continue,
        };
        // Strictly ignore symlinks to prevent directory escapes and loops.
        if meta.file_type().is_symlink() {
            continue;
        }
        if meta.is_dir() {
            collect_local_files(base, &path, out)?;
        } else if meta.is_file() {
            let Ok(rel) = path.strip_prefix(base) else {
                continue;
            };
            let rel_posix = rel
                .components()
                .filter_map(|c| c.as_os_str().to_str())
                .collect::<Vec<_>>()
                .join("/");
            if rel_posix.is_empty() {
                continue;
            }
            let modified_ms = meta
                .modified()
                .ok()
                .and_then(|t| t.duration_since(UNIX_EPOCH).ok())
                .map(|d| d.as_millis() as u64)
                .unwrap_or(0);
            let fp = ManifestFingerprint {
                size: meta.len(),
                modified_ms,
            };
            out.push((path, rel_posix, fp));
        }
    }
    Ok(())
}

/// Perform a 1-tap incremental `VaultMirror` backup from `source_dir` into an
/// unlocked `Vault`, updating the Zero-Knowledge SHA-256 `manifest` in place.
pub fn run_vault_mirror(
    job_id: &str,
    vault: &Vault,
    source_dir: &Path,
    target_vault_dir: &str,
    manifest: &mut BackupManifest,
) -> Result<BackupRunReport> {
    if !source_dir.is_dir() {
        return Err(VaultError::EntryNotFound);
    }

    let base_vault_dir = normalize_vault_dir(target_vault_dir);
    if base_vault_dir != "/" {
        ensure_vault_dir_chain(vault, &base_vault_dir)?;
    }

    let mut files = Vec::new();
    collect_local_files(source_dir, source_dir, &mut files)?;

    let mut files_synced = 0u64;
    let mut files_skipped = 0u64;
    let mut bytes_processed = 0u64;
    let mut seen_hashes = HashSet::with_capacity(files.len());

    for (disk_path, rel_posix, fp) in files {
        let path_hash = hash_rel_path(&rel_posix);
        seen_hashes.insert(path_hash.clone());

        if manifest.entries.get(&path_hash) == Some(&fp) {
            files_skipped = files_skipped.saturating_add(1);
            continue;
        }

        let vault_dst = if base_vault_dir == "/" {
            format!("/{rel_posix}")
        } else {
            format!("{base_vault_dir}/{rel_posix}")
        };

        if let Some((parent_dir, _)) = vault_dst.rsplit_once('/') {
            if !parent_dir.is_empty() {
                ensure_vault_dir_chain(vault, parent_dir)?;
            }
        }

        let written = vault.import_file(&disk_path, &vault_dst, None)?;
        manifest.entries.insert(path_hash, fp);
        files_synced = files_synced.saturating_add(1);
        bytes_processed = bytes_processed.saturating_add(written);
    }

    // Prune hashes of files that no longer exist in source_dir.
    manifest.entries.retain(|k, _| seen_hashes.contains(k));
    manifest.version = MANIFEST_VERSION;

    Ok(BackupRunReport {
        job_id: job_id.to_string(),
        mode: BackupMode::VaultMirror,
        files_synced,
        files_skipped,
        bytes_processed,
        output_path: Some(base_vault_dir),
        completed_unix: now_unix_secs(),
    })
}

/// Perform an atomic `EncryptedSnapshot`: compresses `source_dir` inside an RAII
/// `TempDir` and encrypts it atomically as `<name>-<timestamp>.zip.cvxenc`.
pub fn run_encrypted_snapshot(
    job_id: &str,
    name: &str,
    source_dir: &Path,
    output_dir: &Path,
    password: &str,
    suite: CipherSuite,
    kdf_params: Argon2Params,
) -> Result<BackupRunReport> {
    if !source_dir.is_dir() {
        return Err(VaultError::EntryNotFound);
    }
    kdf_params.validate()?;
    fs::create_dir_all(output_dir)?;

    let temp_dir = TempDir::new()?;
    let tmp_zip = temp_dir.path().join("snapshot.zip");
    let zip_report = compress_paths_to_zip(&[source_dir.to_path_buf()], &tmp_zip)?;

    let now = now_unix_secs();
    let stem = sanitize_snapshot_stem(name);
    let ts = format_utc_timestamp(now);
    let final_path = output_dir.join(format!("{stem}-{ts}.zip.cvxenc"));

    let encrypted_bytes =
        encrypt_standalone_file(&tmp_zip, &final_path, password, suite, kdf_params)?;

    // temp_dir drops here, cleaning up the intermediate snapshot.zip automatically.
    Ok(BackupRunReport {
        job_id: job_id.to_string(),
        mode: BackupMode::EncryptedSnapshot,
        files_synced: zip_report.entries,
        files_skipped: 0,
        bytes_processed: encrypted_bytes,
        output_path: Some(final_path.to_string_lossy().to_string()),
        completed_unix: now,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::archive::extract_archive;
    use crate::standalone::decrypt_standalone_file;

    #[test]
    fn vault_mirror_incremental_diff_and_zk_manifest() {
        let tmp = TempDir::new().unwrap();
        let src = tmp.path().join("docs");
        fs::create_dir_all(src.join("sub")).unwrap();
        fs::write(src.join("secret-report.txt"), b"initial-synthetic-content").unwrap();
        fs::write(src.join("sub/ledger.csv"), b"id,amount\n1,100\n").unwrap();

        // Create a symlink (on Unix) to verify symlinks are strictly ignored.
        #[cfg(unix)]
        {
            std::os::unix::fs::symlink(src.join("secret-report.txt"), src.join("link.txt"))
                .unwrap();
        }

        let vault_root = tmp.path().join("vault");
        let (vault, _) = Vault::create(
            &vault_root,
            "synthetic-backup-pass-2026",
            CipherSuite::XChaCha20Poly1305,
            Argon2Params::mobile(),
        )
        .unwrap();

        let mut manifest = BackupManifest::default();

        // Run 1: initial mirror syncs 2 regular files and ignores symlink.
        let r1 = run_vault_mirror("job-1", &vault, &src, "/Backups/Docs", &mut manifest).unwrap();
        assert_eq!(r1.files_synced, 2);
        assert_eq!(r1.files_skipped, 0);
        assert_eq!(manifest.entries.len(), 2);

        // Verify Zero-Knowledge manifest: zero plaintext filenames in serialized JSON.
        let manifest_json = serde_json::to_string_pretty(&manifest).unwrap();
        assert!(!manifest_json.contains("secret-report"));
        assert!(!manifest_json.contains("ledger.csv"));
        assert!(!manifest_json.contains("sub/"));
        for key in manifest.entries.keys() {
            assert_eq!(key.len(), 64);
            assert!(key.chars().all(|c| c.is_ascii_hexdigit()));
        }

        // Run 2: unchanged source -> 0 synced, 2 skipped.
        let r2 = run_vault_mirror("job-1", &vault, &src, "/Backups/Docs", &mut manifest).unwrap();
        assert_eq!(r2.files_synced, 0);
        assert_eq!(r2.files_skipped, 2);

        // Modify 1 file (different size) and add 1 new file -> 2 synced, 1 skipped.
        fs::write(
            src.join("secret-report.txt"),
            b"updated-synthetic-content-v2-longer",
        )
        .unwrap();
        fs::write(src.join("notes.md"), b"# Synthetic Notes").unwrap();

        let r3 = run_vault_mirror("job-1", &vault, &src, "/Backups/Docs", &mut manifest).unwrap();
        assert_eq!(r3.files_synced, 2);
        assert_eq!(r3.files_skipped, 1);
        assert_eq!(manifest.entries.len(), 3);

        // Verify decrypted contents inside the vault match latest files.
        let updated_bytes = vault
            .read_file_bytes("/Backups/Docs/secret-report.txt", 1024 * 1024)
            .unwrap();
        assert_eq!(updated_bytes, b"updated-synthetic-content-v2-longer");
        let notes_bytes = vault
            .read_file_bytes("/Backups/Docs/notes.md", 1024 * 1024)
            .unwrap();
        assert_eq!(notes_bytes, b"# Synthetic Notes");
    }

    #[test]
    fn encrypted_snapshot_roundtrip_and_atomic_output() {
        let tmp = TempDir::new().unwrap();
        let src = tmp.path().join("project-data");
        fs::create_dir_all(src.join("deep")).unwrap();
        fs::write(src.join("readme.txt"), b"synthetic-snapshot-readme").unwrap();
        fs::write(src.join("deep/payload.bin"), [0xA5u8; 2048]).unwrap();

        let out_dir = tmp.path().join("cloud-sync-out");
        let pw = "snapshot-passphrase-2026";
        let report = run_encrypted_snapshot(
            "snap-1",
            "My Snapshot",
            &src,
            &out_dir,
            pw,
            CipherSuite::Aes256Gcm,
            Argon2Params::mobile(),
        )
        .unwrap();

        let output_path = PathBuf::from(report.output_path.unwrap());
        assert!(output_path.is_file());
        let fname = output_path.file_name().unwrap().to_str().unwrap();
        assert!(fname.starts_with("My-Snapshot-"));
        assert!(fname.ends_with(".zip.cvxenc"));

        // Decrypt snapshot and extract archive to verify full roundtrip integrity.
        let dec_zip = tmp.path().join("restored.zip");
        decrypt_standalone_file(&output_path, &dec_zip, pw).unwrap();
        let restored_dir = tmp.path().join("restored-files");
        extract_archive(&dec_zip, &restored_dir).unwrap();

        assert_eq!(
            fs::read(restored_dir.join("project-data/readme.txt")).unwrap(),
            b"synthetic-snapshot-readme"
        );
        assert_eq!(
            fs::read(restored_dir.join("project-data/deep/payload.bin")).unwrap(),
            vec![0xA5u8; 2048]
        );
    }
}
