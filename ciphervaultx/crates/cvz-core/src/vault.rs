use std::fs::{self, File};
use std::io::{BufReader, Read, Write};
use std::path::{Path, PathBuf};
use std::time::UNIX_EPOCH;

use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine;
use serde::{Deserialize, Serialize};
use unicode_normalization::UnicodeNormalization;

use crate::config::{
    decode_salt_32, encode_b64, CipherSuite, KeySlot, VaultConfig, CONFIG_BACKUP_FILENAME,
    CONFIG_FILENAME, DEFAULT_CHUNK_SIZE, FORMAT_VERSION,
};
use crate::error::{Result, VaultError};
use crate::fsio::{atomic_write_bytes, atomic_write_with, is_temp_file_name, sync_dir};
use crate::kdf::{derive_kek, validate_password_policy, Argon2Params};
use crate::keys::VaultKeys;
use crate::names::{
    decrypt_name, dir_storage_path, encrypt_name, split_vault_path, validate_and_normalize_name,
};
use crate::recovery::RecoveryKey;
use crate::seal::{open_bytes, seal_bytes};
use crate::secret::{random_array, Key32};
use crate::stream::{decrypt_stream, encrypt_stream, plaintext_len, verify_stream};

const DIR_MARKER_FILE: &str = "dir.cvz";
const DIR_MARKER_PENDING: &str = "dir.cvz.pending";
const DIR_MARKER_AAD_PREFIX: &[u8] = b"cvz-dirmarker-v1\0";

pub type ProgressCallback<'a> = &'a mut dyn FnMut(u64, u64);

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum EntryKind {
    File,
    Directory,
    Unreadable,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct VaultEntry {
    pub name: String,
    pub path: String,
    pub kind: EntryKind,
    pub size: u64,
    pub modified_ms: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct VaultSummary {
    pub vault_id: String,
    pub suite: CipherSuite,
    pub chunk_size: u32,
    pub format: u32,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct IntegrityIssue {
    pub path: String,
    pub reason: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct IntegrityReport {
    pub files_checked: u64,
    pub dirs_checked: u64,
    pub issues: Vec<IntegrityIssue>,
}

pub struct Vault {
    root: PathBuf,
    config: VaultConfig,
    vault_id: [u8; 16],
    master_key: Key32,
    keys: VaultKeys,
}

impl Vault {
    pub fn create(
        root: &Path,
        password: &str,
        suite: CipherSuite,
        kdf_params: Argon2Params,
    ) -> Result<(Self, RecoveryKey)> {
        validate_password_policy(password)?;
        kdf_params.validate()?;

        if root.exists() {
            if !root.is_dir() {
                return Err(VaultError::NonEmptyDirectory);
            }
            if fs::read_dir(root)?.next().is_some() {
                return Err(VaultError::NonEmptyDirectory);
            }
        } else {
            fs::create_dir_all(root)?;
        }

        let vault_id = random_array::<16>();
        let master_key = Key32::random();
        let recovery_key = RecoveryKey::generate();
        let salt = random_array::<32>();

        let mut config = VaultConfig {
            format: FORMAT_VERSION,
            vault_id: encode_b64(&vault_id),
            suite,
            chunk_size: DEFAULT_CHUNK_SIZE,
            slots: Vec::new(),
        };

        let pw_kek = derive_kek(password.as_bytes(), &salt, kdf_params)?;
        let pw_sealed =
            config.wrap_master_key(&pw_kek, &master_key, "password", &kdf_params.to_aad_bytes())?;
        config.slots.push(KeySlot::Password {
            salt: encode_b64(&salt),
            kdf: kdf_params,
            sealed: pw_sealed,
        });

        let rec_kek = recovery_key.derive_kek(&vault_id)?;
        let rec_sealed = config.wrap_master_key(&rec_kek, &master_key, "recovery", &[])?;
        config.slots.push(KeySlot::Recovery { sealed: rec_sealed });

        let keys = VaultKeys::derive(&master_key, &vault_id)?;
        let root_storage = dir_storage_path(root, &keys.dir_hash, "")?;
        fs::create_dir_all(&root_storage)?;

        write_config_with_backup(root, &config)?;

        let vault = Self {
            root: root.to_path_buf(),
            config,
            vault_id,
            master_key,
            keys,
        };
        Ok((vault, recovery_key))
    }

    pub fn unlock_with_password(root: &Path, password: &str) -> Result<Self> {
        let config = load_config_with_backup(root)?;
        let vault_id = config.vault_id_bytes()?;

        for slot in &config.slots {
            if let KeySlot::Password { salt, kdf, sealed } = slot {
                kdf.validate()?;
                let salt_bytes = decode_salt_32(salt)?;
                let kek = derive_kek(password.as_bytes(), &salt_bytes, *kdf)?;
                if let Ok(master_key) =
                    config.unwrap_master_key(&kek, sealed, "password", &kdf.to_aad_bytes())
                {
                    let keys = VaultKeys::derive(&master_key, &vault_id)?;
                    return Ok(Self {
                        root: root.to_path_buf(),
                        config,
                        vault_id,
                        master_key,
                        keys,
                    });
                }
            }
        }
        Err(VaultError::InvalidCredentials)
    }

    pub fn unlock_with_recovery(root: &Path, recovery_key: &RecoveryKey) -> Result<Self> {
        let config = load_config_with_backup(root)?;
        let vault_id = config.vault_id_bytes()?;
        let rec_kek = recovery_key.derive_kek(&vault_id)?;

        for slot in &config.slots {
            if let KeySlot::Recovery { sealed } = slot {
                if let Ok(master_key) = config.unwrap_master_key(&rec_kek, sealed, "recovery", &[])
                {
                    let keys = VaultKeys::derive(&master_key, &vault_id)?;
                    return Ok(Self {
                        root: root.to_path_buf(),
                        config,
                        vault_id,
                        master_key,
                        keys,
                    });
                }
            }
        }
        Err(VaultError::InvalidCredentials)
    }

    pub fn reset_password_with_recovery(
        root: &Path,
        recovery_key: &RecoveryKey,
        new_password: &str,
        kdf_params: Argon2Params,
    ) -> Result<Self> {
        validate_password_policy(new_password)?;
        kdf_params.validate()?;

        let mut vault = Self::unlock_with_recovery(root, recovery_key)?;
        vault.replace_password_slot(new_password, kdf_params)?;
        Ok(vault)
    }

    pub fn change_password(
        &mut self,
        current_password: &str,
        new_password: &str,
        kdf_params: Argon2Params,
    ) -> Result<()> {
        validate_password_policy(new_password)?;
        kdf_params.validate()?;

        // Verify current password against existing password slot.
        let mut verified = false;
        for slot in &self.config.slots {
            if let KeySlot::Password { salt, kdf, sealed } = slot {
                let salt_bytes = decode_salt_32(salt)?;
                let kek = derive_kek(current_password.as_bytes(), &salt_bytes, *kdf)?;
                if self
                    .config
                    .unwrap_master_key(&kek, sealed, "password", &kdf.to_aad_bytes())
                    .is_ok()
                {
                    verified = true;
                    break;
                }
            }
        }
        if !verified {
            return Err(VaultError::InvalidCredentials);
        }

        self.replace_password_slot(new_password, kdf_params)
    }

    fn replace_password_slot(
        &mut self,
        new_password: &str,
        kdf_params: Argon2Params,
    ) -> Result<()> {
        let salt = random_array::<32>();
        let pw_kek = derive_kek(new_password.as_bytes(), &salt, kdf_params)?;
        let pw_sealed = self.config.wrap_master_key(
            &pw_kek,
            &self.master_key,
            "password",
            &kdf_params.to_aad_bytes(),
        )?;

        self.config
            .slots
            .retain(|s| !matches!(s, KeySlot::Password { .. }));
        self.config.slots.insert(
            0,
            KeySlot::Password {
                salt: encode_b64(&salt),
                kdf: kdf_params,
                sealed: pw_sealed,
            },
        );
        write_config_with_backup(&self.root, &self.config)
    }

    #[cfg(feature = "pq")]
    pub fn add_hybrid_pq_slot(&mut self, label: &str, recipient_public: &[u8]) -> Result<()> {
        let enc = crate::pq::encapsulate_kek(recipient_public, &self.vault_id, label)?;
        let sealed = self.config.wrap_master_key(
            &enc.kek,
            &self.master_key,
            "hybrid-pq",
            label.as_bytes(),
        )?;
        self.config.slots.push(KeySlot::HybridPq {
            label: label.to_string(),
            x25519_epk: encode_b64(&enc.x25519_epk),
            mlkem_ct: encode_b64(&enc.mlkem_ct),
            sealed,
        });
        write_config_with_backup(&self.root, &self.config)
    }

    #[cfg(feature = "pq")]
    pub fn unlock_with_hybrid_pq(
        root: &Path,
        label: &str,
        keypair: &crate::pq::HybridPqKeypair,
    ) -> Result<Self> {
        let config = load_config_with_backup(root)?;
        let vault_id = config.vault_id_bytes()?;

        for slot in &config.slots {
            if let KeySlot::HybridPq {
                label: slot_label,
                x25519_epk,
                mlkem_ct,
                sealed,
            } = slot
            {
                if slot_label != label {
                    continue;
                }
                let epk_raw = crate::config::decode_b64(x25519_epk)?;
                let epk_arr: [u8; 32] = epk_raw
                    .try_into()
                    .map_err(|_| VaultError::InvalidCredentials)?;
                let ct_raw = crate::config::decode_b64(mlkem_ct)?;
                let kek = keypair.decapsulate_kek(&vault_id, slot_label, &epk_arr, &ct_raw)?;
                if let Ok(master_key) =
                    config.unwrap_master_key(&kek, sealed, "hybrid-pq", slot_label.as_bytes())
                {
                    let keys = VaultKeys::derive(&master_key, &vault_id)?;
                    return Ok(Self {
                        root: root.to_path_buf(),
                        config,
                        vault_id,
                        master_key,
                        keys,
                    });
                }
            }
        }
        Err(VaultError::InvalidCredentials)
    }

    pub fn root(&self) -> &Path {
        &self.root
    }

    pub fn summary(&self) -> VaultSummary {
        VaultSummary {
            vault_id: self.config.vault_id.clone(),
            suite: self.config.suite,
            chunk_size: self.config.chunk_size,
            format: self.config.format,
        }
    }

    pub fn config(&self) -> &VaultConfig {
        &self.config
    }

    pub fn list_dir(&self, virtual_path: &str) -> Result<Vec<VaultEntry>> {
        let parts = split_vault_path(virtual_path)?;
        let dir_id = self.resolve_dir_id(&parts)?;
        let storage_dir = dir_storage_path(&self.root, &self.keys.dir_hash, &dir_id)?;
        let base_prefix = if parts.is_empty() {
            String::new()
        } else {
            format!("/{}", parts.join("/"))
        };

        let mut entries = Vec::new();
        for item in fs::read_dir(&storage_dir)? {
            let item = item?;
            let raw_name = item.file_name().to_string_lossy().to_string();
            if is_temp_file_name(&raw_name) {
                continue;
            }
            let meta = item.metadata()?;
            let modified_ms = meta
                .modified()
                .ok()
                .and_then(|t| t.duration_since(UNIX_EPOCH).ok())
                .map(|d| d.as_millis() as u64)
                .unwrap_or(0);

            match decrypt_name(&self.keys.name_siv, &dir_id, &raw_name) {
                Ok((plain_name, is_dir)) => {
                    let entry_path = format!("{base_prefix}/{plain_name}");
                    if is_dir {
                        // Authenticate directory marker; failure is a hard error, never hidden.
                        let _child_id = self.read_dir_marker(&item.path(), &dir_id, &raw_name)?;
                        entries.push(VaultEntry {
                            name: plain_name,
                            path: entry_path,
                            kind: EntryKind::Directory,
                            size: 0,
                            modified_ms,
                        });
                    } else {
                        let size = plaintext_len(meta.len(), self.config.chunk_size).unwrap_or(0);
                        entries.push(VaultEntry {
                            name: plain_name,
                            path: entry_path,
                            kind: EntryKind::File,
                            size,
                            modified_ms,
                        });
                    }
                }
                Err(_) => {
                    entries.push(VaultEntry {
                        name: raw_name.clone(),
                        path: format!("{base_prefix}/{raw_name}"),
                        kind: EntryKind::Unreadable,
                        size: 0,
                        modified_ms,
                    });
                }
            }
        }

        entries.sort_by(|a, b| {
            let kind_ord = |k: EntryKind| match k {
                EntryKind::Directory => 0,
                EntryKind::File => 1,
                EntryKind::Unreadable => 2,
            };
            kind_ord(a.kind)
                .cmp(&kind_ord(b.kind))
                .then_with(|| a.name.to_lowercase().cmp(&b.name.to_lowercase()))
        });
        Ok(entries)
    }

    pub fn create_dir(&self, virtual_path: &str) -> Result<()> {
        let parts = split_vault_path(virtual_path)?;
        let (name, parent_parts) = parts.split_last().ok_or(VaultError::InvalidName)?;
        let parent_dir_id = self.resolve_dir_id(parent_parts)?;
        let parent_storage = dir_storage_path(&self.root, &self.keys.dir_hash, &parent_dir_id)?;

        let enc_dir_name = encrypt_name(&self.keys.name_siv, &parent_dir_id, name, true)?;
        let enc_file_name = encrypt_name(&self.keys.name_siv, &parent_dir_id, name, false)?;
        let marker_folder = parent_storage.join(&enc_dir_name);
        if marker_folder.exists() || parent_storage.join(&enc_file_name).exists() {
            return Err(VaultError::AlreadyExists);
        }

        let new_dir_id = URL_SAFE_NO_PAD.encode(random_array::<18>());
        let child_storage = dir_storage_path(&self.root, &self.keys.dir_hash, &new_dir_id)?;
        fs::create_dir_all(&child_storage)?;
        fs::create_dir_all(&marker_folder)?;

        self.write_dir_marker(
            &marker_folder.join(DIR_MARKER_FILE),
            &parent_dir_id,
            &enc_dir_name,
            &new_dir_id,
        )?;
        sync_dir(&parent_storage)?;
        Ok(())
    }

    pub fn import_file(
        &self,
        src_path: &Path,
        dst_vault_path: &str,
        mut progress: Option<ProgressCallback<'_>>,
    ) -> Result<u64> {
        let parts = split_vault_path(dst_vault_path)?;
        let (name, parent_parts) = parts.split_last().ok_or(VaultError::InvalidName)?;
        let parent_dir_id = self.resolve_dir_id(parent_parts)?;
        let parent_storage = dir_storage_path(&self.root, &self.keys.dir_hash, &parent_dir_id)?;

        let enc_file_name = encrypt_name(&self.keys.name_siv, &parent_dir_id, name, false)?;
        let enc_dir_name = encrypt_name(&self.keys.name_siv, &parent_dir_id, name, true)?;
        if parent_storage.join(&enc_dir_name).exists() {
            return Err(VaultError::AlreadyExists);
        }

        let total_size = fs::metadata(src_path)?.len();
        let src_file = File::open(src_path)?;
        let mut reader = BufReader::new(src_file);
        let dst_disk = parent_storage.join(&enc_file_name);

        let suite = self.config.suite;
        let chunk_size = self.config.chunk_size;
        let vault_id = self.vault_id;
        let file_header_key = &self.keys.file_header;

        atomic_write_with(&dst_disk, |writer| {
            encrypt_stream(
                &mut reader,
                writer,
                suite,
                chunk_size,
                &vault_id,
                file_header_key,
                |done| {
                    if let Some(cb) = progress.as_deref_mut() {
                        cb(done, total_size);
                    }
                },
            )
        })
    }

    pub fn export_file(
        &self,
        src_vault_path: &str,
        dst_path: &Path,
        mut progress: Option<ProgressCallback<'_>>,
    ) -> Result<u64> {
        if is_path_inside_vault(&self.root, dst_path)? {
            return Err(VaultError::ExportInsideVault);
        }

        let parts = split_vault_path(src_vault_path)?;
        let (name, parent_parts) = parts.split_last().ok_or(VaultError::EntryNotFound)?;
        let parent_dir_id = self.resolve_dir_id(parent_parts)?;
        let parent_storage = dir_storage_path(&self.root, &self.keys.dir_hash, &parent_dir_id)?;

        let enc_file_name = encrypt_name(&self.keys.name_siv, &parent_dir_id, name, false)?;
        let src_disk = parent_storage.join(&enc_file_name);
        if !src_disk.is_file() {
            return Err(VaultError::EntryNotFound);
        }

        let ct_len = fs::metadata(&src_disk)?.len();
        let expected_plain = plaintext_len(ct_len, self.config.chunk_size).unwrap_or(0);
        let src_file = File::open(&src_disk)?;
        let mut reader = BufReader::new(src_file);

        let chunk_size = self.config.chunk_size;
        let vault_id = self.vault_id;
        let file_header_key = &self.keys.file_header;

        atomic_write_with(dst_path, |writer| {
            decrypt_stream(
                &mut reader,
                writer,
                chunk_size,
                &vault_id,
                file_header_key,
                |done| {
                    if let Some(cb) = progress.as_deref_mut() {
                        cb(done, expected_plain);
                    }
                },
            )
        })
    }

    pub fn root_path(&self) -> &Path {
        &self.root
    }

    /// Stream-decrypt a vault file directly into any `Write` sink without
    /// staging intermediate plaintext on disk.
    pub fn export_file_to_writer<W: Write>(
        &self,
        src_vault_path: &str,
        writer: &mut W,
    ) -> Result<u64> {
        let parts = split_vault_path(src_vault_path)?;
        let (name, parent_parts) = parts.split_last().ok_or(VaultError::EntryNotFound)?;
        let parent_dir_id = self.resolve_dir_id(parent_parts)?;
        let parent_storage = dir_storage_path(&self.root, &self.keys.dir_hash, &parent_dir_id)?;

        let enc_file_name = encrypt_name(&self.keys.name_siv, &parent_dir_id, name, false)?;
        let src_disk = parent_storage.join(&enc_file_name);
        if !src_disk.is_file() {
            return Err(VaultError::EntryNotFound);
        }

        let src_file = File::open(&src_disk)?;
        let mut reader = BufReader::new(src_file);
        decrypt_stream(
            &mut reader,
            writer,
            self.config.chunk_size,
            &self.vault_id,
            &self.keys.file_header,
            |_| {},
        )
    }

    pub fn read_file_bytes(&self, src_vault_path: &str, max_bytes: u64) -> Result<Vec<u8>> {
        let parts = split_vault_path(src_vault_path)?;
        let (name, parent_parts) = parts.split_last().ok_or(VaultError::EntryNotFound)?;
        let parent_dir_id = self.resolve_dir_id(parent_parts)?;
        let parent_storage = dir_storage_path(&self.root, &self.keys.dir_hash, &parent_dir_id)?;

        let enc_file_name = encrypt_name(&self.keys.name_siv, &parent_dir_id, name, false)?;
        let src_disk = parent_storage.join(&enc_file_name);
        if !src_disk.is_file() {
            return Err(VaultError::EntryNotFound);
        }
        let ct_len = fs::metadata(&src_disk)?.len();
        let plain_len = plaintext_len(ct_len, self.config.chunk_size)?;
        if plain_len > max_bytes {
            return Err(VaultError::Integrity);
        }

        let mut reader = BufReader::new(File::open(&src_disk)?);
        let mut out = Vec::with_capacity(plain_len as usize);
        decrypt_stream(
            &mut reader,
            &mut out,
            self.config.chunk_size,
            &self.vault_id,
            &self.keys.file_header,
            |_| {},
        )?;
        Ok(out)
    }

    pub fn stat_entry(&self, virtual_path: &str) -> Result<VaultEntry> {
        let parts = split_vault_path(virtual_path)?;
        if parts.is_empty() {
            let root_storage = dir_storage_path(&self.root, &self.keys.dir_hash, "")?;
            let modified_ms = fs::metadata(&root_storage)
                .ok()
                .and_then(|m| m.modified().ok())
                .and_then(|t| t.duration_since(UNIX_EPOCH).ok())
                .map(|d| d.as_millis() as u64)
                .unwrap_or(0);
            return Ok(VaultEntry {
                name: String::new(),
                path: "/".to_string(),
                kind: EntryKind::Directory,
                size: 0,
                modified_ms,
            });
        }

        let (name, parent_parts) = parts.split_last().ok_or(VaultError::EntryNotFound)?;
        let parent_dir_id = self.resolve_dir_id(parent_parts)?;
        let parent_storage = dir_storage_path(&self.root, &self.keys.dir_hash, &parent_dir_id)?;
        let full_path = format!("/{}", parts.join("/"));

        let enc_file = encrypt_name(&self.keys.name_siv, &parent_dir_id, name, false)?;
        let file_disk = parent_storage.join(&enc_file);
        if file_disk.is_file() {
            let meta = fs::metadata(&file_disk)?;
            let size = plaintext_len(meta.len(), self.config.chunk_size).unwrap_or(0);
            let modified_ms = meta
                .modified()
                .ok()
                .and_then(|t| t.duration_since(UNIX_EPOCH).ok())
                .map(|d| d.as_millis() as u64)
                .unwrap_or(0);
            return Ok(VaultEntry {
                name: name.clone(),
                path: full_path,
                kind: EntryKind::File,
                size,
                modified_ms,
            });
        }

        let enc_dir = encrypt_name(&self.keys.name_siv, &parent_dir_id, name, true)?;
        let dir_disk = parent_storage.join(&enc_dir);
        if dir_disk.is_dir() {
            let _child_id = self.read_dir_marker(&dir_disk, &parent_dir_id, &enc_dir)?;
            let meta = fs::metadata(&dir_disk)?;
            let modified_ms = meta
                .modified()
                .ok()
                .and_then(|t| t.duration_since(UNIX_EPOCH).ok())
                .map(|d| d.as_millis() as u64)
                .unwrap_or(0);
            return Ok(VaultEntry {
                name: name.clone(),
                path: full_path,
                kind: EntryKind::Directory,
                size: 0,
                modified_ms,
            });
        }

        Err(VaultError::EntryNotFound)
    }

    pub fn write_file_from_reader<R: Read>(
        &self,
        dst_vault_path: &str,
        reader: &mut R,
    ) -> Result<u64> {
        let parts = split_vault_path(dst_vault_path)?;
        let (name, parent_parts) = parts.split_last().ok_or(VaultError::InvalidName)?;
        let parent_dir_id = self.resolve_dir_id(parent_parts)?;
        let parent_storage = dir_storage_path(&self.root, &self.keys.dir_hash, &parent_dir_id)?;

        let enc_file_name = encrypt_name(&self.keys.name_siv, &parent_dir_id, name, false)?;
        let enc_dir_name = encrypt_name(&self.keys.name_siv, &parent_dir_id, name, true)?;
        if parent_storage.join(&enc_dir_name).exists() {
            return Err(VaultError::AlreadyExists);
        }

        let dst_disk = parent_storage.join(&enc_file_name);
        let suite = self.config.suite;
        let chunk_size = self.config.chunk_size;
        let vault_id = self.vault_id;
        let file_header_key = &self.keys.file_header;

        atomic_write_with(&dst_disk, |writer| {
            encrypt_stream(
                reader,
                writer,
                suite,
                chunk_size,
                &vault_id,
                file_header_key,
                |_| {},
            )
        })
    }

    pub fn read_file_to_writer<W: Write>(
        &self,
        src_vault_path: &str,
        writer: &mut W,
    ) -> Result<u64> {
        let parts = split_vault_path(src_vault_path)?;
        let (name, parent_parts) = parts.split_last().ok_or(VaultError::EntryNotFound)?;
        let parent_dir_id = self.resolve_dir_id(parent_parts)?;
        let parent_storage = dir_storage_path(&self.root, &self.keys.dir_hash, &parent_dir_id)?;

        let enc_file_name = encrypt_name(&self.keys.name_siv, &parent_dir_id, name, false)?;
        let src_disk = parent_storage.join(&enc_file_name);
        if !src_disk.is_file() {
            return Err(VaultError::EntryNotFound);
        }

        let mut reader = BufReader::new(File::open(&src_disk)?);
        decrypt_stream(
            &mut reader,
            writer,
            self.config.chunk_size,
            &self.vault_id,
            &self.keys.file_header,
            |_| {},
        )
    }

    pub fn rename_entry(&self, src_vault_path: &str, new_name: &str) -> Result<()> {
        let new_name_norm = validate_and_normalize_name(new_name)?;
        let parts = split_vault_path(src_vault_path)?;
        let (old_name, parent_parts) = parts.split_last().ok_or(VaultError::EntryNotFound)?;
        if old_name == &new_name_norm {
            return Ok(());
        }
        let parent_dir_id = self.resolve_dir_id(parent_parts)?;
        let parent_storage = dir_storage_path(&self.root, &self.keys.dir_hash, &parent_dir_id)?;

        self.relocate_entry(
            &parent_dir_id,
            &parent_storage,
            old_name,
            &parent_dir_id,
            &parent_storage,
            &new_name_norm,
        )
    }

    pub fn move_entry(&self, src_vault_path: &str, dst_dir_vault_path: &str) -> Result<()> {
        let src_parts = split_vault_path(src_vault_path)?;
        let (name, src_parent_parts) = src_parts.split_last().ok_or(VaultError::EntryNotFound)?;
        let dst_parts = split_vault_path(dst_dir_vault_path)?;

        // Prevent moving a folder into itself or its own subtree.
        if dst_parts.len() >= src_parts.len() && dst_parts[..src_parts.len()] == src_parts[..] {
            return Err(VaultError::InvalidMoveTarget);
        }

        let src_parent_id = self.resolve_dir_id(src_parent_parts)?;
        let dst_parent_id = self.resolve_dir_id(&dst_parts)?;
        if src_parent_id == dst_parent_id {
            return Ok(());
        }

        let src_parent_storage = dir_storage_path(&self.root, &self.keys.dir_hash, &src_parent_id)?;
        let dst_parent_storage = dir_storage_path(&self.root, &self.keys.dir_hash, &dst_parent_id)?;

        self.relocate_entry(
            &src_parent_id,
            &src_parent_storage,
            name,
            &dst_parent_id,
            &dst_parent_storage,
            name,
        )
    }

    fn relocate_entry(
        &self,
        src_parent_id: &str,
        src_parent_storage: &Path,
        old_name: &str,
        dst_parent_id: &str,
        dst_parent_storage: &Path,
        new_name: &str,
    ) -> Result<()> {
        let old_enc_file = encrypt_name(&self.keys.name_siv, src_parent_id, old_name, false)?;
        let old_enc_dir = encrypt_name(&self.keys.name_siv, src_parent_id, old_name, true)?;
        let old_file_path = src_parent_storage.join(&old_enc_file);
        let old_dir_path = src_parent_storage.join(&old_enc_dir);

        let new_enc_file = encrypt_name(&self.keys.name_siv, dst_parent_id, new_name, false)?;
        let new_enc_dir = encrypt_name(&self.keys.name_siv, dst_parent_id, new_name, true)?;
        if dst_parent_storage.join(&new_enc_file).exists()
            || dst_parent_storage.join(&new_enc_dir).exists()
        {
            return Err(VaultError::AlreadyExists);
        }

        if old_file_path.is_file() {
            fs::rename(&old_file_path, dst_parent_storage.join(&new_enc_file))?;
            sync_dir(dst_parent_storage)?;
            if src_parent_storage != dst_parent_storage {
                sync_dir(src_parent_storage)?;
            }
            return Ok(());
        }

        if old_dir_path.is_dir() {
            let child_dir_id = self.read_dir_marker(&old_dir_path, src_parent_id, &old_enc_dir)?;
            let new_dir_path = dst_parent_storage.join(&new_enc_dir);

            // Crash-safe directory move:
            // 1. Write new authenticated marker to dir.cvz.pending inside source folder.
            // 2. Rename source folder to destination folder.
            // 3. Rename dir.cvz.pending -> dir.cvz inside destination folder.
            let pending_src = old_dir_path.join(DIR_MARKER_PENDING);
            self.write_dir_marker(&pending_src, dst_parent_id, &new_enc_dir, &child_dir_id)?;
            fs::rename(&old_dir_path, &new_dir_path)?;
            fs::rename(
                new_dir_path.join(DIR_MARKER_PENDING),
                new_dir_path.join(DIR_MARKER_FILE),
            )?;
            sync_dir(&new_dir_path)?;
            sync_dir(dst_parent_storage)?;
            if src_parent_storage != dst_parent_storage {
                sync_dir(src_parent_storage)?;
            }
            return Ok(());
        }

        Err(VaultError::EntryNotFound)
    }

    pub fn delete_entry(&self, virtual_path: &str) -> Result<()> {
        let parts = split_vault_path(virtual_path)?;
        let (name, parent_parts) = parts.split_last().ok_or(VaultError::EntryNotFound)?;
        let parent_dir_id = self.resolve_dir_id(parent_parts)?;
        let parent_storage = dir_storage_path(&self.root, &self.keys.dir_hash, &parent_dir_id)?;

        let enc_file = encrypt_name(&self.keys.name_siv, &parent_dir_id, name, false)?;
        let file_path = parent_storage.join(&enc_file);
        if file_path.is_file() {
            fs::remove_file(&file_path)?;
            sync_dir(&parent_storage)?;
            return Ok(());
        }

        let enc_dir = encrypt_name(&self.keys.name_siv, &parent_dir_id, name, true)?;
        let marker_folder = parent_storage.join(&enc_dir);
        if marker_folder.is_dir() {
            let child_dir_id = self.read_dir_marker(&marker_folder, &parent_dir_id, &enc_dir)?;
            self.delete_dir_recursive(&child_dir_id)?;
            fs::remove_dir_all(&marker_folder)?;
            sync_dir(&parent_storage)?;
            return Ok(());
        }

        Err(VaultError::EntryNotFound)
    }

    fn delete_dir_recursive(&self, dir_id: &str) -> Result<()> {
        let storage = dir_storage_path(&self.root, &self.keys.dir_hash, dir_id)?;
        if !storage.is_dir() {
            return Ok(());
        }
        for item in fs::read_dir(&storage)? {
            let item = item?;
            let raw_name = item.file_name().to_string_lossy().to_string();
            if is_temp_file_name(&raw_name) {
                continue;
            }
            if raw_name.ends_with(".cvzd") && item.path().is_dir() {
                if let Ok(sub_id) = self.read_dir_marker(&item.path(), dir_id, &raw_name) {
                    self.delete_dir_recursive(&sub_id)?;
                }
            }
        }
        fs::remove_dir_all(&storage)?;
        Ok(())
    }

    pub fn search(&self, query: &str) -> Result<Vec<VaultEntry>> {
        let needle: String = query.nfc().collect::<String>().to_lowercase();
        let mut results = Vec::new();
        self.search_recursive("", "", &needle, &mut results)?;
        Ok(results)
    }

    fn search_recursive(
        &self,
        dir_id: &str,
        prefix: &str,
        needle: &str,
        out: &mut Vec<VaultEntry>,
    ) -> Result<()> {
        let storage = dir_storage_path(&self.root, &self.keys.dir_hash, dir_id)?;
        if !storage.is_dir() {
            return Ok(());
        }
        for item in fs::read_dir(&storage)? {
            let item = item?;
            let raw_name = item.file_name().to_string_lossy().to_string();
            if is_temp_file_name(&raw_name) {
                continue;
            }
            let Ok((plain_name, is_dir)) = decrypt_name(&self.keys.name_siv, dir_id, &raw_name)
            else {
                continue;
            };
            let full_path = format!("{prefix}/{plain_name}");
            let meta = item.metadata()?;
            let modified_ms = meta
                .modified()
                .ok()
                .and_then(|t| t.duration_since(UNIX_EPOCH).ok())
                .map(|d| d.as_millis() as u64)
                .unwrap_or(0);

            if plain_name.to_lowercase().contains(needle) {
                let size = if is_dir {
                    0
                } else {
                    plaintext_len(meta.len(), self.config.chunk_size).unwrap_or(0)
                };
                out.push(VaultEntry {
                    name: plain_name.clone(),
                    path: full_path.clone(),
                    kind: if is_dir {
                        EntryKind::Directory
                    } else {
                        EntryKind::File
                    },
                    size,
                    modified_ms,
                });
            }

            if is_dir {
                if let Ok(child_id) = self.read_dir_marker(&item.path(), dir_id, &raw_name) {
                    self.search_recursive(&child_id, &full_path, needle, out)?;
                }
            }
        }
        Ok(())
    }

    pub fn verify_integrity(&self) -> Result<IntegrityReport> {
        let mut report = IntegrityReport {
            files_checked: 0,
            dirs_checked: 0,
            issues: Vec::new(),
        };
        self.verify_dir_recursive("", "", &mut report)?;
        Ok(report)
    }

    fn verify_dir_recursive(
        &self,
        dir_id: &str,
        prefix: &str,
        report: &mut IntegrityReport,
    ) -> Result<()> {
        report.dirs_checked += 1;
        let storage = dir_storage_path(&self.root, &self.keys.dir_hash, dir_id)?;
        if !storage.is_dir() {
            report.issues.push(IntegrityIssue {
                path: if prefix.is_empty() {
                    "/".to_string()
                } else {
                    prefix.to_string()
                },
                reason: "storage directory missing".to_string(),
            });
            return Ok(());
        }

        for item in fs::read_dir(&storage)? {
            let item = item?;
            let raw_name = item.file_name().to_string_lossy().to_string();
            if is_temp_file_name(&raw_name) {
                continue;
            }
            match decrypt_name(&self.keys.name_siv, dir_id, &raw_name) {
                Ok((plain_name, is_dir)) => {
                    let full_path = format!("{prefix}/{plain_name}");
                    if is_dir {
                        match self.read_dir_marker(&item.path(), dir_id, &raw_name) {
                            Ok(child_id) => {
                                self.verify_dir_recursive(&child_id, &full_path, report)?;
                            }
                            Err(_) => {
                                report.issues.push(IntegrityIssue {
                                    path: full_path,
                                    reason: "directory marker authentication failed".to_string(),
                                });
                            }
                        }
                    } else {
                        report.files_checked += 1;
                        match File::open(item.path()) {
                            Ok(file) => {
                                let mut reader = BufReader::new(file);
                                if verify_stream(
                                    &mut reader,
                                    self.config.chunk_size,
                                    &self.vault_id,
                                    &self.keys.file_header,
                                )
                                .is_err()
                                {
                                    report.issues.push(IntegrityIssue {
                                        path: full_path,
                                        reason: "file header or chunk authentication failed"
                                            .to_string(),
                                    });
                                }
                            }
                            Err(_) => {
                                report.issues.push(IntegrityIssue {
                                    path: full_path,
                                    reason: "unable to read encrypted file".to_string(),
                                });
                            }
                        }
                    }
                }
                Err(_) => {
                    report.issues.push(IntegrityIssue {
                        path: format!("{prefix}/{raw_name}"),
                        reason: "filename authentication failed (unreadable entry)".to_string(),
                    });
                }
            }
        }
        Ok(())
    }

    fn resolve_dir_id(&self, parts: &[String]) -> Result<String> {
        let mut current_id = String::new();
        for comp in parts {
            let storage = dir_storage_path(&self.root, &self.keys.dir_hash, &current_id)?;
            let enc_dir = encrypt_name(&self.keys.name_siv, &current_id, comp, true)?;
            let marker_folder = storage.join(&enc_dir);
            if !marker_folder.is_dir() {
                return Err(VaultError::EntryNotFound);
            }
            current_id = self.read_dir_marker(&marker_folder, &current_id, &enc_dir)?;
        }
        Ok(current_id)
    }

    fn dir_marker_aad(&self, parent_dir_id: &str, encrypted_dir_name: &str) -> Result<Vec<u8>> {
        let parent_bytes = parent_dir_id.as_bytes();
        let parent_len = u32::try_from(parent_bytes.len()).map_err(|_| VaultError::Integrity)?;
        let enc_bytes = encrypted_dir_name.as_bytes();

        let mut aad = Vec::with_capacity(
            DIR_MARKER_AAD_PREFIX.len() + 16 + 4 + parent_bytes.len() + enc_bytes.len(),
        );
        aad.extend_from_slice(DIR_MARKER_AAD_PREFIX);
        aad.extend_from_slice(&self.vault_id);
        aad.extend_from_slice(&parent_len.to_be_bytes());
        aad.extend_from_slice(parent_bytes);
        aad.extend_from_slice(enc_bytes);
        Ok(aad)
    }

    fn write_dir_marker(
        &self,
        marker_file: &Path,
        parent_dir_id: &str,
        encrypted_dir_name: &str,
        child_dir_id: &str,
    ) -> Result<()> {
        let aad = self.dir_marker_aad(parent_dir_id, encrypted_dir_name)?;
        let sealed = seal_bytes(&self.keys.metadata, &aad, child_dir_id.as_bytes())?;
        atomic_write_bytes(marker_file, &sealed)
    }

    fn read_dir_marker(
        &self,
        marker_folder: &Path,
        parent_dir_id: &str,
        encrypted_dir_name: &str,
    ) -> Result<String> {
        let aad = self.dir_marker_aad(parent_dir_id, encrypted_dir_name)?;
        let primary = marker_folder.join(DIR_MARKER_FILE);
        let pending = marker_folder.join(DIR_MARKER_PENDING);

        if let Ok(bytes) = fs::read(&primary) {
            if let Ok(plain) = open_bytes(&self.keys.metadata, &aad, &bytes) {
                if let Ok(id) = String::from_utf8(plain) {
                    return Ok(id);
                }
            }
        }

        // Crash-recovery fallback: if a move crashed after renaming the folder
        // but before renaming dir.cvz.pending -> dir.cvz, verify and promote it.
        if let Ok(bytes) = fs::read(&pending) {
            if let Ok(plain) = open_bytes(&self.keys.metadata, &aad, &bytes) {
                if let Ok(id) = String::from_utf8(plain) {
                    let _ = fs::rename(&pending, &primary);
                    let _ = sync_dir(marker_folder);
                    return Ok(id);
                }
            }
        }

        Err(VaultError::Integrity)
    }
}

fn write_config_with_backup(root: &Path, config: &VaultConfig) -> Result<()> {
    config.validate_policy()?;
    let json = serde_json::to_vec_pretty(config).map_err(|_| VaultError::InvalidConfig)?;
    atomic_write_bytes(&root.join(CONFIG_FILENAME), &json)?;
    atomic_write_bytes(&root.join(CONFIG_BACKUP_FILENAME), &json)?;
    Ok(())
}

fn load_config_with_backup(root: &Path) -> Result<VaultConfig> {
    let primary = root.join(CONFIG_FILENAME);
    let backup = root.join(CONFIG_BACKUP_FILENAME);

    let primary_exists = primary.exists();
    let backup_exists = backup.exists();
    if !primary_exists && !backup_exists {
        return Err(VaultError::NotFound);
    }

    if primary_exists {
        if let Ok(bytes) = fs::read(&primary) {
            if let Ok(cfg) = serde_json::from_slice::<VaultConfig>(&bytes) {
                // Policy violation MUST abort immediately — never fall back to backup.
                cfg.validate_policy()?;
                return Ok(cfg);
            }
        }
    }

    if backup_exists {
        let bytes = fs::read(&backup)?;
        let cfg =
            serde_json::from_slice::<VaultConfig>(&bytes).map_err(|_| VaultError::InvalidConfig)?;
        cfg.validate_policy()?;
        return Ok(cfg);
    }

    Err(VaultError::InvalidConfig)
}

fn is_path_inside_vault(vault_root: &Path, candidate: &Path) -> Result<bool> {
    let canon_root = fs::canonicalize(vault_root)?;
    let canon_candidate = canonicalize_best_effort(candidate)?;
    Ok(canon_candidate.starts_with(&canon_root))
}

fn canonicalize_best_effort(path: &Path) -> Result<PathBuf> {
    if path.exists() {
        return Ok(fs::canonicalize(path)?);
    }
    let abs = if path.is_absolute() {
        path.to_path_buf()
    } else {
        std::env::current_dir()?.join(path)
    };
    let mut missing = Vec::new();
    let mut cur = abs.as_path();
    while !cur.exists() {
        if let Some(name) = cur.file_name() {
            missing.push(name.to_os_string());
        } else {
            break;
        }
        match cur.parent() {
            Some(p) => cur = p,
            None => break,
        }
    }
    let mut base = if cur.exists() {
        fs::canonicalize(cur)?
    } else {
        cur.to_path_buf()
    };
    for part in missing.into_iter().rev() {
        base.push(part);
    }
    Ok(base)
}
