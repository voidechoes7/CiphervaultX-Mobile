//! Read/export interoperability for Cryptomator Vault Format 8 (`SIV_GCM`).
//!
//! Supports:
//! - `vault.cryptomator` (JWT HS256 verified with `encMasterKey || macMasterKey`)
//! - `masterkey.cryptomator` (`scrypt` + RFC 3394 `AES-256-KW` + `versionMac`)
//! - Standard `.c9r` files and directories (`dir.c9r`) as well as `.c9s` shortened entries
//! - 68-byte AES-256-GCM file headers + 32 KiB AES-256-GCM chunks

use std::fs::{self, File};
use std::io::{BufReader, Read, Write};
use std::path::{Path, PathBuf};

use aes_gcm::aead::{Aead, KeyInit, Payload};
use aes_gcm::{Aes256Gcm, Nonce as AesNonce};
use aes_kw::KekAes256;
use aes_siv::siv::Aes256Siv;
use base64::engine::general_purpose::{STANDARD, URL_SAFE, URL_SAFE_NO_PAD};
use base64::Engine;
use data_encoding::BASE32_NOPAD;
use hmac::{Hmac, Mac};
use scrypt::{scrypt, Params as ScryptParams};
use serde::{Deserialize, Serialize};
use sha1::{Digest as Sha1Digest, Sha1};
use sha2::Sha256;
use zeroize::Zeroize;

use crate::error::{Result, VaultError};
use crate::fsio::atomic_write_with;
use crate::secret::{Key32, Key64};
use crate::vault::{EntryKind, VaultEntry};

const CM_HEADER_LEN: usize = 68; // 12 nonce + 40 pt + 16 tag
const CM_CHUNK_PT_MAX: usize = 32_768;
const CM_CHUNK_CT_MAX: usize = 12 + CM_CHUNK_PT_MAX + 16;

type HmacSha256 = Hmac<Sha256>;

#[derive(Debug, Deserialize)]
struct MasterkeyFile {
    version: u32,
    #[serde(rename = "scryptSalt")]
    scrypt_salt: String,
    #[serde(rename = "scryptCostParam")]
    scrypt_cost_param: u32,
    #[serde(rename = "scryptBlockSize")]
    scrypt_block_size: u32,
    #[serde(rename = "primaryMasterKey")]
    primary_master_key: String,
    #[serde(rename = "hmacMasterKey")]
    hmac_master_key: String,
    #[serde(rename = "versionMac")]
    version_mac: String,
}

#[derive(Debug, Deserialize)]
struct VaultJwtPayload {
    format: u32,
    #[serde(rename = "cipherCombo")]
    cipher_combo: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CryptomatorVaultInfo {
    pub path: String,
    pub format: u32,
    pub cipher_combo: String,
}

pub struct CryptomatorVault {
    root: PathBuf,
    enc_key: Key32,
    siv_key: Key64,
    format: u32,
    cipher_combo: String,
}

impl CryptomatorVault {
    pub fn open(root: &Path, password: &str) -> Result<Self> {
        let jwt_path = root.join("vault.cryptomator");
        let mk_path = root.join("masterkey.cryptomator");
        if !jwt_path.is_file() || !mk_path.is_file() {
            return Err(VaultError::NotFound);
        }

        let jwt_raw = fs::read_to_string(&jwt_path)?;
        let mk_raw = fs::read(&mk_path)?;
        let mk: MasterkeyFile =
            serde_json::from_slice(&mk_raw).map_err(|_| VaultError::InvalidConfig)?;

        let salt = STANDARD
            .decode(&mk.scrypt_salt)
            .map_err(|_| VaultError::InvalidConfig)?;
        let log_n = cost_to_log_n(mk.scrypt_cost_param)?;
        let scrypt_params = ScryptParams::new(log_n, mk.scrypt_block_size, 1, 32)
            .map_err(|_| VaultError::InvalidConfig)?;

        let mut kek_bytes = [0u8; 32];
        scrypt(password.as_bytes(), &salt, &scrypt_params, &mut kek_bytes)
            .map_err(|_| VaultError::InvalidConfig)?;
        let kek = KekAes256::from(kek_bytes);
        kek_bytes.zeroize();

        let wrapped_enc = STANDARD
            .decode(&mk.primary_master_key)
            .map_err(|_| VaultError::InvalidConfig)?;
        let wrapped_mac = STANDARD
            .decode(&mk.hmac_master_key)
            .map_err(|_| VaultError::InvalidConfig)?;

        let mut enc_plain = [0u8; 32];
        let mut mac_plain = [0u8; 32];
        kek.unwrap(&wrapped_enc, &mut enc_plain)
            .map_err(|_| VaultError::InvalidCredentials)?;
        kek.unwrap(&wrapped_mac, &mut mac_plain)
            .map_err(|_| VaultError::InvalidCredentials)?;

        // Verify versionMac = HMAC-SHA256(mac_key, version_be_u32).
        let expected_vmac = STANDARD
            .decode(&mk.version_mac)
            .map_err(|_| VaultError::InvalidConfig)?;
        let mut vmac =
            <HmacSha256 as Mac>::new_from_slice(&mac_plain).map_err(|_| VaultError::Integrity)?;
        vmac.update(&mk.version.to_be_bytes());
        if vmac.verify_slice(&expected_vmac).is_err() {
            enc_plain.zeroize();
            mac_plain.zeroize();
            return Err(VaultError::InvalidCredentials);
        }

        // Verify vault.cryptomator JWT HS256 signature with enc_key || mac_key.
        let mut jwt_key = [0u8; 64];
        jwt_key[0..32].copy_from_slice(&enc_plain);
        jwt_key[32..64].copy_from_slice(&mac_plain);
        let payload = verify_vault_jwt(jwt_raw.trim(), &jwt_key)?;
        jwt_key.zeroize();

        if payload.format != 8 || payload.cipher_combo != "SIV_GCM" {
            enc_plain.zeroize();
            mac_plain.zeroize();
            return Err(VaultError::UnsupportedFormat(payload.format));
        }

        // RFC 5297 AES-SIV key layout in aes-siv: K1 (MAC) || K2 (CTR) = mac_key || enc_key.
        let mut siv_bytes = [0u8; 64];
        siv_bytes[0..32].copy_from_slice(&mac_plain);
        siv_bytes[32..64].copy_from_slice(&enc_plain);
        let enc_key = Key32::from_bytes(enc_plain);
        let siv_key = Key64::from_bytes(siv_bytes);
        enc_plain.zeroize();
        mac_plain.zeroize();
        siv_bytes.zeroize();

        Ok(Self {
            root: root.to_path_buf(),
            enc_key,
            siv_key,
            format: payload.format,
            cipher_combo: payload.cipher_combo,
        })
    }

    pub fn info(&self) -> CryptomatorVaultInfo {
        CryptomatorVaultInfo {
            path: self.root.to_string_lossy().to_string(),
            format: self.format,
            cipher_combo: self.cipher_combo.clone(),
        }
    }

    pub fn list_dir(&self, virtual_path: &str) -> Result<Vec<VaultEntry>> {
        let parts = split_path(virtual_path);
        let dir_id = self.resolve_dir_id(&parts)?;
        let storage = self.dir_storage_path(&dir_id)?;
        let base_prefix = if parts.is_empty() {
            String::new()
        } else {
            format!("/{}", parts.join("/"))
        };

        let mut entries = Vec::new();
        if !storage.is_dir() {
            return Ok(entries);
        }

        for item in fs::read_dir(&storage)? {
            let item = item?;
            let raw_name = item.file_name().to_string_lossy().to_string();
            let path = item.path();

            let (plain_name, is_dir, content_file) = if raw_name.ends_with(".c9r") {
                let stem = raw_name.trim_end_matches(".c9r");
                let Ok(name) = self.decrypt_name(&dir_id, stem) else {
                    continue;
                };
                if path.is_dir() {
                    if path.join("dir.c9r").is_file() {
                        (name, true, None)
                    } else if path.join("contents.c9r").is_file() {
                        (name, false, Some(path.join("contents.c9r")))
                    } else {
                        continue;
                    }
                } else {
                    (name, false, Some(path.clone()))
                }
            } else if raw_name.ends_with(".c9s") && path.is_dir() {
                let Ok(orig_enc) = fs::read_to_string(path.join("name.c9s")) else {
                    continue;
                };
                let stem = orig_enc.trim().trim_end_matches(".c9r");
                let Ok(name) = self.decrypt_name(&dir_id, stem) else {
                    continue;
                };
                if path.join("dir.c9r").is_file() {
                    (name, true, None)
                } else if path.join("contents.c9r").is_file() {
                    (name, false, Some(path.join("contents.c9r")))
                } else {
                    continue;
                }
            } else {
                continue;
            };

            let size = content_file
                .as_ref()
                .and_then(|p| fs::metadata(p).ok())
                .map(|m| cm_plaintext_len(m.len()))
                .unwrap_or(0);

            entries.push(VaultEntry {
                name: plain_name.clone(),
                path: format!("{base_prefix}/{plain_name}"),
                kind: if is_dir {
                    EntryKind::Directory
                } else {
                    EntryKind::File
                },
                size,
                modified_ms: 0,
            });
        }

        entries.sort_by(|a, b| {
            let ord = |k: EntryKind| match k {
                EntryKind::Directory => 0,
                EntryKind::File => 1,
                EntryKind::Unreadable => 2,
            };
            ord(a.kind)
                .cmp(&ord(b.kind))
                .then_with(|| a.name.to_lowercase().cmp(&b.name.to_lowercase()))
        });
        Ok(entries)
    }

    pub fn export_file(&self, src_vault_path: &str, dst_path: &Path) -> Result<u64> {
        let parts = split_path(src_vault_path);
        let (target_name, parent_parts) = parts.split_last().ok_or(VaultError::EntryNotFound)?;
        let parent_id = self.resolve_dir_id(parent_parts)?;
        let content_path = self.find_file_on_disk(&parent_id, target_name)?;

        let mut reader = BufReader::new(File::open(&content_path)?);
        let mut header = [0u8; CM_HEADER_LEN];
        if read_exact_or_eof(&mut reader, &mut header)? != CM_HEADER_LEN {
            return Err(VaultError::Integrity);
        }

        let header_nonce: [u8; 12] = header[0..12]
            .try_into()
            .map_err(|_| VaultError::Integrity)?;
        let header_cipher = Aes256Gcm::new(self.enc_key.as_bytes().into());
        let header_pt = header_cipher
            .decrypt(AesNonce::from_slice(&header_nonce), &header[12..])
            .map_err(|_| VaultError::Integrity)?;
        if header_pt.len() != 40 {
            return Err(VaultError::Integrity);
        }
        let content_key_arr: [u8; 32] = header_pt[8..40]
            .try_into()
            .map_err(|_| VaultError::Integrity)?;
        let content_key = Key32::from_bytes(content_key_arr);
        let chunk_cipher = Aes256Gcm::new(content_key.as_bytes().into());

        atomic_write_with(dst_path, |writer| {
            let mut buf = vec![0u8; CM_CHUNK_CT_MAX];
            let mut chunk_idx: u64 = 0;
            let mut total: u64 = 0;
            loop {
                let n = read_exact_or_eof(&mut reader, &mut buf)?;
                if n == 0 {
                    break;
                }
                if n < 12 + 16 {
                    return Err(VaultError::Integrity);
                }
                let chunk_nonce = AesNonce::from_slice(&buf[0..12]);
                let mut aad = [0u8; 20];
                aad[0..8].copy_from_slice(&chunk_idx.to_be_bytes());
                aad[8..20].copy_from_slice(&header_nonce);

                let pt = chunk_cipher
                    .decrypt(
                        chunk_nonce,
                        Payload {
                            msg: &buf[12..n],
                            aad: &aad,
                        },
                    )
                    .map_err(|_| VaultError::Integrity)?;
                writer.write_all(&pt)?;
                total += pt.len() as u64;
                chunk_idx += 1;
            }
            Ok(total)
        })
    }

    fn resolve_dir_id(&self, parts: &[String]) -> Result<String> {
        let mut cur_id = String::new();
        for name in parts {
            let storage = self.dir_storage_path(&cur_id)?;
            let mut found = None;
            if storage.is_dir() {
                for item in fs::read_dir(&storage)? {
                    let item = item?;
                    let raw = item.file_name().to_string_lossy().to_string();
                    let p = item.path();
                    if !p.is_dir() || !p.join("dir.c9r").is_file() {
                        continue;
                    }
                    let decrypted = if raw.ends_with(".c9r") {
                        self.decrypt_name(&cur_id, raw.trim_end_matches(".c9r"))
                            .ok()
                    } else if raw.ends_with(".c9s") {
                        fs::read_to_string(p.join("name.c9s")).ok().and_then(|s| {
                            self.decrypt_name(&cur_id, s.trim().trim_end_matches(".c9r"))
                                .ok()
                        })
                    } else {
                        None
                    };
                    if decrypted.as_deref() == Some(name.as_str()) {
                        let next_id = fs::read_to_string(p.join("dir.c9r"))?;
                        found = Some(next_id.trim().to_string());
                        break;
                    }
                }
            }
            cur_id = found.ok_or(VaultError::EntryNotFound)?;
        }
        Ok(cur_id)
    }

    fn find_file_on_disk(&self, parent_id: &str, target_name: &str) -> Result<PathBuf> {
        let storage = self.dir_storage_path(parent_id)?;
        if !storage.is_dir() {
            return Err(VaultError::EntryNotFound);
        }
        for item in fs::read_dir(&storage)? {
            let item = item?;
            let raw = item.file_name().to_string_lossy().to_string();
            let p = item.path();
            if raw.ends_with(".c9r") {
                if let Ok(plain) = self.decrypt_name(parent_id, raw.trim_end_matches(".c9r")) {
                    if plain == target_name {
                        if p.is_file() {
                            return Ok(p);
                        }
                        if p.is_dir() && p.join("contents.c9r").is_file() {
                            return Ok(p.join("contents.c9r"));
                        }
                    }
                }
            } else if raw.ends_with(".c9s") && p.is_dir() {
                if let Ok(orig) = fs::read_to_string(p.join("name.c9s")) {
                    if let Ok(plain) =
                        self.decrypt_name(parent_id, orig.trim().trim_end_matches(".c9r"))
                    {
                        if plain == target_name && p.join("contents.c9r").is_file() {
                            return Ok(p.join("contents.c9r"));
                        }
                    }
                }
            }
        }
        Err(VaultError::EntryNotFound)
    }

    fn dir_storage_path(&self, dir_id: &str) -> Result<PathBuf> {
        let mut cipher = Aes256Siv::new_from_slice(self.siv_key.as_bytes())
            .map_err(|_| VaultError::Integrity)?;
        let empty: [&[u8]; 0] = [];
        let ct = cipher
            .encrypt(empty, dir_id.as_bytes())
            .map_err(|_| VaultError::Integrity)?;
        let digest = Sha1::digest(&ct);
        let b32 = BASE32_NOPAD.encode(&digest);
        Ok(self.root.join("d").join(&b32[0..2]).join(&b32[2..32]))
    }

    fn decrypt_name(&self, parent_dir_id: &str, b64_stem: &str) -> Result<String> {
        let ct = URL_SAFE
            .decode(b64_stem)
            .or_else(|_| URL_SAFE_NO_PAD.decode(b64_stem))
            .map_err(|_| VaultError::Integrity)?;
        let mut cipher = Aes256Siv::new_from_slice(self.siv_key.as_bytes())
            .map_err(|_| VaultError::Integrity)?;
        let plain = cipher
            .decrypt([parent_dir_id.as_bytes()], &ct)
            .map_err(|_| VaultError::Integrity)?;
        String::from_utf8(plain).map_err(|_| VaultError::Integrity)
    }
}

fn verify_vault_jwt(jwt: &str, key64: &[u8; 64]) -> Result<VaultJwtPayload> {
    let parts: Vec<&str> = jwt.split('.').collect();
    if parts.len() != 3 {
        return Err(VaultError::InvalidConfig);
    }
    let signing_input = format!("{}.{}", parts[0], parts[1]);
    let sig = URL_SAFE_NO_PAD
        .decode(parts[2])
        .or_else(|_| URL_SAFE.decode(parts[2]))
        .map_err(|_| VaultError::InvalidConfig)?;

    let mut mac = <HmacSha256 as Mac>::new_from_slice(key64).map_err(|_| VaultError::Integrity)?;
    mac.update(signing_input.as_bytes());
    mac.verify_slice(&sig)
        .map_err(|_| VaultError::InvalidCredentials)?;

    let payload_bytes = URL_SAFE_NO_PAD
        .decode(parts[1])
        .or_else(|_| URL_SAFE.decode(parts[1]))
        .map_err(|_| VaultError::InvalidConfig)?;
    serde_json::from_slice(&payload_bytes).map_err(|_| VaultError::InvalidConfig)
}

fn cost_to_log_n(cost: u32) -> Result<u8> {
    if cost == 0 || !cost.is_power_of_two() {
        return Err(VaultError::InvalidConfig);
    }
    Ok(cost.trailing_zeros() as u8)
}

fn split_path(path: &str) -> Vec<String> {
    path.trim()
        .trim_matches('/')
        .split('/')
        .filter(|s| !s.is_empty())
        .map(|s| s.to_string())
        .collect()
}

fn cm_plaintext_len(ct_len: u64) -> u64 {
    if ct_len <= CM_HEADER_LEN as u64 {
        return 0;
    }
    let body = ct_len - CM_HEADER_LEN as u64;
    let full = CM_CHUNK_CT_MAX as u64;
    let q = body / full;
    let r = body % full;
    q * (CM_CHUNK_PT_MAX as u64) + r.saturating_sub(28)
}

fn read_exact_or_eof<R: Read>(reader: &mut R, buf: &mut [u8]) -> std::io::Result<usize> {
    let mut total = 0;
    while total < buf.len() {
        match reader.read(&mut buf[total..]) {
            Ok(0) => break,
            Ok(n) => total += n,
            Err(e) if e.kind() == std::io::ErrorKind::Interrupted => continue,
            Err(e) => return Err(e),
        }
    }
    Ok(total)
}
