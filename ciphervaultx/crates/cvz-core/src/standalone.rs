//! Standalone single-file encryption/decryption (`.zip`, `.7z`, `.pdf`, etc. -> `.cvxenc`).
//!
//! Format `CVX1` (self-contained, streaming, atomic, zero-plaintext-on-error):
//!   0..4     "CVX1" magic
//!   4        version = 1
//!   5        suite_id (1 = XChaCha20-Poly1305, 2 = AES-256-GCM)
//!   6..18    Argon2id params: m_cost(u32 BE) || t_cost(u32 BE) || p_cost(u32 BE)
//!   18..50   salt (32 bytes, OsRng)
//!   50..69   nonce_prefix (19 bytes, OsRng)
//!   69..141  wrapped content key (72 bytes = nonce(24) || ct(32) || tag(16))
//!            under KEK = Argon2id(password, salt, params) with AAD = "cvx-standalone-v1\0" || header[0..69]
//!   141..    STREAM chunks (65536 bytes each) with lastFlag authentication

use std::fs::File;
use std::io::{BufReader, Read, Write};
use std::path::Path;

use aes_gcm::aead::{Aead, KeyInit, Payload};
use aes_gcm::{Aes256Gcm, Nonce as AesNonce};
use chacha20poly1305::{XChaCha20Poly1305, XNonce};

use crate::config::{CipherSuite, DEFAULT_CHUNK_SIZE};
use crate::error::{Result, VaultError};
use crate::fsio::atomic_write_with;
use crate::kdf::{derive_kek, validate_password_policy, Argon2Params};
use crate::seal::{open_bytes, seal_bytes, AEAD_TAG_LEN};
use crate::secret::{random_array, Key32};

const MAGIC: &[u8; 4] = b"CVX1";
const VERSION: u8 = 1;
const PREFIX_LEN: usize = 69;
const HEADER_LEN: usize = 141; // 69 + 72
const KEY_AAD_PREFIX: &[u8] = b"cvx-standalone-v1\0";
const CHUNK_AAD_PREFIX: &[u8] = b"cvx-standalone-chunk-v1\0";

fn read_chunk<R: Read>(reader: &mut R, buf: &mut [u8]) -> std::io::Result<usize> {
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

fn encrypt_chunk(
    suite: CipherSuite,
    key: &Key32,
    prefix: &[u8; 19],
    index: u32,
    is_last: bool,
    aad: &[u8],
    pt: &[u8],
) -> Result<Vec<u8>> {
    let last_flag: u8 = if is_last { 0x01 } else { 0x00 };
    let payload = Payload { msg: pt, aad };
    match suite {
        CipherSuite::XChaCha20Poly1305 => {
            let cipher = XChaCha20Poly1305::new(key.as_bytes().into());
            let mut n = [0u8; 24];
            n[0..19].copy_from_slice(prefix);
            n[19..23].copy_from_slice(&index.to_be_bytes());
            n[23] = last_flag;
            cipher
                .encrypt(XNonce::from_slice(&n), payload)
                .map_err(|_| VaultError::Integrity)
        }
        CipherSuite::Aes256Gcm => {
            let cipher = Aes256Gcm::new(key.as_bytes().into());
            let mut n = [0u8; 12];
            n[0..7].copy_from_slice(&prefix[0..7]);
            n[7..11].copy_from_slice(&index.to_be_bytes());
            n[11] = last_flag;
            cipher
                .encrypt(AesNonce::from_slice(&n), payload)
                .map_err(|_| VaultError::Integrity)
        }
    }
}

fn decrypt_chunk(
    suite: CipherSuite,
    key: &Key32,
    prefix: &[u8; 19],
    index: u32,
    is_last: bool,
    aad: &[u8],
    ct: &[u8],
) -> Result<Vec<u8>> {
    let last_flag: u8 = if is_last { 0x01 } else { 0x00 };
    let payload = Payload { msg: ct, aad };
    match suite {
        CipherSuite::XChaCha20Poly1305 => {
            let cipher = XChaCha20Poly1305::new(key.as_bytes().into());
            let mut n = [0u8; 24];
            n[0..19].copy_from_slice(prefix);
            n[19..23].copy_from_slice(&index.to_be_bytes());
            n[23] = last_flag;
            cipher
                .decrypt(XNonce::from_slice(&n), payload)
                .map_err(|_| VaultError::Integrity)
        }
        CipherSuite::Aes256Gcm => {
            let cipher = Aes256Gcm::new(key.as_bytes().into());
            let mut n = [0u8; 12];
            n[0..7].copy_from_slice(&prefix[0..7]);
            n[7..11].copy_from_slice(&index.to_be_bytes());
            n[11] = last_flag;
            cipher
                .decrypt(AesNonce::from_slice(&n), payload)
                .map_err(|_| VaultError::Integrity)
        }
    }
}

/// Encrypt any single file (e.g. `.zip`, `.7z`, `.pdf`) into a self-contained `.cvxenc` file.
pub fn encrypt_standalone_file(
    src_path: &Path,
    dst_path: &Path,
    password: &str,
    suite: CipherSuite,
    kdf_params: Argon2Params,
) -> Result<u64> {
    validate_password_policy(password)?;
    kdf_params.validate()?;

    let salt = random_array::<32>();
    let nonce_prefix = random_array::<19>();
    let content_key = Key32::random();
    let kek = derive_kek(password.as_bytes(), &salt, kdf_params)?;

    let mut hdr_prefix = [0u8; PREFIX_LEN];
    hdr_prefix[0..4].copy_from_slice(MAGIC);
    hdr_prefix[4] = VERSION;
    hdr_prefix[5] = suite.id();
    hdr_prefix[6..18].copy_from_slice(&kdf_params.to_aad_bytes());
    hdr_prefix[18..50].copy_from_slice(&salt);
    hdr_prefix[50..69].copy_from_slice(&nonce_prefix);

    let mut key_aad = Vec::with_capacity(KEY_AAD_PREFIX.len() + PREFIX_LEN);
    key_aad.extend_from_slice(KEY_AAD_PREFIX);
    key_aad.extend_from_slice(&hdr_prefix);
    let wrapped = seal_bytes(&kek, &key_aad, content_key.as_bytes())?;

    let mut chunk_aad = Vec::with_capacity(CHUNK_AAD_PREFIX.len() + PREFIX_LEN);
    chunk_aad.extend_from_slice(CHUNK_AAD_PREFIX);
    chunk_aad.extend_from_slice(&hdr_prefix);

    let mut reader = BufReader::new(File::open(src_path)?);
    let csize = DEFAULT_CHUNK_SIZE as usize;

    atomic_write_with(dst_path, |writer| {
        writer.write_all(&hdr_prefix)?;
        writer.write_all(&wrapped)?;

        let mut current = vec![0u8; csize];
        let mut next_buf = vec![0u8; csize];
        let mut cur_len = read_chunk(&mut reader, &mut current)?;
        if cur_len == 0 {
            let ct = encrypt_chunk(suite, &content_key, &nonce_prefix, 0, true, &chunk_aad, &[])?;
            writer.write_all(&ct)?;
            return Ok(0);
        }

        let mut index = 0u32;
        let mut total = 0u64;
        loop {
            let next_len = if cur_len == csize {
                read_chunk(&mut reader, &mut next_buf)?
            } else {
                0
            };
            let is_last = next_len == 0;
            let ct = encrypt_chunk(
                suite,
                &content_key,
                &nonce_prefix,
                index,
                is_last,
                &chunk_aad,
                &current[..cur_len],
            )?;
            writer.write_all(&ct)?;
            total += cur_len as u64;
            if is_last {
                break;
            }
            index = index.checked_add(1).ok_or(VaultError::Integrity)?;
            std::mem::swap(&mut current, &mut next_buf);
            cur_len = next_len;
        }
        Ok(total)
    })
}

/// Decrypt a standalone `.cvxenc` file atomically (leaves no plaintext file on failure).
pub fn decrypt_standalone_file(src_path: &Path, dst_path: &Path, password: &str) -> Result<u64> {
    let mut reader = BufReader::new(File::open(src_path)?);
    let mut header = [0u8; HEADER_LEN];
    if read_chunk(&mut reader, &mut header)? != HEADER_LEN {
        return Err(VaultError::Integrity);
    }
    if &header[0..4] != MAGIC || header[4] != VERSION {
        return Err(VaultError::Integrity);
    }
    let suite = CipherSuite::from_id(header[5])?;
    let m_cost = u32::from_be_bytes(
        header[6..10]
            .try_into()
            .map_err(|_| VaultError::Integrity)?,
    );
    let t_cost = u32::from_be_bytes(
        header[10..14]
            .try_into()
            .map_err(|_| VaultError::Integrity)?,
    );
    let p_cost = u32::from_be_bytes(
        header[14..18]
            .try_into()
            .map_err(|_| VaultError::Integrity)?,
    );
    let kdf_params = Argon2Params {
        m_cost,
        t_cost,
        p_cost,
    };
    kdf_params.validate()?;

    let salt: [u8; 32] = header[18..50]
        .try_into()
        .map_err(|_| VaultError::Integrity)?;
    let nonce_prefix: [u8; 19] = header[50..69]
        .try_into()
        .map_err(|_| VaultError::Integrity)?;
    let wrapped = &header[69..141];

    let kek = derive_kek(password.as_bytes(), &salt, kdf_params)?;
    let mut key_aad = Vec::with_capacity(KEY_AAD_PREFIX.len() + PREFIX_LEN);
    key_aad.extend_from_slice(KEY_AAD_PREFIX);
    key_aad.extend_from_slice(&header[0..PREFIX_LEN]);
    let plain_key =
        open_bytes(&kek, &key_aad, wrapped).map_err(|_| VaultError::InvalidCredentials)?;
    let key_arr: [u8; 32] = plain_key.try_into().map_err(|_| VaultError::Integrity)?;
    let content_key = Key32::from_bytes(key_arr);

    let mut chunk_aad = Vec::with_capacity(CHUNK_AAD_PREFIX.len() + PREFIX_LEN);
    chunk_aad.extend_from_slice(CHUNK_AAD_PREFIX);
    chunk_aad.extend_from_slice(&header[0..PREFIX_LEN]);

    let full_ct = DEFAULT_CHUNK_SIZE as usize + AEAD_TAG_LEN;
    atomic_write_with(dst_path, |writer| {
        let mut current = vec![0u8; full_ct];
        let mut next_buf = vec![0u8; full_ct];
        let mut cur_len = read_chunk(&mut reader, &mut current)?;
        if cur_len < AEAD_TAG_LEN {
            return Err(VaultError::Integrity);
        }

        let mut index = 0u32;
        let mut total = 0u64;
        loop {
            let next_len = if cur_len == full_ct {
                read_chunk(&mut reader, &mut next_buf)?
            } else {
                0
            };
            let is_last = next_len == 0;
            if cur_len < AEAD_TAG_LEN {
                return Err(VaultError::Integrity);
            }
            let pt = decrypt_chunk(
                suite,
                &content_key,
                &nonce_prefix,
                index,
                is_last,
                &chunk_aad,
                &current[..cur_len],
            )?;
            if !pt.is_empty() {
                writer.write_all(&pt)?;
            }
            total += pt.len() as u64;
            if is_last {
                break;
            }
            index = index.checked_add(1).ok_or(VaultError::Integrity)?;
            std::mem::swap(&mut current, &mut next_buf);
            cur_len = next_len;
        }
        Ok(total)
    })
}
