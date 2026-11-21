use std::io::{Read, Write};

use aes_gcm::aead::{Aead, KeyInit, Payload};
use aes_gcm::{Aes256Gcm, Nonce as AesNonce};
use chacha20poly1305::{XChaCha20Poly1305, XNonce};

use crate::config::CipherSuite;
use crate::error::{Result, VaultError};
use crate::seal::{open_bytes, seal_bytes, AEAD_TAG_LEN};
use crate::secret::{random_array, Key32};

pub const FILE_MAGIC: &[u8; 4] = b"CVZF";
pub const HEADER_VERSION: u8 = 1;
pub const HEADER_LEN: usize = 99;
const NONCE_PREFIX_LEN: usize = 19;
const WRAPPED_KEY_LEN: usize = 72; // 24 nonce + 32 key + 16 tag
const HEADER_AAD_PREFIX: &[u8] = b"cvz-header-v1\0";
const CHUNK_AAD_PREFIX: &[u8] = b"cvz-chunk-v1\0";

#[derive(Debug, Clone)]
pub struct FileHeader {
    pub fixed8: [u8; 8],
    pub suite: CipherSuite,
    pub nonce_prefix: [u8; NONCE_PREFIX_LEN],
    pub content_key: Key32,
}

fn header_aad(fixed8: &[u8; 8], vault_id: &[u8; 16], nonce_prefix: &[u8; 19]) -> Vec<u8> {
    let mut aad = Vec::with_capacity(HEADER_AAD_PREFIX.len() + 8 + 16 + 19);
    aad.extend_from_slice(HEADER_AAD_PREFIX);
    aad.extend_from_slice(fixed8);
    aad.extend_from_slice(vault_id);
    aad.extend_from_slice(nonce_prefix);
    aad
}

fn chunk_aad(fixed8: &[u8; 8], vault_id: &[u8; 16]) -> Vec<u8> {
    let mut aad = Vec::with_capacity(CHUNK_AAD_PREFIX.len() + 8 + 16);
    aad.extend_from_slice(CHUNK_AAD_PREFIX);
    aad.extend_from_slice(fixed8);
    aad.extend_from_slice(vault_id);
    aad
}

/// Compute plaintext length arithmetically from total ciphertext length.
pub fn plaintext_len(ct_len: u64, chunk_size: u32) -> Result<u64> {
    let header_u64 = HEADER_LEN as u64;
    if ct_len < header_u64 {
        return Err(VaultError::Integrity);
    }
    let body = ct_len - header_u64;
    let chunk_u64 = u64::from(chunk_size);
    let full = chunk_u64 + AEAD_TAG_LEN as u64;
    let q = body / full;
    let r = body % full;
    if r == 0 && q == 0 {
        return Err(VaultError::Integrity);
    }
    if r == 0 {
        return Ok(q * chunk_u64);
    }
    if r < AEAD_TAG_LEN as u64 {
        return Err(VaultError::Integrity);
    }
    Ok(q * chunk_u64 + (r - AEAD_TAG_LEN as u64))
}

fn encode_header(
    suite: CipherSuite,
    vault_id: &[u8; 16],
    file_header_key: &Key32,
) -> Result<([u8; HEADER_LEN], FileHeader)> {
    let fixed8: [u8; 8] = [
        FILE_MAGIC[0],
        FILE_MAGIC[1],
        FILE_MAGIC[2],
        FILE_MAGIC[3],
        HEADER_VERSION,
        suite.id(),
        0x00,
        0x00,
    ];
    let nonce_prefix = random_array::<NONCE_PREFIX_LEN>();
    let content_key = Key32::random();
    let aad = header_aad(&fixed8, vault_id, &nonce_prefix);
    let wrapped = seal_bytes(file_header_key, &aad, content_key.as_bytes())?;
    if wrapped.len() != WRAPPED_KEY_LEN {
        return Err(VaultError::Integrity);
    }

    let mut raw = [0u8; HEADER_LEN];
    raw[0..8].copy_from_slice(&fixed8);
    raw[8..27].copy_from_slice(&nonce_prefix);
    raw[27..99].copy_from_slice(&wrapped);

    Ok((
        raw,
        FileHeader {
            fixed8,
            suite,
            nonce_prefix,
            content_key,
        },
    ))
}

fn decode_header(
    raw: &[u8; HEADER_LEN],
    vault_id: &[u8; 16],
    file_header_key: &Key32,
) -> Result<FileHeader> {
    if &raw[0..4] != FILE_MAGIC {
        return Err(VaultError::Integrity);
    }
    if raw[4] != HEADER_VERSION {
        return Err(VaultError::Integrity);
    }
    let suite = CipherSuite::from_id(raw[5])?;
    if raw[6] != 0x00 || raw[7] != 0x00 {
        return Err(VaultError::Integrity);
    }
    let mut fixed8 = [0u8; 8];
    fixed8.copy_from_slice(&raw[0..8]);
    let mut nonce_prefix = [0u8; NONCE_PREFIX_LEN];
    nonce_prefix.copy_from_slice(&raw[8..27]);
    let wrapped = &raw[27..99];

    let aad = header_aad(&fixed8, vault_id, &nonce_prefix);
    let plain = open_bytes(file_header_key, &aad, wrapped)?;
    let key_bytes: [u8; 32] = plain.try_into().map_err(|_| VaultError::Integrity)?;
    Ok(FileHeader {
        fixed8,
        suite,
        nonce_prefix,
        content_key: Key32::from_bytes(key_bytes),
    })
}

enum StreamCipher {
    XChaCha(Box<XChaCha20Poly1305>),
    AesGcm(Box<Aes256Gcm>),
}

impl StreamCipher {
    fn new(suite: CipherSuite, key: &Key32) -> Self {
        match suite {
            CipherSuite::XChaCha20Poly1305 => {
                Self::XChaCha(Box::new(XChaCha20Poly1305::new(key.as_bytes().into())))
            }
            CipherSuite::Aes256Gcm => Self::AesGcm(Box::new(Aes256Gcm::new(key.as_bytes().into()))),
        }
    }

    fn encrypt_chunk(
        &self,
        prefix: &[u8; NONCE_PREFIX_LEN],
        index: u32,
        is_last: bool,
        aad: &[u8],
        plaintext: &[u8],
    ) -> Result<Vec<u8>> {
        let last_flag: u8 = if is_last { 0x01 } else { 0x00 };
        let payload = Payload {
            msg: plaintext,
            aad,
        };
        match self {
            Self::XChaCha(cipher) => {
                let mut n = [0u8; 24];
                n[0..19].copy_from_slice(prefix);
                n[19..23].copy_from_slice(&index.to_be_bytes());
                n[23] = last_flag;
                cipher
                    .encrypt(XNonce::from_slice(&n), payload)
                    .map_err(|_| VaultError::Integrity)
            }
            Self::AesGcm(cipher) => {
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
        &self,
        prefix: &[u8; NONCE_PREFIX_LEN],
        index: u32,
        is_last: bool,
        aad: &[u8],
        ciphertext: &[u8],
    ) -> Result<Vec<u8>> {
        let last_flag: u8 = if is_last { 0x01 } else { 0x00 };
        let payload = Payload {
            msg: ciphertext,
            aad,
        };
        match self {
            Self::XChaCha(cipher) => {
                let mut n = [0u8; 24];
                n[0..19].copy_from_slice(prefix);
                n[19..23].copy_from_slice(&index.to_be_bytes());
                n[23] = last_flag;
                cipher
                    .decrypt(XNonce::from_slice(&n), payload)
                    .map_err(|_| VaultError::Integrity)
            }
            Self::AesGcm(cipher) => {
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
}

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

/// Encrypt a stream into CVZ v1 STREAM format (99-byte header + authenticated chunks).
/// Reports plaintext bytes processed via `on_progress`.
pub fn encrypt_stream<R: Read, W: Write, F: FnMut(u64)>(
    reader: &mut R,
    writer: &mut W,
    suite: CipherSuite,
    chunk_size: u32,
    vault_id: &[u8; 16],
    file_header_key: &Key32,
    mut on_progress: F,
) -> Result<u64> {
    let (raw_header, header) = encode_header(suite, vault_id, file_header_key)?;
    writer.write_all(&raw_header)?;

    let cipher = StreamCipher::new(header.suite, &header.content_key);
    let aad = chunk_aad(&header.fixed8, vault_id);
    let csize = chunk_size as usize;

    // Lookahead one byte so we know whether the current chunk is final even when
    // plaintext length is an exact multiple of chunk_size.
    let mut current = vec![0u8; csize];
    let mut next_buf = vec![0u8; csize];

    let mut cur_len = read_chunk(reader, &mut current)?;
    if cur_len == 0 {
        // Empty file: single authenticated chunk with lastFlag = 1 and empty plaintext.
        let ct = cipher.encrypt_chunk(&header.nonce_prefix, 0, true, &aad, &[])?;
        writer.write_all(&ct)?;
        on_progress(0);
        return Ok(0);
    }

    let mut index: u32 = 0;
    let mut total_plain: u64 = 0;

    loop {
        let next_len = if cur_len == csize {
            read_chunk(reader, &mut next_buf)?
        } else {
            0
        };
        let is_last = next_len == 0;
        let ct = cipher.encrypt_chunk(
            &header.nonce_prefix,
            index,
            is_last,
            &aad,
            &current[..cur_len],
        )?;
        writer.write_all(&ct)?;

        total_plain += cur_len as u64;
        on_progress(total_plain);

        if is_last {
            break;
        }
        index = index.checked_add(1).ok_or(VaultError::Integrity)?;
        std::mem::swap(&mut current, &mut next_buf);
        cur_len = next_len;
    }

    Ok(total_plain)
}

/// Decrypt a CVZ v1 STREAM file, verifying header and every chunk (including lastFlag).
/// Caller MUST write to a temporary file and only persist on `Ok`.
pub fn decrypt_stream<R: Read, W: Write, F: FnMut(u64)>(
    reader: &mut R,
    writer: &mut W,
    chunk_size: u32,
    vault_id: &[u8; 16],
    file_header_key: &Key32,
    mut on_progress: F,
) -> Result<u64> {
    let mut raw_header = [0u8; HEADER_LEN];
    let n = read_chunk(reader, &mut raw_header)?;
    if n != HEADER_LEN {
        return Err(VaultError::Integrity);
    }
    let header = decode_header(&raw_header, vault_id, file_header_key)?;
    let cipher = StreamCipher::new(header.suite, &header.content_key);
    let aad = chunk_aad(&header.fixed8, vault_id);

    let full_ct_len = chunk_size as usize + AEAD_TAG_LEN;
    let mut current = vec![0u8; full_ct_len];
    let mut next_buf = vec![0u8; full_ct_len];

    let mut cur_len = read_chunk(reader, &mut current)?;
    if cur_len < AEAD_TAG_LEN {
        return Err(VaultError::Integrity);
    }

    let mut index: u32 = 0;
    let mut total_plain: u64 = 0;

    loop {
        let next_len = if cur_len == full_ct_len {
            read_chunk(reader, &mut next_buf)?
        } else {
            0
        };
        let is_last = next_len == 0;
        if cur_len < AEAD_TAG_LEN {
            return Err(VaultError::Integrity);
        }
        let plain = cipher.decrypt_chunk(
            &header.nonce_prefix,
            index,
            is_last,
            &aad,
            &current[..cur_len],
        )?;
        if !plain.is_empty() {
            writer.write_all(&plain)?;
        }
        total_plain += plain.len() as u64;
        on_progress(total_plain);

        if is_last {
            // Ensure no trailing unread bytes exist if cur_len < full_ct_len.
            if cur_len < full_ct_len {
                let mut probe = [0u8; 1];
                if read_chunk(reader, &mut probe)? != 0 {
                    return Err(VaultError::Integrity);
                }
            }
            break;
        }
        index = index.checked_add(1).ok_or(VaultError::Integrity)?;
        std::mem::swap(&mut current, &mut next_buf);
        cur_len = next_len;
    }

    Ok(total_plain)
}

/// Verify a CVZ v1 STREAM file without storing plaintext anywhere.
pub fn verify_stream<R: Read>(
    reader: &mut R,
    chunk_size: u32,
    vault_id: &[u8; 16],
    file_header_key: &Key32,
) -> Result<u64> {
    let mut sink = std::io::sink();
    decrypt_stream(
        reader,
        &mut sink,
        chunk_size,
        vault_id,
        file_header_key,
        |_| {},
    )
}
