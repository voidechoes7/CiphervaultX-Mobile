//! Streaming file content encryption (Cryptomator `SIV_GCM` content scheme).
//!
//! ```text
//! file   = header || chunk_0 || chunk_1 || ...
//! header = nonce(12) || AES-256-GCM(encKey, nonce, 0xFF*8 || contentKey(32)) incl. tag(16)  = 68 bytes
//! chunk_i= nonce(12) || AES-256-GCM(contentKey, nonce, plaintext_i (≤32 KiB), AAD = BE64(i) || headerNonce) incl. tag(16)
//! ```
//! * Every file has its own random content key; every chunk its own random 96-bit nonce.
//! * The AAD binds each chunk to its position (no reordering) and to its header (no splicing
//!   between files).
//! * Memory use is O(chunk size) regardless of file size.
//!
//! Known limitation inherited from the format: removing *whole trailing chunks* is not
//! detectable, because there is no authenticated end-of-file marker. See THREAT_MODEL.md.

use std::io::{self, Read, Write};

use super::ffi::{aes256_gcm_decrypt_in_place, aes256_gcm_encrypt_in_place, SecretBuf};
use super::keys::{random_bytes, Masterkey, KEY_LEN};
use crate::error::{Result, VaultError};

pub const NONCE_LEN: usize = 12;
pub const TAG_LEN: usize = 16;
pub const HEADER_PAYLOAD_LEN: usize = 8 + KEY_LEN;
pub const HEADER_LEN: usize = NONCE_LEN + HEADER_PAYLOAD_LEN + TAG_LEN; // 68
pub const CHUNK_PAYLOAD: usize = 32 * 1024;
pub const CHUNK_OVERHEAD: usize = NONCE_LEN + TAG_LEN;
pub const CHUNK_LEN: usize = CHUNK_PAYLOAD + CHUNK_OVERHEAD;

/// Decrypted file header.
pub struct FileHeader {
    nonce: [u8; NONCE_LEN],
    content_key: SecretBuf<[u8; KEY_LEN]>,
}

impl std::fmt::Debug for FileHeader {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("FileHeader(<redacted>)")
    }
}

impl FileHeader {
    pub fn generate() -> Self {
        FileHeader { nonce: random_bytes(), content_key: SecretBuf::new(random_bytes()) }
    }

    pub fn encrypt(&self, mk: &Masterkey) -> [u8; HEADER_LEN] {
        let mut payload = SecretBuf::new([0xFFu8; HEADER_PAYLOAD_LEN]);
        payload[8..].copy_from_slice(&self.content_key[..]);
        let tag = aes256_gcm_encrypt_in_place(mk.enc_key(), &self.nonce, b"", &mut payload[..])
            .expect("header length is fixed and small");
        let mut out = [0u8; HEADER_LEN];
        out[..NONCE_LEN].copy_from_slice(&self.nonce);
        out[NONCE_LEN..NONCE_LEN + HEADER_PAYLOAD_LEN].copy_from_slice(&payload[..]);
        out[NONCE_LEN + HEADER_PAYLOAD_LEN..].copy_from_slice(&tag);
        out
    }

    pub fn decrypt(bytes: &[u8], mk: &Masterkey) -> Result<Self> {
        if bytes.len() != HEADER_LEN {
            return Err(VaultError::Malformed("file header too short".into()));
        }
        let mut nonce = [0u8; NONCE_LEN];
        nonce.copy_from_slice(&bytes[..NONCE_LEN]);
        let mut payload = SecretBuf::new([0u8; HEADER_PAYLOAD_LEN]);
        payload.copy_from_slice(&bytes[NONCE_LEN..NONCE_LEN + HEADER_PAYLOAD_LEN]);
        let mut tag = [0u8; TAG_LEN];
        tag.copy_from_slice(&bytes[NONCE_LEN + HEADER_PAYLOAD_LEN..]);
        aes256_gcm_decrypt_in_place(mk.enc_key(), &nonce, b"", &mut payload[..], &tag, "file header")?;
        let mut ck = SecretBuf::new([0u8; KEY_LEN]);
        ck.copy_from_slice(&payload[8..]);
        Ok(FileHeader { nonce, content_key: ck })
    }
}

fn chunk_aad(index: u64, header_nonce: &[u8; NONCE_LEN]) -> [u8; 8 + NONCE_LEN] {
    let mut aad = [0u8; 8 + NONCE_LEN];
    aad[..8].copy_from_slice(&index.to_be_bytes());
    aad[8..].copy_from_slice(header_nonce);
    aad
}

/// Read until `buf` is full or EOF. Returns bytes read.
fn read_full<R: Read>(r: &mut R, buf: &mut [u8]) -> io::Result<usize> {
    let mut n = 0;
    while n < buf.len() {
        match r.read(&mut buf[n..]) {
            Ok(0) => break,
            Ok(k) => n += k,
            Err(e) if e.kind() == io::ErrorKind::Interrupted => continue,
            Err(e) => return Err(e),
        }
    }
    Ok(n)
}

/// Progress callback: receives the cumulative number of *cleartext* bytes processed.
pub type Progress<'a> = &'a mut dyn FnMut(u64);

/// Encrypt `src` into `dst`. Returns the number of cleartext bytes processed.
pub fn encrypt_stream<R: Read, W: Write>(
    mk: &Masterkey,
    mut src: R,
    mut dst: W,
    mut progress: Option<Progress<'_>>,
) -> Result<u64> {
    let header = FileHeader::generate();
    dst.write_all(&header.encrypt(mk))?;
    let mut buf = SecretBuf::new(vec![0u8; CHUNK_PAYLOAD]);
    let mut index: u64 = 0;
    let mut total: u64 = 0;
    loop {
        let n = read_full(&mut src, &mut buf)?;
        if n == 0 {
            break;
        }
        let nonce: [u8; NONCE_LEN] = random_bytes();
        let tag = aes256_gcm_encrypt_in_place(
            &header.content_key,
            &nonce,
            &chunk_aad(index, &header.nonce),
            &mut buf[..n],
        )?;
        dst.write_all(&nonce)?;
        dst.write_all(&buf[..n])?;
        dst.write_all(&tag)?;
        total += n as u64;
        index += 1;
        if let Some(p) = progress.as_mut() {
            p(total);
        }
        if n < CHUNK_PAYLOAD {
            break;
        }
    }
    dst.flush()?;
    Ok(total)
}

/// Decrypt `src` into `dst`. Any authentication failure aborts with an error; callers
/// must treat already-written output as untrusted and discard it (the vault layer writes
/// to a temp file and only renames on success).
pub fn decrypt_stream<R: Read, W: Write>(
    mk: &Masterkey,
    mut src: R,
    mut dst: W,
    mut progress: Option<Progress<'_>>,
) -> Result<u64> {
    let mut hbuf = [0u8; HEADER_LEN];
    let hn = read_full(&mut src, &mut hbuf)?;
    if hn != HEADER_LEN {
        return Err(VaultError::Malformed("file header too short".into()));
    }
    let header = FileHeader::decrypt(&hbuf, mk)?;
    let mut buf = SecretBuf::new(vec![0u8; CHUNK_LEN]);
    let mut index: u64 = 0;
    let mut total: u64 = 0;
    loop {
        let n = read_full(&mut src, &mut buf)?;
        if n == 0 {
            break;
        }
        if n < CHUNK_OVERHEAD {
            return Err(VaultError::Authentication("truncated chunk"));
        }
        let (nonce_slice, rest) = buf[..n].split_at_mut(NONCE_LEN);
        let mut nonce = [0u8; NONCE_LEN];
        nonce.copy_from_slice(nonce_slice);
        let (ct, tag_slice) = rest.split_at_mut(n - CHUNK_OVERHEAD);
        let mut tag = [0u8; TAG_LEN];
        tag.copy_from_slice(tag_slice);
        aes256_gcm_decrypt_in_place(
            &header.content_key,
            &nonce,
            &chunk_aad(index, &header.nonce),
            ct,
            &tag,
            "file chunk",
        )?;
        dst.write_all(ct)?;
        total += ct.len() as u64;
        index += 1;
        if let Some(p) = progress.as_mut() {
            p(total);
        }
        if n < CHUNK_LEN {
            break;
        }
    }
    dst.flush()?;
    Ok(total)
}

/// Cleartext size for a given ciphertext size, or `None` if the size is impossible.
pub fn cleartext_size(ciphertext_len: u64) -> Option<u64> {
    let body = ciphertext_len.checked_sub(HEADER_LEN as u64)?;
    let full = body / CHUNK_LEN as u64;
    let rem = body % CHUNK_LEN as u64;
    if rem != 0 && rem < CHUNK_OVERHEAD as u64 {
        return None;
    }
    Some(full * CHUNK_PAYLOAD as u64 + rem.saturating_sub(CHUNK_OVERHEAD as u64))
}

/// Ciphertext size for a given cleartext size.
pub fn ciphertext_size(cleartext_len: u64) -> u64 {
    let full = cleartext_len / CHUNK_PAYLOAD as u64;
    let rem = cleartext_len % CHUNK_PAYLOAD as u64;
    HEADER_LEN as u64 + full * CHUNK_LEN as u64 + if rem > 0 { rem + CHUNK_OVERHEAD as u64 } else { 0 }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn synthetic(len: usize, seed: u8) -> Vec<u8> {
        (0..len).map(|i| (i as u8).wrapping_mul(31).wrapping_add(seed)).collect()
    }

    fn enc(mk: &Masterkey, data: &[u8]) -> Vec<u8> {
        let mut out = Vec::new();
        encrypt_stream(mk, data, &mut out, None).unwrap();
        out
    }

    fn dec(mk: &Masterkey, data: &[u8]) -> Result<Vec<u8>> {
        let mut out = Vec::new();
        decrypt_stream(mk, data, &mut out, None)?;
        Ok(out)
    }

    #[test]
    fn roundtrip_various_sizes() {
        let mk = Masterkey::generate();
        for len in [0, 1, 100, CHUNK_PAYLOAD - 1, CHUNK_PAYLOAD, CHUNK_PAYLOAD + 1, 3 * CHUNK_PAYLOAD + 7] {
            let pt = synthetic(len, 3);
            let ct = enc(&mk, &pt);
            assert_eq!(ct.len() as u64, ciphertext_size(len as u64), "len {len}");
            assert_eq!(cleartext_size(ct.len() as u64), Some(len as u64));
            assert_eq!(dec(&mk, &ct).unwrap(), pt, "len {len}");
        }
    }

    #[test]
    fn ciphertext_does_not_contain_plaintext() {
        let mk = Masterkey::generate();
        let pt = b"SYNTHETIC-MARKER-0123456789-SYNTHETIC-MARKER".repeat(50);
        let ct = enc(&mk, &pt);
        assert!(!ct.windows(16).any(|w| w == &pt[..16]));
    }

    #[test]
    fn same_plaintext_encrypts_differently() {
        let mk = Masterkey::generate();
        let pt = synthetic(1000, 1);
        assert_ne!(enc(&mk, &pt), enc(&mk, &pt));
    }

    #[test]
    fn every_single_bit_flip_is_detected() {
        let mk = Masterkey::generate();
        let pt = synthetic(200, 9);
        let ct = enc(&mk, &pt);
        for i in 0..ct.len() {
            let mut bad = ct.clone();
            bad[i] ^= 0x01;
            assert!(dec(&mk, &bad).is_err(), "flip at byte {i} undetected");
        }
    }

    #[test]
    fn chunk_reordering_detected() {
        let mk = Masterkey::generate();
        let pt = synthetic(2 * CHUNK_PAYLOAD, 5);
        let ct = enc(&mk, &pt);
        let mut swapped = ct[..HEADER_LEN].to_vec();
        swapped.extend_from_slice(&ct[HEADER_LEN + CHUNK_LEN..]);
        swapped.extend_from_slice(&ct[HEADER_LEN..HEADER_LEN + CHUNK_LEN]);
        assert!(matches!(dec(&mk, &swapped), Err(VaultError::Authentication(_))));
    }

    #[test]
    fn chunk_splicing_between_files_detected() {
        let mk = Masterkey::generate();
        let a = enc(&mk, &synthetic(100, 1));
        let b = enc(&mk, &synthetic(100, 2));
        let mut franken = a[..HEADER_LEN].to_vec();
        franken.extend_from_slice(&b[HEADER_LEN..]);
        assert!(dec(&mk, &franken).is_err());
    }

    #[test]
    fn mid_chunk_truncation_detected() {
        let mk = Masterkey::generate();
        let ct = enc(&mk, &synthetic(CHUNK_PAYLOAD + 500, 1));
        assert!(dec(&mk, &ct[..ct.len() - 1]).is_err());
        assert!(dec(&mk, &ct[..HEADER_LEN + 10]).is_err());
        assert!(dec(&mk, &ct[..HEADER_LEN - 1]).is_err());
    }

    #[test]
    fn wrong_masterkey_rejected() {
        let ct = enc(&Masterkey::generate(), &synthetic(10, 0));
        assert!(matches!(dec(&Masterkey::generate(), &ct), Err(VaultError::Authentication("file header"))));
    }

    #[test]
    fn appended_garbage_detected() {
        let mk = Masterkey::generate();
        let mut ct = enc(&mk, &synthetic(100, 0));
        ct.extend_from_slice(&[0u8; 40]);
        assert!(dec(&mk, &ct).is_err());
    }

    #[test]
    fn documented_limitation_whole_trailing_chunk_removal() {
        // Inherited from the format: dropping a complete trailing chunk yields a valid,
        // shorter plaintext. This test pins the behaviour so it stays documented.
        let mk = Masterkey::generate();
        let pt = synthetic(2 * CHUNK_PAYLOAD, 4);
        let ct = enc(&mk, &pt);
        let out = dec(&mk, &ct[..HEADER_LEN + CHUNK_LEN]).unwrap();
        assert_eq!(out, &pt[..CHUNK_PAYLOAD]);
    }

    #[test]
    fn progress_reports_cumulative_bytes() {
        let mk = Masterkey::generate();
        let pt = synthetic(2 * CHUNK_PAYLOAD + 10, 0);
        let mut seen = Vec::new();
        let mut cb = |n: u64| seen.push(n);
        encrypt_stream(&mk, &pt[..], &mut Vec::new(), Some(&mut cb)).unwrap();
        assert_eq!(seen, vec![CHUNK_PAYLOAD as u64, 2 * CHUNK_PAYLOAD as u64, pt.len() as u64]);
    }
}
