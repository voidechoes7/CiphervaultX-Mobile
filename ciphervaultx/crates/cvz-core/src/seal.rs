use chacha20poly1305::aead::{Aead, KeyInit, Payload};
use chacha20poly1305::{XChaCha20Poly1305, XNonce};

use crate::error::{Result, VaultError};
use crate::secret::{random_array, Key32};

pub const XCHACHA_NONCE_LEN: usize = 24;
pub const AEAD_TAG_LEN: usize = 16;

/// Seal a small object with XChaCha20-Poly1305: output = nonce(24) || ct || tag(16).
pub fn seal_bytes(key: &Key32, aad: &[u8], plaintext: &[u8]) -> Result<Vec<u8>> {
    let cipher = XChaCha20Poly1305::new(key.as_bytes().into());
    let nonce_bytes = random_array::<XCHACHA_NONCE_LEN>();
    let nonce = XNonce::from_slice(&nonce_bytes);
    let ct = cipher
        .encrypt(
            nonce,
            Payload {
                msg: plaintext,
                aad,
            },
        )
        .map_err(|_| VaultError::Integrity)?;

    let mut out = Vec::with_capacity(XCHACHA_NONCE_LEN + ct.len());
    out.extend_from_slice(&nonce_bytes);
    out.extend_from_slice(&ct);
    Ok(out)
}

/// Open a sealed small object (nonce(24) || ct || tag(16)).
pub fn open_bytes(key: &Key32, aad: &[u8], sealed: &[u8]) -> Result<Vec<u8>> {
    if sealed.len() < XCHACHA_NONCE_LEN + AEAD_TAG_LEN {
        return Err(VaultError::Integrity);
    }
    let (nonce_bytes, ct) = sealed.split_at(XCHACHA_NONCE_LEN);
    let cipher = XChaCha20Poly1305::new(key.as_bytes().into());
    let nonce = XNonce::from_slice(nonce_bytes);
    cipher
        .decrypt(nonce, Payload { msg: ct, aad })
        .map_err(|_| VaultError::Integrity)
}
