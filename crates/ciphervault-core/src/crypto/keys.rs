//! Vault master keys.
//!
//! Every vault has two independent, randomly generated 256-bit keys:
//! * `enc` – AES encryption key (file headers, AES-SIV CTR half)
//! * `mac` – MAC key (AES-SIV S2V/CMAC half, key-file integrity, vault config signature)
//!
//! Keys come exclusively from the OS-backed OpenSSL CSPRNG (`RAND_bytes`), are scrubbed
//! with `OPENSSL_cleanse` on drop, and are never formatted by `Debug`.

use super::ffi::{cleanse, random_fill, SecretBuf};

pub const KEY_LEN: usize = 32;

#[derive(Clone)]
pub struct Masterkey {
    enc: [u8; KEY_LEN],
    mac: [u8; KEY_LEN],
}

impl Masterkey {
    /// Generate a fresh random masterkey from the OS CSPRNG.
    pub fn generate() -> Self {
        let mut k = Masterkey { enc: [0; KEY_LEN], mac: [0; KEY_LEN] };
        random_fill(&mut k.enc);
        random_fill(&mut k.mac);
        k
    }

    pub(crate) fn from_parts(enc: [u8; KEY_LEN], mac: [u8; KEY_LEN]) -> Self {
        Masterkey { enc, mac }
    }

    pub(crate) fn enc_key(&self) -> &[u8; KEY_LEN] {
        &self.enc
    }

    pub(crate) fn mac_key(&self) -> &[u8; KEY_LEN] {
        &self.mac
    }

    /// `enc || mac`, used as the HS256 key of the vault configuration JWT.
    pub(crate) fn raw_enc_mac(&self) -> SecretBuf<[u8; 2 * KEY_LEN]> {
        let mut out = SecretBuf::new([0u8; 2 * KEY_LEN]);
        out[..KEY_LEN].copy_from_slice(&self.enc);
        out[KEY_LEN..].copy_from_slice(&self.mac);
        out
    }

    /// `mac || enc`, the AES-SIV key layout (S2V key first, CTR key second).
    pub(crate) fn siv_key(&self) -> SecretBuf<[u8; 2 * KEY_LEN]> {
        let mut out = SecretBuf::new([0u8; 2 * KEY_LEN]);
        out[..KEY_LEN].copy_from_slice(&self.mac);
        out[KEY_LEN..].copy_from_slice(&self.enc);
        out
    }
}

impl Drop for Masterkey {
    fn drop(&mut self) {
        cleanse(&mut self.enc);
        cleanse(&mut self.mac);
    }
}

impl std::fmt::Debug for Masterkey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("Masterkey(<redacted>)")
    }
}

/// Fill a buffer with OS-provided randomness via OpenSSL `RAND_bytes`.
pub(crate) fn random_bytes<const N: usize>() -> [u8; N] {
    let mut b = [0u8; N];
    random_fill(&mut b);
    b
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn generated_keys_are_distinct_and_nonzero() {
        let a = Masterkey::generate();
        let b = Masterkey::generate();
        assert_ne!(a.enc_key(), b.enc_key());
        assert_ne!(a.enc_key(), a.mac_key());
        assert_ne!(a.enc_key(), &[0u8; KEY_LEN]);
    }

    #[test]
    fn debug_is_redacted() {
        let k = Masterkey::generate();
        let s = format!("{k:?}");
        assert_eq!(s, "Masterkey(<redacted>)");
    }

    #[test]
    fn siv_key_layout_is_mac_then_enc() {
        let k = Masterkey::from_parts([1; 32], [2; 32]);
        let s = k.siv_key();
        assert_eq!(&s[..32], &[2; 32]);
        assert_eq!(&s[32..], &[1; 32]);
    }
}
