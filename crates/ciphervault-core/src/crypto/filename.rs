//! Filename and directory-ID encryption (Cryptomator `SIV_GCM` naming scheme).
//!
//! ```text
//! encName   = base64url(AES-SIV(mac||enc, NFC(name), AD = dirId)) + ".c9r"
//! dirIdHash = base32(SHA1(AES-SIV(mac||enc, dirId)))          -> d/<2 chars>/<30 chars>
//! ```
//! AES-SIV (RFC 5297) is deterministic by design so that a name can be looked up without a
//! separate index; binding the parent directory ID as associated data means equal names in
//! different folders encrypt differently and names cannot be moved between folders
//! undetected. SHA-1 here only shortens an already pseudo-random SIV output into a path; it
//! is not relied upon for collision resistance against an attacker who lacks the keys.

use super::ffi::{aes256_siv_decrypt, aes256_siv_encrypt, nfc_normalize, sha1_digest, SecretBuf};
use super::keys::Masterkey;
use crate::encoding::{b64_decode_url, b64_encode_url, base32_encode};
use crate::error::{Result, VaultError};

pub const ENCRYPTED_EXT: &str = ".c9r";
pub const SHORTENED_EXT: &str = ".c9s";

pub struct NameCryptor {
    key: SecretBuf<[u8; 64]>,
}

impl std::fmt::Debug for NameCryptor {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("NameCryptor(<redacted>)")
    }
}

impl NameCryptor {
    pub fn new(mk: &Masterkey) -> Self {
        NameCryptor { key: mk.siv_key() }
    }

    /// Encrypt a cleartext name within the directory `dir_id`. Returns name incl. `.c9r`.
    pub fn encrypt_name(&self, name: &str, dir_id: &str) -> Result<String> {
        let normalized = nfc_normalize(name);
        let ct = aes256_siv_encrypt(&self.key, Some(dir_id.as_bytes()), normalized.as_bytes())?;
        Ok(format!("{}{}", b64_encode_url(&ct), ENCRYPTED_EXT))
    }

    /// Decrypt an encrypted name (with or without `.c9r`). Fails if it was not created in
    /// `dir_id` or has been modified.
    pub fn decrypt_name(&self, enc_name: &str, dir_id: &str) -> Result<String> {
        let stem = enc_name.strip_suffix(ENCRYPTED_EXT).unwrap_or(enc_name);
        let ct = b64_decode_url(stem).map_err(|_| VaultError::Malformed("name encoding".into()))?;
        let pt = aes256_siv_decrypt(&self.key, Some(dir_id.as_bytes()), &ct)?;
        String::from_utf8(pt).map_err(|_| VaultError::Malformed("name is not utf-8".into()))
    }

    /// Storage path (relative to vault root) of the directory with `dir_id`.
    pub fn dir_path(&self, dir_id: &str) -> Result<(String, String)> {
        let ct = aes256_siv_encrypt(&self.key, None, dir_id.as_bytes())?;
        let hash = base32_encode(&sha1_digest(&ct));
        Ok((hash[..2].to_string(), hash[2..].to_string()))
    }
}

/// Deflated name for encrypted names longer than the shortening threshold.
pub fn shorten(enc_name: &str) -> String {
    format!("{}{}", b64_encode_url(&sha1_digest(enc_name.as_bytes())), SHORTENED_EXT)
}

/// Validate a user-supplied cleartext name.
pub fn validate_name(name: &str) -> Result<()> {
    let bad = name.is_empty()
        || name == "."
        || name == ".."
        || name.chars().count() > 255
        || name.chars().any(|c| c == '/' || c == '\\' || c.is_control());
    if bad {
        return Err(VaultError::InvalidName(
            "names must be 1-255 characters and must not contain '/', '\\' or control characters".into(),
        ));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn roundtrip_and_extension() {
        let nc = NameCryptor::new(&Masterkey::generate());
        let e = nc.encrypt_name("Quarterly report (synthetic).pdf", "").unwrap();
        assert!(e.ends_with(".c9r"));
        assert!(!e.contains("report"));
        assert_eq!(nc.decrypt_name(&e, "").unwrap(), "Quarterly report (synthetic).pdf");
    }

    #[test]
    fn deterministic_per_directory_but_bound_to_dir_id() {
        let nc = NameCryptor::new(&Masterkey::generate());
        let a = nc.encrypt_name("same.txt", "dir-a").unwrap();
        assert_eq!(a, nc.encrypt_name("same.txt", "dir-a").unwrap());
        let b = nc.encrypt_name("same.txt", "dir-b").unwrap();
        assert_ne!(a, b);
        assert!(matches!(nc.decrypt_name(&a, "dir-b"), Err(VaultError::Authentication(_))));
    }

    #[test]
    fn tampered_name_rejected() {
        let nc = NameCryptor::new(&Masterkey::generate());
        let e = nc.encrypt_name("x.txt", "").unwrap();
        let mut chars: Vec<char> = e.chars().collect();
        chars[3] = if chars[3] == 'A' { 'B' } else { 'A' };
        let t: String = chars.into_iter().collect();
        assert!(nc.decrypt_name(&t, "").is_err());
    }

    #[test]
    fn unicode_names_are_normalized() {
        let nc = NameCryptor::new(&Masterkey::generate());
        assert_eq!(
            nc.encrypt_name("caf\u{e9}", "").unwrap(),
            nc.encrypt_name("cafe\u{301}", "").unwrap()
        );
    }

    #[test]
    fn dir_path_shape() {
        let nc = NameCryptor::new(&Masterkey::generate());
        let (a, b) = nc.dir_path("").unwrap();
        assert_eq!(a.len(), 2);
        assert_eq!(b.len(), 30);
        assert_ne!(nc.dir_path("x").unwrap(), (a, b));
    }

    #[test]
    fn name_validation() {
        for bad in ["", ".", "..", "a/b", "a\\b", "a\u{0}b", "line\nbreak"] {
            assert!(validate_name(bad).is_err(), "{bad:?}");
        }
        for ok in ["a", "file.tar.gz", "Ünïcødé 名前", ".hidden"] {
            assert!(validate_name(ok).is_ok(), "{ok:?}");
        }
        assert!(validate_name(&"a".repeat(256)).is_err());
    }
}
