use std::fmt;

use data_encoding::BASE32_NOPAD;
use hkdf::Hkdf;
use sha2::Sha256;
use zeroize::{Zeroize, ZeroizeOnDrop};

use crate::error::{Result, VaultError};
use crate::secret::{random_array, Key32};

const INFO_RECOVERY_KEK: &[u8] = b"ciphervaultz/v1/recovery-kek";

/// 32-byte one-time recovery key with grouped Base32 display and zeroization on drop.
#[derive(Clone, Zeroize, ZeroizeOnDrop)]
pub struct RecoveryKey([u8; 32]);

impl RecoveryKey {
    pub fn generate() -> Self {
        Self(random_array::<32>())
    }

    pub fn from_bytes(bytes: [u8; 32]) -> Self {
        Self(bytes)
    }

    pub fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }

    /// Format as uppercase Base32 without padding, grouped in 4-char hyphenated blocks.
    pub fn to_display_string(&self) -> String {
        let raw = BASE32_NOPAD.encode(&self.0);
        raw.as_bytes()
            .chunks(4)
            .map(|c| std::str::from_utf8(c).unwrap_or_default())
            .collect::<Vec<_>>()
            .join("-")
    }

    /// Parse a grouped or ungrouped Base32 recovery key (case-insensitive, ignoring hyphens/spaces).
    pub fn parse(input: &str) -> Result<Self> {
        let mut cleaned: String = input
            .chars()
            .filter(|c| !c.is_whitespace() && *c != '-')
            .map(|c| c.to_ascii_uppercase())
            .collect();
        let mut decoded = BASE32_NOPAD
            .decode(cleaned.as_bytes())
            .map_err(|_| VaultError::InvalidRecoveryKey)?;
        cleaned.zeroize();
        let arr: [u8; 32] = match decoded.as_slice().try_into() {
            Ok(a) => a,
            Err(_) => {
                decoded.zeroize();
                return Err(VaultError::InvalidRecoveryKey);
            }
        };
        decoded.zeroize();
        Ok(Self(arr))
    }

    /// Derive 32-byte recovery KEK: HKDF-SHA256(salt = vaultId, ikm = recoveryKey, info = "ciphervaultz/v1/recovery-kek").
    pub fn derive_kek(&self, vault_id: &[u8; 16]) -> Result<Key32> {
        let hk = Hkdf::<Sha256>::new(Some(vault_id), &self.0);
        let mut out = [0u8; 32];
        hk.expand(INFO_RECOVERY_KEK, &mut out)
            .map_err(|_| VaultError::Integrity)?;
        let key = Key32::from_bytes(out);
        out.zeroize();
        Ok(key)
    }
}

impl fmt::Debug for RecoveryKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("RecoveryKey([REDACTED])")
    }
}
