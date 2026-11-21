use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine;
use serde::{Deserialize, Serialize};
use zeroize::Zeroize;

use crate::error::{Result, VaultError};
use crate::kdf::Argon2Params;
use crate::seal::{open_bytes, seal_bytes};
use crate::secret::Key32;

pub const FORMAT_VERSION: u32 = 1;
pub const DEFAULT_CHUNK_SIZE: u32 = 65_536;
pub const CONFIG_FILENAME: &str = "cvz.vault.json";
pub const CONFIG_BACKUP_FILENAME: &str = "cvz.vault.json.bak";

const SLOT_AAD_PREFIX: &[u8] = b"cvz-keyslot-v1\0";

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum CipherSuite {
    #[serde(rename = "xchacha20-poly1305")]
    XChaCha20Poly1305,
    #[serde(rename = "aes256-gcm")]
    Aes256Gcm,
}

impl CipherSuite {
    pub const fn id(self) -> u8 {
        match self {
            CipherSuite::XChaCha20Poly1305 => 1,
            CipherSuite::Aes256Gcm => 2,
        }
    }

    pub const fn from_id(id: u8) -> Result<Self> {
        match id {
            1 => Ok(CipherSuite::XChaCha20Poly1305),
            2 => Ok(CipherSuite::Aes256Gcm),
            _ => Err(VaultError::Integrity),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "type")]
pub enum KeySlot {
    #[serde(rename = "password")]
    Password {
        salt: String,
        kdf: Argon2Params,
        sealed: String,
    },
    #[serde(rename = "recovery")]
    Recovery { sealed: String },
    #[serde(rename = "hybrid-pq")]
    HybridPq {
        label: String,
        #[serde(rename = "x25519Epk")]
        x25519_epk: String,
        #[serde(rename = "mlkemCt")]
        mlkem_ct: String,
        sealed: String,
    },
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct VaultConfig {
    pub format: u32,
    #[serde(rename = "vaultId")]
    pub vault_id: String,
    pub suite: CipherSuite,
    #[serde(rename = "chunkSize")]
    pub chunk_size: u32,
    pub slots: Vec<KeySlot>,
}

impl VaultConfig {
    pub fn vault_id_bytes(&self) -> Result<[u8; 16]> {
        let raw = URL_SAFE_NO_PAD
            .decode(&self.vault_id)
            .map_err(|_| VaultError::InvalidConfig)?;
        let arr: [u8; 16] = raw.try_into().map_err(|_| VaultError::InvalidConfig)?;
        Ok(arr)
    }

    /// Validate format version, chunk size, vault ID, and KDF security floors.
    /// Policy violations return distinct errors (UnsupportedFormat / WeakKdfParams)
    /// and MUST abort rather than falling back to backup config.
    pub fn validate_policy(&self) -> Result<()> {
        if self.format != FORMAT_VERSION {
            return Err(VaultError::UnsupportedFormat(self.format));
        }
        if self.chunk_size == 0 || self.chunk_size > 16 * 1024 * 1024 {
            return Err(VaultError::InvalidConfig);
        }
        let _ = self.vault_id_bytes()?;
        for slot in &self.slots {
            if let KeySlot::Password { kdf, .. } = slot {
                kdf.validate()?;
            }
        }
        Ok(())
    }

    /// Build normative slot AAD:
    /// "cvz-keyslot-v1\0" || format(u32 BE) || vaultId(16) || suiteId(u8)
    /// || chunkSize(u32 BE) || kindLen(u32 BE) || kind(UTF-8) || extra
    pub fn slot_aad(&self, kind: &str, extra: &[u8]) -> Result<Vec<u8>> {
        let vault_id = self.vault_id_bytes()?;
        let kind_bytes = kind.as_bytes();
        let kind_len = u32::try_from(kind_bytes.len()).map_err(|_| VaultError::InvalidConfig)?;

        let mut aad = Vec::with_capacity(
            SLOT_AAD_PREFIX.len() + 4 + 16 + 1 + 4 + 4 + kind_bytes.len() + extra.len(),
        );
        aad.extend_from_slice(SLOT_AAD_PREFIX);
        aad.extend_from_slice(&self.format.to_be_bytes());
        aad.extend_from_slice(&vault_id);
        aad.push(self.suite.id());
        aad.extend_from_slice(&self.chunk_size.to_be_bytes());
        aad.extend_from_slice(&kind_len.to_be_bytes());
        aad.extend_from_slice(kind_bytes);
        aad.extend_from_slice(extra);
        Ok(aad)
    }

    pub fn wrap_master_key(
        &self,
        kek: &Key32,
        master_key: &Key32,
        kind: &str,
        extra: &[u8],
    ) -> Result<String> {
        let aad = self.slot_aad(kind, extra)?;
        let sealed = seal_bytes(kek, &aad, master_key.as_bytes())?;
        Ok(URL_SAFE_NO_PAD.encode(sealed))
    }

    pub fn unwrap_master_key(
        &self,
        kek: &Key32,
        sealed_b64: &str,
        kind: &str,
        extra: &[u8],
    ) -> Result<Key32> {
        let aad = self.slot_aad(kind, extra)?;
        let sealed = URL_SAFE_NO_PAD
            .decode(sealed_b64)
            .map_err(|_| VaultError::InvalidCredentials)?;
        let mut plain =
            open_bytes(kek, &aad, &sealed).map_err(|_| VaultError::InvalidCredentials)?;
        let bytes: [u8; 32] = match plain.as_slice().try_into() {
            Ok(arr) => arr,
            Err(_) => {
                plain.zeroize();
                return Err(VaultError::InvalidCredentials);
            }
        };
        plain.zeroize();
        Ok(Key32::from_bytes(bytes))
    }
}

pub fn decode_salt_32(salt_b64: &str) -> Result<[u8; 32]> {
    let raw = URL_SAFE_NO_PAD
        .decode(salt_b64)
        .map_err(|_| VaultError::InvalidConfig)?;
    raw.try_into().map_err(|_| VaultError::InvalidConfig)
}

pub fn encode_b64(bytes: &[u8]) -> String {
    URL_SAFE_NO_PAD.encode(bytes)
}

pub fn decode_b64(s: &str) -> Result<Vec<u8>> {
    URL_SAFE_NO_PAD
        .decode(s)
        .map_err(|_| VaultError::InvalidConfig)
}
