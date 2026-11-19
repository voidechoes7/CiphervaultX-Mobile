use hkdf::Hkdf;
use sha2::Sha256;
use zeroize::Zeroize;

use crate::error::{Result, VaultError};
use crate::secret::{Key32, Key64};

const INFO_NAME_SIV: &[u8] = b"ciphervaultz/v1/name-siv";
const INFO_FILE_HEADER: &[u8] = b"ciphervaultz/v1/file-header";
const INFO_METADATA: &[u8] = b"ciphervaultz/v1/metadata";
const INFO_DIR_HASH: &[u8] = b"ciphervaultz/v1/dir-hash";

#[derive(Clone, Debug)]
pub struct VaultKeys {
    pub name_siv: Key64,
    pub file_header: Key32,
    pub metadata: Key32,
    pub dir_hash: Key32,
}

impl VaultKeys {
    pub fn derive(master_key: &Key32, vault_id: &[u8; 16]) -> Result<Self> {
        let hk = Hkdf::<Sha256>::new(Some(vault_id), master_key.as_bytes());

        let mut name_buf = [0u8; 64];
        hk.expand(INFO_NAME_SIV, &mut name_buf)
            .map_err(|_| VaultError::Integrity)?;
        let name_siv = Key64::from_bytes(name_buf);
        name_buf.zeroize();

        let file_header = expand_32(&hk, INFO_FILE_HEADER)?;
        let metadata = expand_32(&hk, INFO_METADATA)?;
        let dir_hash = expand_32(&hk, INFO_DIR_HASH)?;

        Ok(Self {
            name_siv,
            file_header,
            metadata,
            dir_hash,
        })
    }
}

fn expand_32(hk: &Hkdf<Sha256>, info: &[u8]) -> Result<Key32> {
    let mut buf = [0u8; 32];
    hk.expand(info, &mut buf)
        .map_err(|_| VaultError::Integrity)?;
    let key = Key32::from_bytes(buf);
    buf.zeroize();
    Ok(key)
}
