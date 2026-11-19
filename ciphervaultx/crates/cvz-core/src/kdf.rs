use argon2::{Algorithm, Argon2, Params, Version};
use serde::{Deserialize, Serialize};
use zeroize::Zeroize;

use crate::error::{Result, VaultError};
use crate::secret::Key32;

pub const MIN_MEMORY_KIB: u32 = 65_536;
pub const MIN_TIME_COST: u32 = 2;
pub const MIN_PARALLELISM: u32 = 1;
pub const MAX_PARALLELISM: u32 = 16;
pub const MIN_PASSWORD_CHARS: usize = 12;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum KdfProfile {
    Desktop,
    Mobile,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct Argon2Params {
    pub m_cost: u32,
    pub t_cost: u32,
    pub p_cost: u32,
}

impl Argon2Params {
    pub const fn desktop() -> Self {
        Self {
            m_cost: 262_144,
            t_cost: 3,
            p_cost: 1,
        }
    }

    pub const fn mobile() -> Self {
        Self {
            m_cost: 65_536,
            t_cost: 3,
            p_cost: 1,
        }
    }

    pub const fn for_profile(profile: KdfProfile) -> Self {
        match profile {
            KdfProfile::Desktop => Self::desktop(),
            KdfProfile::Mobile => Self::mobile(),
        }
    }

    pub fn validate(&self) -> Result<()> {
        if self.m_cost < MIN_MEMORY_KIB
            || self.t_cost < MIN_TIME_COST
            || self.p_cost < MIN_PARALLELISM
            || self.p_cost > MAX_PARALLELISM
        {
            return Err(VaultError::WeakKdfParams);
        }
        Ok(())
    }

    pub fn to_aad_bytes(&self) -> [u8; 12] {
        let mut out = [0u8; 12];
        out[0..4].copy_from_slice(&self.m_cost.to_be_bytes());
        out[4..8].copy_from_slice(&self.t_cost.to_be_bytes());
        out[8..12].copy_from_slice(&self.p_cost.to_be_bytes());
        out
    }
}

pub fn validate_password_policy(password: &str) -> Result<()> {
    if password.chars().count() < MIN_PASSWORD_CHARS {
        return Err(VaultError::WeakPassword);
    }
    Ok(())
}

pub fn derive_kek(password: &[u8], salt: &[u8; 32], params: Argon2Params) -> Result<Key32> {
    params.validate()?;
    let argon_params = Params::new(params.m_cost, params.t_cost, params.p_cost, Some(32))
        .map_err(|_| VaultError::WeakKdfParams)?;
    let argon2 = Argon2::new(Algorithm::Argon2id, Version::V0x13, argon_params);

    let mut out = [0u8; 32];
    argon2
        .hash_password_into(password, salt, &mut out)
        .map_err(|_| VaultError::Integrity)?;
    let key = Key32::from_bytes(out);
    out.zeroize();
    Ok(key)
}
