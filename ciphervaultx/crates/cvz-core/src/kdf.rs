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

/// Constant-time equality check for fixed-length 32-byte digests.
fn ct_eq_32(a: &[u8; 32], b: &[u8; 32]) -> bool {
    let mut diff = 0u8;
    for i in 0..32 {
        diff |= a[i] ^ b[i];
    }
    diff == 0
}

/// Generate a PHC-formatted Argon2id hash suitable for `CVZ_PRIVATE_ACCESS_HASH`.
///
/// Uses a 32-byte OS CSPRNG salt and the mobile-safe floor (`m=65536, t=3, p=1`)
/// so unlocking works smoothly across Windows, Android, and iOS while staying
/// strictly above the CVZ minimum KDF floor.
pub fn generate_access_gate_hash(passphrase: &str) -> Result<String> {
    use base64::engine::general_purpose::STANDARD_NO_PAD;
    use base64::Engine;
    use rand_core::{OsRng, RngCore};

    if passphrase.chars().count() < 8 {
        return Err(VaultError::WeakPassword);
    }

    let params = Argon2Params::mobile();
    let mut salt = [0u8; 32];
    OsRng.fill_bytes(&mut salt);

    let derived = derive_kek(passphrase.as_bytes(), &salt, params)?;
    let salt_b64 = STANDARD_NO_PAD.encode(salt);
    let hash_b64 = STANDARD_NO_PAD.encode(derived.as_bytes());
    salt.zeroize();

    Ok(format!(
        "$argon2id$v=19$m={},t={},p={}${}${}",
        params.m_cost, params.t_cost, params.p_cost, salt_b64, hash_b64
    ))
}

/// Verify a passphrase against a single `$argon2id$v=19$m=...,t=...,p=...$<salt>$<hash>` entry.
pub fn verify_access_gate_hash(passphrase: &str, phc: &str) -> bool {
    use base64::engine::general_purpose::STANDARD_NO_PAD;
    use base64::Engine;

    let parts: Vec<&str> = phc.trim().split('$').collect();
    // Expected: ["", "argon2id", "v=19", "m=...,t=...,p=...", "<salt>", "<hash>"]
    if parts.len() != 6 || !parts[0].is_empty() || parts[1] != "argon2id" || parts[2] != "v=19" {
        return false;
    }

    let mut m_cost: Option<u32> = None;
    let mut t_cost: Option<u32> = None;
    let mut p_cost: Option<u32> = None;
    for kv in parts[3].split(',') {
        let Some((k, v)) = kv.split_once('=') else {
            return false;
        };
        let Ok(num) = v.parse::<u32>() else {
            return false;
        };
        match k {
            "m" => m_cost = Some(num),
            "t" => t_cost = Some(num),
            "p" => p_cost = Some(num),
            _ => return false,
        }
    }

    let (Some(m_cost), Some(t_cost), Some(p_cost)) = (m_cost, t_cost, p_cost) else {
        return false;
    };
    let params = Argon2Params {
        m_cost,
        t_cost,
        p_cost,
    };
    if params.validate().is_err() {
        return false;
    }

    let Ok(salt_vec) = STANDARD_NO_PAD.decode(parts[4]) else {
        return false;
    };
    let Ok(hash_vec) = STANDARD_NO_PAD.decode(parts[5]) else {
        return false;
    };
    let Ok(salt): std::result::Result<[u8; 32], _> = salt_vec.try_into() else {
        return false;
    };
    let Ok(expected): std::result::Result<[u8; 32], _> = hash_vec.try_into() else {
        return false;
    };

    match derive_kek(passphrase.as_bytes(), &salt, params) {
        Ok(derived) => ct_eq_32(derived.as_bytes(), &expected),
        Err(_) => false,
    }
}

/// Verify a passphrase against any hash in the authorized list.
pub fn verify_access_gate_any(passphrase: &str, hashes: &[&str]) -> bool {
    let mut matched = false;
    for h in hashes {
        if verify_access_gate_hash(passphrase, h) {
            matched = true;
        }
    }
    matched
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn access_gate_hash_roundtrip_and_multi_user() {
        let h1 = generate_access_gate_hash("owner-secret-phrase-2026").unwrap();
        let h2 = generate_access_gate_hash("spouse-secret-phrase-2026").unwrap();
        assert!(h1.starts_with("$argon2id$v=19$m=65536,t=3,p=1$"));

        let list = [h1.as_str(), h2.as_str()];
        assert!(verify_access_gate_any("owner-secret-phrase-2026", &list));
        assert!(verify_access_gate_any("spouse-secret-phrase-2026", &list));
        assert!(!verify_access_gate_any("wrong-passphrase-123", &list));
        // Reject weak m_cost below CVZ floor
        let weak = h1.replace("m=65536", "m=1024");
        assert!(!verify_access_gate_hash("owner-secret-phrase-2026", &weak));
    }
}
