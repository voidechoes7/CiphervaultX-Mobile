//! Password-protected masterkey file (`masterkey.cryptomator` layout, vault format 8).
//!
//! ```text
//! KEK          = scrypt(NFC(password), salt, N, r, p, 32)
//! wrappedEnc   = AES-256-KeyWrap(KEK, encKey)      (RFC 3394, 40 bytes)
//! wrappedMac   = AES-256-KeyWrap(KEK, macKey)
//! versionMac   = HMAC-SHA256(macKey, BE32(version))
//! ```
//! RFC 3394 unwrap carries a 64-bit integrity check, so a wrong password is detected
//! deterministically. The KEK only exists transiently in zeroizing memory.

use super::ffi::{
    aes256_unwrap, aes256_wrap, cleanse, ct_eq, hmac_sha256, nfc_normalize, scrypt_derive, scrypt_pq_hybrid_derive,
    SecretBuf,
};
use super::keys::{random_bytes, Masterkey, KEY_LEN};
use crate::encoding::{b64_decode_std, b64_encode_std};
use crate::error::{Result, VaultError};
use crate::json::{escape_json_str, parse_flat_object};

/// Legacy `version` field value mandated by vault format 8 (real format lives in vault config).
pub const MASTERKEY_FILE_VERSION: u32 = 999;

/// scrypt cost parameters.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct KdfParams {
    /// log2(N)
    pub log_n: u8,
    pub r: u32,
    pub p: u32,
}

impl KdfParams {
    /// Default for new vaults: N = 2^17, r = 8, p = 1 (≈128 MiB, a few hundred ms on desktop).
    /// Stronger than Cryptomator's default (2^15) while staying format-compatible,
    /// because readers use the parameters stored in the file.
    pub const DEFAULT: KdfParams = KdfParams { log_n: 17, r: 8, p: 1 };
    /// Cryptomator default; recommended floor for constrained mobile devices.
    pub const COMPAT: KdfParams = KdfParams { log_n: 15, r: 8, p: 1 };
    /// FOR TESTS ONLY – deliberately weak to keep the suite fast.
    #[doc(hidden)]
    pub const INSECURE_TEST: KdfParams = KdfParams { log_n: 10, r: 8, p: 1 };

    /// Bounds checked when *reading* a key file, preventing memory/CPU exhaustion from
    /// a hostile file (e.g. N = 2^40).
    fn validate_for_read(&self) -> Result<()> {
        if self.log_n == 0 || self.log_n > 22 || self.r == 0 || self.r > 32 || self.p == 0 || self.p > 16 {
            return Err(VaultError::Unsupported("scrypt parameters out of accepted range".into()));
        }
        Ok(())
    }
}

#[derive(Debug, Clone)]
pub struct MasterkeyFile {
    pub version: u32,
    pub scrypt_salt: String,
    pub scrypt_cost_param: u64,
    pub scrypt_block_size: u32,
    pub scrypt_parallelism: u32,
    pub primary_master_key: String,
    pub hmac_master_key: String,
    pub version_mac: String,
    /// Optional KDF mode (`None` = standard Cryptomator `scrypt`, `Some("scrypt-pq-sha3-512")` = Post-Quantum Hybrid).
    pub kdf_mode: Option<String>,
}

fn derive_kek(
    password: &str,
    salt: &[u8],
    params: KdfParams,
    kdf_mode: Option<&str>,
    pq_seed: Option<&[u8]>,
) -> Result<SecretBuf<[u8; KEY_LEN]>> {
    let mut normalized = nfc_normalize(password).into_bytes();
    let mut kek = SecretBuf::new([0u8; KEY_LEN]);
    let res = match kdf_mode {
        Some("scrypt-pq-sha3-512") => {
            scrypt_pq_hybrid_derive(&normalized, salt, params.log_n, params.r, params.p, pq_seed, &mut kek)
        }
        None | Some("scrypt") => scrypt_derive(&normalized, salt, params.log_n, params.r, params.p, &mut kek[..]),
        Some(other) => Err(VaultError::Unsupported(format!("unsupported kdfMode: {other}"))),
    };
    cleanse(&mut normalized);
    res?;
    Ok(kek)
}

fn version_mac(mac_key: &[u8], version: u32) -> [u8; 32] {
    hmac_sha256(mac_key, &version.to_be_bytes())
}

impl MasterkeyFile {
    /// Wrap `key` under a password. A fresh 32-byte salt is drawn from the OS CSPRNG.
    pub fn wrap(key: &Masterkey, password: &str, params: KdfParams) -> Result<Self> {
        Self::wrap_with_mode(key, password, params, None, None)
    }

    /// Wrap `key` under Post-Quantum Hybrid mode (`scrypt-pq-sha3-512`) with an optional 512-bit recovery seed.
    pub fn wrap_pq_hybrid(
        key: &Masterkey,
        password: &str,
        params: KdfParams,
        pq_seed: Option<&[u8]>,
    ) -> Result<Self> {
        Self::wrap_with_mode(key, password, params, Some("scrypt-pq-sha3-512"), pq_seed)
    }

    fn wrap_with_mode(
        key: &Masterkey,
        password: &str,
        params: KdfParams,
        kdf_mode: Option<&str>,
        pq_seed: Option<&[u8]>,
    ) -> Result<Self> {
        if password.is_empty() {
            return Err(VaultError::InvalidName("password must not be empty".into()));
        }
        let salt: [u8; 32] = random_bytes();
        let kek = derive_kek(password, &salt, params, kdf_mode, pq_seed)?;
        let wenc = aes256_wrap(&kek, key.enc_key())?;
        let wmac = aes256_wrap(&kek, key.mac_key())?;
        let vmac = version_mac(key.mac_key(), MASTERKEY_FILE_VERSION);
        Ok(MasterkeyFile {
            version: MASTERKEY_FILE_VERSION,
            scrypt_salt: b64_encode_std(&salt),
            scrypt_cost_param: 1u64 << params.log_n,
            scrypt_block_size: params.r,
            scrypt_parallelism: params.p,
            primary_master_key: b64_encode_std(&wenc),
            hmac_master_key: b64_encode_std(&wmac),
            version_mac: b64_encode_std(&vmac),
            kdf_mode: kdf_mode.map(|s| s.to_string()),
        })
    }

    pub fn kdf_params(&self) -> Result<KdfParams> {
        let n = self.scrypt_cost_param;
        if n < 2 || !n.is_power_of_two() {
            return Err(VaultError::Malformed("scrypt cost parameter must be a power of two".into()));
        }
        let p = KdfParams { log_n: n.trailing_zeros() as u8, r: self.scrypt_block_size, p: self.scrypt_parallelism };
        p.validate_for_read()?;
        Ok(p)
    }

    /// Derive the KEK from `password` and unwrap the masterkey.
    pub fn unlock(&self, password: &str) -> Result<Masterkey> {
        self.unlock_with_pq_seed(password, None)
    }

    /// Derive the KEK from `password` + optional post-quantum seed and unwrap the masterkey.
    pub fn unlock_with_pq_seed(&self, password: &str, pq_seed: Option<&[u8]>) -> Result<Masterkey> {
        let params = self.kdf_params()?;
        let salt = b64_decode_std(&self.scrypt_salt).map_err(|_| VaultError::Malformed("salt encoding".into()))?;
        let wenc = b64_decode_std(&self.primary_master_key).map_err(|_| VaultError::Malformed("key encoding".into()))?;
        let wmac = b64_decode_std(&self.hmac_master_key).map_err(|_| VaultError::Malformed("key encoding".into()))?;
        let vmac = b64_decode_std(&self.version_mac).map_err(|_| VaultError::Malformed("mac encoding".into()))?;
        if wenc.len() != KEY_LEN + 8 || wmac.len() != KEY_LEN + 8 {
            return Err(VaultError::Malformed("wrapped key length".into()));
        }
        let kek = derive_kek(password, &salt, params, self.kdf_mode.as_deref(), pq_seed)?;
        let mut enc = SecretBuf::new([0u8; KEY_LEN]);
        let mut mac = SecretBuf::new([0u8; KEY_LEN]);
        aes256_unwrap(&kek, &wenc, &mut enc)?;
        aes256_unwrap(&kek, &wmac, &mut mac)?;
        // Constant-time verification of the version MAC (detects version rollback).
        let expected_mac = version_mac(&mac[..], self.version);
        if !ct_eq(&expected_mac, &vmac) {
            return Err(VaultError::Authentication("masterkey version MAC"));
        }
        Ok(Masterkey::from_parts(*enc, *mac))
    }

    pub fn to_json(&self) -> Result<Vec<u8>> {
        let mut s = String::from("{\n");
        s.push_str(&format!("  \"version\": {},\n", self.version));
        s.push_str(&format!("  \"scryptSalt\": {},\n", escape_json_str(&self.scrypt_salt)));
        s.push_str(&format!("  \"scryptCostParam\": {},\n", self.scrypt_cost_param));
        s.push_str(&format!("  \"scryptBlockSize\": {},\n", self.scrypt_block_size));
        if self.scrypt_parallelism != 1 {
            s.push_str(&format!("  \"scryptParallelism\": {},\n", self.scrypt_parallelism));
        }
        if let Some(ref mode) = self.kdf_mode {
            s.push_str(&format!("  \"kdfMode\": {},\n", escape_json_str(mode)));
        }
        s.push_str(&format!("  \"primaryMasterKey\": {},\n", escape_json_str(&self.primary_master_key)));
        s.push_str(&format!("  \"hmacMasterKey\": {},\n", escape_json_str(&self.hmac_master_key)));
        s.push_str(&format!("  \"versionMac\": {}\n", escape_json_str(&self.version_mac)));
        s.push('}');
        Ok(s.into_bytes())
    }

    pub fn from_json(bytes: &[u8]) -> Result<Self> {
        let m = parse_flat_object(bytes)?;
        let req_str = |k: &str| -> Result<String> {
            m.get(k)
                .and_then(|v| v.as_str())
                .map(|s| s.to_string())
                .ok_or_else(|| VaultError::Malformed(format!("missing or invalid '{k}'")))
        };
        let req_u64 = |k: &str| -> Result<u64> {
            m.get(k)
                .and_then(|v| v.as_u64())
                .ok_or_else(|| VaultError::Malformed(format!("missing or invalid '{k}'")))
        };
        Ok(MasterkeyFile {
            version: req_u64("version")? as u32,
            scrypt_salt: req_str("scryptSalt")?,
            scrypt_cost_param: req_u64("scryptCostParam")?,
            scrypt_block_size: req_u64("scryptBlockSize")? as u32,
            scrypt_parallelism: m.get("scryptParallelism").and_then(|v| v.as_u64()).unwrap_or(1) as u32,
            primary_master_key: req_str("primaryMasterKey")?,
            hmac_master_key: req_str("hmacMasterKey")?,
            version_mac: req_str("versionMac")?,
            kdf_mode: m.get("kdfMode").and_then(|v| v.as_str()).map(|s| s.to_string()),
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const P: KdfParams = KdfParams::INSECURE_TEST;

    #[test]
    fn wrap_unlock_roundtrip() {
        let k = Masterkey::generate();
        let f = MasterkeyFile::wrap(&k, "correct horse battery staple", P).unwrap();
        let k2 = f.unlock("correct horse battery staple").unwrap();
        assert_eq!(k.enc_key(), k2.enc_key());
        assert_eq!(k.mac_key(), k2.mac_key());
    }

    #[test]
    fn pq_hybrid_wrap_and_seed_binding() {
        let k = Masterkey::generate();
        let seed = b"quantum-fortress-512-bit-hardware-seed";
        let f = MasterkeyFile::wrap_pq_hybrid(&k, "passphrase-alpha", P, Some(seed)).unwrap();
        assert_eq!(f.kdf_mode.as_deref(), Some("scrypt-pq-sha3-512"));

        // Unlocking without the PQ seed must fail even with the right password
        assert!(matches!(f.unlock("passphrase-alpha"), Err(VaultError::InvalidPassword)));

        // Unlocking with both password and PQ seed succeeds
        let k2 = f.unlock_with_pq_seed("passphrase-alpha", Some(seed)).unwrap();
        assert_eq!(k.enc_key(), k2.enc_key());
        assert_eq!(k.mac_key(), k2.mac_key());
    }

    #[test]
    fn wrong_password_rejected() {
        let k = Masterkey::generate();
        let f = MasterkeyFile::wrap(&k, "pw-one", P).unwrap();
        assert!(matches!(f.unlock("pw-two"), Err(VaultError::InvalidPassword)));
        assert!(matches!(f.unlock(""), Err(VaultError::InvalidPassword)));
    }

    #[test]
    fn password_is_nfc_normalized() {
        let k = Masterkey::generate();
        // "é" precomposed vs. decomposed
        let f = MasterkeyFile::wrap(&k, "caf\u{e9}", P).unwrap();
        assert!(f.unlock("cafe\u{301}").is_ok());
    }

    #[test]
    fn salts_are_unique() {
        let k = Masterkey::generate();
        let a = MasterkeyFile::wrap(&k, "x", P).unwrap();
        let b = MasterkeyFile::wrap(&k, "x", P).unwrap();
        assert_ne!(a.scrypt_salt, b.scrypt_salt);
        assert_ne!(a.primary_master_key, b.primary_master_key);
    }

    #[test]
    fn tampered_wrapped_key_rejected() {
        let k = Masterkey::generate();
        let mut f = MasterkeyFile::wrap(&k, "pw", P).unwrap();
        let mut raw = b64_decode_std(&f.primary_master_key).unwrap();
        raw[10] ^= 1;
        f.primary_master_key = b64_encode_std(&raw);
        assert!(f.unlock("pw").is_err());
    }

    #[test]
    fn tampered_version_rejected() {
        let k = Masterkey::generate();
        let mut f = MasterkeyFile::wrap(&k, "pw", P).unwrap();
        f.version = 7;
        assert!(matches!(f.unlock("pw"), Err(VaultError::Authentication(_))));
    }

    #[test]
    fn hostile_kdf_params_rejected_before_derivation() {
        let k = Masterkey::generate();
        let mut f = MasterkeyFile::wrap(&k, "pw", P).unwrap();
        f.scrypt_cost_param = 1u64 << 40;
        assert!(matches!(f.unlock("pw"), Err(VaultError::Unsupported(_))));
        f.scrypt_cost_param = 1000;
        assert!(matches!(f.unlock("pw"), Err(VaultError::Malformed(_))));
    }

    #[test]
    fn empty_password_refused_on_create() {
        assert!(MasterkeyFile::wrap(&Masterkey::generate(), "", P).is_err());
    }

    #[test]
    fn json_roundtrip_and_no_plaintext_keys() {
        let k = Masterkey::generate();
        let f = MasterkeyFile::wrap(&k, "pw", P).unwrap();
        let json = f.to_json().unwrap();
        let text = String::from_utf8(json.clone()).unwrap();
        assert!(!text.contains(&b64_encode_std(k.enc_key())));
        assert!(!text.contains("\"pw\""));
        let f2 = MasterkeyFile::from_json(&json).unwrap();
        assert!(f2.unlock("pw").is_ok());
    }
}
