//! Vault configuration (`vault.cryptomator`): a compact JWS signed with HS256 using
//! `encKey || macKey`. Implemented by hand (≈40 lines) to avoid a general JWT dependency
//! and its algorithm-confusion surface: only `HS256` is accepted, and the signature is
//! verified in constant time *before* the payload is trusted.

use super::ffi::{ct_eq, hmac_sha256};
use super::keys::Masterkey;
use crate::encoding::{b64_decode_url, b64_encode_url_nopad, uuid_v4};
use crate::error::{Result, VaultError};
use crate::json::{escape_json_str, parse_flat_object};

pub const VAULT_FORMAT: u32 = 8;
pub const CIPHER_COMBO: &str = "SIV_GCM";
pub const MASTERKEY_KID: &str = "masterkeyfile:masterkey.cryptomator";
pub const DEFAULT_SHORTENING_THRESHOLD: usize = 220;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VaultConfig {
    pub jti: String,
    pub format: u32,
    pub cipher_combo: String,
    pub shortening_threshold: usize,
}

impl VaultConfig {
    pub fn new() -> Self {
        VaultConfig {
            jti: uuid_v4(),
            format: VAULT_FORMAT,
            cipher_combo: CIPHER_COMBO.into(),
            shortening_threshold: DEFAULT_SHORTENING_THRESHOLD,
        }
    }

    fn payload_json(&self) -> Vec<u8> {
        format!(
            r#"{{"jti":{},"format":{},"cipherCombo":{},"shorteningThreshold":{}}}"#,
            escape_json_str(&self.jti),
            self.format,
            escape_json_str(&self.cipher_combo),
            self.shortening_threshold
        )
        .into_bytes()
    }

    pub fn sign(&self, mk: &Masterkey) -> Result<String> {
        let header_json = format!(
            r#"{{"kid":{},"typ":"JWT","alg":"HS256"}}"#,
            escape_json_str(MASTERKEY_KID)
        );
        let signing_input = format!(
            "{}.{}",
            b64_encode_url_nopad(header_json.as_bytes()),
            b64_encode_url_nopad(&self.payload_json())
        );
        let sig = hmac_sha256(&mk.raw_enc_mac()[..], signing_input.as_bytes());
        Ok(format!("{signing_input}.{}", b64_encode_url_nopad(&sig)))
    }

    /// Read the key id without verifying (needed to know *which* key to load).
    pub fn peek_kid(token: &str) -> Result<String> {
        let h = token.split('.').next().ok_or_else(|| VaultError::Malformed("vault config".into()))?;
        let m = parse_flat_object(&b64_decode_url(h).map_err(|_| VaultError::Malformed("jwt".into()))?)?;
        m.get("kid")
            .and_then(|v| v.as_str())
            .map(|s| s.to_string())
            .ok_or_else(|| VaultError::Malformed("jwt missing kid".into()))
    }

    pub fn verify(token: &str, mk: &Masterkey) -> Result<Self> {
        let parts: Vec<&str> = token.trim().split('.').collect();
        if parts.len() != 3 {
            return Err(VaultError::Malformed("vault config is not a compact JWS".into()));
        }
        let header = parse_flat_object(&b64_decode_url(parts[0]).map_err(|_| VaultError::Malformed("jwt header".into()))?)?;
        let alg = header.get("alg").and_then(|v| v.as_str()).unwrap_or("");
        if alg != "HS256" {
            return Err(VaultError::Unsupported(format!("vault config algorithm {alg}")));
        }
        let sig = b64_decode_url(parts[2]).map_err(|_| VaultError::Malformed("jwt signature".into()))?;
        let signing_input = format!("{}.{}", parts[0], parts[1]);
        let expected_sig = hmac_sha256(&mk.raw_enc_mac()[..], signing_input.as_bytes());
        if !ct_eq(&expected_sig, &sig) {
            return Err(VaultError::Authentication("vault config signature"));
        }
        let payload =
            parse_flat_object(&b64_decode_url(parts[1]).map_err(|_| VaultError::Malformed("jwt payload".into()))?)?;
        let jti = payload
            .get("jti")
            .and_then(|v| v.as_str())
            .ok_or_else(|| VaultError::Malformed("jwt missing jti".into()))?
            .to_string();
        let format = payload
            .get("format")
            .and_then(|v| v.as_u64())
            .ok_or_else(|| VaultError::Malformed("jwt missing format".into()))? as u32;
        let cipher_combo = payload
            .get("cipherCombo")
            .and_then(|v| v.as_str())
            .ok_or_else(|| VaultError::Malformed("jwt missing cipherCombo".into()))?
            .to_string();
        let shortening_threshold = payload
            .get("shorteningThreshold")
            .and_then(|v| v.as_u64())
            .unwrap_or(DEFAULT_SHORTENING_THRESHOLD as u64) as usize;
        let cfg = VaultConfig { jti, format, cipher_combo, shortening_threshold };
        if cfg.format != VAULT_FORMAT {
            return Err(VaultError::Unsupported(format!("vault format {}", cfg.format)));
        }
        if cfg.cipher_combo != CIPHER_COMBO {
            return Err(VaultError::Unsupported(format!("cipher combo {}", cfg.cipher_combo)));
        }
        if cfg.shortening_threshold < 36 {
            return Err(VaultError::Unsupported("shortening threshold too small".into()));
        }
        Ok(cfg)
    }
}

impl Default for VaultConfig {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sign_verify_roundtrip() {
        let mk = Masterkey::generate();
        let cfg = VaultConfig::new();
        let tok = cfg.sign(&mk).unwrap();
        assert_eq!(VaultConfig::verify(&tok, &mk).unwrap(), cfg);
        assert_eq!(VaultConfig::peek_kid(&tok).unwrap(), MASTERKEY_KID);
    }

    #[test]
    fn wrong_key_rejected() {
        let tok = VaultConfig::new().sign(&Masterkey::generate()).unwrap();
        assert!(matches!(VaultConfig::verify(&tok, &Masterkey::generate()), Err(VaultError::Authentication(_))));
    }

    #[test]
    fn payload_tamper_rejected() {
        let mk = Masterkey::generate();
        let tok = VaultConfig::new().sign(&mk).unwrap();
        let parts: Vec<&str> = tok.split('.').collect();
        let mut cfg = VaultConfig::verify(&tok, &mk).unwrap();
        cfg.shortening_threshold = 50;
        let forged = format!("{}.{}.{}", parts[0], b64_encode_url_nopad(&cfg.payload_json()), parts[2]);
        assert!(VaultConfig::verify(&forged, &mk).is_err());
    }

    #[test]
    fn alg_none_rejected() {
        let mk = Masterkey::generate();
        let tok = VaultConfig::new().sign(&mk).unwrap();
        let parts: Vec<&str> = tok.split('.').collect();
        let h = b64_encode_url_nopad(br#"{"kid":"masterkeyfile:masterkey.cryptomator","typ":"JWT","alg":"none"}"#);
        let forged = format!("{h}.{}.", parts[1]);
        assert!(matches!(VaultConfig::verify(&forged, &mk), Err(VaultError::Unsupported(_))));
    }
}
