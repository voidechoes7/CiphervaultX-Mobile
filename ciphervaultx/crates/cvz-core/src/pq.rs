//! Optional hybrid post-quantum key slot (X25519 + ML-KEM-768).
//!
//! HONEST SECURITY NOTE:
//! - Disabled by default (`pq` Cargo feature).
//! - Provides NO security benefit for data at rest: AES-256 and XChaCha20 already
//!   provide adequate post-quantum security against Grover's algorithm.
//! - Only relevant for future asymmetric key exchange, which is not implemented.
//! - The `ml-kem` crate is pre-1.0 and unaudited.

use hkdf::Hkdf;
use ml_kem::kem::{Decapsulate, Encapsulate};
use ml_kem::{Encoded, EncodedSizeUser, KemCore, MlKem768, MlKem768Params};
use rand_core::OsRng;
use sha2::{Digest, Sha256};
use x25519_dalek::{EphemeralSecret, PublicKey as X25519PublicKey, StaticSecret};
use zeroize::Zeroize;

use crate::error::{Result, VaultError};
use crate::secret::Key32;

const HYBRID_KEM_INFO_PREFIX: &[u8] = b"cvz-hybrid-kem-v1\0";
const HYBRID_KEM_SALT: &[u8] = b"ciphervaultz";
const PQ_SLOT_CTX_PREFIX: &[u8] = b"cvz-pq-slot-v1\0";

pub struct HybridPqKeypair {
    x_secret: StaticSecret,
    x_public: [u8; 32],
    kem_dk: <MlKem768 as KemCore>::DecapsulationKey,
    kem_ek_bytes: Vec<u8>,
}

impl HybridPqKeypair {
    pub fn generate() -> Self {
        let x_secret = StaticSecret::random_from_rng(OsRng);
        let x_public = X25519PublicKey::from(&x_secret).to_bytes();
        let (kem_dk, kem_ek) = MlKem768::generate(&mut OsRng);
        let kem_ek_bytes = kem_ek.as_bytes().as_slice().to_vec();
        Self {
            x_secret,
            x_public,
            kem_dk,
            kem_ek_bytes,
        }
    }

    /// Public bundle: x_public(32) || kem_public
    pub fn public_bytes(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(32 + self.kem_ek_bytes.len());
        out.extend_from_slice(&self.x_public);
        out.extend_from_slice(&self.kem_ek_bytes);
        out
    }

    pub fn decapsulate_kek(
        &self,
        vault_id: &[u8; 16],
        label: &str,
        x25519_epk: &[u8; 32],
        mlkem_ct: &[u8],
    ) -> Result<Key32> {
        let eph_pub = X25519PublicKey::from(*x25519_epk);
        let ss_x = self.x_secret.diffie_hellman(&eph_pub);

        let ct_arr = ml_kem::Ciphertext::<MlKem768>::try_from(mlkem_ct)
            .map_err(|_| VaultError::InvalidCredentials)?;
        let ss_k = self
            .kem_dk
            .decapsulate(&ct_arr)
            .map_err(|_| VaultError::InvalidCredentials)?;

        derive_hybrid_kek(
            ss_k.as_slice(),
            ss_x.as_bytes(),
            mlkem_ct,
            x25519_epk,
            &self.x_public,
            vault_id,
            label,
        )
    }
}

pub struct HybridEncapsulation {
    pub x25519_epk: [u8; 32],
    pub mlkem_ct: Vec<u8>,
    pub kek: Key32,
}

/// Encapsulate a KEK to a recipient's `public_bytes` (x_public(32) || kem_public).
pub fn encapsulate_kek(
    recipient_public: &[u8],
    vault_id: &[u8; 16],
    label: &str,
) -> Result<HybridEncapsulation> {
    if recipient_public.len() <= 32 {
        return Err(VaultError::InvalidConfig);
    }
    let recip_x_bytes: [u8; 32] = recipient_public[0..32]
        .try_into()
        .map_err(|_| VaultError::InvalidConfig)?;
    let recip_x = X25519PublicKey::from(recip_x_bytes);

    let ek_encoded =
        Encoded::<<MlKem768 as KemCore>::EncapsulationKey>::try_from(&recipient_public[32..])
            .map_err(|_| VaultError::InvalidConfig)?;
    let recip_kem = ml_kem::kem::EncapsulationKey::<MlKem768Params>::from_bytes(&ek_encoded);

    let eph = EphemeralSecret::random_from_rng(OsRng);
    let eph_pub = X25519PublicKey::from(&eph).to_bytes();
    let ss_x = eph.diffie_hellman(&recip_x);

    let (ct, ss_k) = recip_kem
        .encapsulate(&mut OsRng)
        .map_err(|_| VaultError::Integrity)?;
    let ct_bytes = ct.as_slice().to_vec();

    let kek = derive_hybrid_kek(
        ss_k.as_slice(),
        ss_x.as_bytes(),
        &ct_bytes,
        &eph_pub,
        &recip_x_bytes,
        vault_id,
        label,
    )?;

    Ok(HybridEncapsulation {
        x25519_epk: eph_pub,
        mlkem_ct: ct_bytes,
        kek,
    })
}

fn derive_hybrid_kek(
    ss_k: &[u8],
    ss_x: &[u8; 32],
    ct: &[u8],
    eph_pub: &[u8; 32],
    recip_x: &[u8; 32],
    vault_id: &[u8; 16],
    label: &str,
) -> Result<Key32> {
    let mut ikm = Vec::with_capacity(ss_k.len() + ss_x.len());
    ikm.extend_from_slice(ss_k);
    ikm.extend_from_slice(ss_x);

    let ct_hash = Sha256::digest(ct);
    let mut ctx = Vec::with_capacity(PQ_SLOT_CTX_PREFIX.len() + 16 + label.len());
    ctx.extend_from_slice(PQ_SLOT_CTX_PREFIX);
    ctx.extend_from_slice(vault_id);
    ctx.extend_from_slice(label.as_bytes());

    let mut info =
        Vec::with_capacity(HYBRID_KEM_INFO_PREFIX.len() + ct_hash.len() + 32 + 32 + ctx.len());
    info.extend_from_slice(HYBRID_KEM_INFO_PREFIX);
    info.extend_from_slice(&ct_hash);
    info.extend_from_slice(eph_pub);
    info.extend_from_slice(recip_x);
    info.extend_from_slice(&ctx);

    let hk = Hkdf::<Sha256>::new(Some(HYBRID_KEM_SALT), &ikm);
    let mut out = [0u8; 32];
    let res = hk.expand(&info, &mut out);
    ikm.zeroize();
    res.map_err(|_| VaultError::Integrity)?;
    let key = Key32::from_bytes(out);
    out.zeroize();
    Ok(key)
}
