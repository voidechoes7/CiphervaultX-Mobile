use std::fmt;

use rand_core::{OsRng, RngCore};
use zeroize::{Zeroize, ZeroizeOnDrop};

/// 32-byte secret key material that zeroizes on drop and redacts Debug output.
#[derive(Clone, Zeroize, ZeroizeOnDrop)]
pub struct Key32([u8; 32]);

impl Key32 {
    pub fn from_bytes(bytes: [u8; 32]) -> Self {
        Self(bytes)
    }

    pub fn random() -> Self {
        Self(random_array::<32>())
    }

    pub fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }
}

impl fmt::Debug for Key32 {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("Key32([REDACTED])")
    }
}

/// 64-byte secret key material (used for AES-SIV-CMAC-512) that zeroizes on drop.
#[derive(Clone, Zeroize, ZeroizeOnDrop)]
pub struct Key64([u8; 64]);

impl Key64 {
    pub fn from_bytes(bytes: [u8; 64]) -> Self {
        Self(bytes)
    }

    pub fn as_bytes(&self) -> &[u8; 64] {
        &self.0
    }
}

impl fmt::Debug for Key64 {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("Key64([REDACTED])")
    }
}

/// Fill a fixed-size byte array from the operating system CSPRNG.
pub fn random_array<const N: usize>() -> [u8; N] {
    let mut out = [0u8; N];
    OsRng.fill_bytes(&mut out);
    out
}
