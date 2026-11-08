//! Error types for the vault engine.
//!
//! Errors never carry secret material (passwords, keys, plaintext). Messages are
//! safe to log and to show in the UI.

use std::fmt;
use std::io;

/// Result alias for core operations.
pub type Result<T> = std::result::Result<T, VaultError>;

#[derive(Debug)]
pub enum VaultError {
    /// Password-derived key failed to unwrap the masterkey (wrong password or tampered key file).
    InvalidPassword,

    /// An authenticated decryption failed: ciphertext, header, nonce or tag was modified,
    /// chunks were reordered/truncated, or the wrong key was used.
    Authentication(&'static str),

    /// Structural problem with on-disk data that is not an authentication failure.
    Malformed(String),

    /// Vault format or cipher combination not supported by this build.
    Unsupported(String),

    NotFound(String),

    AlreadyExists(String),

    InvalidName(String),

    Io(io::Error),
}

impl fmt::Display for VaultError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            VaultError::InvalidPassword => write!(f, "invalid password or corrupted masterkey file"),
            VaultError::Authentication(ctx) => {
                write!(f, "authentication failed: data is corrupted or has been tampered with ({ctx})")
            }
            VaultError::Malformed(m) => write!(f, "malformed vault data: {m}"),
            VaultError::Unsupported(m) => write!(f, "unsupported vault: {m}"),
            VaultError::NotFound(m) => write!(f, "not found: {m}"),
            VaultError::AlreadyExists(m) => write!(f, "already exists: {m}"),
            VaultError::InvalidName(m) => write!(f, "invalid name: {m}"),
            VaultError::Io(e) => write!(f, "i/o error: {e}"),
        }
    }
}

impl std::error::Error for VaultError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            VaultError::Io(e) => Some(e),
            _ => None,
        }
    }
}

impl From<io::Error> for VaultError {
    fn from(e: io::Error) -> Self {
        VaultError::Io(e)
    }
}
