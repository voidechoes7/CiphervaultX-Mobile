//! # ciphervault-core
//!
//! UI-agnostic engine for CipherVault-X. Layers (each depends only on the ones below):
//!
//! * [`sync`]    – modular cloud synchronization adapters (encrypted ciphertext only; zero-knowledge)
//! * [`vault`]   – encrypted virtual filesystem (paths, folders, import/export, search, integrity)
//! * [`fsutil`]  – atomic, crash-safe filesystem primitives
//! * [`crypto`]  – keys, KDF + key wrapping, content/name encryption via OpenSSL 3 + ICU (no I/O)
//!
//! The crate has no Tauri, network or logging dependency so it can be reused unchanged by
//! the desktop shell, a future Android/iOS bridge and a CLI.
//!
//! **Status:** not independently audited. Do not rely on it for production secrets yet.

#![deny(unsafe_code)]
#![deny(missing_debug_implementations)]

pub mod crypto;
pub mod encoding;
pub mod error;
pub mod fsutil;
pub mod json;
pub mod sync;
pub mod vault;

pub use crypto::masterkey_file::KdfParams;
pub use error::{Result, VaultError};
pub use sync::{CloudAdapter, LocalMirrorAdapter, SyncEngine, SyncSummary};
pub use vault::{Entry, EntryKind, IntegrityReport, Vault};
