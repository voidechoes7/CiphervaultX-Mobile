#![forbid(unsafe_code)]

pub mod archive;
pub mod backup;
pub mod config;
pub mod cryptomator;
pub mod error;
pub mod fsio;
pub mod kdf;
pub mod keys;
pub mod names;
#[cfg(feature = "pq")]
pub mod pq;
pub mod recovery;
pub mod seal;
pub mod secret;
pub mod standalone;
pub mod stream;
pub mod vault;

pub use archive::ArchiveReport;
pub use backup::{
    BackupJob, BackupManifest, BackupMode, BackupRunReport, BackupSchedule, ManifestFingerprint,
};
pub use config::{CipherSuite, KeySlot, VaultConfig, DEFAULT_CHUNK_SIZE, FORMAT_VERSION};
pub use error::{Result, VaultError};
pub use kdf::{Argon2Params, KdfProfile};
pub use recovery::RecoveryKey;
pub use vault::{
    EntryKind, IntegrityIssue, IntegrityReport, ProgressCallback, Vault, VaultEntry, VaultSummary,
};
