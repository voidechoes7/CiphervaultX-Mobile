use thiserror::Error;

pub type Result<T> = std::result::Result<T, VaultError>;

#[derive(Debug, Error)]
pub enum VaultError {
    #[error("vault not found")]
    NotFound,

    #[error("vault directory must be empty")]
    NonEmptyDirectory,

    #[error("invalid credentials")]
    InvalidCredentials,

    #[error("password does not meet minimum policy requirements")]
    WeakPassword,

    #[error("KDF parameters are below the enforced security floor")]
    WeakKdfParams,

    #[error("unsupported vault format version: {0}")]
    UnsupportedFormat(u32),

    #[error("invalid vault configuration")]
    InvalidConfig,

    #[error("cryptographic integrity check failed")]
    Integrity,

    #[error("invalid filename or path component")]
    InvalidName,

    #[error("encrypted filename exceeds maximum portable length")]
    NameTooLong,

    #[error("entry already exists")]
    AlreadyExists,

    #[error("entry not found")]
    EntryNotFound,

    #[error("cannot move a directory into its own subtree")]
    InvalidMoveTarget,

    #[error("refusing to export plaintext inside the vault directory")]
    ExportInsideVault,

    #[error("invalid recovery key format")]
    InvalidRecoveryKey,

    #[error("vault is locked")]
    Locked,

    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),
}
