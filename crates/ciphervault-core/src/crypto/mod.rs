//! Cryptographic layer. No filesystem access happens in this module tree.
//!
//! All primitives delegate to the system's audited OpenSSL 3.0 (`libcrypto`) and ICU
//! (`libicuuc`) libraries; nothing here is a novel cryptographic algorithm.
//! The construction follows the publicly documented Cryptomator vault format 8
//! (`SIV_GCM` cipher combo). See SECURITY.md for the rationale and limitations.

pub mod config;
pub mod content;
pub mod ffi;
pub mod filename;
pub mod keys;
pub mod masterkey_file;
