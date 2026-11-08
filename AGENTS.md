# Agent & Contributor Engineering Guidelines (`AGENTS.md`)

## Core Security Invariants (Never Violate)

1. **Do Not Invent Cryptography**: Never introduce custom ciphers, custom modes of operation, or homegrown KDFs. Adhere strictly to the Cryptomator Vault Format 8 (`SIV_GCM`) specification.
2. **Never Log or Return Secrets**: Error types (`VaultError`), IPC responses, and log statements must never include passphrases, `Masterkey` bytes, KEKs, `contentKey` bytes, or cleartext file payloads.
3. **Always Use Atomic Writes**: Every mutation to a vault or exported file must go through `fsutil::AtomicFile` or `fsutil::write_atomic` so interrupted or unauthenticated operations leave no partial artifacts.
4. **Synthetic Test Data Only**: Never commit or process real personal or sensitive documents. All unit and integration tests must generate synthetic byte streams inside RAII `TempDir` directories.
5. **Enforce Ciphertext-Only Cloud Sync**: Any new `CloudAdapter` implementation must be invoked exclusively through `SyncEngine`, which runs `verify_ciphertext_only` on every file before upload.

## Verification Checklist Before Committing

- Run `cargo test -p ciphervault-core` and ensure all 61 unit, tamper, streaming, recovery, and sync tests pass with 0 warnings.
- Build `ciphervaultd` (`cargo build --bin ciphervaultd`) and verify the RPC endpoints respond cleanly.
