# Security Design & Cryptomator Format Assessment (`SECURITY.md`)

> **Disclaimer:** CipherVault-X has **not** been independently audited by an external security firm. Do not rely on it as production-secure until an independent cryptographic and implementation audit has been completed.

## 1. Cryptomator Vault Format 8 Assessment & License Compatibility

### Why Adopt Cryptomator's Vault Format 8 (`SIV_GCM`)?
Before writing any code, we reviewed the official Cryptomator security specifications:
- [Cryptomator Security Architecture](https://docs.cryptomator.org/security/architecture/)
- [Cryptomator Vault Cryptography (Format 8)](https://docs.cryptomator.org/security/vault/)
- [Cryptomator `cryptolib` Repository](https://github.com/cryptomator/cryptolib)

**Decision:** Adopting the established **Cryptomator Vault Format 8 (`SIV_GCM`)** on-disk specification is strongly preferable to inventing a custom vault format:
1. **Battle-tested design**: Its constructions (scrypt + RFC 3394 AES-KW, HS256 signed vault config, RFC 5297 AES-256-SIV filenames bound to parent `dirId`, 68-byte AES-256-GCM file header + 32 KiB AES-256-GCM chunks bound to chunk index and header nonce) were audited by Cure53 and have years of real-world scrutiny.
2. **Cloud-sync friendliness**: Encrypting individual files and flattening the directory tree under `d/<2>/<30>/` avoids monolithic container re-uploads and prevents cloud sync conflicts from corrupting an entire vault.

### License Compatibility Analysis
- Cryptomator's Java (`cryptolib`) and Swift (`cryptolib-swift`) libraries are licensed under **AGPL-3.0-or-later** (dual-licensed commercially by Skymatic GmbH) and target the JVM and Apple runtimes respectively rather than Rust.
- The **vault format specification itself** is publicly documented at `docs.cryptomator.org`.
- CipherVault-X implements the documented Format 8 specification cleanly in Rust on top of audited **OpenSSL 3.0 (`libcrypto`, Apache-2.0)** and **ICU (`libicuuc`, Unicode-3.0)** primitives (with a pure-Rust RustCrypto `Cargo.toml` specification for cross-compilation), and is licensed under **GPL-3.0-or-later**. No AGPL code from `cryptolib` was copied without license compliance.

## 2. Cryptographic Primitives & Parameters

| Function | Algorithm | Key / Nonce Size | Notes |
| :--- | :--- | :--- | :--- |
| CSPRNG | OpenSSL `RAND_bytes` (OS CSPRNG) | N/A | Generates salts, masterkeys, content keys, header/chunk nonces, UUIDs |
| Password KDF | `scrypt` (`EVP_PBE_scrypt`) over NFC password | 256-bit salt, 256-bit KEK | Default $N=2^{17}, r=8, p=1$ (128 MiB); Compat $N=2^{15}, r=8, p=1$; bounded on read ($N \le 2^{22}$) |
| Key Wrapping | AES-256 Key Wrap (RFC 3394, `EVP_aes_256_wrap`) | 256-bit KEK $\to$ 40-byte wrapped key | Wraps `encKey` and `macKey` independently; 64-bit integrity check detects wrong password |
| Config Signature | Compact JWS `HS256` (`HMAC-SHA256`) | 512-bit key (`encKey \|\| macKey`) | Rejects `alg != "HS256"` (`alg: none` blocked); constant-time `CRYPTO_memcmp` verification |
| Filename Encryption | AES-256-SIV (RFC 5297) | 512-bit key (`macKey \|\| encKey`) | Deterministic per directory (`AAD = dirId`); URL-safe Base64 + `.c9r` |
| Directory Hashing | `Base32(SHA1(AES-256-SIV(dirId)))` | 512-bit SIV key | Maps `dirId` to `d/<2 chars>/<30 chars>`; SHA-1 only shortens SIV output |
| File Header | AES-256-GCM | 256-bit `encKey`, 96-bit random nonce | Encrypts `0xFF*8 \|\| 32-byte contentKey` + 16-byte tag = 68 bytes |
| File Chunks | Streaming AES-256-GCM | 256-bit `contentKey`, 96-bit random nonce/chunk | Up to 32 KiB payload + 12B nonce + 16B tag; `AAD = BE64(chunkIdx) \|\| headerNonce` |

## 3. Secret Hygiene & Plaintext Exposure Prevention

1. **Zeroization on Drop**: [`Masterkey`](file:///home/antigravity/voidechoes7/CiphervaultX/crates/ciphervault-core/src/crypto/keys.rs) and [`SecretBuf`](file:///home/antigravity/voidechoes7/CiphervaultX/crates/ciphervault-core/src/crypto/ffi.rs#L508-L542) call `OPENSSL_cleanse` on drop so keys, KEKs, file content keys, and cleartext chunk buffers are scrubbed from RAM.
2. **Redacted Formatting**: `Debug` implementations on `Masterkey`, `FileHeader`, `NameCryptor`, and `SecretBuf` always print `<redacted>`.
3. **No Partial Plaintext on Tamper**: [`Vault::export_file`](file:///home/antigravity/voidechoes7/CiphervaultX/crates/ciphervault-core/src/vault/mod.rs#L406-L411) decrypts into an [`AtomicFile`](file:///home/antigravity/voidechoes7/CiphervaultX/crates/ciphervault-core/src/fsutil.rs#L17-L84) and only renames on complete AEAD verification; any bit flip in any chunk deletes the temporary file immediately.
4. **Ciphertext-Only Sync Guard**: [`verify_ciphertext_only`](file:///home/antigravity/voidechoes7/CiphervaultX/crates/ciphervault-core/src/sync.rs#L106-L172) blocks any file that does not match the Cryptomator Format 8 ciphertext layout from being uploaded.
