# CipherVault-X

> **Security Notice:** CipherVault-X is an engineering implementation of a client-side zero-knowledge encrypted file vault following the Cryptomator Vault Format 8 (`SIV_GCM`) specification. **It has not yet undergone an independent third-party cryptographic security audit** and must not be described or deployed as production-certified until independently reviewed.

CipherVault-X encrypts files, filenames, and directory structures locally before they touch disk or any cloud synchronization provider.

## Key Capabilities

- **Cryptomator Vault Format 8 (`SIV_GCM`) Compatibility**:
  - **Masterkeys**: Independent 256-bit AES encryption key (`encKey`) and 256-bit MAC key (`macKey`) generated from the OS CSPRNG (`RAND_bytes`).
  - **Key Derivation & Wrapping**: `scrypt` ($N=2^{17}, r=8, p=1$ default; $N=2^{15}$ compatibility profile) over Unicode NFC-normalized passphrases, wrapping `encKey` and `macKey` via **RFC 3394 AES-256 Key Wrap** (`masterkey.cryptomator`).
  - **Signed Vault Configuration**: `vault.cryptomator` compact JWS strictly verified with `HS256` (`HMAC-SHA256` keyed with `encKey || macKey`) in constant time before any payload field is trusted.
  - **Streaming File Content Encryption**: 68-byte authenticated header (12-byte random nonce + AES-256-GCM encrypted `0xFF * 8 || 32-byte contentKey` + 16-byte GCM tag) followed by 32 KiB cleartext chunks encrypted with **AES-256-GCM**, each with a fresh 96-bit nonce and AAD = $\text{BE64}(\text{chunkIndex}) \parallel \text{headerNonce}$.
  - **Deterministic Filename & Directory Obfuscation**: **RFC 5297 AES-256-SIV** over NFC-normalized cleartext names with the parent directory's UUID (`dirId`) bound as associated data, encoded as URL-safe Base64 + `.c9r` (with `.c9s` SHA-1 deflation over 220 characters). Directory hierarchy is flattened under `d/<2 chars>/<30 chars>/` (`Base32(SHA1(AES-SIV(dirId)))`).
- **Crash-Safe Atomic Filesystem Operations**: Every file write, export, and key rotation writes to a random temporary file in the target directory, calls `fsync`, and atomically renames into place, with RAII cleanup on error or authentication failure.
- **Zero-Knowledge Cloud Synchronization**: Modular `CloudAdapter` trait and `SyncEngine` with a strict pre-upload ciphertext verifier (`verify_ciphertext_only`) that rejects any non-ciphertext or stray plaintext file before it can reach an adapter.
- **Six Built-In Themes**: Obsidian Dark, Arctic Light, Midnight Blue, OLED Black, Emerald, and System Adaptive.

## Repository Structure

```text
CiphervaultX/
├── Cargo.toml                         # Rust workspace manifest
├── crates/ciphervault-core/           # UI-agnostic cryptography, vault FS & cloud sync engine
│   └── src/
│       ├── crypto/                    # OpenSSL 3 + ICU FFI, keys, masterkey_file, config, content, filename
│       ├── vault/                     # Encrypted virtual filesystem + 19 integration/recovery tests
│       ├── sync.rs                    # Zero-knowledge cloud sync engine & LocalMirrorAdapter
│       ├── fsutil.rs                  # AtomicFile (temp + fsync + rename) & RAII TempDir
│       ├── encoding.rs                # Base64, Base32 (RFC 4648), Hex, UUID v4
│       ├── json.rs                    # Strict flat-JSON parser & string escaper
│       └── bin/ciphervaultd.rs        # Standalone local HTTP/RPC daemon & CLI server
├── src-tauri/                         # Tauri 2 desktop/mobile shell & least-privilege capabilities
├── src/                               # React + TypeScript + Tailwind CSS frontend
├── dist/                              # Pre-built self-contained UI bundle served by ciphervaultd
└── .github/workflows/ci.yml           # Multi-OS test suite + Windows MSI/NSIS & Android APK CI
```

## Quick Start

### Run the Cryptographic & Recovery Test Suite (61 tests)

```bash
cargo test -p ciphervault-core
```

### Run the Live Local Daemon & UI

```bash
cargo run --bin ciphervaultd -- 4173 dist/index.html
```

### Build the Tauri 2 Desktop Application (when WebView SDK & npm are available)

```bash
npm install
npm run tauri build
```

## License

Licensed under **GPL-3.0-or-later**. See [SECURITY.md](file:///home/antigravity/voidechoes7/CiphervaultX/SECURITY.md) for the license compatibility analysis regarding Cryptomator's `cryptolib`.
