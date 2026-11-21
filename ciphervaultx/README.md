# Fortress / CipherVaultX (CVZ v1)

A privacy-first, client-side encrypted file vault built with **Rust**, **Tauri 2**, **React**, and **TypeScript**.

> **Pre-Audit Notice:** Fortress / CipherVaultX has **not** undergone an independent security audit. It must not be treated as production-ready, and no claim that it is "more secure than Cryptomator" is supported by evidence.

## What It Does
- Encrypts every file and every filename locally before touching disk using the custom **CVZ v1** format (not compatible with Cryptomator).
- Protects vault master keys with **Argon2id** (enforced floor: `m >= 65536 KiB`, `t >= 2`, `1 <= p <= 16`) and a one-time **Recovery Key**.
- Encrypts files in **STREAM** chunks (`XChaCha20-Poly1305` or `AES-256-GCM`) with final-chunk authentication (`lastFlag`) to detect truncation and chunk reordering.
- Authenticates directory markers (`dir.cvz`) with parent directory and encrypted name in AAD, preventing silent marker swaps.
- Provides a locked-down Tauri 2 WebView with zero filesystem permissions; all cryptographic and disk I/O runs in Rust.
- Includes six themes (`Obsidian Dark`, `Arctic Light`, `Midnight Blue`, `OLED Black`, `Emerald`, `System Adaptive`), keyboard focus rings, and `prefers-reduced-motion` support.

## What It Does Not Do (Yet)
- No cloud synchronization, file sharing, or multi-device key exchange.
- No virtual drive / Windows Explorer integration.
- No long filename shortening (encoded names > 200 chars are rejected).
- No iOS build.

## Development & Verification
```bash
# Rust workspace
cargo fmt --all -- --check
cargo clippy --workspace --all-targets -- -D warnings
cargo test -p cvz-core --all-features
cargo test -p cvz-core --release --all-features
cargo build --workspace

# Frontend
npm install
npm test
npm run build
```

## License
Apache-2.0 — see [LICENSE](./LICENSE).
