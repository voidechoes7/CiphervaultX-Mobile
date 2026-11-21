# Security Specification & Honest Posture — Fortress / CipherVaultX

> **Pre-Audit Warning:** Fortress / CipherVaultX has **not** been independently audited. Do not treat it as production-ready or claim it is more secure than Cryptomator.

## Cryptographic Primitives (CVZ v1)
- **Password KDF:** Argon2id v0x13, 32-byte random salt (`OsRng`), 32-byte output. Enforced minimum floor on both creation and unlock: `m >= 65536 KiB`, `t >= 2`, `1 <= p <= 16`.
- **Master Key & Subkeys:** Random 32-byte master key (`OsRng`), never derived directly from the password. Four subkeys derived via HKDF-SHA256 with `salt = vaultId`:
  - `ciphervaultz/v1/name-siv` (64B, AES-SIV-CMAC-512)
  - `ciphervaultz/v1/file-header` (32B, XChaCha20-Poly1305)
  - `ciphervaultz/v1/metadata` (32B, XChaCha20-Poly1305)
  - `ciphervaultz/v1/dir-hash` (32B, HMAC-SHA256)
- **Anti-Downgrade Slot AAD:** Key-slot wrapping binds format version, `vaultId`, `suiteId`, `chunkSize`, slot kind, and KDF parameters (or PQ label) into XChaCha20-Poly1305 AAD.
- **File Streaming:** 99-byte `CVZF` header + STREAM chunked AEAD (`XChaCha20-Poly1305` or `AES-256-GCM`) with `u32_be(index)` and `lastFlag` (`0x01` on final chunk, `0x00` otherwise).
- **Optional Hybrid PQ Slot (`pq` feature, OFF by default):** X25519 + ML-KEM-768. Provides **no** security improvement for data at rest (AES-256 and XChaCha20 are already post-quantum adequate against Grover's algorithm). Uses pre-1.0, unaudited `ml-kem`.

## Structural Trade-offs vs. Cryptomator
- **Three concrete structural improvements in CVZ v1:**
  1. Final-chunk `lastFlag` authentication detects truncation and appended chunks.
  2. Authenticated directory markers bind parent `dirId` and encrypted directory name in AAD.
  3. Enforced Argon2id security floor on both creation and unlock, with no silent backup fallback on policy violations.
- **One major structural disadvantage:**
  - CVZ v1 is new, unaudited cryptographic software. Unreviewed cryptography must be treated as unproven.

## Reporting Vulnerabilities
Please open a private security advisory on GitHub rather than posting exploit details publicly.
