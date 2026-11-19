# Project Status — Fortress / CipherVaultX

- **Stage:** Pre-audit functional implementation (CVZ v1).
- **Core Cryptography (`crates/cvz-core`):** Implemented according to normative CVZ v1 specification (Argon2id floor, HKDF-SHA256 subkeys, XChaCha20-Poly1305 & AES-256-GCM STREAM, AES-SIV-CMAC-512 filenames, HMAC-SHA256 flat storage, authenticated directory markers, atomic writes, optional `pq` feature).
- **Desktop Shell (`src-tauri`):** Tauri 2 IPC shell, session state, inactivity auto-lock, JSON vault registry, minimal capability (`core:default` + `dialog:default`).
- **Frontend (`src/`):** React 18 + TypeScript + Tailwind CSS with six themes, dashboard, vault wizard, unlock/recovery dialog, file explorer with streaming progress and in-memory preview, and settings/integrity verification view.
- **Audit Status:** **Not independently audited.** Treat as unproven cryptographic software.
