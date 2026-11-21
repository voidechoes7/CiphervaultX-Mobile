# Architecture — Fortress / CipherVaultX (CVZ v1)

## Workspace Layout
- `crates/cvz-core/` — Pure Rust cryptographic and vault storage library. Zero Tauri, UI, or network dependencies. `#![forbid(unsafe_code)]`.
- `src-tauri/` — Tauri 2 desktop/mobile shell, session state (`Arc<RwLock<Vault>>`), inactivity auto-lock task, JSON vault registry, and IPC commands.
- `src/` — React 18 + TypeScript + Tailwind CSS UI. Communicates with Rust strictly through typed IPC commands in `src/lib/api.ts`.

## Trust Boundary
- The WebView capability (`src-tauri/capabilities/default.json`) grants only `core:default` and `dialog:default`.
- The WebView has **zero** direct filesystem permissions. Every file read, write, encryption, decryption, and integrity scan executes inside Rust.
- Master keys and derived subkeys live exclusively in Rust memory (`Key32` / `Key64`, zeroized on drop) and are never serialized or sent to the frontend.

## On-Disk Layout (`CVZ v1`)
```text
<vault-root>/
├── cvz.vault.json          # Authenticated key-slot metadata (no unwrapped keys)
├── cvz.vault.json.bak      # Identical backup written atomically on every config update
└── d/
    └── <2-char-b32>/
        └── <30-char-b32>/  # Flat storage folder for a single dirId (HMAC-SHA256)
            ├── <aes-siv-b64url>.cvz          # 99-byte CVZF header + STREAM chunks
            └── <aes-siv-b64url>.cvzd/
                └── dir.cvz                   # Authenticated sealed child dirId
```

## Crash Safety & Atomicity
- All config writes, encrypted imports, and decrypted exports use `tempfile` (`.cvz-tmp-*`) in the destination directory, followed by `flush`, `sync_all`, atomic `persist` (rename), and parent directory `fsync` on Unix.
- Failed exports never leave plaintext at the destination path.
- Directory moves write the new authenticated marker to `dir.cvz.pending`, rename the folder, and promote `dir.cvz.pending` -> `dir.cvz`.
