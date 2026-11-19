# Agent & Contributor Guidelines — Fortress / CipherVaultX

## Inviolable Rules
1. Never weaken cryptographic parameters (Argon2 floor, AEAD authentication, STREAM `lastFlag`, directory marker AAD, `#![forbid(unsafe_code)]`).
2. Never add `#[ignore]` to security or tamper tests, and never remove `known_limitation_whole_file_swap_not_detected`.
3. Never log, print, serialize, or transmit passwords, keys, or plaintext filenames.
4. Never grant filesystem permissions to the Tauri WebView (`src-tauri/capabilities/default.json`).
5. Always describe the software honestly as pre-audit and never claim it is more secure than Cryptomator.
6. Document license and rationale for every added dependency.
