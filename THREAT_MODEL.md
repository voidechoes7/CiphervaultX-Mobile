# Threat Model & Documented Limitations (`THREAT_MODEL.md`)

## 1. Assets Protected

1. **File Cleartext Contents**: Confidential documents, archives, and media stored inside a vault.
2. **File & Folder Names**: Cleartext filenames and directory names.
3. **Directory Hierarchy**: Parent-child relationships and nesting depth of directories.
4. **Masterkeys (`encKey`, `macKey`) & Passphrases**: Cryptographic key material protecting the vault.

## 2. Adversary Capabilities In Scope

- **Untrusted Cloud Storage Provider / Passive Network Observer**: Has full read access to all synchronized files (`vault.cryptomator`, `masterkey.cryptomator`, and `d/XX/YYYY.../*.c9r`) across time.
- **Active Storage Tampering Adversary**: Can flip bits, reorder 32 KiB chunks within a file, splice chunks from one encrypted file into another, swap encrypted filenames between directories, or modify `vault.cryptomator` / `masterkey.cryptomator`.
- **Offline Brute-Force Adversary**: Possesses a copy of `masterkey.cryptomator` and attempts dictionary/brute-force attacks against the user's passphrase.

## 3. Security Defenses Against In-Scope Threats

| Threat | Defense Mechanism | Verified By Test |
| :--- | :--- | :--- |
| Bit flip in file header or chunk | AES-256-GCM 128-bit authentication tag fails decryption | `crypto::content::tests::every_single_bit_flip_is_detected` |
| Chunk reordering within a file | 64-bit big-endian chunk index bound in GCM AAD | `crypto::content::tests::chunk_reordering_detected` |
| Splicing chunks across two files | 12-byte file header nonce bound in every chunk's GCM AAD | `crypto::content::tests::chunk_splicing_between_files_detected` |
| Moving encrypted file to another directory | Parent `dirId` bound as AES-256-SIV AAD on filename | `vault::tests::file_moved_between_dirs_on_disk_is_rejected` |
| Tampering with `vault.cryptomator` | Compact JWS `HS256` verified with `encKey \|\| macKey`; `alg: none` rejected | `crypto::config::tests::payload_tamper_rejected`, `alg_none_rejected` |
| Tampering with `masterkey.cryptomator` | RFC 3394 64-bit IV check + `HMAC-SHA256` over `version` | `crypto::masterkey_file::tests::tampered_wrapped_key_rejected`, `tampered_version_rejected` |
| Malicious KDF DoS (`scryptCostParam = 2^40`) | `KdfParams::validate_for_read` rejects $\log_2 N > 22$ before allocating memory | `crypto::masterkey_file::tests::hostile_kdf_params_rejected_before_derivation` |
| Partial plaintext left on disk after failed export | `AtomicFile` RAII guard unlinks temp file on any error | `vault::tests::tampered_file_is_detected_and_export_leaves_no_plaintext` |
| Accidental plaintext file synced to cloud | `sync::verify_ciphertext_only` rejects non-ciphertext paths/headers | `sync::tests::plaintext_leak_in_vault_folder_is_blocked_from_upload` |

## 4. Documented Limitations & Out-of-Scope Threats

1. **Whole Trailing Chunk Truncation (Inherited from Cryptomator Format 8)**:
   - Because Cryptomator Format 8 does not store an authenticated end-of-file marker or total chunk count in the header (to allow streaming random-access writes), an attacker who removes **one or more complete 32 KiB + 28 B chunks from the very end of a file** produces a valid, shorter plaintext. Mid-chunk truncation is always detected. This behavior is pinned in `crypto::content::tests::documented_limitation_whole_trailing_chunk_removal`.
2. **Metadata Leakage Inherent to File-Based Encryption**:
   - Individual ciphertext file sizes reveal the approximate cleartext file size (exact up to header/chunk overhead).
   - Modification timestamps (`mtime`), the number of files in each flattened directory (`d/<2>/<30>`), and the approximate length of filenames are visible to the storage provider.
3. **Compromised Host OS / Malware Running as the User**:
   - If the host operating system is compromised while a vault is unlocked, an attacker with ptrace/memory-read privileges or keylogger access can capture the passphrase or read decrypted data.
4. **No Independent Security Audit Yet**:
   - While CipherVault-X uses standard, audited OpenSSL 3 primitives and follows the Cryptomator Format 8 specification, the Rust integration code itself has not yet been audited by an external security consultancy.
