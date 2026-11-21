# Threat Model — Fortress / CipherVaultX (CVZ v1)

## In-Scope Threats (Mitigated)
- **Passive cloud/storage observer:** Sees only ciphertext files, AES-SIV encrypted names, and flat HMAC-hashed directories.
- **Active file tampering:** Bit flips in file headers or chunks, chunk reordering, chunk duplication/appending, and truncation fail AEAD authentication.
- **Active metadata tampering:** Moving an encrypted file between directories causes AES-SIV filename decryption failure (surfaced as `Unreadable`). Swapping directory markers fails marker authentication (`Integrity` error).
- **Config downgrade attacks:** Editing `suite`, `chunkSize`, or `kdf` parameters breaks slot AAD unwrapping; lowering KDF parameters below the floor triggers `WeakKdfParams` without falling back to `.bak`.

## Known Limitations & Out-of-Scope Threats
1. **Whole-file substitution:** Swapping the entire encrypted contents of two files within the same vault is **not** detected (file headers bind `vaultId`, not filename/path). Verified by `known_limitation_whole_file_swap_not_detected`.
2. **Rollback attacks:** Replacing the entire vault directory (or individual files) with an older valid snapshot is **not** detected.
3. **Metadata leakage:** File count, directory fan-out, approximate file sizes, and filesystem modification timestamps remain visible to a storage observer.
4. **Memory locking:** Key material is zeroized on drop (`zeroize`), but pages are **not** locked with `mlock` / `VirtualLock` and could be paged to swap or read by privileged malware on a compromised host.
5. **Long filenames:** Encrypted names exceeding 200 characters are rejected (`NameTooLong`), not shortened.
6. **Compromised endpoint:** Malware with user/admin privileges on the unlocked device can read unlocked memory or intercept inputs.
7. **No independent audit:** No third-party cryptographic or implementation audit has been conducted.
