use std::fs::{self, File};
use std::io::{Read, Write};
use std::path::Path;

use cvz_core::{Argon2Params, CipherSuite, Vault, VaultError};
use sha2::{Digest, Sha256};
use tempfile::tempdir;

fn sha256_file(path: &Path) -> [u8; 32] {
    let mut f = File::open(path).expect("open");
    let mut h = Sha256::new();
    let mut buf = [0u8; 65_536];
    loop {
        let n = f.read(&mut buf).expect("read");
        if n == 0 {
            break;
        }
        h.update(&buf[..n]);
    }
    h.finalize().into()
}

/// End-to-end automated verification of FASE 7 smoke steps 2–9, including Step 9
/// (corrupting a single byte of ciphertext and verifying integrity scan reports 1 issue).
#[test]
fn smoke_20mb_roundtrip_lock_and_step9_single_byte_corruption() {
    let dir = tempdir().expect("tempdir");
    let vault_root = dir.path().join("smoke_vault");
    let work = dir.path().join("work");
    fs::create_dir_all(&work).expect("work");

    let password = "synthetic-smoke-password-2026!";
    let (vault, recovery) = Vault::create(
        &vault_root,
        password,
        CipherSuite::XChaCha20Poly1305,
        Argon2Params::mobile(),
    )
    .expect("create vault");
    assert!(!recovery.to_display_string().is_empty());

    // Step 3: Import ~20 MB synthetic file with progress reporting.
    let src = work.join("synthetic_20mb.bin");
    let total_size = 20 * 1024 * 1024usize;
    {
        let mut f = File::create(&src).expect("create 20mb");
        let block = vec![0xA5u8; 1024 * 1024];
        for _ in 0..20 {
            f.write_all(&block).expect("write block");
        }
    }
    let orig_sha = sha256_file(&src);

    let mut progress_events = 0u64;
    let mut cb = |_done: u64, _total: u64| {
        progress_events += 1;
    };
    let imported = vault
        .import_file(&src, "/synthetic_20mb.bin", Some(&mut cb))
        .expect("import 20mb");
    assert_eq!(imported, total_size as u64);
    assert!(progress_events > 0);

    // Step 4: Export and compare SHA-256.
    let dst = work.join("exported_20mb.bin");
    vault
        .export_file("/synthetic_20mb.bin", &dst, None)
        .expect("export 20mb");
    assert_eq!(sha256_file(&dst), orig_sha);

    // Step 5 & 6: Drop (lock) and reject wrong password.
    drop(vault);
    assert!(matches!(
        Vault::unlock_with_password(&vault_root, "wrong-password-123456"),
        Err(VaultError::InvalidCredentials)
    ));

    // Step 7: Inspect vault config on disk — no unwrapped master key or password.
    let cfg_text = fs::read_to_string(vault_root.join("cvz.vault.json")).expect("read cfg");
    assert!(!cfg_text.contains(password));
    assert!(!cfg_text.contains("masterKey"));
    assert!(!cfg_text.contains("synthetic_20mb.bin"));

    // Step 8: Unlock and run full integrity scan -> 0 issues.
    let vault = Vault::unlock_with_password(&vault_root, password).expect("unlock");
    let clean_report = vault.verify_integrity().expect("verify clean");
    assert_eq!(clean_report.files_checked, 1);
    assert!(clean_report.issues.is_empty());

    // Step 9: Corrupt 1 byte of the encrypted file on disk and re-run integrity scan -> exactly 1 issue.
    let mut ct_file = None;
    fn find_first_cvz(dir: &Path, out: &mut Option<std::path::PathBuf>) {
        if out.is_some() {
            return;
        }
        if let Ok(rd) = fs::read_dir(dir) {
            for e in rd.flatten() {
                let p = e.path();
                let name = e.file_name().to_string_lossy().to_string();
                if p.is_file() && name.ends_with(".cvz") && name != "dir.cvz" {
                    *out = Some(p);
                    return;
                } else if p.is_dir() {
                    find_first_cvz(&p, out);
                }
            }
        }
    }
    find_first_cvz(&vault_root, &mut ct_file);
    let ct_path = ct_file.expect("encrypted file on disk");
    let mut bytes = fs::read(&ct_path).expect("read ct");
    bytes[500] ^= 0xFF;
    fs::write(&ct_path, &bytes).expect("write corrupted ct");

    let corrupt_report = vault.verify_integrity().expect("verify after 1-byte flip");
    assert_eq!(corrupt_report.files_checked, 1);
    assert_eq!(corrupt_report.issues.len(), 1);
    assert_eq!(corrupt_report.issues[0].path, "/synthetic_20mb.bin");
}
