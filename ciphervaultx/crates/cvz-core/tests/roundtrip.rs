use std::fs::{self, File};
use std::io::{Read, Write};
use std::path::Path;

use cvz_core::{Argon2Params, CipherSuite, EntryKind, KdfProfile, RecoveryKey, Vault, VaultError};
use sha2::{Digest, Sha256};
use tempfile::tempdir;

const TEST_PASS: &str = "correct-horse-battery-staple-99";
const TEST_PASS_2: &str = "another-strong-passphrase-2026!";

fn fast_valid_kdf() -> Argon2Params {
    // Enforced security floor (m >= 65536, t >= 2, p = 1); real Argon2id, never weakened.
    Argon2Params {
        m_cost: 65_536,
        t_cost: 2,
        p_cost: 1,
    }
}

fn sha256_file(path: &Path) -> [u8; 32] {
    let mut f = File::open(path).expect("open file for sha256");
    let mut hasher = Sha256::new();
    let mut buf = [0u8; 65_536];
    loop {
        let n = f.read(&mut buf).expect("read for sha256");
        if n == 0 {
            break;
        }
        hasher.update(&buf[..n]);
    }
    hasher.finalize().into()
}

fn synthetic_bytes(len: usize, seed: u8) -> Vec<u8> {
    (0..len)
        .map(|i| ((i.wrapping_mul(31).wrapping_add(seed as usize)) & 0xff) as u8)
        .collect()
}

#[test]
fn roundtrip_boundary_sizes_both_suites() {
    let sizes = [0usize, 1, 65_535, 65_536, 65_537, 131_072, 200_000];
    for suite in [CipherSuite::XChaCha20Poly1305, CipherSuite::Aes256Gcm] {
        let dir = tempdir().expect("tempdir");
        let vault_root = dir.path().join("vault");
        let work = dir.path().join("work");
        fs::create_dir_all(&work).expect("work dir");

        let (vault, _rec) =
            Vault::create(&vault_root, TEST_PASS, suite, fast_valid_kdf()).expect("create vault");

        for &sz in &sizes {
            let data = synthetic_bytes(sz, (sz % 251) as u8);
            let src = work.join(format!("in_{sz}.bin"));
            let dst = work.join(format!("out_{sz}.bin"));
            fs::write(&src, &data).expect("write src");

            let vpath = format!("/file_{sz}.bin");
            let written = vault
                .import_file(&src, &vpath, None)
                .expect("import boundary file");
            assert_eq!(written, sz as u64);

            let exported = vault
                .export_file(&vpath, &dst, None)
                .expect("export boundary file");
            assert_eq!(exported, sz as u64);
            assert_eq!(fs::read(&dst).expect("read exported"), data);
        }

        let report = vault.verify_integrity().expect("verify integrity");
        assert_eq!(report.files_checked, sizes.len() as u64);
        assert!(report.issues.is_empty(), "issues: {:?}", report.issues);
    }
}

#[test]
fn streaming_64mib_roundtrip_sha256() {
    let dir = tempdir().expect("tempdir");
    let vault_root = dir.path().join("vault");
    let work = dir.path().join("work");
    fs::create_dir_all(&work).expect("work dir");

    let src = work.join("large_64mib.bin");
    let dst = work.join("large_64mib_out.bin");

    // Generate 64 MiB deterministically in 1 MiB chunks so memory stays bounded.
    let total_bytes: u64 = 64 * 1024 * 1024;
    {
        let mut f = File::create(&src).expect("create 64mib");
        let mut block = vec![0u8; 1024 * 1024];
        for m in 0u64..64 {
            for (i, b) in block.iter_mut().enumerate() {
                *b = ((m as usize).wrapping_mul(17).wrapping_add(i)) as u8;
            }
            f.write_all(&block).expect("write 1mib block");
        }
        f.flush().expect("flush");
    }

    let expected_hash = sha256_file(&src);
    let (vault, _) = Vault::create(
        &vault_root,
        TEST_PASS,
        CipherSuite::XChaCha20Poly1305,
        fast_valid_kdf(),
    )
    .expect("create vault");

    let mut progress_calls = 0u64;
    let mut cb = |_done: u64, _total: u64| {
        progress_calls += 1;
    };
    let imported = vault
        .import_file(&src, "/large.bin", Some(&mut cb))
        .expect("import 64mib");
    assert_eq!(imported, total_bytes);
    assert!(progress_calls > 10);

    let exported = vault
        .export_file("/large.bin", &dst, None)
        .expect("export 64mib");
    assert_eq!(exported, total_bytes);
    assert_eq!(sha256_file(&dst), expected_hash);
}

#[test]
fn auth_password_policy_recovery_and_change_password() {
    let dir = tempdir().expect("tempdir");
    let vault_root = dir.path().join("vault");

    // Short password rejected by policy.
    let err = Vault::create(
        &vault_root,
        "short123",
        CipherSuite::Aes256Gcm,
        fast_valid_kdf(),
    )
    .err()
    .expect("short password must fail");
    assert!(matches!(err, VaultError::WeakPassword));

    let (mut vault, recovery) = Vault::create(
        &vault_root,
        TEST_PASS,
        CipherSuite::Aes256Gcm,
        fast_valid_kdf(),
    )
    .expect("create");

    // Wrong password rejected.
    let err = Vault::unlock_with_password(&vault_root, "wrong-password-123456")
        .err()
        .expect("wrong password must fail");
    assert!(matches!(err, VaultError::InvalidCredentials));

    // Change password invalidates old password.
    vault
        .change_password(TEST_PASS, TEST_PASS_2, fast_valid_kdf())
        .expect("change password");
    assert!(matches!(
        Vault::unlock_with_password(&vault_root, TEST_PASS),
        Err(VaultError::InvalidCredentials)
    ));
    assert!(Vault::unlock_with_password(&vault_root, TEST_PASS_2).is_ok());

    // Recovery key display/parse roundtrip + unlock + password reset.
    let displayed = recovery.to_display_string();
    let parsed = RecoveryKey::parse(&displayed).expect("parse recovery key");
    assert!(Vault::unlock_with_recovery(&vault_root, &parsed).is_ok());

    let new_pw = "brand-new-reset-passphrase-42";
    let _reset_vault = Vault::reset_password_with_recovery(
        &vault_root,
        &parsed,
        new_pw,
        Argon2Params::for_profile(KdfProfile::Mobile),
    )
    .expect("reset with recovery");

    assert!(matches!(
        Vault::unlock_with_password(&vault_root, TEST_PASS_2),
        Err(VaultError::InvalidCredentials)
    ));
    assert!(Vault::unlock_with_password(&vault_root, new_pw).is_ok());
}

#[test]
fn no_plaintext_names_or_content_on_disk() {
    let dir = tempdir().expect("tempdir");
    let vault_root = dir.path().join("vault");
    let work = dir.path().join("work");
    fs::create_dir_all(&work).expect("work");

    let canary_name = "TOP_SECRET_CANARY_FILENAME_98765.txt";
    let canary_dir = "PRIVATE_CANARY_FOLDER_54321";
    let canary_body = "CANARY_PLAINTEXT_PAYLOAD_DO_NOT_LEAK_XYZ123";

    let src = work.join("input.txt");
    fs::write(&src, canary_body).expect("write canary");

    let (vault, _) = Vault::create(
        &vault_root,
        TEST_PASS,
        CipherSuite::XChaCha20Poly1305,
        fast_valid_kdf(),
    )
    .expect("create");
    vault
        .create_dir(&format!("/{canary_dir}"))
        .expect("create dir");
    vault
        .import_file(&src, &format!("/{canary_dir}/{canary_name}"), None)
        .expect("import canary");

    fn walk_and_check(dir: &Path, forbidden: &[&str]) {
        for entry in fs::read_dir(dir).expect("read_dir") {
            let entry = entry.expect("entry");
            let path = entry.path();
            let name = entry.file_name().to_string_lossy().to_string();
            for needle in forbidden {
                assert!(
                    !name.contains(needle),
                    "plaintext canary '{needle}' leaked in filename '{name}'"
                );
            }
            if path.is_dir() {
                walk_and_check(&path, forbidden);
            } else {
                let bytes = fs::read(&path).expect("read disk file");
                let text = String::from_utf8_lossy(&bytes);
                for needle in forbidden {
                    assert!(
                        !text.contains(needle),
                        "plaintext canary '{needle}' leaked inside disk file {:?}",
                        path
                    );
                }
            }
        }
    }

    walk_and_check(
        &vault_root,
        &[canary_name, canary_dir, canary_body, TEST_PASS],
    );
}

#[test]
fn folder_ops_unicode_nfc_and_safety_guards() {
    let dir = tempdir().expect("tempdir");
    let vault_root = dir.path().join("vault");
    let work = dir.path().join("work");
    fs::create_dir_all(&work).expect("work");

    let (vault, _) = Vault::create(
        &vault_root,
        TEST_PASS,
        CipherSuite::XChaCha20Poly1305,
        fast_valid_kdf(),
    )
    .expect("create");

    // Unicode NFC equivalence: "caf\u{00e9}" (composed) == "cafe\u{0301}" (decomposed).
    let nfc_folder = "/caf\u{00e9}";
    let nfd_folder = "/cafe\u{0301}";
    vault.create_dir(nfc_folder).expect("create nfc folder");

    let src = work.join("note.txt");
    fs::write(&src, b"hello unicode").expect("write");
    vault
        .import_file(
            &src,
            &format!("{nfd_folder}/r\u{00e9}sum\u{00e9}.txt"),
            None,
        )
        .expect("import via NFD parent path");

    let listed = vault.list_dir(nfc_folder).expect("list via NFC path");
    assert_eq!(listed.len(), 1);
    assert_eq!(listed[0].name, "r\u{00e9}sum\u{00e9}.txt");

    // Search works with NFD query against NFC stored name.
    let found = vault.search("resume").expect("search miss");
    assert!(found.is_empty());
    let found_nfc = vault.search("re\u{0301}sume\u{0301}").expect("search nfd");
    assert_eq!(found_nfc.len(), 1);

    // Rename & move.
    vault.create_dir("/archive").expect("create archive folder");
    vault
        .create_dir("/archive/sub")
        .expect("create archive/sub");

    // Refuse moving folder into its own subtree.
    let err = vault
        .move_entry("/archive", "/archive/sub")
        .err()
        .expect("subtree move must fail");
    assert!(matches!(err, VaultError::InvalidMoveTarget));

    vault
        .rename_entry(nfc_folder, "docs")
        .expect("rename folder");
    vault
        .move_entry("/docs", "/archive")
        .expect("move folder into /archive");

    let moved_contents = vault.list_dir("/archive/docs").expect("list moved folder");
    assert_eq!(moved_contents.len(), 1);
    assert_eq!(moved_contents[0].kind, EntryKind::File);

    // Delete moved folder recursively.
    vault.delete_entry("/archive/docs").expect("delete folder");
    let archive_items = vault.list_dir("/archive").expect("list archive");
    assert_eq!(archive_items.len(), 1);
    assert_eq!(archive_items[0].name, "sub");
}

#[test]
fn non_empty_dir_export_inside_vault_and_config_backup() {
    let dir = tempdir().expect("tempdir");

    // Refuse creating vault in non-empty directory.
    let non_empty = dir.path().join("non_empty");
    fs::create_dir_all(&non_empty).expect("mkdir");
    fs::write(non_empty.join("existing.txt"), b"hi").expect("write");
    assert!(matches!(
        Vault::create(
            &non_empty,
            TEST_PASS,
            CipherSuite::XChaCha20Poly1305,
            fast_valid_kdf(),
        ),
        Err(VaultError::NonEmptyDirectory)
    ));

    // Create valid vault.
    let vault_root = dir.path().join("vault");
    let work = dir.path().join("work");
    fs::create_dir_all(&work).expect("work");
    let (vault, _) = Vault::create(
        &vault_root,
        TEST_PASS,
        CipherSuite::XChaCha20Poly1305,
        fast_valid_kdf(),
    )
    .expect("create");

    let src = work.join("a.txt");
    fs::write(&src, b"secret data").expect("write");
    vault.import_file(&src, "/a.txt", None).expect("import");

    // Refuse exporting inside vault directory.
    let bad_dst = vault_root.join("leaked.txt");
    assert!(matches!(
        vault.export_file("/a.txt", &bad_dst, None),
        Err(VaultError::ExportInsideVault)
    ));
    assert!(!bad_dst.exists());

    // Corrupt primary config JSON -> backup config is used seamlessly.
    fs::write(vault_root.join("cvz.vault.json"), b"{not valid json!!!").expect("corrupt primary");
    assert!(Vault::unlock_with_password(&vault_root, TEST_PASS).is_ok());

    // Remove both configs -> NotFound.
    fs::remove_file(vault_root.join("cvz.vault.json")).expect("rm primary");
    fs::remove_file(vault_root.join("cvz.vault.json.bak")).expect("rm backup");
    assert!(matches!(
        Vault::unlock_with_password(&vault_root, TEST_PASS),
        Err(VaultError::NotFound)
    ));
}

#[cfg(feature = "pq")]
#[test]
fn hybrid_pq_slot_roundtrip() {
    let dir = tempdir().expect("tempdir");
    let vault_root = dir.path().join("vault_pq");

    let (mut vault, _) = Vault::create(
        &vault_root,
        TEST_PASS,
        CipherSuite::XChaCha20Poly1305,
        fast_valid_kdf(),
    )
    .expect("create");

    let kp = cvz_core::pq::HybridPqKeypair::generate();
    vault
        .add_hybrid_pq_slot("device-alpha", &kp.public_bytes())
        .expect("add pq slot");

    let unlocked = Vault::unlock_with_hybrid_pq(&vault_root, "device-alpha", &kp)
        .expect("unlock with hybrid pq");
    assert_eq!(unlocked.summary().vault_id, vault.summary().vault_id);

    // Wrong label must fail.
    assert!(matches!(
        Vault::unlock_with_hybrid_pq(&vault_root, "wrong-label", &kp),
        Err(VaultError::InvalidCredentials)
    ));
}
