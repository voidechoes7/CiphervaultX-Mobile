use std::fs;
use std::path::{Path, PathBuf};

use cvz_core::{Argon2Params, CipherSuite, EntryKind, Vault, VaultError};
use tempfile::tempdir;

const TEST_PASS: &str = "adversarial-test-passphrase-2026";

fn fast_valid_kdf() -> Argon2Params {
    Argon2Params {
        m_cost: 65_536,
        t_cost: 2,
        p_cost: 1,
    }
}

fn find_files_with_ext(root: &Path, ext: &str) -> Vec<PathBuf> {
    let mut out = Vec::new();
    fn walk(dir: &Path, ext: &str, out: &mut Vec<PathBuf>) {
        if let Ok(rd) = fs::read_dir(dir) {
            for e in rd.flatten() {
                let p = e.path();
                let name = e.file_name().to_string_lossy().to_string();
                if p.is_file() && name.ends_with(ext) && name != "dir.cvz" {
                    out.push(p);
                } else if p.is_dir() {
                    walk(&p, ext, out);
                }
            }
        }
    }
    walk(root, ext, &mut out);
    out.sort();
    out
}

fn find_dirs_with_ext(root: &Path, ext: &str) -> Vec<PathBuf> {
    let mut out = Vec::new();
    fn walk(dir: &Path, ext: &str, out: &mut Vec<PathBuf>) {
        if let Ok(rd) = fs::read_dir(dir) {
            for e in rd.flatten() {
                let p = e.path();
                let name = e.file_name().to_string_lossy().to_string();
                if p.is_dir() && name.ends_with(ext) {
                    out.push(p);
                } else if p.is_dir() {
                    walk(&p, ext, out);
                }
            }
        }
    }
    walk(root, ext, &mut out);
    out.sort();
    out
}

#[test]
fn single_bit_flips_in_header_and_chunks_fail_and_leave_no_output() {
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

    // 2 chunks (100 KiB > 64 KiB chunk size)
    let payload: Vec<u8> = (0..100_000usize).map(|i| (i % 251) as u8).collect();
    let src = work.join("two_chunks.bin");
    fs::write(&src, &payload).expect("write src");
    vault
        .import_file(&src, "/two_chunks.bin", None)
        .expect("import");

    let ct_files = find_files_with_ext(&vault_root, ".cvz");
    assert_eq!(ct_files.len(), 1);
    let ct_path = &ct_files[0];
    let original_ct = fs::read(ct_path).expect("read ct");

    // Header offsets: 0, 4, 5, 6, 10, 30, 60, 98 + chunk 0 + chunk 1
    let chunk0_offset = 99 + 100;
    let chunk1_offset = 99 + (65_536 + 16) + 100;
    let offsets = [
        0usize,
        4,
        5,
        6,
        10,
        30,
        60,
        98,
        chunk0_offset,
        chunk1_offset,
    ];

    for (i, &off) in offsets.iter().enumerate() {
        let mut tampered = original_ct.clone();
        tampered[off] ^= 0x01;
        fs::write(ct_path, &tampered).expect("write tampered");

        let dst = work.join(format!("should_not_exist_{i}.bin"));
        let err = vault
            .export_file("/two_chunks.bin", &dst, None)
            .err()
            .unwrap_or_else(|| panic!("flip at offset {off} MUST fail"));
        assert!(
            matches!(err, VaultError::Integrity),
            "expected Integrity at offset {off}, got {err:?}"
        );
        assert!(
            !dst.exists(),
            "failed export at offset {off} left plaintext file behind"
        );
    }

    // Restore and confirm integrity scan detects a single-byte corruption cleanly.
    let mut tampered = original_ct.clone();
    tampered[chunk1_offset] ^= 0x80;
    fs::write(ct_path, &tampered).expect("write tampered");

    let report = vault.verify_integrity().expect("verify integrity");
    assert_eq!(report.files_checked, 1);
    assert_eq!(report.issues.len(), 1);
    assert_eq!(report.issues[0].path, "/two_chunks.bin");
}

#[test]
fn truncation_append_and_chunk_swap_all_fail() {
    let dir = tempdir().expect("tempdir");
    let vault_root = dir.path().join("vault");
    let work = dir.path().join("work");
    fs::create_dir_all(&work).expect("work");

    let (vault, _) = Vault::create(
        &vault_root,
        TEST_PASS,
        CipherSuite::Aes256Gcm,
        fast_valid_kdf(),
    )
    .expect("create");

    // Exactly 2 full chunks (131072 bytes)
    let payload: Vec<u8> = (0..131_072usize).map(|i| ((i * 7) & 0xff) as u8).collect();
    let src = work.join("exact2.bin");
    fs::write(&src, &payload).expect("write");
    vault
        .import_file(&src, "/exact2.bin", None)
        .expect("import");

    let ct_path = find_files_with_ext(&vault_root, ".cvz")[0].clone();
    let original_ct = fs::read(&ct_path).expect("read ct");
    let full_chunk = 65_536 + 16;

    // 1. Truncate at header boundary (99 bytes)
    fs::write(&ct_path, &original_ct[..99]).expect("write");
    assert!(matches!(
        vault.export_file("/exact2.bin", &work.join("t1.bin"), None),
        Err(VaultError::Integrity)
    ));

    // 2. Truncate at chunk boundary (drop chunk 1 -> chunk 0 has lastFlag = 0!)
    fs::write(&ct_path, &original_ct[..99 + full_chunk]).expect("write");
    assert!(matches!(
        vault.export_file("/exact2.bin", &work.join("t2.bin"), None),
        Err(VaultError::Integrity)
    ));

    // 3. Truncate mid-chunk
    fs::write(&ct_path, &original_ct[..99 + full_chunk + 500]).expect("write");
    assert!(matches!(
        vault.export_file("/exact2.bin", &work.join("t3.bin"), None),
        Err(VaultError::Integrity)
    ));

    // 4. Append a copy of chunk 0
    let mut appended = original_ct.clone();
    appended.extend_from_slice(&original_ct[99..99 + full_chunk]);
    fs::write(&ct_path, &appended).expect("write");
    assert!(matches!(
        vault.export_file("/exact2.bin", &work.join("t4.bin"), None),
        Err(VaultError::Integrity)
    ));

    // 5. Swap chunk 0 and chunk 1
    let mut swapped = Vec::with_capacity(original_ct.len());
    swapped.extend_from_slice(&original_ct[..99]);
    swapped.extend_from_slice(&original_ct[99 + full_chunk..99 + 2 * full_chunk]);
    swapped.extend_from_slice(&original_ct[99..99 + full_chunk]);
    fs::write(&ct_path, &swapped).expect("write");
    assert!(matches!(
        vault.export_file("/exact2.bin", &work.join("t5.bin"), None),
        Err(VaultError::Integrity)
    ));
}

#[test]
fn swapping_directory_markers_fails_authentication() {
    let dir = tempdir().expect("tempdir");
    let vault_root = dir.path().join("vault");

    let (vault, _) = Vault::create(
        &vault_root,
        TEST_PASS,
        CipherSuite::XChaCha20Poly1305,
        fast_valid_kdf(),
    )
    .expect("create");
    vault.create_dir("/alpha").expect("mkdir alpha");
    vault.create_dir("/beta").expect("mkdir beta");

    let marker_dirs = find_dirs_with_ext(&vault_root, ".cvzd");
    assert_eq!(marker_dirs.len(), 2);

    let m0 = marker_dirs[0].join("dir.cvz");
    let m1 = marker_dirs[1].join("dir.cvz");
    let b0 = fs::read(&m0).expect("read m0");
    let b1 = fs::read(&m1).expect("read m1");
    fs::write(&m0, &b1).expect("swap m0");
    fs::write(&m1, &b0).expect("swap m1");

    // Listing root or either swapped directory must fail with Integrity (never empty list).
    assert!(matches!(vault.list_dir("/"), Err(VaultError::Integrity)));
    assert!(matches!(
        vault.list_dir("/alpha"),
        Err(VaultError::Integrity)
    ));
    assert!(matches!(
        vault.list_dir("/beta"),
        Err(VaultError::Integrity)
    ));
}

#[test]
fn moving_encrypted_file_between_dirs_lists_as_unreadable() {
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
    vault.create_dir("/dir_a").expect("mkdir a");
    vault.create_dir("/dir_b").expect("mkdir b");

    let src = work.join("secret.txt");
    fs::write(&src, b"bound to dir_a").expect("write");
    vault
        .import_file(&src, "/dir_a/secret.txt", None)
        .expect("import");

    // Locate the encrypted file inside dir_a's storage folder and move it on disk to root storage.
    let ct_file = find_files_with_ext(&vault_root, ".cvz")[0].clone();
    let root_storage = ct_file
        .parent()
        .unwrap()
        .parent()
        .unwrap()
        .parent()
        .unwrap();
    // Find another storage directory under vault_root/d that is not ct_file's parent.
    let mut target_storage = None;
    for l1 in fs::read_dir(root_storage).expect("read d") {
        for l2 in fs::read_dir(l1.expect("l1").path()).expect("read l1") {
            let p = l2.expect("l2").path();
            if p != ct_file.parent().unwrap() {
                target_storage = Some(p);
                break;
            }
        }
    }
    let dst_storage = target_storage.expect("another storage dir");
    let raw_name = ct_file.file_name().unwrap().to_os_string();
    fs::rename(&ct_file, dst_storage.join(&raw_name)).expect("disk move");

    // Check across root, dir_a, dir_b that the moved file shows up as Unreadable (never silently dropped).
    let mut saw_unreadable = false;
    for vdir in ["/", "/dir_a", "/dir_b"] {
        for e in vault.list_dir(vdir).expect("list_dir") {
            if e.kind == EntryKind::Unreadable {
                saw_unreadable = true;
            }
        }
    }
    assert!(
        saw_unreadable,
        "moved ciphertext file must appear as Unreadable"
    );
}

#[test]
fn config_suite_downgrade_and_weak_kdf_rejected() {
    let dir = tempdir().expect("tempdir");
    let vault_root = dir.path().join("vault");

    let (_vault, _) = Vault::create(
        &vault_root,
        TEST_PASS,
        CipherSuite::XChaCha20Poly1305,
        fast_valid_kdf(),
    )
    .expect("create");

    let cfg_path = vault_root.join("cvz.vault.json");
    let original_json = fs::read_to_string(&cfg_path).expect("read config");

    // 1. Suite downgrade in config -> slot AAD mismatch -> InvalidCredentials.
    let downgraded = original_json.replace("xchacha20-poly1305", "aes256-gcm");
    fs::write(&cfg_path, &downgraded).expect("write downgraded");
    assert!(matches!(
        Vault::unlock_with_password(&vault_root, TEST_PASS),
        Err(VaultError::InvalidCredentials)
    ));

    // 2. KDF parameters below floor in config -> WeakKdfParams (MUST NOT fall back to backup!).
    let weak_kdf = original_json.replace("\"m_cost\": 65536", "\"m_cost\": 1024");
    fs::write(&cfg_path, &weak_kdf).expect("write weak kdf");
    assert!(matches!(
        Vault::unlock_with_password(&vault_root, TEST_PASS),
        Err(VaultError::WeakKdfParams)
    ));
}

#[test]
fn known_limitation_whole_file_swap_not_detected() {
    // This test intentionally pins a real, documented architectural limitation:
    // swapping the entire encrypted contents of two files in the same vault is NOT
    // detected because file headers bind vaultId (not the filename/parent path).
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

    let f1 = work.join("one.txt");
    let f2 = work.join("two.txt");
    fs::write(&f1, b"CONTENT_ONE").expect("write 1");
    fs::write(&f2, b"CONTENT_TWO").expect("write 2");

    vault.import_file(&f1, "/one.txt", None).expect("import 1");
    vault.import_file(&f2, "/two.txt", None).expect("import 2");

    let ct_files = find_files_with_ext(&vault_root, ".cvz");
    assert_eq!(ct_files.len(), 2);
    let b0 = fs::read(&ct_files[0]).expect("read 0");
    let b1 = fs::read(&ct_files[1]).expect("read 1");
    fs::write(&ct_files[0], &b1).expect("swap 0");
    fs::write(&ct_files[1], &b0).expect("swap 1");

    // Integrity scan passes (confirming the documented limitation).
    let report = vault.verify_integrity().expect("verify");
    assert!(report.issues.is_empty());

    // And the contents are swapped.
    let out1 = vault.read_file_bytes("/one.txt", 1024).expect("read one");
    let out2 = vault.read_file_bytes("/two.txt", 1024).expect("read two");
    assert_eq!(out1, b"CONTENT_TWO");
    assert_eq!(out2, b"CONTENT_ONE");
}
