//! Vault integration tests. All data is synthetic and lives in temp dirs.

use super::*;
use crate::fsutil::TempDir;
use std::io::Cursor;

const PW: &str = "synthetic-test-password";

fn new_vault() -> (TempDir, Vault) {
    let d = TempDir::new().unwrap();
    let v = Vault::create(&d.path().join("vault"), PW, KdfParams::INSECURE_TEST).unwrap();
    (d, v)
}

fn put(v: &Vault, p: &str, data: &[u8]) {
    v.write_file(p, Cursor::new(data.to_vec()), false, None).unwrap();
}

fn get(v: &Vault, p: &str) -> Vec<u8> {
    let mut out = Vec::new();
    v.read_file(p, &mut out, None).unwrap();
    out
}

/// Every regular file under the vault directory.
fn all_files(root: &Path) -> Vec<PathBuf> {
    let mut out = Vec::new();
    let mut stack = vec![root.to_path_buf()];
    while let Some(d) = stack.pop() {
        for e in fs::read_dir(d).unwrap() {
            let p = e.unwrap().path();
            if p.is_dir() {
                stack.push(p)
            } else {
                out.push(p)
            }
        }
    }
    out
}

#[test]
fn create_then_unlock() {
    let (_d, v) = new_vault();
    let root = v.root().to_path_buf();
    assert!(Vault::is_vault(&root));
    drop(v);
    let v = Vault::unlock(&root, PW).unwrap();
    assert!(v.list("/").unwrap().is_empty());
}

#[test]
fn wrong_password_cannot_unlock() {
    let (_d, v) = new_vault();
    let root = v.root().to_path_buf();
    assert!(matches!(Vault::unlock(&root, "nope"), Err(VaultError::InvalidPassword)));
}

#[test]
fn create_refuses_non_empty_folder() {
    let d = TempDir::new().unwrap();
    fs::write(d.path().join("existing.txt"), b"x").unwrap();
    assert!(matches!(Vault::create(d.path(), PW, KdfParams::INSECURE_TEST), Err(VaultError::AlreadyExists(_))));
}

#[test]
fn file_roundtrip_and_listing() {
    let (_d, v) = new_vault();
    put(&v, "/hello.txt", b"synthetic hello");
    v.create_dir("/Docs").unwrap();
    put(&v, "/Docs/inner.bin", &[7u8; 1000]);
    let l = v.list("/").unwrap();
    assert_eq!(l.iter().map(|e| e.name.as_str()).collect::<Vec<_>>(), ["Docs", "hello.txt"]);
    assert_eq!(l[1].size, Some(15));
    assert_eq!(get(&v, "/hello.txt"), b"synthetic hello");
    assert_eq!(get(&v, "/Docs/inner.bin"), vec![7u8; 1000]);
    assert_eq!(v.list("/Docs").unwrap()[0].path, "/Docs/inner.bin");
}

#[test]
fn no_plaintext_names_or_contents_on_disk() {
    let (_d, v) = new_vault();
    let marker = b"PLAINTEXT-CANARY-7f3a";
    v.create_dir("/CanaryFolder").unwrap();
    put(&v, "/CanaryFolder/CanaryFile.txt", &marker.repeat(100));
    for f in all_files(v.root()) {
        let path = f.to_string_lossy();
        assert!(!path.contains("Canary"), "plaintext name in {path}");
        let bytes = fs::read(&f).unwrap();
        assert!(!bytes.windows(marker.len()).any(|w| w == marker), "plaintext content in {path}");
    }
}

#[test]
fn directory_structure_is_flat_on_disk() {
    let (_d, v) = new_vault();
    v.create_dir_all("/a/b/c/d").unwrap();
    // depth on disk is bounded regardless of cleartext depth: d/XX/YYY/<node>/dir.c9r
    for f in all_files(v.root()) {
        let rel = f.strip_prefix(v.root()).unwrap();
        assert!(rel.components().count() <= 5, "{rel:?}");
    }
}

#[test]
fn overwrite_semantics() {
    let (_d, v) = new_vault();
    put(&v, "/f", b"one");
    assert!(matches!(v.write_file("/f", Cursor::new(b"two".to_vec()), false, None), Err(VaultError::AlreadyExists(_))));
    v.write_file("/f", Cursor::new(b"three".to_vec()), true, None).unwrap();
    assert_eq!(get(&v, "/f"), b"three");
}

#[test]
fn rename_move_and_delete() {
    let (_d, v) = new_vault();
    v.create_dir_all("/A/Sub").unwrap();
    v.create_dir("/B").unwrap();
    put(&v, "/A/Sub/x.txt", b"x");
    v.rename("/A/Sub/x.txt", "/B/y.txt").unwrap();
    assert_eq!(get(&v, "/B/y.txt"), b"x");
    assert!(!v.exists("/A/Sub/x.txt"));
    v.rename("/A", "/B/A2").unwrap();
    assert!(v.exists("/B/A2/Sub"));
    assert!(v.rename("/B", "/B/A2/Sub/B").is_err(), "move into itself must fail");
    put(&v, "/B/A2/Sub/z", b"z");
    v.delete("/B").unwrap();
    assert!(v.list("/").unwrap().is_empty());
    // only root storage dir remains
    let dirs: Vec<_> = all_files(&v.root().join(DATA_DIR));
    assert!(dirs.is_empty(), "leftover files: {dirs:?}");
}

#[test]
fn long_names_are_shortened_and_work() {
    let (_d, v) = new_vault();
    let long = "L".repeat(200);
    v.create_dir(&format!("/{long}")).unwrap();
    put(&v, &format!("/{long}/{long}.txt"), b"deep");
    assert!(all_files(v.root()).iter().any(|p| p.to_string_lossy().contains(".c9s")));
    assert_eq!(v.list("/").unwrap()[0].name, long);
    assert_eq!(get(&v, &format!("/{long}/{long}.txt")), b"deep");
    v.rename(&format!("/{long}/{long}.txt"), "/short.txt").unwrap();
    assert_eq!(get(&v, "/short.txt"), b"deep");
    v.rename("/short.txt", &format!("/{long}.bin")).unwrap();
    assert_eq!(get(&v, &format!("/{long}.bin")), b"deep");
    v.delete(&format!("/{long}")).unwrap();
    assert_eq!(v.list("/").unwrap().len(), 1);
    assert!(v.check_integrity().unwrap().problems.is_empty());
}

#[test]
fn search_finds_nested_matches_case_insensitively() {
    let (_d, v) = new_vault();
    v.create_dir_all("/Projects/Alpha").unwrap();
    put(&v, "/Projects/Alpha/Budget-2026.xlsx", b"1");
    put(&v, "/budget-old.txt", b"2");
    put(&v, "/other.txt", b"3");
    let mut r: Vec<_> = v.search("BUDGET", "/", 100).unwrap().into_iter().map(|e| e.path).collect();
    r.sort();
    assert_eq!(r, ["/Projects/Alpha/Budget-2026.xlsx", "/budget-old.txt"]);
}

#[test]
fn path_traversal_rejected() {
    let (_d, v) = new_vault();
    assert!(v.write_file("/../escape", Cursor::new(vec![]), false, None).is_err());
    assert!(v.create_dir("/a\\b").is_err());
}

#[test]
fn tampered_file_is_detected_and_export_leaves_no_plaintext() {
    let (d, v) = new_vault();
    put(&v, "/t.bin", &vec![1u8; 100_000]);
    let ct = all_files(v.root()).into_iter().find(|p| p.extension().is_some_and(|e| e == "c9r")).unwrap();
    let mut bytes = fs::read(&ct).unwrap();
    bytes[70_000] ^= 0x80;
    fs::write(&ct, bytes).unwrap();
    let dest = d.path().join("export.bin");
    assert!(matches!(v.export_file("/t.bin", &dest, false, None), Err(VaultError::Authentication(_))));
    assert!(!dest.exists(), "partial plaintext must not be left behind");
    assert_eq!(fs::read_dir(d.path()).unwrap().count(), 1, "no temp files left");
    let rep = v.check_integrity().unwrap();
    assert_eq!(rep.problems.len(), 1);
    assert_eq!(rep.problems[0].location, "/t.bin");
}

#[test]
fn file_moved_between_dirs_on_disk_is_rejected() {
    // An attacker moves a ciphertext node into another directory: the name no longer
    // authenticates (AD = dirId) so it is not presented as a valid file.
    let (_d, v) = new_vault();
    v.create_dir("/Sub").unwrap();
    put(&v, "/secret.txt", b"s");
    let root_storage = v.storage_dir("").unwrap();
    let sub_id = Vault::read_dir_id(&v.node("", "Sub").unwrap().path).unwrap();
    let sub_storage = v.storage_dir(&sub_id).unwrap();
    let enc = v.node("", "secret.txt").unwrap().enc_name;
    fs::rename(root_storage.join(&enc), sub_storage.join(&enc)).unwrap();
    assert!(v.list("/Sub").unwrap().is_empty());
    assert_eq!(v.check_integrity().unwrap().problems.len(), 1);
}

#[test]
fn tampered_vault_config_prevents_unlock() {
    let (_d, v) = new_vault();
    let root = v.root().to_path_buf();
    let p = root.join(CONFIG_FILE);
    let mut tok = fs::read_to_string(&p).unwrap();
    tok.pop();
    tok.push('A');
    fs::write(&p, tok).unwrap();
    assert!(Vault::unlock(&root, PW).is_err());
}

#[test]
fn change_password_keeps_data_and_backup() {
    let (_d, v) = new_vault();
    put(&v, "/keep.txt", b"keep");
    let root = v.root().to_path_buf();
    drop(v);
    Vault::change_password(&root, PW, "new-synthetic-pw", KdfParams::INSECURE_TEST).unwrap();
    assert!(Vault::unlock(&root, PW).is_err());
    let v = Vault::unlock(&root, "new-synthetic-pw").unwrap();
    assert_eq!(get(&v, "/keep.txt"), b"keep");
    assert!(root.join("masterkey.cryptomator.bkup").exists());
    assert!(Vault::change_password(&root, "wrong", "x", KdfParams::INSECURE_TEST).is_err());
}

#[test]
fn backup_copy_of_vault_restores_everything() {
    // Recovery drill: copy the ciphertext tree elsewhere, delete original, unlock copy.
    let (d, v) = new_vault();
    v.create_dir_all("/r/s").unwrap();
    put(&v, "/r/s/data.bin", &vec![42u8; 70_000]);
    let root = v.root().to_path_buf();
    drop(v);
    let backup = d.path().join("backup");
    copy_tree(&root, &backup);
    fs::remove_dir_all(&root).unwrap();
    let v = Vault::unlock(&backup, PW).unwrap();
    assert_eq!(get(&v, "/r/s/data.bin"), vec![42u8; 70_000]);
    let rep = v.check_integrity().unwrap();
    assert!(rep.problems.is_empty(), "{:?}", rep.problems);
    assert_eq!(rep.files, 1);
    assert_eq!(rep.directories, 3);
}

#[test]
fn large_file_streaming_roundtrip() {
    // 24 MiB synthetic stream generated on the fly (never fully in memory on the write side).
    struct Gen(u64, u64);
    impl Read for Gen {
        fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
            let n = (buf.len() as u64).min(self.1 - self.0) as usize;
            for (i, b) in buf[..n].iter_mut().enumerate() {
                *b = ((self.0 + i as u64) % 251) as u8;
            }
            self.0 += n as u64;
            Ok(n)
        }
    }
    struct Check(u64, bool);
    impl Write for Check {
        fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
            for b in buf {
                if *b != (self.0 % 251) as u8 {
                    self.1 = false;
                }
                self.0 += 1;
            }
            Ok(buf.len())
        }
        fn flush(&mut self) -> std::io::Result<()> {
            Ok(())
        }
    }
    let (_d, v) = new_vault();
    let len = 24 * 1024 * 1024 + 123;
    let mut last = 0;
    let mut cb = |n: u64| last = n;
    let e = v.write_file("/big.bin", Gen(0, len), false, Some(&mut cb)).unwrap();
    assert_eq!(last, len);
    assert_eq!(e.size, Some(len));
    let mut chk = Check(0, true);
    assert_eq!(v.read_file("/big.bin", &mut chk, None).unwrap(), len);
    assert!(chk.1 && chk.0 == len);
}

#[test]
fn integrity_check_clean_vault() {
    let (_d, v) = new_vault();
    v.create_dir_all("/x/y").unwrap();
    put(&v, "/x/y/z", b"z");
    put(&v, "/root.txt", b"");
    let rep = v.check_integrity().unwrap();
    assert!(rep.problems.is_empty(), "{:?}", rep.problems);
    assert_eq!((rep.directories, rep.files, rep.bytes_verified), (3, 2, 1));
}

#[test]
fn preview_size_limit() {
    let (_d, v) = new_vault();
    put(&v, "/p.txt", &[b'a'; 2000]);
    assert_eq!(v.read_to_vec("/p.txt", 4096).unwrap().len(), 2000);
    assert!(v.read_to_vec("/p.txt", 1000).is_err());
}

fn copy_tree(from: &Path, to: &Path) {
    fs::create_dir_all(to).unwrap();
    for e in fs::read_dir(from).unwrap() {
        let e = e.unwrap();
        let t = to.join(e.file_name());
        if e.path().is_dir() {
            copy_tree(&e.path(), &t)
        } else {
            fs::copy(e.path(), t).unwrap();
        }
    }
}
