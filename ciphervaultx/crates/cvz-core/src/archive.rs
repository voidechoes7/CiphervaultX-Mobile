//! Atomic, symlink-safe ZIP compression and ZIP/7z extraction with Zip-Slip and
//! Zip-Bomb defenses.

use std::collections::HashSet;
use std::fs::{self, File};
use std::io::{self, Read};
use std::path::{Component, Path, PathBuf};

use serde::{Deserialize, Serialize};
use tempfile::NamedTempFile;
use zip::write::SimpleFileOptions;
use zip::{CompressionMethod, ZipArchive, ZipWriter};

use crate::error::{Result, VaultError};
use crate::fsio::atomic_write_with;
use crate::vault::{EntryKind, Vault};

pub const MAX_ARCHIVE_ENTRIES: u64 = 50_000;
pub const MAX_EXTRACTED_BYTES: u64 = 4 * 1024 * 1024 * 1024; // 4 GiB safety cap

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ArchiveReport {
    pub bytes: u64,
    pub entries: u64,
}

/// Strictly validate an archive-relative path against Zip-Slip traversal.
pub fn sanitize_rel_path(raw: &str) -> Result<PathBuf> {
    if raw.contains('\0') {
        return Err(VaultError::InvalidName);
    }
    let normalized = raw.replace('\\', "/");
    let mut clean = PathBuf::new();
    for comp in Path::new(&normalized).components() {
        match comp {
            Component::Normal(seg) => {
                let s = seg.to_str().ok_or(VaultError::InvalidName)?;
                if s.is_empty() || s == "." || s == ".." {
                    return Err(VaultError::InvalidName);
                }
                clean.push(s);
            }
            Component::CurDir => {}
            Component::ParentDir | Component::RootDir | Component::Prefix(_) => {
                return Err(VaultError::InvalidName);
            }
        }
    }
    if clean.as_os_str().is_empty() {
        return Err(VaultError::InvalidName);
    }
    Ok(clean)
}

fn format_zip_entry_name(rel: &Path) -> Result<String> {
    let mut parts = Vec::new();
    for comp in rel.components() {
        match comp {
            Component::Normal(s) => {
                parts.push(s.to_str().ok_or(VaultError::InvalidName)?.to_string());
            }
            Component::CurDir => {}
            _ => return Err(VaultError::InvalidName),
        }
    }
    if parts.is_empty() {
        return Err(VaultError::InvalidName);
    }
    Ok(parts.join("/"))
}

fn add_path_recursive(
    writer: &mut ZipWriter<File>,
    src: &Path,
    archive_prefix: &Path,
    options: SimpleFileOptions,
    report: &mut ArchiveReport,
) -> Result<()> {
    let meta = fs::symlink_metadata(src)?;
    if meta.file_type().is_symlink() {
        return Ok(());
    }

    if meta.is_dir() {
        let dir_name = format!("{}/", format_zip_entry_name(archive_prefix)?);
        writer
            .add_directory(dir_name, options)
            .map_err(|_| VaultError::Integrity)?;
        report.entries = report.entries.saturating_add(1);

        let mut children: Vec<PathBuf> = fs::read_dir(src)?
            .filter_map(|e| e.ok().map(|entry| entry.path()))
            .collect();
        children.sort();
        for child in children {
            let Some(child_name) = child.file_name() else {
                continue;
            };
            let next_prefix = archive_prefix.join(child_name);
            add_path_recursive(writer, &child, &next_prefix, options, report)?;
        }
    } else if meta.is_file() {
        let entry_name = format_zip_entry_name(archive_prefix)?;
        writer
            .start_file(entry_name, options)
            .map_err(|_| VaultError::Integrity)?;
        let mut f = File::open(src)?;
        let copied = io::copy(&mut f, writer)?;
        report.bytes = report.bytes.saturating_add(copied);
        report.entries = report.entries.saturating_add(1);
    }
    Ok(())
}

/// Compress one or more local files or folders into a `.zip` file atomically.
/// Symlinks are ignored to prevent escape or cycles.
pub fn compress_paths_to_zip(src_paths: &[PathBuf], dst_zip_path: &Path) -> Result<ArchiveReport> {
    if src_paths.is_empty() {
        return Err(VaultError::InvalidName);
    }
    let parent = dst_zip_path
        .parent()
        .filter(|p| !p.as_os_str().is_empty())
        .unwrap_or_else(|| Path::new("."));
    fs::create_dir_all(parent)?;

    let tmp = NamedTempFile::new_in(parent)?;
    let tmp_file = tmp.reopen()?;
    let mut writer = ZipWriter::new(tmp_file);
    let options = SimpleFileOptions::default().compression_method(CompressionMethod::Deflated);

    let mut report = ArchiveReport {
        bytes: 0,
        entries: 0,
    };
    let mut used_top_names = HashSet::new();

    for src in src_paths {
        if !src.exists() {
            return Err(VaultError::EntryNotFound);
        }
        let base_name = src
            .file_name()
            .and_then(|n| n.to_str())
            .filter(|n| !n.is_empty())
            .unwrap_or("item")
            .to_string();
        let mut unique = base_name.clone();
        let mut suffix = 2u32;
        while !used_top_names.insert(unique.clone()) {
            unique = format!("{base_name}-{suffix}");
            suffix += 1;
        }
        add_path_recursive(&mut writer, src, Path::new(&unique), options, &mut report)?;
    }

    let finished = writer.finish().map_err(|_| VaultError::Integrity)?;
    finished.sync_all()?;
    tmp.persist(dst_zip_path).map_err(|e| e.error)?;
    Ok(report)
}

/// Export an unlocked vault directory directly into an atomic `.zip` archive
/// without staging intermediate plaintext files on disk.
pub fn export_vault_folder_to_zip(
    vault: &Vault,
    vault_dir: &str,
    dst_zip_path: &Path,
) -> Result<ArchiveReport> {
    // Reject writing decrypted ZIP inside the encrypted vault directory itself.
    let vault_root =
        fs::canonicalize(vault.root_path()).unwrap_or_else(|_| vault.root_path().to_path_buf());
    let dst_parent_raw = dst_zip_path
        .parent()
        .filter(|p| !p.as_os_str().is_empty())
        .unwrap_or_else(|| Path::new("."));
    fs::create_dir_all(dst_parent_raw)?;
    let dst_parent =
        fs::canonicalize(dst_parent_raw).unwrap_or_else(|_| dst_parent_raw.to_path_buf());
    if dst_parent.starts_with(&vault_root) {
        return Err(VaultError::ExportInsideVault);
    }

    let tmp = NamedTempFile::new_in(&dst_parent)?;
    let tmp_file = tmp.reopen()?;
    let mut writer = ZipWriter::new(tmp_file);
    let options = SimpleFileOptions::default().compression_method(CompressionMethod::Deflated);
    let mut report = ArchiveReport {
        bytes: 0,
        entries: 0,
    };

    fn walk_vault_dir(
        vault: &Vault,
        vault_dir: &str,
        zip_prefix: &Path,
        writer: &mut ZipWriter<File>,
        options: SimpleFileOptions,
        report: &mut ArchiveReport,
    ) -> Result<()> {
        let entries = vault.list_dir(vault_dir)?;
        for entry in entries {
            let safe_name = sanitize_rel_path(&entry.name)?;
            let next_prefix = zip_prefix.join(safe_name);
            match entry.kind {
                EntryKind::Directory => {
                    let dir_name = format!("{}/", format_zip_entry_name(&next_prefix)?);
                    writer
                        .add_directory(dir_name, options)
                        .map_err(|_| VaultError::Integrity)?;
                    report.entries = report.entries.saturating_add(1);
                    walk_vault_dir(vault, &entry.path, &next_prefix, writer, options, report)?;
                }
                EntryKind::File => {
                    let file_name = format_zip_entry_name(&next_prefix)?;
                    writer
                        .start_file(file_name, options)
                        .map_err(|_| VaultError::Integrity)?;
                    let bytes = vault.export_file_to_writer(&entry.path, writer)?;
                    report.bytes = report.bytes.saturating_add(bytes);
                    report.entries = report.entries.saturating_add(1);
                }
                EntryKind::Unreadable => {
                    return Err(VaultError::Integrity);
                }
            }
        }
        Ok(())
    }

    let root_folder_name = vault_dir
        .trim_end_matches('/')
        .rsplit('/')
        .next()
        .filter(|s| !s.is_empty())
        .unwrap_or("vault-export");
    let root_prefix = sanitize_rel_path(root_folder_name)?;
    let root_zip_dir = format!("{}/", format_zip_entry_name(&root_prefix)?);
    writer
        .add_directory(root_zip_dir, options)
        .map_err(|_| VaultError::Integrity)?;
    report.entries = 1;

    walk_vault_dir(
        vault,
        vault_dir,
        &root_prefix,
        &mut writer,
        options,
        &mut report,
    )?;

    let finished = writer.finish().map_err(|_| VaultError::Integrity)?;
    finished.sync_all()?;
    tmp.persist(dst_zip_path).map_err(|e| e.error)?;
    Ok(report)
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ArchiveFormat {
    Zip,
    SevenZ,
}

fn detect_archive_format(path: &Path) -> Result<ArchiveFormat> {
    let mut f = File::open(path)?;
    let mut magic = [0u8; 6];
    let n = f.read(&mut magic)?;
    if n >= 4 && &magic[0..4] == b"PK\x03\x04" {
        return Ok(ArchiveFormat::Zip);
    }
    if n >= 4 && &magic[0..4] == b"PK\x05\x06" {
        return Ok(ArchiveFormat::Zip);
    }
    if n >= 6 && magic == [0x37, 0x7A, 0xBC, 0xAF, 0x27, 0x1C] {
        return Ok(ArchiveFormat::SevenZ);
    }
    let ext = path
        .extension()
        .and_then(|e| e.to_str())
        .map(|s| s.to_lowercase());
    match ext.as_deref() {
        Some("zip") => Ok(ArchiveFormat::Zip),
        Some("7z") => Ok(ArchiveFormat::SevenZ),
        _ => Err(VaultError::UnsupportedFormat(0)),
    }
}

fn extract_zip(src: &Path, dst_dir: &Path) -> Result<ArchiveReport> {
    fs::create_dir_all(dst_dir)?;
    let file = File::open(src)?;
    let mut archive = ZipArchive::new(file).map_err(|_| VaultError::Integrity)?;

    let mut report = ArchiveReport {
        bytes: 0,
        entries: 0,
    };

    for i in 0..archive.len() {
        if report.entries >= MAX_ARCHIVE_ENTRIES {
            return Err(VaultError::Integrity);
        }
        let mut entry = archive.by_index(i).map_err(|_| VaultError::Integrity)?;
        // Reject symlinks stored in ZIP unix mode bits
        if let Some(mode) = entry.unix_mode() {
            if (mode & 0o170000) == 0o120000 {
                continue;
            }
        }
        let rel = sanitize_rel_path(entry.name())?;
        let out_path = dst_dir.join(&rel);

        if entry.is_dir() {
            fs::create_dir_all(&out_path)?;
            report.entries = report.entries.saturating_add(1);
            continue;
        }
        if let Some(parent) = out_path.parent() {
            fs::create_dir_all(parent)?;
        }

        let remaining = MAX_EXTRACTED_BYTES.saturating_sub(report.bytes);
        let written = atomic_write_with(&out_path, |writer| {
            let mut limited = (&mut entry).take(remaining.saturating_add(1));
            let copied = io::copy(&mut limited, writer)?;
            if copied > remaining {
                return Err(VaultError::Integrity);
            }
            Ok(copied)
        })?;
        report.bytes = report.bytes.saturating_add(written);
        report.entries = report.entries.saturating_add(1);
    }

    Ok(report)
}

fn extract_sevenz(src: &Path, dst_dir: &Path) -> Result<ArchiveReport> {
    fs::create_dir_all(dst_dir)?;
    let mut reader = sevenz_rust::SevenZReader::open(src, sevenz_rust::Password::empty())
        .map_err(|_| VaultError::Integrity)?;

    let mut report = ArchiveReport {
        bytes: 0,
        entries: 0,
    };

    reader
        .for_each_entries(|entry, data_reader| {
            if report.entries >= MAX_ARCHIVE_ENTRIES {
                return Err(sevenz_rust::Error::other("archive entry limit exceeded"));
            }
            let rel = sanitize_rel_path(entry.name())
                .map_err(|_| sevenz_rust::Error::other("unsafe archive path rejected"))?;
            let out_path = dst_dir.join(&rel);
            if entry.is_directory() {
                fs::create_dir_all(&out_path).map_err(sevenz_rust::Error::io)?;
                report.entries = report.entries.saturating_add(1);
                return Ok(true);
            }
            if let Some(parent) = out_path.parent() {
                fs::create_dir_all(parent).map_err(sevenz_rust::Error::io)?;
            }
            let remaining = MAX_EXTRACTED_BYTES.saturating_sub(report.bytes);
            let written = atomic_write_with(&out_path, |writer| {
                let mut limited = data_reader.take(remaining.saturating_add(1));
                let copied = io::copy(&mut limited, writer)?;
                if copied > remaining {
                    return Err(VaultError::Integrity);
                }
                Ok(copied)
            })
            .map_err(|_| sevenz_rust::Error::other("atomic extraction failed"))?;
            report.bytes = report.bytes.saturating_add(written);
            report.entries = report.entries.saturating_add(1);
            Ok(true)
        })
        .map_err(|_| VaultError::Integrity)?;

    Ok(report)
}

/// Extract a `.zip` or `.7z` archive into `dst_dir` atomically with strict
/// Zip-Slip and Zip-Bomb protections.
pub fn extract_archive(src_archive_path: &Path, dst_dir: &Path) -> Result<ArchiveReport> {
    if !src_archive_path.is_file() {
        return Err(VaultError::EntryNotFound);
    }
    match detect_archive_format(src_archive_path)? {
        ArchiveFormat::Zip => extract_zip(src_archive_path, dst_dir),
        ArchiveFormat::SevenZ => extract_sevenz(src_archive_path, dst_dir),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::CipherSuite;
    use crate::kdf::Argon2Params;
    use std::io::Write;
    use tempfile::TempDir;

    #[test]
    fn zip_compress_and_extract_roundtrip() {
        let tmp = TempDir::new().unwrap();
        let src_dir = tmp.path().join("synthetic-folder");
        fs::create_dir_all(src_dir.join("nested")).unwrap();
        fs::write(src_dir.join("alpha.txt"), b"synthetic-alpha-payload").unwrap();
        fs::write(src_dir.join("nested/beta.bin"), [0x5Au8; 4096]).unwrap();

        let zip_path = tmp.path().join("bundle.zip");
        let rep = compress_paths_to_zip(std::slice::from_ref(&src_dir), &zip_path).unwrap();
        assert!(zip_path.is_file());
        assert!(rep.entries >= 3);
        assert_eq!(rep.bytes, 23 + 4096);

        let out_dir = tmp.path().join("extracted");
        let ext = extract_archive(&zip_path, &out_dir).unwrap();
        assert_eq!(ext.bytes, 23 + 4096);
        assert_eq!(
            fs::read(out_dir.join("synthetic-folder/alpha.txt")).unwrap(),
            b"synthetic-alpha-payload"
        );
        assert_eq!(
            fs::read(out_dir.join("synthetic-folder/nested/beta.bin")).unwrap(),
            vec![0x5Au8; 4096]
        );
    }

    #[test]
    fn rejects_zip_slip_traversal() {
        let tmp = TempDir::new().unwrap();
        let evil_zip = tmp.path().join("evil.zip");
        {
            let f = File::create(&evil_zip).unwrap();
            let mut w = ZipWriter::new(f);
            w.start_file("../escape.txt", SimpleFileOptions::default())
                .unwrap();
            w.write_all(b"pwned").unwrap();
            w.finish().unwrap();
        }
        let out_dir = tmp.path().join("out");
        let res = extract_archive(&evil_zip, &out_dir);
        assert!(res.is_err());
        assert!(!tmp.path().join("escape.txt").exists());
    }

    #[test]
    fn export_vault_folder_to_zip_roundtrip() {
        let tmp = TempDir::new().unwrap();
        let vault_root = tmp.path().join("vault");
        let (vault, _) = Vault::create(
            &vault_root,
            "synthetic-passphrase-1234",
            CipherSuite::XChaCha20Poly1305,
            Argon2Params::mobile(),
        )
        .unwrap();

        let src_file = tmp.path().join("doc.txt");
        fs::write(&src_file, b"vault-zip-export-test").unwrap();
        vault.create_dir("/Docs").unwrap();
        vault.import_file(&src_file, "/Docs/doc.txt", None).unwrap();

        let zip_out = tmp.path().join("docs-export.zip");
        let rep = export_vault_folder_to_zip(&vault, "/Docs", &zip_out).unwrap();
        assert_eq!(rep.bytes, 21);

        // Must reject exporting inside the vault root itself
        let bad_out = vault_root.join("leak.zip");
        assert!(export_vault_folder_to_zip(&vault, "/Docs", &bad_out).is_err());

        let extracted = tmp.path().join("unpacked");
        extract_archive(&zip_out, &extracted).unwrap();
        assert_eq!(
            fs::read(extracted.join("Docs/doc.txt")).unwrap(),
            b"vault-zip-export-test"
        );
    }
}
