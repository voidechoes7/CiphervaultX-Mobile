//! Encrypted vault filesystem.
//!
//! Maps a *cleartext* virtual tree (`/Docs/report.txt`) onto the on-disk vault layout:
//!
//! ```text
//! <vault>/
//!   vault.cryptomator            signed vault config (JWT, HS256)
//!   masterkey.cryptomator        password-wrapped keys
//!   d/<2>/<30>/                  one storage dir per cleartext directory (path = hash(dirId))
//!       <encName>.c9r            regular file: header + chunks
//!       <encName>.c9r/dir.c9r    sub-directory: contains its dirId (random UUID)
//!       <hash>.c9s/name.c9s      long names: full encrypted name ...
//!       <hash>.c9s/contents.c9r  ... and the file contents, or
//!       <hash>.c9s/dir.c9r       ... the dirId
//!       dirid.c9r                encrypted backup of this directory's own id (recovery)
//! ```
//! The directory hierarchy is therefore *not* visible on disk: all storage dirs are siblings.

use std::fs::{self, File};
use std::io::{BufReader, BufWriter, Read, Write};
use std::path::{Path, PathBuf};

use crate::crypto::config::VaultConfig;
use crate::crypto::content::{self, Progress};
use crate::crypto::filename::{self, NameCryptor, ENCRYPTED_EXT, SHORTENED_EXT};
use crate::crypto::keys::Masterkey;
use crate::crypto::masterkey_file::{KdfParams, MasterkeyFile};
use crate::encoding::uuid_v4;
use crate::error::{Result, VaultError};
use crate::fsutil::{self, AtomicFile, TEMP_PREFIX};

pub const CONFIG_FILE: &str = "vault.cryptomator";
pub const MASTERKEY_FILE: &str = "masterkey.cryptomator";
pub const DATA_DIR: &str = "d";
const DIR_FILE: &str = "dir.c9r";
const CONTENTS_FILE: &str = "contents.c9r";
const NAME_FILE: &str = "name.c9s";
#[allow(dead_code)]
const SYMLINK_FILE: &str = "symlink.c9r";
const DIRID_BACKUP: &str = "dirid.c9r";
const ROOT_DIR_ID: &str = "";
const IO_BUF: usize = 256 * 1024;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EntryKind {
    File,
    Directory,
}

impl EntryKind {
    pub fn as_str(&self) -> &'static str {
        match self {
            EntryKind::File => "file",
            EntryKind::Directory => "directory",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Entry {
    pub name: String,
    /// Cleartext virtual path, `/`-separated, starting with `/`.
    pub path: String,
    pub kind: EntryKind,
    /// Cleartext size in bytes (files only).
    pub size: Option<u64>,
    /// Modification time, seconds since UNIX epoch (from ciphertext metadata).
    pub modified: Option<u64>,
}

#[derive(Debug, Default, Clone)]
pub struct IntegrityReport {
    pub directories: u64,
    pub files: u64,
    pub bytes_verified: u64,
    pub problems: Vec<IntegrityProblem>,
}

#[derive(Debug, Clone)]
pub struct IntegrityProblem {
    /// Cleartext location if known, else the ciphertext storage path.
    pub location: String,
    pub error: String,
}

/// A located node (file or directory) in a storage dir.
struct Node {
    /// `<enc>.c9r` or `<hash>.c9s`
    path: PathBuf,
    shortened: bool,
    enc_name: String,
}

impl Node {
    fn kind(&self) -> Option<EntryKind> {
        if self.path.is_file() && !self.shortened {
            Some(EntryKind::File)
        } else if self.path.join(DIR_FILE).is_file() {
            Some(EntryKind::Directory)
        } else if self.shortened && self.path.join(CONTENTS_FILE).is_file() {
            Some(EntryKind::File)
        } else {
            None
        }
    }
    fn exists(&self) -> bool {
        self.path.exists()
    }
    fn contents_path(&self) -> PathBuf {
        if self.shortened {
            self.path.join(CONTENTS_FILE)
        } else {
            self.path.clone()
        }
    }
}

/// An unlocked vault. Dropping it (= locking) zeroizes all key material.
pub struct Vault {
    root: PathBuf,
    mk: Masterkey,
    names: NameCryptor,
    config: VaultConfig,
}

impl std::fmt::Debug for Vault {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Vault").field("root", &self.root).field("config", &self.config).finish_non_exhaustive()
    }
}

/// Split a virtual path into normalized components, rejecting `..` and similar.
pub fn components(vpath: &str) -> Result<Vec<String>> {
    let mut out = Vec::new();
    for c in vpath.split('/').filter(|c| !c.is_empty()) {
        filename::validate_name(c)?;
        out.push(c.to_string());
    }
    Ok(out)
}

fn join_vpath(parent: &str, name: &str) -> String {
    if parent == "/" || parent.is_empty() {
        format!("/{name}")
    } else {
        format!("{}/{name}", parent.trim_end_matches('/'))
    }
}

fn mtime(p: &Path) -> Option<u64> {
    fs::metadata(p).ok()?.modified().ok()?.duration_since(std::time::UNIX_EPOCH).ok().map(|d| d.as_secs())
}

impl Vault {
    /// Quick structural check (no password needed).
    pub fn is_vault(root: &Path) -> bool {
        root.join(CONFIG_FILE).is_file() && root.join(MASTERKEY_FILE).is_file() && root.join(DATA_DIR).is_dir()
    }

    /// Create a brand-new vault in `root` (must be absent or an empty directory).
    pub fn create(root: &Path, password: &str, params: KdfParams) -> Result<Vault> {
        if root.exists() {
            if !root.is_dir() || fs::read_dir(root)?.next().is_some() {
                return Err(VaultError::AlreadyExists("target folder is not empty".into()));
            }
        } else {
            fs::create_dir_all(root)?;
        }
        let mk = Masterkey::generate();
        let mkf = MasterkeyFile::wrap(&mk, password, params)?;
        let config = VaultConfig::new();
        let token = config.sign(&mk)?;
        let vault = Vault { root: root.to_path_buf(), names: NameCryptor::new(&mk), mk, config };
        fs::create_dir_all(vault.storage_dir(ROOT_DIR_ID)?)?;
        fsutil::write_atomic(&root.join(MASTERKEY_FILE), &mkf.to_json()?, false)?;
        fsutil::write_atomic(&root.join(CONFIG_FILE), token.as_bytes(), false)?;
        Ok(vault)
    }

    /// Unlock an existing vault with its password.
    pub fn unlock(root: &Path, password: &str) -> Result<Vault> {
        if !Self::is_vault(root) {
            return Err(VaultError::NotFound("no vault at this location".into()));
        }
        let token = fs::read_to_string(root.join(CONFIG_FILE))?;
        let kid = VaultConfig::peek_kid(&token)?;
        if kid != crate::crypto::config::MASTERKEY_KID {
            return Err(VaultError::Unsupported(format!("key source {kid}")));
        }
        let mkf = MasterkeyFile::from_json(&fs::read(root.join(MASTERKEY_FILE))?)?;
        let mk = mkf.unlock(password)?;
        let config = VaultConfig::verify(&token, &mk)?;
        Ok(Vault { root: root.to_path_buf(), names: NameCryptor::new(&mk), mk, config })
    }

    /// Re-wrap the (unchanged) vault keys under a new password. The previous key file is
    /// kept as `masterkey.cryptomator.bkup` until the new one is safely in place.
    pub fn change_password(root: &Path, old: &str, new: &str, params: KdfParams) -> Result<()> {
        let path = root.join(MASTERKEY_FILE);
        let old_bytes = fs::read(&path)?;
        let mk = MasterkeyFile::from_json(&old_bytes)?.unlock(old)?;
        let new_file = MasterkeyFile::wrap(&mk, new, params)?;
        fsutil::write_atomic(&root.join(format!("{MASTERKEY_FILE}.bkup")), &old_bytes, true)?;
        fsutil::write_atomic(&path, &new_file.to_json()?, true)?;
        // Verify before declaring success.
        MasterkeyFile::from_json(&fs::read(&path)?)?.unlock(new)?;
        Ok(())
    }

    pub fn root(&self) -> &Path {
        &self.root
    }

    pub fn config(&self) -> &VaultConfig {
        &self.config
    }

    // ---------------------------------------------------------------- resolution

    fn storage_dir(&self, dir_id: &str) -> Result<PathBuf> {
        let (a, b) = self.names.dir_path(dir_id)?;
        Ok(self.root.join(DATA_DIR).join(a).join(b))
    }

    fn node(&self, parent_dir_id: &str, name: &str) -> Result<Node> {
        filename::validate_name(name)?;
        let enc = self.names.encrypt_name(name, parent_dir_id)?;
        let dir = self.storage_dir(parent_dir_id)?;
        if enc.len() > self.config.shortening_threshold {
            Ok(Node { path: dir.join(filename::shorten(&enc)), shortened: true, enc_name: enc })
        } else {
            Ok(Node { path: dir.join(&enc), shortened: false, enc_name: enc })
        }
    }

    fn read_dir_id(node_path: &Path) -> Result<String> {
        let raw = fs::read(node_path.join(DIR_FILE))?;
        let id = String::from_utf8(raw).map_err(|_| VaultError::Malformed("directory id".into()))?;
        if id.is_empty() || id.len() > 36 || !id.is_ascii() {
            return Err(VaultError::Malformed("directory id".into()));
        }
        Ok(id)
    }

    /// Resolve the dirId of a cleartext directory path.
    fn resolve_dir(&self, vpath: &str) -> Result<String> {
        let mut dir_id = ROOT_DIR_ID.to_string();
        for c in components(vpath)? {
            let n = self.node(&dir_id, &c)?;
            if n.kind() != Some(EntryKind::Directory) {
                return Err(VaultError::NotFound(format!("directory {vpath}")));
            }
            dir_id = Self::read_dir_id(&n.path)?;
        }
        Ok(dir_id)
    }

    /// Resolve parent dirId and leaf name.
    fn resolve_parent(&self, vpath: &str) -> Result<(String, String, String)> {
        let mut comps = components(vpath)?;
        let name = comps.pop().ok_or_else(|| VaultError::InvalidName("the root cannot be used here".into()))?;
        let parent_path = format!("/{}", comps.join("/"));
        let id = self.resolve_dir(&parent_path)?;
        Ok((id, name, parent_path))
    }

    fn resolve_node(&self, vpath: &str) -> Result<(Node, EntryKind)> {
        let (pid, name, _) = self.resolve_parent(vpath)?;
        let n = self.node(&pid, &name)?;
        let kind = n.kind().ok_or_else(|| VaultError::NotFound(vpath.to_string()))?;
        Ok((n, kind))
    }

    // ---------------------------------------------------------------- listing

    /// Iterate (enc_name, node_path, shortened) entries of a storage directory.
    fn raw_children(&self, dir_id: &str) -> Result<Vec<Node>> {
        let dir = self.storage_dir(dir_id)?;
        let mut out = Vec::new();
        for e in fs::read_dir(&dir)? {
            let e = e?;
            let fname = e.file_name().to_string_lossy().into_owned();
            if fname.starts_with(TEMP_PREFIX) || fname == DIRID_BACKUP {
                continue;
            }
            if fname.ends_with(ENCRYPTED_EXT) {
                out.push(Node { path: e.path(), shortened: false, enc_name: fname });
            } else if fname.ends_with(SHORTENED_EXT) {
                let enc = fs::read_to_string(e.path().join(NAME_FILE)).unwrap_or_default();
                out.push(Node { path: e.path(), shortened: true, enc_name: enc });
            }
        }
        Ok(out)
    }

    fn entry_for(&self, n: &Node, dir_id: &str, parent_vpath: &str) -> Result<Option<Entry>> {
        let name = self.names.decrypt_name(&n.enc_name, dir_id)?;
        if n.shortened && filename::shorten(&n.enc_name) != n.path.file_name().unwrap_or_default().to_string_lossy() {
            return Err(VaultError::Authentication("long-name mapping"));
        }
        let Some(kind) = n.kind() else {
            return Ok(None); // symlinks and unknown nodes are not supported; skip
        };
        let size = match kind {
            EntryKind::File => fs::metadata(n.contents_path()).ok().and_then(|m| content::cleartext_size(m.len())),
            EntryKind::Directory => None,
        };
        Ok(Some(Entry {
            path: join_vpath(parent_vpath, &name),
            name,
            kind,
            size,
            modified: mtime(&n.contents_path()),
        }))
    }

    /// List a directory. Entries whose names fail authentication are skipped here and
    /// reported by [`Vault::check_integrity`].
    pub fn list(&self, vpath: &str) -> Result<Vec<Entry>> {
        let dir_id = self.resolve_dir(vpath)?;
        let parent = format!("/{}", components(vpath)?.join("/"));
        let mut out: Vec<Entry> = self
            .raw_children(&dir_id)?
            .iter()
            .filter_map(|n| self.entry_for(n, &dir_id, &parent).ok().flatten())
            .collect();
        out.sort_by(|a, b| {
            (a.kind != EntryKind::Directory, a.name.to_lowercase()).cmp(&(b.kind != EntryKind::Directory, b.name.to_lowercase()))
        });
        Ok(out)
    }

    pub fn stat(&self, vpath: &str) -> Result<Entry> {
        let (pid, name, parent) = self.resolve_parent(vpath)?;
        let n = self.node(&pid, &name)?;
        self.entry_for(&n, &pid, &parent)?.ok_or_else(|| VaultError::NotFound(vpath.into()))
    }

    pub fn exists(&self, vpath: &str) -> bool {
        self.resolve_node(vpath).is_ok()
    }

    // ---------------------------------------------------------------- directories

    pub fn create_dir(&self, vpath: &str) -> Result<Entry> {
        let (pid, name, _) = self.resolve_parent(vpath)?;
        let n = self.node(&pid, &name)?;
        if n.exists() {
            return Err(VaultError::AlreadyExists(vpath.into()));
        }
        let new_id = uuid_v4();
        let storage = self.storage_dir(&new_id)?;
        fs::create_dir_all(&storage)?;
        // Encrypted backup of the directory id, used for recovery if dir.c9r is lost.
        let mut backup = AtomicFile::create(&storage.join(DIRID_BACKUP), false)?;
        content::encrypt_stream(&self.mk, new_id.as_bytes(), &mut backup, None)?;
        backup.commit()?;
        self.write_dir_node(&n, &new_id)?;
        self.stat(vpath)
    }

    fn write_dir_node(&self, n: &Node, dir_id: &str) -> Result<()> {
        fs::create_dir(&n.path)?;
        let r = (|| -> Result<()> {
            if n.shortened {
                fsutil::write_atomic(&n.path.join(NAME_FILE), n.enc_name.as_bytes(), false)?;
            }
            fsutil::write_atomic(&n.path.join(DIR_FILE), dir_id.as_bytes(), false)?;
            Ok(())
        })();
        if r.is_err() {
            let _ = fs::remove_dir_all(&n.path);
        }
        r
    }

    /// Create every missing directory along `vpath`.
    pub fn create_dir_all(&self, vpath: &str) -> Result<()> {
        let mut cur = String::from("/");
        for c in components(vpath)? {
            cur = join_vpath(&cur, &c);
            match self.resolve_node(&cur) {
                Ok((_, EntryKind::Directory)) => {}
                Ok((_, EntryKind::File)) => return Err(VaultError::AlreadyExists(format!("{cur} is a file"))),
                Err(_) => {
                    self.create_dir(&cur)?;
                }
            }
        }
        Ok(())
    }

    // ---------------------------------------------------------------- files

    /// Stream-encrypt `src` into the vault at `vpath`. Atomic: on any error nothing is
    /// left behind and an existing file is untouched.
    pub fn write_file<R: Read>(&self, vpath: &str, src: R, overwrite: bool, progress: Option<Progress<'_>>) -> Result<Entry> {
        let (pid, name, _) = self.resolve_parent(vpath)?;
        let n = self.node(&pid, &name)?;
        match n.kind() {
            Some(EntryKind::Directory) => return Err(VaultError::AlreadyExists(format!("{vpath} is a directory"))),
            Some(EntryKind::File) if !overwrite => return Err(VaultError::AlreadyExists(vpath.into())),
            _ => {}
        }
        if n.shortened && !n.path.exists() {
            fs::create_dir(&n.path)?;
            fsutil::write_atomic(&n.path.join(NAME_FILE), n.enc_name.as_bytes(), false)?;
        }
        let mut out = AtomicFile::create(&n.contents_path(), overwrite)?;
        {
            let mut w = BufWriter::with_capacity(IO_BUF, &mut out);
            content::encrypt_stream(&self.mk, BufReader::with_capacity(IO_BUF, src), &mut w, progress)?;
            w.flush()?;
        }
        out.commit()?;
        self.stat(vpath)
    }

    /// Import a file from the host filesystem into directory `dest_dir`, keeping its name.
    pub fn import_file(&self, src: &Path, dest_dir: &str, overwrite: bool, progress: Option<Progress<'_>>) -> Result<Entry> {
        let name = src
            .file_name()
            .and_then(|n| n.to_str())
            .ok_or_else(|| VaultError::InvalidName("source file name is not valid UTF-8".into()))?
            .to_string();
        let f = File::open(src)?;
        self.write_file(&join_vpath(dest_dir, &name), f, overwrite, progress)
    }

    /// Decrypt a file into `dst`. On authentication failure an error is returned; the caller
    /// must discard partial output (see [`Vault::export_file`]).
    pub fn read_file<W: Write>(&self, vpath: &str, dst: W, progress: Option<Progress<'_>>) -> Result<u64> {
        let (n, kind) = self.resolve_node(vpath)?;
        if kind != EntryKind::File {
            return Err(VaultError::NotFound(format!("{vpath} is not a file")));
        }
        let f = BufReader::with_capacity(IO_BUF, File::open(n.contents_path())?);
        let mut w = BufWriter::with_capacity(IO_BUF, dst);
        let total = content::decrypt_stream(&self.mk, f, &mut w, progress)?;
        w.flush()?;
        Ok(total)
    }

    /// Decrypt into memory, refusing files larger than `max_bytes` (used for previews).
    pub fn read_to_vec(&self, vpath: &str, max_bytes: u64) -> Result<Vec<u8>> {
        let e = self.stat(vpath)?;
        if e.size.unwrap_or(u64::MAX) > max_bytes {
            return Err(VaultError::Unsupported("file too large for preview".into()));
        }
        let mut v = Vec::new();
        self.read_file(vpath, &mut v, None)?;
        Ok(v)
    }

    /// **Explicit plaintext export** to the host filesystem. Written atomically: if the
    /// ciphertext fails authentication, no plaintext file appears at `dest`.
    pub fn export_file(&self, vpath: &str, dest: &Path, overwrite: bool, progress: Option<Progress<'_>>) -> Result<u64> {
        let mut out = AtomicFile::create(dest, overwrite)?;
        let n = self.read_file(vpath, &mut out, progress)?;
        out.commit()?;
        Ok(n)
    }

    // ---------------------------------------------------------------- mutation

    /// Delete a file or (recursively) a directory.
    pub fn delete(&self, vpath: &str) -> Result<()> {
        let (n, kind) = self.resolve_node(vpath)?;
        if kind == EntryKind::Directory {
            let id = Self::read_dir_id(&n.path)?;
            self.delete_dir_contents(&id)?;
            let storage = self.storage_dir(&id)?;
            if storage.exists() {
                fs::remove_dir_all(&storage)?;
            }
            if let Some(p) = storage.parent() {
                let _ = fs::remove_dir(p); // only succeeds if empty
            }
            fs::remove_dir_all(&n.path)?;
        } else if n.shortened {
            fs::remove_dir_all(&n.path)?;
        } else {
            fs::remove_file(&n.path)?;
        }
        Ok(())
    }

    fn delete_dir_contents(&self, dir_id: &str) -> Result<()> {
        for child in self.raw_children(dir_id)? {
            if child.kind() == Some(EntryKind::Directory) {
                if let Ok(id) = Self::read_dir_id(&child.path) {
                    self.delete_dir_contents(&id)?;
                    let s = self.storage_dir(&id)?;
                    if s.exists() {
                        fs::remove_dir_all(&s)?;
                    }
                    if let Some(p) = s.parent() {
                        let _ = fs::remove_dir(p);
                    }
                }
            }
        }
        Ok(())
    }

    /// Rename and/or move a file or directory. File contents are not re-encrypted; only
    /// the name is re-encrypted for the new parent.
    pub fn rename(&self, from: &str, to: &str) -> Result<Entry> {
        let (src, kind) = self.resolve_node(from)?;
        let from_c = components(from)?;
        let to_c = components(to)?;
        if kind == EntryKind::Directory && to_c.len() > from_c.len() && to_c[..from_c.len()] == from_c[..] {
            return Err(VaultError::InvalidName("cannot move a folder into itself".into()));
        }
        let (dpid, dname, _) = self.resolve_parent(to)?;
        let dst = self.node(&dpid, &dname)?;
        if dst.exists() {
            return Err(VaultError::AlreadyExists(to.into()));
        }
        if !src.shortened && !dst.shortened {
            fs::rename(&src.path, &dst.path)?; // single atomic rename
        } else {
            match kind {
                EntryKind::Directory => {
                    let id = Self::read_dir_id(&src.path)?;
                    self.write_dir_node(&dst, &id)?;
                }
                EntryKind::File => {
                    if dst.shortened {
                        fs::create_dir(&dst.path)?;
                        fsutil::write_atomic(&dst.path.join(NAME_FILE), dst.enc_name.as_bytes(), false)?;
                    }
                    fs::rename(src.contents_path(), dst.contents_path())?;
                }
            }
            if src.path.is_dir() {
                fs::remove_dir_all(&src.path)?;
            } else if src.path.exists() {
                fs::remove_file(&src.path)?;
            }
        }
        self.stat(to)
    }

    // ---------------------------------------------------------------- search & integrity

    /// Case-insensitive substring search on cleartext names below `under`.
    pub fn search(&self, query: &str, under: &str, limit: usize) -> Result<Vec<Entry>> {
        let q = query.to_lowercase();
        let mut out = Vec::new();
        let mut stack = vec![format!("/{}", components(under)?.join("/"))];
        while let Some(dir) = stack.pop() {
            for e in self.list(&dir)? {
                if e.kind == EntryKind::Directory {
                    stack.push(e.path.clone());
                }
                if e.name.to_lowercase().contains(&q) {
                    out.push(e);
                    if out.len() >= limit {
                        return Ok(out);
                    }
                }
            }
        }
        Ok(out)
    }

    /// Walk the whole vault, authenticating every name, directory id and every byte of
    /// every file. Never writes plaintext anywhere.
    pub fn check_integrity(&self) -> Result<IntegrityReport> {
        let mut rep = IntegrityReport::default();
        let mut stack = vec![(ROOT_DIR_ID.to_string(), "/".to_string())];
        while let Some((id, vpath)) = stack.pop() {
            rep.directories += 1;
            let storage = self.storage_dir(&id)?;
            if !storage.is_dir() {
                rep.problems.push(IntegrityProblem { location: vpath.clone(), error: "storage directory missing".into() });
                continue;
            }
            if !id.is_empty() {
                let mut buf = Vec::new();
                match File::open(storage.join(DIRID_BACKUP)) {
                    Ok(f) => match content::decrypt_stream(&self.mk, f, &mut buf, None) {
                        Ok(_) if buf == id.as_bytes() => {}
                        Ok(_) => rep.problems.push(IntegrityProblem { location: vpath.clone(), error: "directory id backup mismatch".into() }),
                        Err(e) => rep.problems.push(IntegrityProblem { location: vpath.clone(), error: format!("directory id backup: {e}") }),
                    },
                    Err(_) => rep.problems.push(IntegrityProblem { location: vpath.clone(), error: "directory id backup missing".into() }),
                }
            }
            for n in self.raw_children(&id)? {
                let entry = match self.entry_for(&n, &id, &vpath) {
                    Ok(Some(e)) => e,
                    Ok(None) => continue,
                    Err(e) => {
                        rep.problems.push(IntegrityProblem { location: n.path.display().to_string(), error: e.to_string() });
                        continue;
                    }
                };
                match entry.kind {
                    EntryKind::Directory => match Self::read_dir_id(&n.path) {
                        Ok(cid) => stack.push((cid, entry.path)),
                        Err(e) => rep.problems.push(IntegrityProblem { location: entry.path, error: e.to_string() }),
                    },
                    EntryKind::File => {
                        let r = File::open(n.contents_path()).map_err(VaultError::from).and_then(|f| {
                            content::decrypt_stream(&self.mk, BufReader::with_capacity(IO_BUF, f), std::io::sink(), None)
                        });
                        match r {
                            Ok(b) => {
                                rep.files += 1;
                                rep.bytes_verified += b;
                            }
                            Err(e) => rep.problems.push(IntegrityProblem { location: entry.path, error: e.to_string() }),
                        }
                    }
                }
            }
        }
        Ok(rep)
    }
}

#[cfg(test)]
mod tests;
