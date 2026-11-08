//! Filesystem helpers: atomic, crash-safe writes.
//!
//! Every file the vault writes goes to a uniquely named temporary file *in the same
//! directory*, is flushed + fsynced, and is then renamed over the destination. A crash or
//! an authentication failure therefore never leaves a half-written file under the final
//! name. Temporary files are removed on every error path (RAII guard).

use std::fs::{self, File, OpenOptions};
use std::io::{self, Write};
use std::path::{Path, PathBuf};

use crate::crypto::keys::random_bytes;
use crate::encoding::hex_encode;

pub const TEMP_PREFIX: &str = ".cvx-tmp-";

/// A temp file that deletes itself unless `commit` is called.
pub struct AtomicFile {
    tmp: PathBuf,
    dest: PathBuf,
    file: Option<File>,
    overwrite: bool,
}

impl std::fmt::Debug for AtomicFile {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("AtomicFile").field("dest", &self.dest).finish()
    }
}

impl AtomicFile {
    /// Create a temp file next to `dest`. If `overwrite` is false, `commit` fails when
    /// `dest` exists.
    pub fn create(dest: &Path, overwrite: bool) -> io::Result<Self> {
        let parent = dest.parent().ok_or_else(|| io::Error::new(io::ErrorKind::InvalidInput, "no parent dir"))?;
        if !overwrite && dest.exists() {
            return Err(io::Error::new(io::ErrorKind::AlreadyExists, "destination exists"));
        }
        let tmp = parent.join(format!("{TEMP_PREFIX}{}", hex_encode(&random_bytes::<8>())));
        let file = OpenOptions::new().write(true).create_new(true).open(&tmp)?;
        Ok(AtomicFile { tmp, dest: dest.to_path_buf(), file: Some(file), overwrite })
    }

    pub fn file(&mut self) -> &mut File {
        self.file.as_mut().expect("file present until commit")
    }

    /// fsync and atomically move into place.
    pub fn commit(mut self) -> io::Result<()> {
        let f = self.file.take().expect("file present until commit");
        f.sync_all()?;
        drop(f);
        if !self.overwrite && self.dest.exists() {
            return Err(io::Error::new(io::ErrorKind::AlreadyExists, "destination exists"));
        }
        fs::rename(&self.tmp, &self.dest)?;
        sync_dir(self.dest.parent());
        Ok(())
    }
}

impl Write for AtomicFile {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        self.file().write(buf)
    }
    fn flush(&mut self) -> io::Result<()> {
        self.file().flush()
    }
}

impl Drop for AtomicFile {
    fn drop(&mut self) {
        if self.file.take().is_some() || self.tmp.exists() {
            let _ = fs::remove_file(&self.tmp);
        }
    }
}

/// Write `data` atomically to `dest`.
pub fn write_atomic(dest: &Path, data: &[u8], overwrite: bool) -> io::Result<()> {
    let mut f = AtomicFile::create(dest, overwrite)?;
    f.write_all(data)?;
    f.commit()
}

/// Best effort directory fsync so the rename itself is durable (no-op on Windows).
fn sync_dir(dir: Option<&Path>) {
    #[cfg(unix)]
    if let Some(d) = dir {
        if let Ok(f) = File::open(d) {
            let _ = f.sync_all();
        }
    }
    #[cfg(not(unix))]
    let _ = dir;
}

/// RAII temporary directory for isolated test fixtures.
#[derive(Debug)]
pub struct TempDir {
    path: PathBuf,
}

impl TempDir {
    pub fn new() -> io::Result<Self> {
        let base = std::env::temp_dir();
        let path = base.join(format!("ciphervault-test-{}", hex_encode(&random_bytes::<8>())));
        fs::create_dir_all(&path)?;
        Ok(TempDir { path })
    }

    pub fn path(&self) -> &Path {
        &self.path
    }
}

impl Drop for TempDir {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.path);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn commit_writes_and_cleans_temp() {
        let d = TempDir::new().unwrap();
        let p = d.path().join("a.bin");
        write_atomic(&p, b"hello", false).unwrap();
        assert_eq!(fs::read(&p).unwrap(), b"hello");
        assert_eq!(fs::read_dir(d.path()).unwrap().count(), 1);
    }

    #[test]
    fn drop_without_commit_leaves_nothing() {
        let d = TempDir::new().unwrap();
        let p = d.path().join("a.bin");
        {
            let mut f = AtomicFile::create(&p, false).unwrap();
            f.write_all(b"partial").unwrap();
        }
        assert!(!p.exists());
        assert_eq!(fs::read_dir(d.path()).unwrap().count(), 0);
    }

    #[test]
    fn no_overwrite_is_respected() {
        let d = TempDir::new().unwrap();
        let p = d.path().join("a.bin");
        write_atomic(&p, b"one", false).unwrap();
        assert!(write_atomic(&p, b"two", false).is_err());
        write_atomic(&p, b"three", true).unwrap();
        assert_eq!(fs::read(&p).unwrap(), b"three");
        assert_eq!(fs::read_dir(d.path()).unwrap().count(), 1);
    }
}
