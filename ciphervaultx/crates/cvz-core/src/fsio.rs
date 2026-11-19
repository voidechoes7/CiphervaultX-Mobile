use std::fs::File;
use std::io::Write;
use std::path::Path;

use tempfile::Builder;

use crate::error::Result;

pub const TMP_PREFIX: &str = ".cvz-tmp-";

/// Atomically write to `dest` via a temporary file in the same directory:
/// write -> flush -> sync_all -> persist (rename) -> fsync parent directory on Unix.
pub fn atomic_write_with<T, F>(dest: &Path, write_fn: F) -> Result<T>
where
    F: FnOnce(&mut File) -> Result<T>,
{
    let parent = dest.parent().unwrap_or_else(|| Path::new("."));
    let mut tmp = Builder::new().prefix(TMP_PREFIX).tempfile_in(parent)?;
    let out = write_fn(tmp.as_file_mut())?;
    tmp.as_file_mut().flush()?;
    tmp.as_file_mut().sync_all()?;
    tmp.persist(dest).map_err(|e| e.error)?;
    sync_dir(parent)?;
    Ok(out)
}

pub fn atomic_write_bytes(dest: &Path, data: &[u8]) -> Result<()> {
    atomic_write_with(dest, |f| {
        f.write_all(data)?;
        Ok(())
    })
}

pub fn is_temp_file_name(name: &str) -> bool {
    name.starts_with(TMP_PREFIX)
}

#[cfg(unix)]
pub fn sync_dir(dir: &Path) -> Result<()> {
    let f = File::open(dir)?;
    f.sync_all()?;
    Ok(())
}

#[cfg(not(unix))]
pub fn sync_dir(_dir: &Path) -> Result<()> {
    Ok(())
}
