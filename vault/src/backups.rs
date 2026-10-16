//! Backup files in a directory: safe write (temporary file + rename) and keeping only the last N.
//! The contents are already encrypted (`ts/` or `regino-keys`) – this module only stores them.

use std::fs;
use std::io::Write;
use std::path::{Path, PathBuf};

#[derive(Debug, thiserror::Error)]
pub enum BackupError {
    #[error("Invalid backup file name: {0}")]
    BadName(String),
    #[error("{0}")]
    Io(#[from] std::io::Error),
}

/// The name must be `<prefix><time>.<ext>` – only letters, digits, hyphen and underscore (no paths).
/// `ext` is chosen by the app (e.g. `demo`).
fn valid_name(name: &str, prefix: &str, ext: &str) -> bool {
    let suffix = format!(".{ext}");
    !ext.is_empty()
        && ext.chars().all(|c| c.is_ascii_alphanumeric())
        && name.starts_with(prefix)
        && name.ends_with(&suffix)
        && name.len() <= 80
        && name[..name.len() - suffix.len()]
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_')
}

/// Writes a backup and deletes the oldest ones beyond `keep` (by name – the time in the name sorts chronologically).
pub fn write_backup(
    dir: &Path,
    prefix: &str,
    ext: &str,
    name: &str,
    contents: &[u8],
    keep: usize,
) -> Result<PathBuf, BackupError> {
    if !valid_name(name, prefix, ext) {
        return Err(BackupError::BadName(name.to_string()));
    }
    fs::create_dir_all(dir)?;
    let target = dir.join(name);
    let tmp = dir.join(format!(".{name}.tmp"));
    {
        let mut f = fs::File::create(&tmp)?;
        f.write_all(contents)?;
        f.sync_all()?;
    }
    fs::rename(&tmp, &target)?;
    let mut ours: Vec<PathBuf> = list_backups(dir, prefix, ext)?;
    ours.sort();
    while ours.len() > keep.max(1) {
        fs::remove_file(ours.remove(0))?;
    }
    Ok(target)
}

/// Backups in the directory, from oldest to newest.
pub fn list_backups(dir: &Path, prefix: &str, ext: &str) -> Result<Vec<PathBuf>, BackupError> {
    if !dir.exists() {
        return Ok(Vec::new());
    }
    let mut out: Vec<PathBuf> = fs::read_dir(dir)?
        .filter_map(|e| e.ok())
        .map(|e| e.path())
        .filter(|p| {
            p.file_name()
                .and_then(|n| n.to_str())
                .is_some_and(|n| valid_name(n, prefix, ext))
        })
        .collect();
    out.sort();
    Ok(out)
}
