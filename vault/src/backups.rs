//! Backup files in a directory: safe write (temporary file + `fsync` + rename + `fsync` of the
//! directory) and keeping only the last N. The contents are already encrypted (`ts/` or
//! `regino-keys`) – this module only stores them.
//!
//! Names are `<prefix><time>.<ext>` with only letters, digits, `-` and `_` (the prefix is checked
//! too), so a name can never leave the directory. Pruning never deletes the file just written,
//! even if the clock went back and it sorts before older backups.
//!
//! Deleting data (crypto-shredding, question 16 in AUDIT.md): backups made before a client was
//! deleted still contain the client's wrapped key. After deleting a client the app writes a fresh
//! backup and calls [`discard_backups_before`] with its name; copies the user made elsewhere (cloud,
//! USB) are outside the app's reach and the app must say so.

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
    sync_dir(dir)?;
    remove_stale_temp_files(dir, prefix, ext, name);
    // the new file is never pruned, even if it sorts first (clock set back)
    let mut older: Vec<PathBuf> = list_backups(dir, prefix, ext)?.into_iter().filter(|p| *p != target).collect();
    while older.len() + 1 > keep.max(1) {
        fs::remove_file(older.remove(0))?;
    }
    Ok(target)
}

/// Deletes all backups of the app that sort before `name` (by the time in the name) and returns how
/// many were deleted. Use after deleting a client: write a fresh backup, then discard the older ones
/// that still carry the client's wrapped key.
pub fn discard_backups_before(dir: &Path, prefix: &str, ext: &str, name: &str) -> Result<usize, BackupError> {
    if !valid_name(name, prefix, ext) {
        return Err(BackupError::BadName(name.to_string()));
    }
    let mut n = 0;
    for p in list_backups(dir, prefix, ext)? {
        if p.file_name().and_then(|f| f.to_str()).is_some_and(|f| f < name) {
            fs::remove_file(p)?;
            n += 1;
        }
    }
    if n > 0 {
        sync_dir(dir)?;
    }
    Ok(n)
}

/// Makes the rename durable: on Unix the directory entry is flushed too. On Windows `rename`
/// (MoveFileEx) is already durable enough and directories cannot be opened for `fsync`.
fn sync_dir(dir: &Path) -> std::io::Result<()> {
    #[cfg(unix)]
    fs::File::open(dir)?.sync_all()?;
    #[cfg(not(unix))]
    let _ = dir;
    Ok(())
}

/// Temporary files `.<name>.tmp` of this app left by a crash before the rename (best effort).
fn remove_stale_temp_files(dir: &Path, prefix: &str, ext: &str, current: &str) {
    let Ok(entries) = fs::read_dir(dir) else { return };
    for e in entries.flatten() {
        let file = e.file_name();
        let Some(n) = file.to_str() else { continue };
        let inner = n.strip_prefix('.').and_then(|x| x.strip_suffix(".tmp"));
        if inner.is_some_and(|i| i != current && valid_name(i, prefix, ext)) {
            let _ = fs::remove_file(e.path());
        }
    }
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
