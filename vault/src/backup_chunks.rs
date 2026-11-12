//! Chunk folder of backups (large files, `regino_keys::backup_chunks`, `ts/src/backupChunks.ts`):
//! one file `<name>.rgb` per chunk, shared by all backups in the directory.
//!
//! Order that survives a power cut at any moment:
//! 1. every chunk is written as `<name>.rgb.tmp`, `fsync`, renamed, the folder `fsync`-ed ([`put_chunk`]);
//!    a chunk that already exists is skipped (same name = same content), so an interrupted backup
//!    resumes where it stopped;
//! 2. the backup itself (the manifest, `backups::write_backup`) is written **last** and lists its chunks
//!    in plain text (`chunks`, bound in its AAD);
//! 3. [`gc_chunks`] deletes chunks no backup lists and leftover `.tmp` files – only those older than
//!    `min_age` (the app uses one day), so chunks of a backup being written right now are never touched.

use crate::backups::{list_backups, BackupError};
use std::collections::HashSet;
use std::fs;
use std::io::Write;
use std::path::{Path, PathBuf};
use std::time::{Duration, SystemTime};

pub const CHUNK_EXT: &str = "rgb";

fn valid_name(name: &str) -> bool {
    name.len() == 64 && name.bytes().all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
}

fn chunk_path(chunk_dir: &Path, name: &str) -> Result<PathBuf, BackupError> {
    if !valid_name(name) {
        return Err(BackupError::BadName(name.to_string()));
    }
    Ok(chunk_dir.join(format!("{name}.{CHUNK_EXT}")))
}

/// Whether the chunk is already in the folder (an earlier backup, or before an interruption).
pub fn has_chunk(chunk_dir: &Path, name: &str) -> Result<bool, BackupError> {
    Ok(chunk_path(chunk_dir, name)?.is_file())
}

/// Writes a sealed chunk durably; returns `false` when it was already there with the same size (nothing written).
pub fn put_chunk(chunk_dir: &Path, name: &str, blob: &[u8]) -> Result<bool, BackupError> {
    let target = chunk_path(chunk_dir, name)?;
    // An existing file is trusted only when it has the expected size: the sealed blob of one content always has
    // the same length, so a truncated or empty file (interrupted copy, sync glitch) is written again instead of
    // being referenced by every later backup (0.13.4).
    if fs::metadata(&target).is_ok_and(|m| m.is_file() && m.len() == blob.len() as u64) {
        return Ok(false);
    }
    fs::create_dir_all(chunk_dir)?;
    let tmp = chunk_dir.join(format!("{name}.{CHUNK_EXT}.tmp"));
    {
        let mut f = fs::File::create(&tmp)?;
        f.write_all(blob)?;
        f.sync_all()?;
    }
    fs::rename(&tmp, &target)?;
    #[cfg(unix)]
    fs::File::open(chunk_dir)?.sync_all()?;
    Ok(true)
}

pub fn read_chunk(chunk_dir: &Path, name: &str) -> Result<Vec<u8>, BackupError> {
    Ok(fs::read(chunk_path(chunk_dir, name)?)?)
}

/// Names listed by the backups in `backup_dir` (plain `chunks` field of version-2 backups).
/// A backup that cannot be read keeps everything: the caller gets an error and deletes nothing.
pub fn referenced_chunks(backup_dir: &Path, prefix: &str, ext: &str) -> Result<HashSet<String>, BackupError> {
    let mut set = HashSet::new();
    let mut add = |v: &serde_json::Value| {
        if let Some(list) = v.get("chunks").and_then(|c| c.as_array()) {
            set.extend(list.iter().filter_map(|c| c.as_str()).map(str::to_string));
        }
    };
    let listed = list_backups(backup_dir, prefix, ext)?;
    for p in &listed {
        let v: serde_json::Value = serde_json::from_slice(&fs::read(p)?).map_err(|e| BackupError::Io(std::io::Error::new(std::io::ErrorKind::InvalidData, e)))?;
        add(&v);
    }
    // Copies the user made by hand in the same folder (`… - Copy.<ext>`, `… (1).<ext>`) do not match the strict
    // name pattern, but their chunks must stay too (0.13.4). They are not ours to fail on: one that cannot be
    // read or parsed is skipped.
    if let Ok(entries) = fs::read_dir(backup_dir) {
        let suffix = format!(".{ext}");
        for e in entries.flatten() {
            let p = e.path();
            if listed.contains(&p) || !p.is_file() || !e.file_name().to_str().is_some_and(|n| n.ends_with(&suffix)) {
                continue;
            }
            if let Some(v) = fs::read(&p).ok().and_then(|b| serde_json::from_slice::<serde_json::Value>(&b).ok()) {
                add(&v);
            }
        }
    }
    Ok(set)
}

/// Deletes chunks that no backup lists and stale temporary files, older than `min_age`; returns how many.
/// Call after writing a backup (old ones were pruned) and after `discard_backups_before`.
pub fn gc_chunks(chunk_dir: &Path, backup_dir: &Path, prefix: &str, ext: &str, min_age: Duration) -> Result<usize, BackupError> {
    let referenced = referenced_chunks(backup_dir, prefix, ext)?;
    let Ok(entries) = fs::read_dir(chunk_dir) else { return Ok(0) };
    let now = SystemTime::now();
    let mut n = 0;
    for e in entries.flatten() {
        let file = e.file_name();
        let Some(f) = file.to_str() else { continue };
        let old = e.metadata().and_then(|m| m.modified()).ok().and_then(|t| now.duration_since(t).ok()).is_none_or(|age| age >= min_age);
        if !old {
            continue;
        }
        let stale_tmp = f.ends_with(&format!(".{CHUNK_EXT}.tmp"));
        let unreferenced = f.strip_suffix(&format!(".{CHUNK_EXT}")).is_some_and(|name| valid_name(name) && !referenced.contains(name));
        if stale_tmp || unreferenced {
            fs::remove_file(e.path())?;
            n += 1;
        }
    }
    Ok(n)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::backups::{discard_backups_before, write_backup};

    fn name(i: u8) -> String {
        format!("{i:02x}").repeat(32)
    }

    fn manifest(chunks: &[String]) -> Vec<u8> {
        serde_json::json!({ "format": "demo-backup", "version": 2, "chunks": chunks }).to_string().into_bytes()
    }

    #[test]
    fn shared_chunks_resume_and_gc() {
        let root = tempfile::tempdir().unwrap();
        let (dir, kd) = (root.path(), root.path().join("kusky"));
        // first backup: chunks 1 and 2
        assert!(put_chunk(&kd, &name(1), b"one").unwrap());
        assert!(put_chunk(&kd, &name(2), b"two").unwrap());
        write_backup(dir, "demo-", "demo", "demo-2026-10-01.demo", &manifest(&[name(1), name(2)]), 30).unwrap();
        // second backup reuses chunk 1, adds 3 – only the new one is written
        assert!(!put_chunk(&kd, &name(1), b"one").unwrap());
        assert!(put_chunk(&kd, &name(3), b"three").unwrap());
        write_backup(dir, "demo-", "demo", "demo-2026-10-02.demo", &manifest(&[name(1), name(3)]), 30).unwrap();
        assert_eq!(fs::read_dir(&kd).unwrap().count(), 3);
        // interrupted third backup: a chunk and a half-written temp file, no manifest
        put_chunk(&kd, &name(4), b"four").unwrap();
        fs::write(kd.join(format!("{}.rgb.tmp", name(5))), b"half").unwrap();
        // fresh files are protected (a backup may be running)
        assert_eq!(gc_chunks(&kd, dir, "demo-", "demo", Duration::from_secs(86_400)).unwrap(), 0);
        assert_eq!(gc_chunks(&kd, dir, "demo-", "demo", Duration::ZERO).unwrap(), 2);
        assert!(has_chunk(&kd, &name(1)).unwrap() && has_chunk(&kd, &name(2)).unwrap() && !has_chunk(&kd, &name(4)).unwrap());
        // deleting the older backup frees chunk 2 only
        discard_backups_before(dir, "demo-", "demo", "demo-2026-10-02.demo").unwrap();
        assert_eq!(gc_chunks(&kd, dir, "demo-", "demo", Duration::ZERO).unwrap(), 1);
        assert_eq!(read_chunk(&kd, &name(1)).unwrap(), b"one");
        assert!(read_chunk(&kd, &name(2)).is_err());
        assert!(put_chunk(&kd, "../../x", b"x").is_err());
    }

    /// 0.13.4: a copy of a backup made by hand in the backup folder keeps its chunks, although its name does not
    /// match the pattern; a file with the extension that is not a backup is skipped and blocks nothing.
    #[test]
    fn hand_made_copies_keep_their_chunks() {
        let root = tempfile::tempdir().unwrap();
        let (dir, kd) = (root.path(), root.path().join("kusky"));
        put_chunk(&kd, &name(1), b"one").unwrap();
        put_chunk(&kd, &name(2), b"two").unwrap();
        put_chunk(&kd, &name(3), b"three").unwrap();
        write_backup(dir, "demo-", "demo", "demo-2026-10-02.demo", &manifest(&[name(1)]), 30).unwrap();
        fs::write(dir.join("demo-2026-09-01 - Copy.demo"), manifest(&[name(2)])).unwrap();
        fs::write(dir.join("demo-2026-09-01 (1).demo"), manifest(&[name(2)])).unwrap();
        fs::write(dir.join("notes (old).demo"), b"not a backup").unwrap();
        assert_eq!(gc_chunks(&kd, dir, "demo-", "demo", Duration::ZERO).unwrap(), 1);
        assert!(has_chunk(&kd, &name(1)).unwrap() && has_chunk(&kd, &name(2)).unwrap() && !has_chunk(&kd, &name(3)).unwrap());
        // once the copies are gone, their chunk goes too
        fs::remove_file(dir.join("demo-2026-09-01 - Copy.demo")).unwrap();
        fs::remove_file(dir.join("demo-2026-09-01 (1).demo")).unwrap();
        assert_eq!(gc_chunks(&kd, dir, "demo-", "demo", Duration::ZERO).unwrap(), 1);
        assert!(!has_chunk(&kd, &name(2)).unwrap());
    }

    /// 0.13.4: a truncated or empty chunk file is written again; one of the right size is left alone.
    #[test]
    fn damaged_chunk_is_rewritten() {
        let root = tempfile::tempdir().unwrap();
        let kd = root.path().join("kusky");
        assert!(put_chunk(&kd, &name(1), b"sealed chunk").unwrap());
        assert!(!put_chunk(&kd, &name(1), b"sealed chunk").unwrap());
        fs::write(kd.join(format!("{}.rgb", name(1))), b"").unwrap();
        assert!(put_chunk(&kd, &name(1), b"sealed chunk").unwrap());
        assert_eq!(read_chunk(&kd, &name(1)).unwrap(), b"sealed chunk");
        fs::write(kd.join(format!("{}.rgb", name(1))), b"seal").unwrap();
        assert!(put_chunk(&kd, &name(1), b"sealed chunk").unwrap());
        assert_eq!(read_chunk(&kd, &name(1)).unwrap(), b"sealed chunk");
        assert!(!put_chunk(&kd, &name(1), b"sealed chunk").unwrap());
    }

    #[test]
    fn unreadable_backup_deletes_nothing() {
        let root = tempfile::tempdir().unwrap();
        let kd = root.path().join("kusky");
        put_chunk(&kd, &name(1), b"one").unwrap();
        fs::write(root.path().join("demo-2026-10-01.demo"), b"{broken").unwrap();
        assert!(gc_chunks(&kd, root.path(), "demo-", "demo", Duration::ZERO).is_err());
        assert!(has_chunk(&kd, &name(1)).unwrap());
        assert_eq!(gc_chunks(&root.path().join("none"), root.path().join("x").as_path(), "demo-", "demo", Duration::ZERO).unwrap(), 0);
    }
}
