use regino_vault::backups::{discard_backups_before, list_backups, write_backup, BackupError};

const P: &str = "demo-backup-";

#[test]
fn writes_and_keeps_last_n() {
    let dir = tempfile::tempdir().unwrap();
    let d = dir.path().join("Backups");
    for i in 1..=10 {
        let name = format!("{P}2026-10-{i:02}-1200.demo");
        let path = write_backup(&d, P, "demo", &name, format!("contents {i}").as_bytes(), 8).unwrap();
        assert_eq!(std::fs::read_to_string(path).unwrap(), format!("contents {i}"));
    }
    let left: Vec<String> = list_backups(&d, P, "demo")
        .unwrap()
        .iter()
        .map(|p| p.file_name().unwrap().to_string_lossy().into_owned())
        .collect();
    assert_eq!(left.len(), 8);
    assert_eq!(left.first().unwrap(), &format!("{P}2026-10-03-1200.demo"));
    assert_eq!(left.last().unwrap(), &format!("{P}2026-10-10-1200.demo"));
    // no temporary files left
    assert_eq!(std::fs::read_dir(&d).unwrap().count(), 8);
}

#[test]
fn leaves_foreign_files_in_directory_alone() {
    let dir = tempfile::tempdir().unwrap();
    std::fs::write(dir.path().join("vacation.jpg"), b"x").unwrap();
    std::fs::write(dir.path().join("demo-backup-old.txt"), b"x").unwrap();
    write_backup(dir.path(), P, "demo", &format!("{P}a.demo"), b"1", 1).unwrap();
    write_backup(dir.path(), P, "demo", &format!("{P}b.demo"), b"2", 1).unwrap();
    assert!(dir.path().join("vacation.jpg").exists());
    assert!(dir.path().join("demo-backup-old.txt").exists());
    assert_eq!(list_backups(dir.path(), P, "demo").unwrap().len(), 1);
    // keep = 0 behaves like 1 (the newest backup is never deleted)
    write_backup(dir.path(), P, "demo", &format!("{P}c.demo"), b"3", 0).unwrap();
    assert_eq!(list_backups(dir.path(), P, "demo").unwrap().len(), 1);
}

#[test]
fn rejects_dangerous_names() {
    let dir = tempfile::tempdir().unwrap();
    for bad in [
        "../demo-backup-x.demo",
        "demo-backup-x.exe",
        "other-x.demo",
        "demo-backup-a b.demo",
        "demo-backup-..\\x.demo",
    ] {
        assert!(
            matches!(
                write_backup(dir.path(), P, "demo", bad, b"x", 8),
                Err(BackupError::BadName(_))
            ),
            "{bad}"
        );
    }
    assert!(list_backups(&dir.path().join("missing"), P, "demo")
        .unwrap()
        .is_empty());
}

#[test]
fn extension_is_set_by_app_and_other_apps_backups_are_ignored() {
    let dir = tempfile::tempdir().unwrap();
    write_backup(dir.path(), "backup-", "other", "backup-1.other", b"d", 5).unwrap();
    write_backup(dir.path(), "backup-", "demo", "backup-1.demo", b"g", 5).unwrap();
    assert_eq!(list_backups(dir.path(), "backup-", "other").unwrap().len(), 1);
    assert_eq!(list_backups(dir.path(), "backup-", "demo").unwrap().len(), 1);
    assert!(matches!(write_backup(dir.path(), "backup-", "", "backup-1.", b"x", 5), Err(BackupError::BadName(_))));
    assert!(matches!(write_backup(dir.path(), "backup-", "a/b", "backup-1.a/b", b"x", 5), Err(BackupError::BadName(_))));
}

fn names(d: &std::path::Path) -> Vec<String> {
    list_backups(d, P, "demo").unwrap().iter().map(|p| p.file_name().unwrap().to_string_lossy().into_owned()).collect()
}

/// Question 9: a backup written with a clock set back sorts first – it must not be pruned at once.
#[test]
fn new_backup_is_never_pruned_even_if_it_sorts_first() {
    let dir = tempfile::tempdir().unwrap();
    write_backup(dir.path(), P, "demo", &format!("{P}2026-10-18-1200.demo"), b"new", 1).unwrap();
    let p = write_backup(dir.path(), P, "demo", &format!("{P}2026-10-17-1200.demo"), b"clock back", 1).unwrap();
    assert!(p.exists());
    assert_eq!(names(dir.path()), vec![format!("{P}2026-10-17-1200.demo")]);
}

/// Question 9: a temporary file left by a crash is removed by the next write; foreign ones stay.
#[test]
fn stale_temporary_files_are_cleaned() {
    let dir = tempfile::tempdir().unwrap();
    std::fs::write(dir.path().join(format!(".{P}2026-10-01-1200.demo.tmp")), b"half").unwrap();
    std::fs::write(dir.path().join(".other.tmp"), b"x").unwrap();
    write_backup(dir.path(), P, "demo", &format!("{P}2026-10-02-1200.demo"), b"ok", 5).unwrap();
    assert!(!dir.path().join(format!(".{P}2026-10-01-1200.demo.tmp")).exists());
    assert!(dir.path().join(".other.tmp").exists());
}

/// Question 9: the prefix is part of the checked name, so a prefix with a path does not escape.
#[test]
fn prefix_with_path_is_rejected() {
    let dir = tempfile::tempdir().unwrap();
    for (prefix, name) in [("../", "../x.demo"), ("a/", "a/x.demo"), ("..\\", "..\\x.demo")] {
        assert!(matches!(write_backup(dir.path(), prefix, "demo", name, b"x", 5), Err(BackupError::BadName(_))), "{name}");
    }
}

/// Question 16 / issue #3: after a client is deleted, a fresh backup is written and the older ones
/// (which still carry the client's wrapped key) are discarded.
#[test]
fn discard_backups_before_a_fresh_one() {
    let dir = tempfile::tempdir().unwrap();
    for d in ["01", "02", "03"] {
        write_backup(dir.path(), P, "demo", &format!("{P}2026-10-{d}-1200.demo"), b"old", 10).unwrap();
    }
    let fresh = format!("{P}2026-10-04-1200.demo");
    write_backup(dir.path(), P, "demo", &fresh, b"after deletion", 10).unwrap();
    std::fs::write(dir.path().join("vacation.jpg"), b"x").unwrap();
    assert_eq!(discard_backups_before(dir.path(), P, "demo", &fresh).unwrap(), 3);
    assert_eq!(names(dir.path()), vec![fresh.clone()]);
    assert!(dir.path().join("vacation.jpg").exists());
    assert_eq!(discard_backups_before(dir.path(), P, "demo", &fresh).unwrap(), 0);
    assert!(matches!(discard_backups_before(dir.path(), P, "demo", "../x.demo"), Err(BackupError::BadName(_))));
}
