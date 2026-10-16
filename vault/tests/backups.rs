use regino_vault::backups::{list_backups, write_backup, BackupError};

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
