use regino_vault::{Error, Key, Vault};
use serde_json::{json, Value};

fn tmp() -> (tempfile::TempDir, std::path::PathBuf) {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("demo.db");
    (dir, path)
}

#[test]
fn writes_and_reads_back_after_reopen() {
    let (_d, path) = tmp();
    let key = Key::generate().unwrap();
    {
        let v = Vault::open(&path, &key).unwrap();
        v.exec("CREATE TABLE t (id INTEGER PRIMARY KEY, name TEXT, amount INTEGER, rate REAL)")
            .unwrap();
        let n = v
            .run(
                "INSERT INTO t (name, amount, rate) VALUES (?, ?, ?), (?, ?, ?)",
                &[
                    json!("Billa"),
                    json!(-2340),
                    json!(1.5),
                    json!(null),
                    json!(true),
                    json!(0.25),
                ],
            )
            .unwrap();
        assert_eq!(n, 2);
    }
    let v = Vault::open(&path, &Key::from_hex(&key.to_hex()).unwrap()).unwrap();
    let rows = v
        .all("SELECT name, amount, rate FROM t ORDER BY id", &[])
        .unwrap();
    assert_eq!(
        Value::Array(rows.into_iter().map(Value::Object).collect()),
        json!([
            { "name": "Billa", "amount": -2340, "rate": 1.5 },
            { "name": null, "amount": 1, "rate": 0.25 }
        ])
    );
    let filtered = v
        .all(
            "SELECT count(*) AS n FROM t WHERE name = ?",
            &[json!("Billa")],
        )
        .unwrap();
    assert_eq!(filtered[0]["n"], json!(1));
}

#[test]
fn wrong_key_does_not_open_and_overwrites_nothing() {
    let (_d, path) = tmp();
    let key = Key::generate().unwrap();
    {
        let v = Vault::open(&path, &key).unwrap();
        v.exec("CREATE TABLE t (x TEXT); INSERT INTO t VALUES ('secret')")
            .unwrap();
    }
    let wrong = Key::generate().unwrap();
    assert!(matches!(Vault::open(&path, &wrong), Err(Error::WrongKey)));
    // the correct key still works
    let v = Vault::open(&path, &key).unwrap();
    assert_eq!(
        v.all("SELECT x FROM t", &[]).unwrap()[0]["x"],
        json!("secret")
    );
}

#[test]
fn file_is_encrypted() {
    let (_d, path) = tmp();
    let key = Key::generate().unwrap();
    {
        let v = Vault::open(&path, &key).unwrap();
        v.exec("PRAGMA journal_mode = DELETE; CREATE TABLE t (x TEXT); INSERT INTO t VALUES ('IBAN SK3112000000198742637541')")
            .unwrap();
    }
    let bytes = std::fs::read(&path).unwrap();
    assert!(
        !bytes.windows(4).any(|w| w == b"IBAN"),
        "text is readable in the file"
    );
    assert!(
        !bytes.starts_with(b"SQLite format 3"),
        "SQLite header is readable"
    );
}

#[test]
fn rekey_reencrypts_file() {
    let (_d, path) = tmp();
    let old = Key::generate().unwrap();
    let new = Key::generate().unwrap();
    {
        let v = Vault::open(&path, &old).unwrap();
        v.exec(
            "PRAGMA journal_mode = DELETE; CREATE TABLE t (x INTEGER); INSERT INTO t VALUES (42)",
        )
        .unwrap();
        v.rekey(&new).unwrap();
    }
    assert!(matches!(Vault::open(&path, &old), Err(Error::WrongKey)));
    let v = Vault::open(&path, &new).unwrap();
    assert_eq!(v.all("SELECT x FROM t", &[]).unwrap()[0]["x"], json!(42));
}

#[test]
fn transaction_and_foreign_keys() {
    let (_d, path) = tmp();
    let v = Vault::open(&path, &Key::generate().unwrap()).unwrap();
    v.exec("CREATE TABLE a (id TEXT PRIMARY KEY); CREATE TABLE b (a_id TEXT REFERENCES a(id))")
        .unwrap();
    assert!(
        v.run("INSERT INTO b VALUES (?)", &[json!("no")]).is_err(),
        "foreign keys are disabled"
    );
    v.exec("BEGIN IMMEDIATE").unwrap();
    v.run("INSERT INTO a VALUES (?)", &[json!("x")]).unwrap();
    v.exec("ROLLBACK").unwrap();
    assert_eq!(
        v.all("SELECT count(*) AS n FROM a", &[]).unwrap()[0]["n"],
        json!(0)
    );
}

fn open_tmp() -> (tempfile::TempDir, Vault) {
    let (d, path) = tmp();
    (d, Vault::open(&path, &Key::generate().unwrap()).unwrap())
}

#[test]
fn array_and_object_params_are_rejected() {
    let (_d, v) = open_tmp();
    assert!(matches!(
        v.run("SELECT ?", &[json!([1, 2])]),
        Err(Error::BadValue(_))
    ));
    assert!(matches!(
        v.run("SELECT ?", &[json!({"a": 1})]),
        Err(Error::BadValue(_))
    ));
}

#[test]
fn blob_results_are_rejected() {
    let (_d, v) = open_tmp();
    assert!(matches!(
        v.all("SELECT x'00' AS b", &[]),
        Err(Error::BadValue(_))
    ));
}

#[test]
fn invalid_hex_keys_are_rejected() {
    assert!(matches!(Key::from_hex("abc"), Err(Error::BadKey)));
    assert!(matches!(
        Key::from_hex(&"zz".repeat(32)),
        Err(Error::BadKey)
    ));
    let k = Key::generate().unwrap();
    assert_eq!(
        Key::from_hex(&k.to_hex()).unwrap().to_hex().as_str(),
        k.to_hex().as_str()
    );
}

#[test]
fn sql_syntax_error_is_an_error() {
    let (_d, v) = open_tmp();
    assert!(matches!(v.exec("SELEC error"), Err(Error::Sql(_))));
}

#[test]
fn profile_id_must_not_be_a_path() {
    use regino_vault::valid_profile_id;
    assert!(valid_profile_id("p-01abc"));
    assert!(valid_profile_id("cottage"));
    assert!(!valid_profile_id(""));
    assert!(!valid_profile_id("../x"));
    assert!(!valid_profile_id("a/b"));
    assert!(!valid_profile_id("Big"));
    assert!(!valid_profile_id(&"a".repeat(33)));
}

#[test]
fn json_functions_for_change_log() {
    // Change-log triggers (migration 005) need json_object and json_extract.
    let (_d, path) = tmp();
    let v = Vault::open(&path, &Key::generate().unwrap()).unwrap();
    let rows = v
        .all(
            "SELECT json_object('a', 1, 'b', 'x') AS o, json_extract('\"m1\"', '$') AS e",
            &[],
        )
        .unwrap();
    assert_eq!(rows[0]["o"], serde_json::json!("{\"a\":1,\"b\":\"x\"}"));
    assert_eq!(rows[0]["e"], serde_json::json!("m1"));
}

#[test]
fn concurrent_open_with_right_and_wrong_key() {
    let (_d, path) = tmp();
    let key = Key::generate().unwrap();
    Vault::open(&path, &key).unwrap().exec("CREATE TABLE t (x INTEGER)").unwrap();
    let hex = key.to_hex().as_str().to_string();
    let threads: Vec<_> = (0..8)
        .map(|i| {
            let (path, hex) = (path.clone(), hex.clone());
            std::thread::spawn(move || {
                for _ in 0..5 {
                    if i % 2 == 0 {
                        assert!(Vault::open(&path, &Key::from_hex(&hex).unwrap()).is_ok());
                    } else {
                        let wrong = Key::generate().unwrap();
                        assert!(matches!(Vault::open(&path, &wrong), Err(Error::WrongKey)));
                    }
                }
            })
        })
        .collect();
    for t in threads {
        t.join().unwrap();
    }
}

/// Question 7: in WAL mode (the default of `Vault::open`) the WAL file holds encrypted pages too.
#[test]
fn wal_file_is_encrypted() {
    let (_d, path) = tmp();
    let key = Key::generate().unwrap();
    let v = Vault::open(&path, &key).unwrap();
    v.exec("CREATE TABLE t (x TEXT)").unwrap();
    for _ in 0..50 {
        v.run("INSERT INTO t VALUES (?)", &[json!("MARKER-PLAINTEXT-1234567890")]).unwrap();
    }
    // the connection is still open, so the pages sit in the -wal file (no checkpoint yet)
    let wal = path.with_file_name("demo.db-wal");
    let wal_bytes = std::fs::read(&wal).unwrap();
    assert!(!wal_bytes.is_empty(), "expected a WAL file");
    for f in [std::fs::read(&path).unwrap(), wal_bytes] {
        assert!(!f.windows(6).any(|w| w == b"MARKER"), "plaintext readable");
    }
}

/// Question 7: `rekey` while the database is in WAL mode with uncheckpointed data.
#[test]
fn rekey_in_wal_mode() {
    let (_d, path) = tmp();
    let old = Key::generate().unwrap();
    let new = Key::generate().unwrap();
    {
        let v = Vault::open(&path, &old).unwrap();
        v.exec("CREATE TABLE t (x INTEGER); INSERT INTO t VALUES (7)").unwrap();
        v.rekey(&new).unwrap();
        v.exec("INSERT INTO t VALUES (8)").unwrap();
    }
    assert!(matches!(Vault::open(&path, &old), Err(Error::WrongKey)));
    let v = Vault::open(&path, &new).unwrap();
    assert_eq!(v.all("SELECT count(*) AS n FROM t", &[]).unwrap()[0]["n"], json!(2));
}
