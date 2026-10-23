use regino_vault::{keystore, Error, Key, Vault};

// In-memory mock keystore instead of Windows Credential Manager. Set up once for all tests
// (they run in parallel; each uses its own entry).
fn mock_store() {
    static INIT: std::sync::Once = std::sync::Once::new();
    INIT.call_once(|| keyring_core::set_default_store(keyring_core::mock::Store::new().unwrap()));
}

#[test]
fn first_run_creates_key_later_runs_load_it() {
    mock_store();
    let (k1, created1) = keystore::load_or_create_key("regino-crypto.test", "db-test-1").unwrap();
    assert!(created1);
    let (k2, created2) = keystore::load_or_create_key("regino-crypto.test", "db-test-1").unwrap();
    assert!(!created2);
    assert_eq!(k1.to_hex().as_str(), k2.to_hex().as_str());

    // different entry = different key
    let (k3, _) = keystore::load_or_create_key("regino-crypto.test", "db-test-2").unwrap();
    assert_ne!(k1.to_hex().as_str(), k3.to_hex().as_str());
}

#[test]
fn keystore_key_opens_database_even_after_rekey() {
    mock_store();
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("demo.db");
    let (key, _) = keystore::load_or_create_key("regino-crypto.test", "db-test-3").unwrap();
    {
        let v = Vault::open(&path, &key).unwrap();
        v.exec("CREATE TABLE t (x INTEGER); INSERT INTO t VALUES (1)")
            .unwrap();
        let new = regino_vault::Key::generate().unwrap();
        v.rekey(&new).unwrap();
        keystore::store_key("regino-crypto.test", "db-test-3", &new).unwrap();
    }
    let (loaded, created) = keystore::load_or_create_key("regino-crypto.test", "db-test-3").unwrap();
    assert!(!created);
    assert!(Vault::open(&path, &loaded).is_ok());
    assert!(matches!(Vault::open(&path, &key), Err(Error::WrongKey)));
}

const SVC: &str = "regino-crypto.test";

fn pending(user: &str) -> keyring_core::Entry {
    keyring_core::Entry::new(SVC, &format!("{user}{}", keystore::PENDING_SUFFIX)).unwrap()
}

fn no_pending(user: &str) -> bool {
    matches!(pending(user).get_secret(), Err(keyring_core::Error::NoEntry))
}

fn new_db(path: &std::path::Path, user: &str) -> Key {
    let (key, _) = keystore::load_or_create_key(SVC, user).unwrap();
    let v = Vault::open(path, &key).unwrap();
    v.exec("CREATE TABLE t (x INTEGER); INSERT INTO t VALUES (1)").unwrap();
    key
}

/// 0.12.1: `keystore::rekey` re-encrypts the file and switches the entry; afterwards only the new
/// key opens the file, the keystore holds it and no pending entry is left behind.
#[test]
fn rekey_switches_file_and_keystore_together() {
    mock_store();
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("demo.db");
    let old = new_db(&path, "rekey-1");
    let new = Key::generate().unwrap();
    {
        let v = Vault::open(&path, &old).unwrap();
        keystore::rekey(&v, SVC, "rekey-1", &new).unwrap();
        v.exec("INSERT INTO t VALUES (2)").unwrap();
    }
    assert!(no_pending("rekey-1"));
    let (loaded, created) = keystore::load_or_create_key(SVC, "rekey-1").unwrap();
    assert!(!created);
    assert_eq!(loaded.to_hex().as_str(), new.to_hex().as_str());
    assert!(matches!(Vault::open(&path, &old), Err(Error::WrongKey)));
    let v = Vault::open(&path, &loaded).unwrap();
    assert_eq!(v.all("SELECT count(*) AS n FROM t", &[]).unwrap()[0]["n"], serde_json::json!(2));
    // nothing to finish afterwards
    assert!(!keystore::finish_rekey(SVC, "rekey-1", &path).unwrap());
}

/// Crash after step 1 (pending written, file not re-encrypted): the pending key does not open the
/// file, so it is dropped and the main entry stays.
#[test]
fn finish_rekey_drops_pending_key_that_does_not_open_the_file() {
    mock_store();
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("demo.db");
    let old = new_db(&path, "rekey-2");
    let abandoned = Key::generate().unwrap();
    pending("rekey-2").set_secret(abandoned.as_bytes()).unwrap();
    assert!(!keystore::finish_rekey(SVC, "rekey-2", &path).unwrap());
    assert!(no_pending("rekey-2"));
    let (loaded, _) = keystore::load_or_create_key(SVC, "rekey-2").unwrap();
    assert_eq!(loaded.to_hex().as_str(), old.to_hex().as_str());
    assert!(Vault::open(&path, &loaded).is_ok());
    assert!(matches!(Vault::open(&path, &abandoned), Err(Error::WrongKey)));
}

/// Crash after step 2 (file re-encrypted, main entry still the old key): the pending key opens the
/// file and becomes the main entry.
#[test]
fn finish_rekey_promotes_pending_key_that_opens_the_file() {
    mock_store();
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("demo.db");
    let old = new_db(&path, "rekey-3");
    let new = Key::generate().unwrap();
    {
        let v = Vault::open(&path, &old).unwrap();
        pending("rekey-3").set_secret(new.as_bytes()).unwrap();
        v.rekey(&new).unwrap();
        // process dies here – the main entry still holds `old`
    }
    assert!(keystore::finish_rekey(SVC, "rekey-3", &path).unwrap());
    assert!(no_pending("rekey-3"));
    let (loaded, created) = keystore::load_or_create_key(SVC, "rekey-3").unwrap();
    assert!(!created);
    assert_eq!(loaded.to_hex().as_str(), new.to_hex().as_str());
    assert!(Vault::open(&path, &loaded).is_ok());
    // crash after step 3 (main already switched): promoting again is harmless
    pending("rekey-3").set_secret(new.as_bytes()).unwrap();
    assert!(keystore::finish_rekey(SVC, "rekey-3", &path).unwrap());
    assert!(no_pending("rekey-3"));
    assert_eq!(keystore::load_or_create_key(SVC, "rekey-3").unwrap().0.to_hex().as_str(), new.to_hex().as_str());
}

/// Nothing to finish: no pending entry, the main entry is untouched (and not created).
/// A pending entry without a database file, or with a wrong length, is only removed.
#[test]
fn finish_rekey_without_pending_entry_or_file_changes_nothing() {
    mock_store();
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("demo.db");
    assert!(!keystore::finish_rekey(SVC, "rekey-4", &path).unwrap());
    assert!(matches!(
        keyring_core::Entry::new(SVC, "rekey-4").unwrap().get_secret(),
        Err(keyring_core::Error::NoEntry)
    ));
    // pending key, but no file yet: nothing to open, the pending entry goes, no file is created
    pending("rekey-4").set_secret(Key::generate().unwrap().as_bytes()).unwrap();
    assert!(!keystore::finish_rekey(SVC, "rekey-4", &path).unwrap());
    assert!(no_pending("rekey-4"));
    assert!(!path.exists());
    // a pending entry of the wrong length never opens a database
    let old = new_db(&path, "rekey-4");
    pending("rekey-4").set_secret(b"short").unwrap();
    assert!(!keystore::finish_rekey(SVC, "rekey-4", &path).unwrap());
    assert!(no_pending("rekey-4"));
    assert_eq!(keystore::load_or_create_key(SVC, "rekey-4").unwrap().0.to_hex().as_str(), old.to_hex().as_str());
}

#[test]
fn corrupted_key_in_keystore_is_an_error() {
    mock_store();
    keyring_core::Entry::new("regino-crypto.test", "db-test-4")
        .unwrap()
        .set_secret(b"short")
        .unwrap();
    assert!(matches!(
        keystore::load_or_create_key("regino-crypto.test", "db-test-4"),
        Err(Error::KeyStore(_))
    ));
}

#[test]
fn to_hex_is_lowercase_and_round_trips() {
    let mut b = zeroize::Zeroizing::new([0u8; regino_vault::KEY_LEN]);
    for (i, x) in b.iter_mut().enumerate() {
        *x = (i as u8).wrapping_mul(37).wrapping_add(0xa5);
    }
    let k = Key::from_bytes(b);
    let hex = k.to_hex();
    assert_eq!(hex.len(), 64);
    assert!(hex.starts_with("a5ca"), "{}", hex.as_str());
    assert_eq!(Key::from_hex(&hex).unwrap().as_bytes(), k.as_bytes());
}
