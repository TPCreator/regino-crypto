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
