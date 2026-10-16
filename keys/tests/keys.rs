use regino_keys::{kdf, shamir, wrap, Error, Key};

// Fast parameters for tests only (the minimum the library allows).
const FAST: kdf::KdfParams = kdf::KdfParams::MIN;

#[test]
fn same_password_and_salt_give_same_key() {
    let salt = [7u8; 16];
    assert_eq!(kdf::derive(b"quiet evening", &salt, FAST).unwrap(), kdf::derive(b"quiet evening", &salt, FAST).unwrap());
    assert_ne!(kdf::derive(b"quiet evening", &salt, FAST).unwrap(), kdf::derive(b"quiet evening!", &salt, FAST).unwrap());
    assert_ne!(kdf::derive(b"quiet evening", &salt, FAST).unwrap(), kdf::derive(b"quiet evening", &[8u8; 16], FAST).unwrap());
}

#[test]
fn rejects_weak_argon2_params() {
    let weak = kdf::KdfParams { memory_kib: 1024, iterations: 1, parallelism: 1 };
    assert_eq!(kdf::derive(b"x", &[0u8; 16], weak).unwrap_err(), Error::KdfParams);
    assert_eq!(kdf::KdfParams::default().memory_kib, 65536);
}

#[test]
fn wrapped_key_unwraps_only_with_correct_key_and_context() {
    let kek = Key::generate().unwrap();
    let dek = Key::generate().unwrap();
    let blob = wrap::wrap_key(&kek, &dek, b"demo/client/A").unwrap();
    assert_eq!(wrap::unwrap_key(&kek, &blob, b"demo/client/A").unwrap(), dek);
    assert_eq!(wrap::unwrap_key(&Key::generate().unwrap(), &blob, b"demo/client/A").unwrap_err(), Error::Decrypt);
    assert_eq!(wrap::unwrap_key(&kek, &blob, b"demo/client/B").unwrap_err(), Error::Decrypt);
    let mut bad = blob.clone();
    *bad.last_mut().unwrap() ^= 1;
    assert_eq!(wrap::unwrap_key(&kek, &bad, b"demo/client/A").unwrap_err(), Error::Decrypt);
    assert_eq!(wrap::unwrap_key(&kek, &blob[..10], b"demo/client/A").unwrap_err(), Error::Format);
}

#[test]
fn sealed_data_and_wrapped_key_cannot_be_confused() {
    let k = Key::generate().unwrap();
    let sealed = wrap::seal(&k, b"session notes", b"ctx").unwrap();
    assert_eq!(wrap::open(&k, &sealed, b"ctx").unwrap().as_slice(), b"session notes");
    assert_eq!(wrap::unwrap_key(&k, &sealed, b"ctx").unwrap_err(), Error::Format);
    // same input twice = different ciphertext (random nonce)
    assert_ne!(sealed, wrap::seal(&k, b"session notes", b"ctx").unwrap());
}

#[test]
fn discarding_client_key_shreds_data() {
    let master = Key::generate().unwrap();
    let client = Key::generate().unwrap();
    let wrapped = wrap::wrap_key(&master, &client, b"client/1").unwrap();
    let note = wrap::seal(&client, b"sensitive", b"note/1").unwrap();
    drop(wrapped); // "delete client" = discard the wrapped key
    assert_eq!(wrap::open(&master, &note, b"note/1").unwrap_err(), Error::Decrypt);
}

#[test]
fn any_two_of_three_shares_suffice() {
    let key = Key::generate().unwrap();
    let parts = shamir::split(&key, 2, 3).unwrap();
    assert_eq!(parts.len(), 3);
    for (a, b) in [(0, 1), (0, 2), (1, 2), (2, 0)] {
        assert_eq!(shamir::combine(&[parts[a].clone(), parts[b].clone()]).unwrap(), key);
    }
    assert_eq!(shamir::combine(&parts).unwrap(), key);
}

#[test]
fn one_share_even_repeated_is_not_enough() {
    let parts = shamir::split(&Key::generate().unwrap(), 2, 3).unwrap();
    assert_eq!(shamir::combine(&[parts[0].clone()]).unwrap_err(), Error::NotEnoughShares(2));
    assert_eq!(shamir::combine(&[parts[0].clone(), parts[0].clone()]).unwrap_err(), Error::NotEnoughShares(2));
    assert_eq!(shamir::combine(&[]).unwrap_err(), Error::NotEnoughShares(2));
}

#[test]
fn foreign_or_corrupted_share_fails() {
    let a = shamir::split(&Key::generate().unwrap(), 2, 3).unwrap();
    let b = shamir::split(&Key::generate().unwrap(), 2, 3).unwrap();
    assert_eq!(shamir::combine(&[a[0].clone(), b[1].clone()]).unwrap_err(), Error::BadShares);
    let mut broken = a[1].clone();
    *broken.last_mut().unwrap() ^= 0x55;
    assert_eq!(shamir::combine(&[a[0].clone(), broken]).unwrap_err(), Error::BadShares);
    assert_eq!(shamir::combine(&[b"junk".to_vec(), a[0].clone()]).unwrap_err(), Error::Format);
}

#[test]
fn rejects_nonsensical_split() {
    let k = Key::generate().unwrap();
    assert!(matches!(shamir::split(&k, 1, 3), Err(Error::BadSplit { .. })));
    assert!(matches!(shamir::split(&k, 4, 3), Err(Error::BadSplit { .. })));
    assert_eq!(shamir::split(&k, 3, 5).unwrap().len(), 5);
}

#[test]
fn key_is_not_printed_to_log() {
    assert_eq!(format!("{:?}", Key::generate().unwrap()), "Key(***)");
}
