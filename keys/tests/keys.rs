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

/// A "backup" as an app makes it: the master key's material (from the recovery phrase) opens the
/// wrapped client keys it contains. Issue #3 / question 16: a backup made *before* the client was
/// deleted still opens the client's records; a backup made *after* does not. Deleting a client is
/// therefore crypto-shredding only together with deleting (or re-creating) the older backups.
#[test]
fn shredding_reaches_only_backups_made_after_deletion() {
    struct Backup {
        wrapped_clients: Vec<(Vec<u8>, Vec<u8>)>, // (context, wrapped key)
        sealed: Vec<(Vec<u8>, Vec<u8>)>,          // (context, sealed record)
    }
    fn open_all(master: &Key, b: &Backup) -> Vec<Vec<u8>> {
        let mut out = Vec::new();
        for (ctx, w) in &b.wrapped_clients {
            let k = wrap::unwrap_key(master, w, ctx).unwrap();
            for (rctx, r) in &b.sealed {
                if let Ok(plain) = wrap::open(&k, r, rctx) {
                    out.push(plain.to_vec());
                }
            }
        }
        out
    }
    let master = Key::generate().unwrap();
    let client = Key::generate().unwrap();
    let wrapped = wrap::wrap_key(&master, &client, b"app/client/1").unwrap();
    let record = wrap::seal(&client, b"session note", b"app/note/1").unwrap();
    let before = Backup { wrapped_clients: vec![(b"app/client/1".to_vec(), wrapped)], sealed: vec![(b"app/note/1".to_vec(), record.clone())] };
    // the client is deleted: the wrapped key is discarded, the sealed record may still linger
    let after = Backup { wrapped_clients: vec![], sealed: vec![(b"app/note/1".to_vec(), record)] };
    assert_eq!(open_all(&master, &before), vec![b"session note".to_vec()]);
    assert!(open_all(&master, &after).is_empty());
}

/// Question 2: the AAD is `magic(4) || context`. The magic has a fixed length and the context is the
/// only variable field, so the map context -> AAD is injective and a blob cannot be moved between
/// the two magics or between contexts, even contexts that are prefixes of each other.
#[test]
fn aad_binds_magic_and_whole_context() {
    let k = Key::generate().unwrap();
    let inner = Key::generate().unwrap();
    let w = wrap::wrap_key(&k, &inner, b"app/client/1").unwrap();
    for ctx in [&b"app/client/"[..], b"app/client/10", b"app/client/1\0", b"", b"RGW1app/client/1"] {
        assert_eq!(wrap::unwrap_key(&k, &w, ctx).unwrap_err(), Error::Decrypt);
    }
    // the same bytes relabelled as a sealed blob (RGS1) do not open: the magic is in the AAD
    let mut relabelled = w.clone();
    relabelled[..4].copy_from_slice(b"RGS1");
    assert_eq!(wrap::open(&k, &relabelled, b"app/client/1").unwrap_err(), Error::Decrypt);
    let s = wrap::seal(&k, inner.as_bytes(), b"app/client/1").unwrap();
    let mut as_wrap = s.clone();
    as_wrap[..4].copy_from_slice(b"RGW1");
    assert_eq!(wrap::unwrap_key(&k, &as_wrap, b"app/client/1").unwrap_err(), Error::Decrypt);
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

/// Question 6: blahaj samples Shamir coefficients uniformly from 0..=255 (the original `sharks`
/// crate excluded 0). With threshold 2 the share at x = 1 is `a1 XOR secret` in GF(256), so its bytes
/// must be uniform over all 256 values – including the value equal to the secret (a1 = 0).
#[test]
fn shamir_coefficients_are_uniform_including_zero() {
    let key = Key::from_bytes([0x5a; 32]);
    let mut counts = [0u32; 256];
    for _ in 0..2048 {
        let parts = shamir::split(&key, 2, 2).unwrap();
        let first = &parts[0];
        assert_eq!(first[13], 1, "first share is x = 1");
        for &y in &first[14..] {
            counts[y as usize] += 1;
        }
    }
    // 65 536 samples, 256 expected per value; bounds are about ±8 standard deviations
    let (min, max) = (counts.iter().min().unwrap(), counts.iter().max().unwrap());
    assert!(*min > 120 && *max < 400, "min {min}, max {max}");
    assert!(counts[0x5a] > 120, "coefficient 0 never drawn");
}
