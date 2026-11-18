//! Point 5 of the decision on the review of 2026-11-18 (`docs/rozhodnutia.md`): a unique `seal` when a list is
//! made, shares of Shamir in buffers that are wiped. Formats unchanged.

use regino_keys::sign::{self, Manifest, Member, SigningKey};
use regino_keys::{shamir, Error, Key};
use zeroize::Zeroizing;

fn key(n: u8) -> SigningKey {
    SigningKey::from_seed(&Key::from_bytes([n; 32]))
}

fn member(id: &str, k: &SigningKey, seal: Vec<u8>) -> Member {
    let seal_version = if seal.is_empty() { 0 } else { 1 };
    Member { id: id.into(), role: "member".into(), admin: true, sign: k.public_key(), seal, seal_version }
}

/// F-07: two members with one non-empty seal are refused when the list is made; reading is unchanged.
#[test]
fn unique_seal_when_a_list_is_made() {
    let (a, b) = (key(1), key(2));
    let list = |members| Manifest { scope: "demo|x".into(), version: 1, epoch: 0, prev: [0; 32], members };
    let shared = list(vec![member("a", &a, vec![4; 65]), member("b", &b, vec![4; 65])]);
    assert_eq!(sign::sign_manifest(&a, &shared), Err(Error::Format));
    // empty seals (members without a sealing key) may repeat; different seals are fine
    assert!(sign::sign_manifest(&a, &list(vec![member("a", &a, vec![]), member("b", &b, vec![])])).is_ok());
    assert!(sign::sign_manifest(&a, &list(vec![member("a", &a, vec![4; 65]), member("b", &b, vec![5; 65])])).is_ok());
    // a list made before 0.16.0 with a shared seal is read as before (signed here through the message bytes)
    let msg = {
        let ok = sign::sign_manifest(&a, &list(vec![member("a", &a, vec![4; 65]), member("b", &b, vec![5; 65])])).unwrap();
        let mut m = ok[..ok.len() - sign::SIGNATURE_LEN].to_vec();
        let at = m.len() - 65;
        m[at..].fill(4); // b's seal (the last field) becomes a's
        m
    };
    let old = [msg.as_slice(), &sign::sign_prepared(&a, &msg, None).unwrap()[..]].concat();
    let read = sign::open_manifest(&old).unwrap();
    assert_eq!(read.manifest.members[0].seal, read.manifest.members[1].seal);
    assert!(sign::verify_manifest(&old, "demo|x", &[a.public_key()], None).is_ok());
}

/// F-06: `split_zeroizing` / `combine_zeroizing` – the same shares and format as `split` / `combine`.
#[test]
fn shamir_shares_in_zeroizing_buffers() {
    let k = Key::generate().unwrap();
    let parts = shamir::split_zeroizing(&k, 2, 3).unwrap();
    assert_eq!(parts.len(), 3);
    assert!(parts.iter().all(|p| p.len() == shamir::SHARE_LEN));
    assert_eq!(shamir::combine_zeroizing(&parts[1..]).unwrap(), k);
    // interchangeable with the plain functions
    let plain: Vec<Vec<u8>> = parts.iter().map(|p| p.to_vec()).collect();
    assert_eq!(shamir::combine(&plain[..2]).unwrap(), k);
    let wrapped: Vec<Zeroizing<Vec<u8>>> = shamir::split(&k, 3, 5).unwrap().into_iter().map(Zeroizing::new).collect();
    assert_eq!(shamir::combine_zeroizing(&wrapped[2..]).unwrap(), k);
    assert_eq!(shamir::combine_zeroizing(&wrapped[..2]).unwrap_err(), Error::NotEnoughShares(3));
    assert_eq!(shamir::combine_zeroizing(&[]).unwrap_err(), Error::NotEnoughShares(2));
    assert!(matches!(shamir::split_zeroizing(&k, 1, 3), Err(Error::BadSplit { .. })));
}
