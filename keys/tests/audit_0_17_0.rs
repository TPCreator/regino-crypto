//! Audit validation 2026-11-25 (docs/validacia-auditu-2026-11-25.md): additions of 0.17.0 – no change of formats.
//! L-06: a member list longer than any canonical list is refused before decoding; L-01: structured contexts
//! (the same bytes as `structuredContext` in TypeScript, testvectors/regino/context-0.17.0.json).

use regino_keys::sign::{self, Manifest, Member, SigningKey, MAX_CONTEXT, MAX_KEY, MAX_MANIFEST_LEN, MAX_MEMBERS, MAX_NAME, MAX_VERSION};
use regino_keys::{context, wrap, Error, Key};
use serde_json::Value;

#[test]
fn largest_canonical_list_has_exactly_the_bound() {
    let admin = SigningKey::generate().unwrap();
    let members: Vec<Member> = (0..MAX_MEMBERS)
        .map(|i| {
            let mut id = format!("{i:04}");
            id.push_str(&"m".repeat(MAX_NAME - id.len()));
            let mut seal = vec![0u8; MAX_KEY];
            seal[..8].copy_from_slice(&(i as u64).to_be_bytes());
            let sign = if i == 0 { admin.public_key() } else { SigningKey::generate().unwrap().public_key() };
            Member { id, role: "r".repeat(MAX_NAME), admin: i == 0, sign, seal, seal_version: MAX_VERSION }
        })
        .collect();
    let m = Manifest { scope: "s".repeat(MAX_CONTEXT), version: 1, epoch: MAX_VERSION, prev: [0; 32], members };
    let blob = sign::sign_manifest(&admin, &m).unwrap();
    assert_eq!(blob.len(), MAX_MANIFEST_LEN);
    let a = sign::verify_manifest(&blob, &m.scope, &[admin.public_key()], None).unwrap();
    assert_eq!(a.manifest.members.len(), MAX_MEMBERS);
    // one byte more can never be canonical: refused before anything is decoded
    let mut longer = blob.clone();
    longer.push(0);
    assert!(matches!(sign::open_manifest(&longer), Err(Error::Format)));
    assert!(matches!(sign::open_manifest(&vec![0u8; MAX_MANIFEST_LEN + 1]), Err(Error::Format)));
}

#[test]
fn structured_contexts_match_the_shared_vectors() {
    let v: Value = serde_json::from_str(include_str!("../../testvectors/regino/context-0.17.0.json")).unwrap();
    for c in v["valid"].as_array().unwrap() {
        let parts: Vec<&str> = c["parts"].as_array().unwrap().iter().map(|p| p.as_str().unwrap()).collect();
        assert_eq!(context::structured(&parts).unwrap(), c["context"].as_str().unwrap());
    }
    for c in v["invalid"].as_array().unwrap() {
        let parts: Vec<String> = c["parts"].as_array().unwrap().iter().map(|p| p.as_str().unwrap().to_string()).collect();
        let parts: Vec<&str> = parts.iter().map(String::as_str).collect();
        assert!(context::structured(&parts).is_err(), "{parts:?}");
    }
    // a wrapped key under one structured context does not open under the other one that a joined context confused
    let key = Key::generate().unwrap();
    let a = context::structured(&["app", "client", "a/b", "c"]).unwrap();
    let b = context::structured(&["app", "client", "a", "b/c"]).unwrap();
    let w = wrap::wrap_key(&key, &key, a.as_bytes()).unwrap();
    assert!(wrap::unwrap_key(&key, &w, a.as_bytes()).is_ok());
    assert!(matches!(wrap::unwrap_key(&key, &w, b.as_bytes()), Err(Error::Decrypt)));
}
