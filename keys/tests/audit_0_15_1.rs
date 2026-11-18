//! Fixes after the audit of 0.15.0 (2026-11-15): each test failed before its fix (`AUDIT.md` § 4.5).

use ed25519_dalek::Signer as _;
use regino_keys::sign::{self, Manifest, Member, SigningKey};
use regino_keys::{Error, Key};

fn key(n: u8) -> SigningKey {
    SigningKey::from_seed(&Key::from_bytes([n; 32]))
}

fn member(id: &str, admin: bool, k: &SigningKey) -> Member {
    Member { id: id.into(), role: "member".into(), admin, sign: k.public_key(), seal: [&[4u8][..], k.public_key().as_bytes()].concat(), seal_version: 1 }
}

fn replace(blob: &[u8], from: &[u8], to: &[u8]) -> Vec<u8> {
    let at = blob.windows(from.len()).position(|w| w == from).expect("found");
    let mut out = blob.to_vec();
    out[at..at + from.len()].copy_from_slice(to);
    out
}

/// N2: the signature of a member list is checked before the public keys of its members (up to 1000 point
/// decodings for a forged blob); a list with a valid signature and a bad member key is still refused.
#[test]
fn n2_signature_before_member_keys() {
    let (a, b) = (key(1), key(2));
    let m = Manifest { scope: "demo|x".into(), version: 1, epoch: 0, prev: [0; 32], members: vec![member("a", true, &a), member("b", false, &b)] };
    let blob = sign::sign_manifest(&a, &m).unwrap();
    let mut identity = [0u8; 32];
    identity[0] = 1; // small order
    let forged = replace(&blob, b.public_key().as_bytes(), &identity);
    assert_eq!(sign::open_manifest(&forged), Err(Error::BadSignature));
    assert_eq!(sign::verify_manifest(&forged, "demo|x", &[a.public_key()], None), Err(Error::BadSignature));
    // the same bytes with a valid signature of the named signer: the member key is refused after the signature
    let msg = &forged[..forged.len() - sign::SIGNATURE_LEN];
    let sig = ed25519_dalek::SigningKey::from_bytes(&[1; 32]).sign(msg).to_bytes();
    let signed = [msg, &sig[..]].concat();
    assert_eq!(sign::open_manifest(&signed), Err(Error::Format));
    assert_eq!(sign::sign_prepared(&a, msg, None), Err(Error::Format));
    assert!(sign::open_manifest(&blob).is_ok());
}

/// N5: a `Key` keeps its bytes in one place (moving it moves a pointer, no unwiped copies), and the
/// AEAD and Argon2id crates wipe their own key state and memory blocks (feature `zeroize`).
#[test]
fn n5_key_in_one_place_and_zeroize_features() {
    assert_eq!(std::mem::size_of::<Key>(), std::mem::size_of::<usize>());
    let k = Key::from_bytes([7; 32]);
    assert_eq!(k.as_bytes(), &[7; 32]);
    assert!(Key::generate().unwrap() != k);
    let manifest = include_str!("../Cargo.toml");
    for dep in ["argon2", "chacha20poly1305", "aes-gcm"] {
        let line = manifest.lines().find(|l| l.starts_with(&format!("{dep} ="))).expect(dep);
        assert!(line.contains("\"zeroize\""), "{line}");
    }
}

/// N7: the lower bound for reading on a phone (the same numbers as `MOBILE_BACKUP_CODE_KDF` in TypeScript).
#[test]
fn n7_mobile_bound() {
    use regino_keys::backup_code::{valid_params, valid_params_mobile, DEFAULT_PARAMS, MOBILE_MAX_PARAMS, MOBILE_MAX_WORK_KIB};
    use regino_keys::kdf::KdfParams;
    assert_eq!((MOBILE_MAX_PARAMS.memory_kib, MOBILE_MAX_PARAMS.iterations, MOBILE_MAX_PARAMS.parallelism, MOBILE_MAX_WORK_KIB), (65536, 8, 4, 131072));
    assert!(valid_params_mobile(DEFAULT_PARAMS) && valid_params_mobile(KdfParams::MIN));
    for p in [
        KdfParams { memory_kib: 131072, iterations: 2, parallelism: 1 },
        KdfParams { memory_kib: 65536, iterations: 4, parallelism: 1 },
        KdfParams { memory_kib: 32768, iterations: 8, parallelism: 1 },
    ] {
        assert!(valid_params(p) && !valid_params_mobile(p), "{p:?}");
    }
    assert!(!valid_params_mobile(KdfParams { memory_kib: 1 << 30, iterations: 1, parallelism: 1 }));
}
