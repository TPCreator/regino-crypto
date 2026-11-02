//! Wycheproof test vectors (testvectors/wycheproof): the implementations that `wrap` and
//! `recovery` rely on must accept valid inputs and reject invalid ones.

use chacha20poly1305::aead::{Aead, KeyInit, Payload};
use chacha20poly1305::XChaCha20Poly1305;
use hkdf::Hkdf;
use serde_json::Value;
use sha2::Sha256;

fn load(name: &str) -> Value {
    let path = format!("{}/../testvectors/wycheproof/{name}", env!("CARGO_MANIFEST_DIR"));
    serde_json::from_str(&std::fs::read_to_string(path).expect("test vector file")).expect("JSON")
}

fn hex(v: &Value) -> Vec<u8> {
    let s = v.as_str().expect("hex");
    (0..s.len()).step_by(2).map(|i| u8::from_str_radix(&s[i..i + 2], 16).expect("hex")).collect()
}

fn tests(doc: &Value) -> impl Iterator<Item = &Value> {
    doc["testGroups"].as_array().unwrap().iter().flat_map(|g| g["tests"].as_array().unwrap())
}

#[test]
fn xchacha20_poly1305() {
    let doc = load("xchacha20_poly1305_test.json");
    let mut n = 0;
    for t in tests(&doc) {
        let id = &t["tcId"];
        let key: [u8; 32] = hex(&t["key"]).try_into().unwrap();
        let cipher = XChaCha20Poly1305::new(&key.into());
        let nonce: [u8; 24] = hex(&t["iv"]).try_into().unwrap();
        let aad = hex(&t["aad"]);
        let msg = hex(&t["msg"]);
        let mut sealed = hex(&t["ct"]);
        sealed.extend(hex(&t["tag"]));
        let opened = cipher.decrypt(&nonce.into(), Payload { msg: &sealed, aad: &aad });
        match t["result"].as_str() {
            Some("valid") => {
                assert_eq!(opened.as_deref(), Ok(msg.as_slice()), "tcId {id}");
                let enc = cipher.encrypt(&nonce.into(), Payload { msg: &msg, aad: &aad });
                assert_eq!(enc.as_deref(), Ok(sealed.as_slice()), "tcId {id}");
            }
            _ => assert!(opened.is_err(), "invalid input accepted: tcId {id}"),
        }
        n += 1;
    }
    assert_eq!(n, 306);
}

#[test]
fn hkdf_sha256() {
    let doc = load("hkdf_sha256_test.json");
    let mut n = 0;
    for t in tests(&doc) {
        let id = &t["tcId"];
        let salt = hex(&t["salt"]);
        let size = t["size"].as_u64().unwrap() as usize;
        let hk = Hkdf::<Sha256>::new(if salt.is_empty() { None } else { Some(&salt) }, &hex(&t["ikm"]));
        let mut okm = vec![0u8; size];
        let r = hk.expand(&hex(&t["info"]), &mut okm);
        match t["result"].as_str() {
            Some("valid") => {
                assert!(r.is_ok(), "tcId {id}");
                assert_eq!(okm, hex(&t["okm"]), "tcId {id}");
            }
            // Invalid = output too long (> 255 * 32 bytes) – must fail.
            _ => assert!(r.is_err(), "invalid input accepted: tcId {id}"),
        }
        n += 1;
    }
    assert_eq!(n, 86);
}

/// Ed25519 (`sign`): strict verification must give the Wycheproof verdict for every vector, and the
/// public keys of all groups must pass `PublicKey::from_bytes` (they are torsion-free).
#[test]
fn ed25519() {
    use ed25519_dalek::{Signature, VerifyingKey};
    let doc = load("ed25519_test.json");
    let mut n = 0;
    for g in doc["testGroups"].as_array().unwrap() {
        let pk: [u8; 32] = hex(&g["publicKey"]["pk"]).try_into().unwrap();
        regino_keys::sign::PublicKey::from_bytes(&pk).expect("Wycheproof key is a valid signing key");
        let key = VerifyingKey::from_bytes(&pk).unwrap();
        for t in g["tests"].as_array().unwrap() {
            let sig = hex(&t["sig"]);
            let ok = <[u8; 64]>::try_from(sig.as_slice()).is_ok_and(|s| key.verify_strict(&hex(&t["msg"]), &Signature::from_bytes(&s)).is_ok());
            assert_eq!(ok, t["result"] == "valid", "tcId {}", t["tcId"]);
            n += 1;
        }
    }
    assert!(n > 100);
}
