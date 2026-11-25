//! Argon2id key from a password made by the TypeScript side (0.18.0, `ts/src/kdf.ts` `passwordKey`,
//! `testvectors/regino/password-key-0.18.0.json`): `kdf::derive` gives the same key byte for byte, and the
//! parameters TypeScript refuses are refused here too (before any work). The other direction (Rust keys of
//! `keys-0.11.1.json` reproduced in TypeScript) is `ts/src/kdf.test.ts`.

use regino_keys::{kdf, Error};
use serde_json::Value;

fn hex(v: &Value) -> Vec<u8> {
    let s = v.as_str().expect("hex string");
    (0..s.len()).step_by(2).map(|i| u8::from_str_radix(&s[i..i + 2], 16).expect("hex")).collect()
}

fn vectors() -> Value {
    serde_json::from_str(include_str!("../../testvectors/regino/password-key-0.18.0.json")).expect("JSON")
}

fn params(c: &Value) -> kdf::KdfParams {
    let n = |k: &str| u32::try_from(c[k].as_u64().expect(k)).expect(k);
    kdf::KdfParams { memory_kib: n("memory_kib"), iterations: n("iterations"), parallelism: n("parallelism") }
}

#[test]
fn typescript_password_keys_derive_in_rust() {
    let doc = vectors();
    assert_eq!(doc["version"], "0.18.0");
    let cases = doc["derive"].as_array().unwrap();
    assert_eq!(cases.len(), 7);
    for c in cases {
        let name = c["name"].as_str().unwrap();
        let password = hex(&c["password"]);
        // the bytes are the UTF-8 of the text as given (no normalisation)
        assert_eq!(password, c["password_text"].as_str().unwrap().as_bytes(), "{name}");
        let salt: [u8; 16] = hex(&c["salt"]).try_into().expect("16-byte salt");
        let p = params(c);
        assert!(p.is_valid(), "{name}");
        let key = kdf::derive(&password, &salt, p).unwrap();
        assert_eq!(key.as_bytes().as_slice(), hex(&c["key"]).as_slice(), "{name}");
    }
    // NFC and NFD of the same text are different passwords
    assert_ne!(cases[1]["key"], cases[2]["key"]);
    // the default of TypeScript (Testurion) is the Rust default
    assert_eq!(params(&cases[5]), kdf::KdfParams::default());
}

#[test]
fn parameters_refused_by_typescript_are_refused_in_rust() {
    let doc = vectors();
    let cases = doc["refused"].as_array().unwrap();
    assert_eq!(cases.len(), 7);
    for c in cases {
        let p = params(c);
        assert!(!p.is_valid(), "{}", c["name"]);
        assert_eq!(kdf::derive(b"password", &[0u8; 16], p).unwrap_err(), Error::KdfParams, "{}", c["name"]);
    }
}
