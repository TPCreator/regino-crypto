//! Key file wraps made by the TypeScript side (0.22.0, `ts/src/keyfile.ts`,
//! `testvectors/regino/keyfile-0.22.0.json`): Rust gives the same bytes with the same nonce and opens them,
//! and the password and recovery keys behind them are the same.

use regino_keys::{kdf, keyfile, recovery, Key};
use serde_json::Value;

fn hex(v: &Value) -> Vec<u8> {
    let s = v.as_str().expect("hex string");
    (0..s.len()).step_by(2).map(|i| u8::from_str_radix(&s[i..i + 2], 16).expect("hex")).collect()
}

fn key(v: &Value) -> Key {
    Key::from_bytes(hex(v).try_into().expect("32 bytes"))
}

fn vectors() -> Value {
    serde_json::from_str(include_str!("../../testvectors/regino/keyfile-0.22.0.json")).expect("JSON")
}

#[test]
fn typescript_wraps_match() {
    let doc = vectors();
    assert_eq!(doc["version"], "0.22.0");
    for w in doc["wraps"].as_array().unwrap() {
        let (app, method) = (w["app"].as_str().unwrap(), w["method"].as_str().unwrap());
        let nonce: [u8; 12] = hex(&w["nonce"]).try_into().unwrap();
        let made = keyfile::wrap_master_with_nonce(&key(&w["kek"]), &key(&w["master"]), app, method, nonce).unwrap();
        assert_eq!(made, hex(&w["wrap"]), "{app} {method}");
        assert_eq!(keyfile::unwrap_master(&key(&w["kek"]), &made, app, method).unwrap(), key(&w["master"]));
    }
}

#[test]
fn password_and_recovery_keys_match() {
    let doc = vectors();
    let p = &doc["password"];
    let salt: [u8; 16] = hex(&p["salt"]).try_into().unwrap();
    let n = |k: &str| u32::try_from(p["kdf"][k].as_u64().unwrap()).unwrap();
    let params = kdf::KdfParams { memory_kib: n("m"), iterations: n("t"), parallelism: n("p") };
    let kek = kdf::derive(p["password"].as_str().unwrap().as_bytes(), &salt, params).unwrap();
    assert_eq!(kek, key(&p["kek"]));
    assert_eq!(keyfile::unwrap_master(&kek, &hex(&p["wrap"]), "testapp", "password").unwrap(), key(&p["master"]));
    for r in doc["recovery"].as_array().unwrap() {
        let kek = recovery::recovery_key(&hex(&r["secret"]), r["app"].as_str().unwrap()).unwrap();
        assert_eq!(kek, key(&r["kek"]));
        assert_eq!(keyfile::unwrap_master(&kek, &hex(&r["wrap"]), "testapp", "recovery").unwrap(), key(&r["master"]));
    }
}
