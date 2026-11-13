//! Recovery code in English (0.14.0, `testvectors/regino/recovery-en-0.14.0.json`, made by the TypeScript
//! side). Words <-> secret is done only in TypeScript; Rust receives the secret. The vectors show that the
//! same secret – written in Slovak or English words, or as the QR text – gives the same recovery key here.

use regino_keys::recovery::recovery_key;
use serde_json::Value;

fn hex(v: &Value) -> Vec<u8> {
    let s = v.as_str().expect("hex string");
    (0..s.len()).step_by(2).map(|i| u8::from_str_radix(&s[i..i + 2], 16).expect("hex")).collect()
}

fn to_hex(b: &[u8]) -> String {
    b.iter().map(|x| format!("{x:02x}")).collect()
}

#[test]
fn english_codes_give_the_same_recovery_key_as_typescript() {
    let doc: Value =
        serde_json::from_str(include_str!("../../testvectors/regino/recovery-en-0.14.0.json")).unwrap();
    assert_eq!(doc["version"], "0.14.0");
    let app = doc["app"].as_str().unwrap();
    let codes = doc["codes"].as_array().unwrap();
    assert_eq!(codes.len(), 4);
    for c in codes {
        let secret = hex(&c["secret"]);
        let words = c["en"].as_str().unwrap().split(' ').count();
        assert_eq!(words, if secret.len() == 16 { 12 } else { 24 });
        assert_eq!(c["sk"].as_str().unwrap().split(' ').count(), words);
        let key = recovery_key(&secret, app).unwrap();
        assert_eq!(to_hex(key.as_bytes()), c["recovery_key"].as_str().unwrap(), "{}", c["en"]);
    }
}

#[test]
fn ambiguous_code_has_two_different_secrets_and_keys() {
    let doc: Value =
        serde_json::from_str(include_str!("../../testvectors/regino/recovery-en-0.14.0.json")).unwrap();
    let a = &doc["ambiguous"];
    let (sk, en) = (hex(&a["sk"]), hex(&a["en"]));
    assert_eq!((sk.len(), en.len()), (16, 16));
    assert!(recovery_key(&sk, "demo").unwrap() != recovery_key(&en, "demo").unwrap());
}
