//! Device keys made by TypeScript `deviceKeyFromSecret` / `deviceKeyFromPasskey` (0.20.0,
//! `testvectors/regino/device-vault-0.20.0.json`): Rust `device::device_key` gives the same 32 bytes, so a
//! Windows Hello signature, an OS keystore secret or a passkey PRF output gives one key on both sides.

use regino_keys::device;
use serde_json::Value;

fn unhex(h: &str) -> Vec<u8> {
    (0..h.len()).step_by(2).map(|i| u8::from_str_radix(&h[i..i + 2], 16).unwrap()).collect()
}

#[test]
fn device_keys_are_the_same_as_in_typescript() {
    let d: Value = serde_json::from_str(include_str!("../../testvectors/regino/device-vault-0.20.0.json")).unwrap();
    assert_eq!(d["version"], "0.20.0");
    let keys = d["keys"].as_array().unwrap();
    assert_eq!(keys.len(), 3);
    for k in keys {
        let s = |f: &str| k[f].as_str().unwrap();
        let key = device::device_key(&unhex(s("secret")), s("app"), s("method")).unwrap();
        assert_eq!(key.as_bytes().to_vec(), unhex(s("key")), "{}", s("name"));
    }
    // a secret shorter than 32 bytes is refused on both sides
    assert!(device::device_key(&[0u8; 31], "demo", "passkey-prf").is_err());
}
