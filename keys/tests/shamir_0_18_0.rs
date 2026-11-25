//! Shamir shares made by the TypeScript side (0.18.0, `testvectors/regino/shamir-0.18.0.json`, `ts/src/shamir.ts`).
//! Every subset of at least `threshold` shares gives the key here, every smaller subset is refused, and the
//! refused cases end with the error the vector names. The other direction (shares made by Rust combined in
//! TypeScript) is `keys-0.11.1.json` in `ts/src/shamir.test.ts`.

use regino_keys::{shamir, Error};
use serde_json::Value;

fn hex(v: &Value) -> Vec<u8> {
    let s = v.as_str().expect("hex string");
    (0..s.len()).step_by(2).map(|i| u8::from_str_radix(&s[i..i + 2], 16).expect("hex")).collect()
}

fn vectors() -> Value {
    serde_json::from_str(include_str!("../../testvectors/regino/shamir-0.18.0.json")).expect("JSON")
}

fn shares(v: &Value) -> Vec<Vec<u8>> {
    v.as_array().expect("shares").iter().map(hex).collect()
}

#[test]
fn shares_made_by_typescript_combine_in_rust() {
    let doc = vectors();
    assert_eq!(doc["version"], "0.18.0");
    let cases = doc["split"].as_array().unwrap();
    assert_eq!(cases.len(), 5);
    for c in cases {
        let name = c["name"].as_str().unwrap();
        let key = hex(&c["key"]);
        let threshold = c["threshold"].as_u64().unwrap() as usize;
        let all = shares(&c["shares"]);
        assert!(all.iter().all(|s| s.len() == shamir::SHARE_LEN), "{name}");
        let n = all.len();
        let mut checked = 0;
        for mask in 1u32..(1 << n) {
            let subset: Vec<Vec<u8>> = (0..n).filter(|&i| mask & (1 << i) != 0).map(|i| all[i].clone()).collect();
            let r = shamir::combine(&subset);
            if subset.len() >= threshold {
                assert_eq!(r.unwrap().as_bytes().as_slice(), key.as_slice(), "{name}, mask {mask:b}");
                checked += 1;
            } else {
                assert_eq!(r.unwrap_err(), Error::NotEnoughShares(threshold as u8), "{name}, mask {mask:b}");
            }
        }
        assert!(checked >= 1, "{name}");
    }
}

#[test]
fn refused_typescript_cases_are_refused_in_rust() {
    let doc = vectors();
    let cases = doc["refused"].as_array().unwrap();
    assert_eq!(cases.len(), 14);
    for c in cases {
        let name = c["name"].as_str().unwrap();
        let expected = match c["rust"].as_str().unwrap() {
            "Format" => Error::Format,
            "BadShares" => Error::BadShares,
            "NotEnoughShares(2)" => Error::NotEnoughShares(2),
            "NotEnoughShares(3)" => Error::NotEnoughShares(3),
            other => panic!("unknown error {other}"),
        };
        assert_eq!(shamir::combine(&shares(&c["shares"])).unwrap_err(), expected, "{name}");
    }
}

#[test]
fn rust_shares_mixed_with_typescript_shares_of_another_split_are_refused() {
    // a fresh Rust split of the same key has the same fingerprint, but other random coefficients:
    // mixing its share with a TypeScript share of the same key gives a wrong polynomial → BadShares
    let doc = vectors();
    let c = &doc["split"][0];
    let key = regino_keys::Key::from_bytes(hex(&c["key"]).try_into().unwrap());
    let rust = shamir::split(&key, 2, 3).unwrap();
    let ts = shares(&c["shares"]);
    assert_eq!(rust[0][..13], ts[0][..13], "same header (magic, threshold, fingerprint)");
    assert_eq!(shamir::combine(&[rust[0].clone(), rust[1].clone()]).unwrap(), key);
    assert_eq!(shamir::combine(&[ts[0].clone(), rust[1].clone()]).unwrap_err(), Error::BadShares);
}
