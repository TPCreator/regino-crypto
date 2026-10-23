//! Data made by regino-keys 0.11.1 (`testvectors/regino/keys-0.11.1.json`, generated with the previous
//! generation of RustCrypto crates and blahaj 0.6) must open or match bit for bit with the current build:
//! wrapped keys, sealed data, chunks, fingerprints, Argon2id/HKDF keys and Shamir shares.
//! The expected values in the file are never changed.

use regino_keys::{chunks, device, kdf, recovery, shamir, wrap, Error, Key};
use serde_json::Value;

fn vectors() -> Value {
    serde_json::from_str(include_str!("../../testvectors/regino/keys-0.11.1.json")).expect("JSON")
}

fn hex(v: &Value) -> Vec<u8> {
    let s = v.as_str().expect("hex string");
    (0..s.len()).step_by(2).map(|i| u8::from_str_radix(&s[i..i + 2], 16).expect("hex")).collect()
}

fn key(v: &Value) -> Key {
    Key::from_bytes(hex(v).try_into().expect("32 bytes"))
}

fn text(v: &Value) -> &str {
    v.as_str().expect("string")
}

fn list<'a>(doc: &'a Value, name: &str) -> &'a [Value] {
    doc[name].as_array().expect(name).as_slice()
}

#[test]
fn vectors_are_from_0_11_1() {
    assert_eq!(vectors()["version"], "0.11.1");
}

#[test]
fn argon2id_keys_are_identical() {
    let doc = vectors();
    for t in list(&doc, "kdf") {
        let params = kdf::KdfParams {
            memory_kib: t["memory_kib"].as_u64().unwrap() as u32,
            iterations: t["iterations"].as_u64().unwrap() as u32,
            parallelism: t["parallelism"].as_u64().unwrap() as u32,
        };
        let salt: [u8; 16] = hex(&t["salt"]).try_into().unwrap();
        assert_eq!(kdf::derive(&hex(&t["password"]), &salt, params).unwrap(), key(&t["key"]), "{params:?}");
    }
}

#[test]
fn wrapped_keys_unwrap() {
    let doc = vectors();
    for t in list(&doc, "wrap") {
        let blob = hex(&t["blob"]);
        assert_eq!(wrap::unwrap_key(&key(&t["kek"]), &blob, text(&t["context"]).as_bytes()).unwrap(), key(&t["inner"]));
        assert_eq!(wrap::unwrap_key(&key(&t["kek"]), &blob, b"other").unwrap_err(), Error::Decrypt);
    }
}

#[test]
fn sealed_data_opens() {
    let doc = vectors();
    for t in list(&doc, "seal") {
        let blob = hex(&t["blob"]);
        assert_eq!(wrap::open(&key(&t["key"]), &blob, text(&t["context"]).as_bytes()).unwrap().as_slice(), hex(&t["plain"]).as_slice());
        assert_eq!(wrap::open(&key(&t["key"]), &blob, b"x").unwrap_err(), Error::Decrypt);
    }
}

#[test]
fn chunks_open_only_in_place() {
    let doc = vectors();
    for t in list(&doc, "chunks") {
        let k = key(&t["key"]);
        let ctx = text(&t["context"]).as_bytes();
        let (index, last) = (t["index"].as_u64().unwrap(), t["last"].as_bool().unwrap());
        let blob = hex(&t["blob"]);
        assert_eq!(chunks::open_chunk(&k, ctx, index, last, &blob).unwrap().as_slice(), hex(&t["plain"]).as_slice());
        assert_eq!(chunks::open_chunk(&k, ctx, index + 1, last, &blob).unwrap_err(), Error::Decrypt);
        assert_eq!(chunks::open_chunk(&k, ctx, index, !last, &blob).unwrap_err(), Error::Decrypt);
    }
}

#[test]
fn fingerprints_are_identical() {
    let doc = vectors();
    for t in list(&doc, "fingerprint") {
        let mut f = chunks::Fingerprint::new(&key(&t["key"]), text(&t["context"]).as_bytes()).unwrap();
        f.update(&hex(&t["plain"]));
        assert_eq!(f.finish().to_vec(), hex(&t["fingerprint"]));
    }
}

#[test]
fn recovery_and_device_keys_are_identical() {
    let doc = vectors();
    for t in list(&doc, "recovery") {
        assert_eq!(recovery::recovery_key(&hex(&t["secret"]), text(&t["app"])).unwrap(), key(&t["key"]));
    }
    for t in list(&doc, "device") {
        assert_eq!(device::device_key(&hex(&t["secret"]), text(&t["app"]), text(&t["method"])).unwrap(), key(&t["key"]));
    }
}

/// Shares split by blahaj 0.6: every subset of `threshold` shares recovers the key with blahaj 0.7
/// (same GF(256) tables and share layout; only the random source changed), fewer shares never do.
#[test]
fn shamir_shares_from_0_11_1_combine() {
    let doc = vectors();
    for t in list(&doc, "shamir") {
        let expected = key(&t["key"]);
        let threshold = t["threshold"].as_u64().unwrap() as usize;
        let shares: Vec<Vec<u8>> = t["shares"].as_array().unwrap().iter().map(hex).collect();
        let n = shares.len();
        let mut checked = 0;
        for mask in 1u32..(1 << n) {
            let subset: Vec<Vec<u8>> = (0..n).filter(|&i| mask & (1 << i) != 0).map(|i| shares[i].clone()).collect();
            if subset.len() >= threshold {
                assert_eq!(shamir::combine(&subset).unwrap(), expected, "{threshold}-of-{n}, mask {mask:b}");
                checked += 1;
            } else {
                assert_eq!(shamir::combine(&subset).unwrap_err(), Error::NotEnoughShares(threshold as u8), "mask {mask:b}");
            }
        }
        assert!(checked >= 4, "{threshold}-of-{n}: {checked} subsets");
    }
}
