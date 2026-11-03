//! Additions of 0.13.1 (`testvectors/regino/group-key-0.13.1.json`, `signing-0.13.1.json`, made by the
//! TypeScript side): group key code and id, a chain verified from an anchor (with pins), a wrapped key for
//! a named recipient, and the context prefix of `sign_prepared` for every kind.

use regino_keys::sign::{self, Pinned, PublicKey, SigningKey, WrapStatement};
use regino_keys::{group, Error, Key};
use serde_json::Value;

fn load(s: &str) -> Value {
    serde_json::from_str(s).expect("JSON")
}

fn hex(v: &Value) -> Vec<u8> {
    let s = v.as_str().expect("hex string");
    (0..s.len()).step_by(2).map(|i| u8::from_str_radix(&s[i..i + 2], 16).expect("hex")).collect()
}

fn text(v: &Value) -> &str {
    v.as_str().unwrap()
}

fn key(n: u8) -> SigningKey {
    SigningKey::from_seed(&Key::from_bytes([n; 32]))
}

fn vectors() -> Value {
    load(include_str!("../../testvectors/regino/signing-0.13.1.json"))
}

fn want(e: &str) -> Error {
    match e {
        "untrusted" => Error::UntrustedSigner,
        "chain" => Error::BadChain,
        "withheld" => Error::Withheld,
        e => panic!("{e}"),
    }
}

#[test]
fn group_key_code_and_id_match_typescript() {
    let doc = load(include_str!("../../testvectors/regino/group-key-0.13.1.json"));
    assert_eq!(doc["version"], "0.13.1");
    for t in doc["code"].as_array().unwrap() {
        let k: [u8; 32] = hex(&t["key"]).try_into().unwrap();
        assert_eq!(group::group_key_code(&k, text(&t["context"])).unwrap(), text(&t["code"]));
    }
    for t in doc["id"].as_array().unwrap() {
        let k: [u8; 32] = hex(&t["key"]).try_into().unwrap();
        assert_eq!(group::group_key_id(&k, text(&t["label"])).unwrap(), text(&t["id"]));
    }
    let k = [0x11u8; 32];
    assert_eq!(group::group_key_code(&k, ""), Err(Error::EmptyContext));
    assert_eq!(group::group_key_id(&k, ""), Err(Error::EmptyContext));
    // code and id are independent of each other
    assert_ne!(group::group_key_code(&k, "x").unwrap().replace(' ', ""), group::group_key_id(&k, "x").unwrap()[..20]);
}

#[test]
fn chain_from_anchor_gives_the_same_verdicts_as_typescript() {
    let doc = vectors();
    let anchor = PublicKey::from_bytes(&hex(&doc["anchor"])).unwrap();
    let scope = text(&doc["scope"]);
    for t in doc["from_anchor"].as_array().unwrap() {
        let blobs: Vec<Vec<u8>> = t["blobs"].as_array().unwrap().iter().map(hex).collect();
        let refs: Vec<&[u8]> = blobs.iter().map(|b| b.as_slice()).collect();
        let pinned = t.get("pinned").map(|p| Pinned {
            version: p["version"].as_u64().unwrap(),
            hashes: p["hashes"].as_array().unwrap().iter().map(|h| hex(h).try_into().unwrap()).collect(),
        });
        let got = sign::verify_manifest_chain_from_anchor(&refs, scope, &[anchor], pinned.as_ref());
        match text(&t["expect"]) {
            "ok" => {
                let list = got.unwrap_or_else(|e| panic!("{}: {e:?}", t["case"]));
                assert_eq!(list.len() as u64, t["accepted"].as_u64().unwrap(), "{}", t["case"]);
                for (a, c) in list.iter().zip(doc["chain"].as_array().unwrap()) {
                    if blobs.len() > 1 {
                        assert_eq!(a.hash.to_vec(), hex(&c["hash"]));
                    }
                }
            }
            e => assert_eq!(got.map(|l| l.len()), Err(want(e)), "{}", t["case"]),
        }
    }
    // without anchors nothing is accepted (fail-closed); a pin with no hashes or more hashes than versions is refused
    let blobs: Vec<Vec<u8>> = doc["chain"].as_array().unwrap().iter().map(|c| hex(&c["blob"])).collect();
    let refs: Vec<&[u8]> = blobs.iter().map(|b| b.as_slice()).collect();
    assert_eq!(sign::verify_manifest_chain_from_anchor(&refs, scope, &[], None).map(|l| l.len()), Err(Error::UntrustedSigner));
    for p in [Pinned { version: 2, hashes: vec![] }, Pinned { version: 1, hashes: vec![[0; 32], [0; 32]] }] {
        assert_eq!(sign::verify_manifest_chain_from_anchor(&refs, scope, &[anchor], Some(&p)).map(|l| l.len()), Err(Error::Format));
    }
    assert_eq!(sign::verify_manifest_chain_from_anchor(&refs, "other", &[anchor], None).map(|l| l.len()), Err(Error::BadChain));
}

#[test]
fn wrapped_key_for_a_named_recipient() {
    let doc = vectors();
    let blobs: Vec<Vec<u8>> = doc["chain"].as_array().unwrap().iter().map(|c| hex(&c["blob"])).collect();
    let refs: Vec<&[u8]> = blobs.iter().map(|b| b.as_slice()).collect();
    let anchor = PublicKey::from_bytes(&hex(&doc["anchor"])).unwrap();
    let list = sign::verify_manifest_chain_from_anchor(&refs, text(&doc["scope"]), &[anchor], None).unwrap().pop().unwrap();
    let signer = key(2);
    for t in doc["recipient"].as_array().unwrap() {
        let (recipient, wrapped, sig) = (hex(&t["recipient"]), hex(&t["wrapped"]), hex(&t["signature"]));
        let st = WrapStatement {
            context: text(&t["context"]),
            object_id: text(&t["object_id"]),
            version: t["version"].as_u64().unwrap(),
            manifest: hex(&t["manifest"]).try_into().unwrap(),
            recipient: &recipient,
            wrapped: &wrapped,
        };
        assert_eq!(sign::sign_wrap(&signer, &st).unwrap().to_vec(), sig);
        // the plain check (0.13.0) accepts all of them; the recipient check decides
        sign::verify_wrap_for(&list, &[], &signer.public_key(), &st, &sig).unwrap();
        let got = sign::verify_wrap_for_recipient(&list, &[], &signer.public_key(), &st, &sig, text(&t["recipient_id"]));
        let expect = if text(&t["expect"]) == "ok" { Ok(()) } else { Err(Error::BadChain) };
        assert_eq!(got, expect, "{}", t["case"]);
        if expect.is_ok() {
            assert_eq!(sign::verify_wrap_for_recipient(&list, &[], &key(9).public_key(), &st, &sig, text(&t["recipient_id"])), Err(Error::UntrustedSigner));
        }
    }
}

#[test]
fn prefix_applies_to_every_kind() {
    let doc = vectors();
    let k = key(2);
    assert_eq!(doc["prepared"]["seed"], "02".repeat(32));
    let prefix = text(&doc["prepared"]["prefix"]);
    for t in doc["prepared"]["messages"].as_array().unwrap() {
        let msg = hex(&t["message"]);
        let sig = hex(&t["signature"]);
        assert_eq!(sign::sign_prepared(&k, &msg, None).unwrap().to_vec(), sig, "{}", t["case"]);
        let got = sign::sign_prepared(&k, &msg, Some(prefix)).map(|s| s.to_vec());
        if t["allowed"].as_bool().unwrap() {
            assert_eq!(got, Ok(sig), "{}", t["case"]);
        } else {
            assert_eq!(got, Err(Error::Format), "{}", t["case"]);
        }
    }
}
