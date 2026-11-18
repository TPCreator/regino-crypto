//! Audit S1/S2 (0.15.1): the shared vectors `testvectors/regino/signing-0.15.1.json` were made by the
//! TypeScript side; Rust must give the same blobs, confirmation and wrap signatures and the same verdicts
//! for `require_anchor_on_latest` (a chain continued by a removed admin) and `require_current_epoch`.

use regino_keys::sign::{self, AcceptedManifest, ChainOptions, ManifestConfirmation, PublicKey, SigningKey, WrapOptions, WrapStatement};
use regino_keys::{Error, Key};
use serde_json::Value;

fn v() -> Value {
    serde_json::from_str(include_str!("../../testvectors/regino/signing-0.15.1.json")).expect("JSON")
}

fn hex(v: &Value) -> Vec<u8> {
    let s = v.as_str().expect("hex string");
    (0..s.len()).step_by(2).map(|i| u8::from_str_radix(&s[i..i + 2], 16).expect("hex")).collect()
}

fn key(v: &Value, name: &str) -> SigningKey {
    SigningKey::from_seed(&Key::from_bytes([v["seeds"][name].as_u64().unwrap() as u8; 32]))
}

fn public(v: &Value, name: &str) -> PublicKey {
    PublicKey::from_bytes(&hex(&v["public"][name])).unwrap()
}

fn list(v: &Value, name: &str) -> AcceptedManifest {
    sign::open_manifest(&hex(&v["blobs"][name])).unwrap()
}

#[test]
fn keys_blobs_and_confirmations() {
    let v = v();
    assert_eq!(v["version"], "0.15.1");
    for name in ["anchor", "alice", "bob", "mallory", "mgmt"] {
        assert_eq!(key(&v, name).public_key(), public(&v, name), "{name}");
    }
    for name in ["v1", "v2", "f2"] {
        let a = list(&v, name);
        assert_eq!(a.hash.to_vec(), hex(&v["hashes"][name]), "{name}");
        // Ed25519 is deterministic: Rust signs the same message to the same blob
        let signer = ["anchor", "alice", "bob"].into_iter().find(|n| key(&v, n).public_key() == a.signer).unwrap();
        let blob = hex(&v["blobs"][name]);
        let msg = &blob[..blob.len() - sign::SIGNATURE_LEN];
        assert_eq!(sign::sign_prepared(&key(&v, signer), msg, None).unwrap().to_vec(), blob[msg.len()..].to_vec(), "{name}");
        // v1 and f2 of the fixture give alice and bob one seal: read as before, but since 0.16.0 such a list is
        // not made again (F-07); v2 has one member and is signed to the same blob
        let shared = a.manifest.members.len() > 1 && a.manifest.members.iter().all(|m| m.seal == a.manifest.members[0].seal);
        assert_eq!(shared, name != "v2", "{name}");
        let made = sign::sign_manifest(&key(&v, signer), &a.manifest);
        if shared {
            assert_eq!(made, Err(Error::Format), "{name}");
        } else {
            assert_eq!(made.unwrap(), blob, "{name}");
        }
    }
    for c in v["confirmations"].as_array().unwrap() {
        let (k, l) = (key(&v, c["signer"].as_str().unwrap()), list(&v, c["list"].as_str().unwrap()));
        let sig = hex(&c["signature"]);
        assert_eq!(sign::confirm_manifest(&k, &l).unwrap().to_vec(), sig);
        assert_eq!(sign::sign_prepared(&k, &hex(&c["message"]), Some("dovernik|")).unwrap().to_vec(), sig);
        assert_eq!(sign::verify_manifest_confirmation(&k.public_key(), &l, &sig), Ok(()));
        assert_eq!(sign::verify_manifest_confirmation(&public(&v, "mallory"), &l, &sig), Err(Error::BadSignature));
        // the prefix rule of sign_prepared applies to the scope; another signer is refused
        assert_eq!(sign::sign_prepared(&k, &hex(&c["message"]), Some("gazda|")), Err(Error::Format));
        assert_eq!(sign::sign_prepared(&key(&v, "mallory"), &hex(&c["message"]), None), Err(Error::Format));
    }
}

#[test]
fn require_anchor_on_latest() {
    let v = v();
    let confirmations: Vec<ManifestConfirmation> = v["confirmations"]
        .as_array()
        .unwrap()
        .iter()
        .map(|c| ManifestConfirmation { signer: public(&v, c["signer"].as_str().unwrap()), signature: hex(&c["signature"]).try_into().unwrap() })
        .collect();
    for t in v["chains"].as_array().unwrap() {
        let blobs: Vec<Vec<u8>> = t["blobs"].as_array().unwrap().iter().map(|b| hex(&v["blobs"][b.as_str().unwrap()])).collect();
        let refs: Vec<&[u8]> = blobs.iter().map(|b| b.as_slice()).collect();
        let o = &t["opts"];
        let opts = ChainOptions {
            require_anchor_on_latest: o["require_anchor_on_latest"].as_bool().unwrap_or(false),
            signers: o["signers"].as_array().map(|a| a.iter().map(|s| public(&v, s.as_str().unwrap())).collect()).unwrap_or_default(),
            anchors_may_sign: o["anchors_may_sign"].as_bool().unwrap_or(true),
            confirmations: o["confirmations"].as_array().map(|a| a.iter().map(|i| confirmations[i.as_u64().unwrap() as usize].clone()).collect()).unwrap_or_default(),
            ..ChainOptions::default()
        };
        let r = sign::verify_manifest_chain_from_anchor_with(&refs, v["scope"].as_str().unwrap(), &[public(&v, "anchor")], &opts);
        match t["expect"].as_str().unwrap() {
            "ok" => {
                let hashes: Vec<Vec<u8>> = t["hashes"].as_array().unwrap().iter().map(hex).collect();
                assert_eq!(r.unwrap().iter().map(|a| a.hash.to_vec()).collect::<Vec<_>>(), hashes, "{}", t["case"]);
            }
            "untrusted" => assert_eq!(r.unwrap_err(), Error::UntrustedSigner, "{}", t["case"]),
            other => panic!("{other}"),
        }
    }
    // a malformed confirmation is never accepted (the signature does not verify)
    let v1 = list(&v, "v1");
    let v2 = list(&v, "v2");
    let blobs = [v1.blob.as_slice(), v2.blob.as_slice()];
    let bad = ManifestConfirmation { signer: public(&v, "anchor"), signature: [0; 64] };
    let opts = ChainOptions { require_anchor_on_latest: true, confirmations: vec![bad.clone(), bad], ..ChainOptions::default() };
    assert_eq!(sign::verify_manifest_chain_from_anchor_with(&blobs, v["scope"].as_str().unwrap(), &[public(&v, "anchor")], &opts).unwrap_err(), Error::UntrustedSigner);
}

#[test]
fn require_current_epoch() {
    let v = v();
    let v2 = list(&v, "v2");
    let alice = key(&v, "alice");
    for w in v["wraps"].as_array().unwrap() {
        let (recipient, wrapped, sig) = (hex(&w["recipient"]), hex(&w["wrapped"]), hex(&w["signature"]));
        let st = WrapStatement {
            context: w["context"].as_str().unwrap(),
            object_id: w["object_id"].as_str().unwrap(),
            version: w["version"].as_u64().unwrap(),
            manifest: hex(&w["manifest"]).try_into().unwrap(),
            recipient: &recipient,
            wrapped: &wrapped,
        };
        assert_eq!(sign::sign_wrap(&alice, &st).unwrap().to_vec(), sig);
        assert_eq!(sign::sign_prepared(&alice, &hex(&w["message"]), Some("dovernik|")).unwrap().to_vec(), sig);
        let verdict = |r: Result<(), Error>| match r {
            Ok(()) => "ok",
            Err(Error::BadChain) => "chain",
            Err(e) => panic!("{e:?}"),
        };
        assert_eq!(verdict(sign::verify_wrap_for(&v2, &[], &alice.public_key(), &st, &sig)), w["default"], "{}", w["version"]);
        let strict = WrapOptions { require_current_epoch: true, ..WrapOptions::default() };
        assert_eq!(verdict(sign::verify_wrap_for_with(&v2, &[], &alice.public_key(), &st, &sig, &strict)), w["require_current_epoch"], "{}", w["version"]);
        // with a recipient id: alice's seal is the fixed recipient of the vectors
        let both = WrapOptions { recipient_id: Some("alice"), require_current_epoch: true };
        assert_eq!(verdict(sign::verify_wrap_for_with(&v2, &[], &alice.public_key(), &st, &sig, &both)), w["require_current_epoch"]);
        let other = WrapOptions { recipient_id: Some("bob"), ..WrapOptions::default() };
        assert_eq!(sign::verify_wrap_for_with(&v2, &[], &alice.public_key(), &st, &sig, &other), Err(Error::BadChain));
    }
}
