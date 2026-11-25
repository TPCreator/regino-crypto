//! Review 2026-11-18 (Gemini 4 Argon F-01, decision point 2): `verify_write_key` – the check for the key an
//! app seals new items with, every check always on. Uses the shared vectors of 0.15.1 (the same verdicts as
//! `openWriteKey` in TypeScript, ts/src/signing0160.test.ts).

use regino_keys::sign::{self, AcceptedManifest, ChainOptions, ManifestConfirmation, PublicKey, WriteKeyChain, WrapStatement};
use regino_keys::Error;
use serde_json::Value;

fn v() -> Value {
    serde_json::from_str(include_str!("../../testvectors/regino/signing-0.15.1.json")).expect("JSON")
}

fn hex(v: &Value) -> Vec<u8> {
    let s = v.as_str().expect("hex string");
    (0..s.len()).step_by(2).map(|i| u8::from_str_radix(&s[i..i + 2], 16).expect("hex")).collect()
}

fn public(v: &Value, name: &str) -> PublicKey {
    PublicKey::from_bytes(&hex(&v["public"][name])).unwrap()
}

fn list(v: &Value, name: &str) -> AcceptedManifest {
    sign::open_manifest(&hex(&v["blobs"][name])).unwrap()
}

fn confirmation(v: &Value, i: usize) -> ManifestConfirmation {
    let c = &v["confirmations"][i];
    ManifestConfirmation { signer: public(v, c["signer"].as_str().unwrap()), signature: hex(&c["signature"]).try_into().unwrap() }
}

#[test]
fn write_key_has_every_check_on() {
    let v = v();
    let scope = v["scope"].as_str().unwrap();
    let anchors = [public(&v, "anchor")];
    let alice = public(&v, "alice");
    let (v1, v2, f2) = (list(&v, "v1"), list(&v, "v2"), list(&v, "f2"));
    let chain_v2 = [v1.blob.as_slice(), v2.blob.as_slice()];
    let chain_f2 = [v1.blob.as_slice(), f2.blob.as_slice()];
    // confirmations[0]: the anchor confirms v2; [1]: mgmt confirms v2; [4]: bob confirms his fork
    let confirmed = ChainOptions { confirmations: vec![confirmation(&v, 0)], ..ChainOptions::default() };
    let unconfirmed = ChainOptions::default();
    let off = ChainOptions { require_anchor_on_latest: false, ..ChainOptions::default() };
    let by_mgmt = ChainOptions { signers: vec![public(&v, "mgmt")], confirmations: vec![confirmation(&v, 1)], ..ChainOptions::default() };
    let fork = ChainOptions { confirmations: vec![confirmation(&v, 4)], ..ChainOptions::default() };
    let mut checked = 0;
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
        let run = |blobs: &[&[u8]], opts: &ChainOptions, id: &str| {
            sign::verify_write_key(&WriteKeyChain { blobs, scope, anchors: &anchors, opts }, id, &alice, &st, &sig)
        };
        let current = w["require_current_epoch"] == "ok";
        for opts in [&confirmed, &by_mgmt] {
            match run(&chain_v2, opts, "alice") {
                Ok(l) => {
                    assert!(current, "an earlier epoch is never a write key");
                    assert_eq!(l.hash, v2.hash);
                }
                Err(e) => {
                    assert!(!current);
                    assert_eq!(e, Error::BadChain);
                }
            }
            // recipient id is always checked
            assert_eq!(run(&chain_v2, opts, "bob").unwrap_err(), Error::BadChain);
            assert_eq!(run(&chain_v2, opts, "").unwrap_err(), Error::BadChain);
        }
        // require_anchor_on_latest is always on, whatever the options say
        for opts in [&unconfirmed, &off] {
            assert_eq!(run(&chain_v2, opts, "alice").unwrap_err(), Error::UntrustedSigner);
        }
        // the removed admin's fork, even with his own confirmation
        assert_eq!(run(&chain_f2, &fork, "alice").unwrap_err(), Error::UntrustedSigner);
        // the old function keeps its default: the key of the earlier epoch still verifies for reading
        assert_eq!(sign::verify_wrap_for(&v2, &anchors, &alice, &st, &sig), Ok(()));
        checked += 1;
    }
    assert_eq!(checked, 2);
}
