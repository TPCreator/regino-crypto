//! Additions of 0.13.2 (`testvectors/regino/signing-0.13.2.json`, made by the TypeScript side): options of
//! the chain verified from an anchor (`signers`, `anchors_may_sign`, `pinned_trusted`) and
//! `inspect_manifest_chain` (structure only, no trust).

use regino_keys::sign::{self, ChainOptions, Pinned, PublicKey};
use regino_keys::Error;
use serde_json::Value;

fn vectors() -> Value {
    serde_json::from_str(include_str!("../../testvectors/regino/signing-0.13.2.json")).expect("JSON")
}

fn hex(v: &Value) -> Vec<u8> {
    let s = v.as_str().expect("hex string");
    (0..s.len()).step_by(2).map(|i| u8::from_str_radix(&s[i..i + 2], 16).expect("hex")).collect()
}

fn text(v: &Value) -> &str {
    v.as_str().unwrap()
}

fn pinned(v: &Value) -> Option<Pinned> {
    (!v.is_null()).then(|| Pinned {
        version: v["version"].as_u64().unwrap(),
        hashes: v["hashes"].as_array().unwrap().iter().map(|h| hex(h).try_into().unwrap()).collect(),
    })
}

fn want(e: &str) -> Error {
    match e {
        "untrusted" => Error::UntrustedSigner,
        "chain" | "chain_scope" => Error::BadChain,
        "withheld" => Error::Withheld,
        "signature" => Error::BadSignature,
        e => panic!("{e}"),
    }
}

#[test]
fn chain_options_give_the_same_verdicts_as_typescript() {
    let doc = vectors();
    assert_eq!(doc["version"], "0.13.2");
    let anchor = PublicKey::from_bytes(&hex(&doc["anchor"])).unwrap();
    let signer = PublicKey::from_bytes(&hex(&doc["signer"])).unwrap();
    for t in doc["from_anchor"].as_array().unwrap() {
        let blobs: Vec<Vec<u8>> = t["blobs"].as_array().unwrap().iter().map(hex).collect();
        let refs: Vec<&[u8]> = blobs.iter().map(|b| b.as_slice()).collect();
        let o = &t["opts"];
        let opts = ChainOptions {
            pinned: o.get("pinned").and_then(pinned),
            signers: if o.get("signers").is_some() { vec![signer] } else { vec![] },
            anchors_may_sign: o.get("anchors_may_sign").and_then(Value::as_bool).unwrap_or(true),
            pinned_trusted: o.get("pinned_trusted").and_then(Value::as_bool).unwrap_or(false),
        };
        let got = sign::verify_manifest_chain_from_anchor_with(&refs, text(&doc["scope"]), &[anchor], &opts).map(|l| l.len() as u64);
        match text(&t["expect"]) {
            "ok" => assert_eq!(got, Ok(t["accepted"].as_u64().unwrap()), "{}", t["case"]),
            e => assert_eq!(got, Err(want(e)), "{}", t["case"]),
        }
    }
    // the defaults are the behaviour of 0.13.1
    let d = ChainOptions::default();
    assert!(d.anchors_may_sign && !d.pinned_trusted && d.signers.is_empty() && d.pinned.is_none());
    // pinned_trusted without a pin changes nothing: the anchor is still required
    let t = &doc["from_anchor"][5];
    let blobs: Vec<Vec<u8>> = t["blobs"].as_array().unwrap().iter().map(hex).collect();
    let refs: Vec<&[u8]> = blobs.iter().map(|b| b.as_slice()).collect();
    let o = ChainOptions { pinned_trusted: true, ..ChainOptions::default() };
    assert_eq!(sign::verify_manifest_chain_from_anchor_with(&refs, text(&doc["scope"]), &[anchor], &o).map(|l| l.len()), Err(Error::UntrustedSigner));
}

#[test]
fn inspect_checks_structure_only() {
    let doc = vectors();
    for t in doc["inspect"].as_array().unwrap() {
        let blobs: Vec<Vec<u8>> = t["blobs"].as_array().unwrap().iter().map(hex).collect();
        let refs: Vec<&[u8]> = blobs.iter().map(|b| b.as_slice()).collect();
        let scope = if text(&t["expect"]) == "chain_scope" { "dovernik|center|12|case|01JOTHER" } else { text(&doc["scope"]) };
        let got = sign::inspect_manifest_chain(&refs, scope, pinned(&t["pinned"]).as_ref());
        match text(&t["expect"]) {
            "ok" => {
                let list = got.unwrap();
                let rows = t["rows"].as_array().unwrap();
                assert_eq!(list.len(), rows.len());
                for (a, r) in list.iter().zip(rows) {
                    assert_eq!(a.version, r["version"].as_u64().unwrap());
                    assert_eq!(a.epoch, r["epoch"].as_u64().unwrap());
                    assert_eq!(a.signer.as_bytes().to_vec(), hex(&r["signer"]));
                    assert_eq!(a.hash.to_vec(), hex(&r["hash"]));
                    let ids: Vec<&str> = a.members.iter().map(|m| m.id.as_str()).collect();
                    let want: Vec<&str> = r["members"].as_array().unwrap().iter().map(text).collect();
                    assert_eq!(ids, want);
                }
                // the same chain is refused by the trusted verification (stranger as signer, no anchor)
                let anchor = PublicKey::from_bytes(&hex(&doc["anchor"])).unwrap();
                assert!(sign::verify_manifest_chain_from_anchor(&refs, scope, &[anchor], None).is_err());
            }
            e => assert_eq!(got.map(|l| l.len()), Err(want(e)), "{}", t["case"]),
        }
    }
    assert_eq!(sign::inspect_manifest_chain(&[], "x", None).map(|l| l.len()), Err(Error::BadChain));
    // a later version for another case, linked to version 1
    let first = hex(&doc["inspect"][0]["blobs"][0]);
    let a = sign::open_manifest(&first).unwrap();
    let key = regino_keys::sign::SigningKey::from_seed(&regino_keys::Key::from_bytes([9; 32]));
    let other = sign::sign_manifest(&key, &sign::Manifest { scope: "x|y".into(), ..sign::Manifest::next(&a, vec![]) }).unwrap();
    assert_eq!(sign::inspect_manifest_chain(&[&first, &other], text(&doc["scope"]), None).map(|l| l.len()), Err(Error::BadChain));
}
