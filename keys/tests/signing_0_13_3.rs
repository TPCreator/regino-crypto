//! Combinations of chain options recommended by the review of 0.13.2 (`testvectors/regino/signing-0.13.3.json`,
//! made by the TypeScript side): Rust must give the same verdicts and the same hashes.

use regino_keys::sign::{self, ChainOptions, Pinned, PublicKey};
use regino_keys::Error;
use serde_json::Value;

fn hex(v: &Value) -> Vec<u8> {
    let s = v.as_str().expect("hex string");
    (0..s.len()).step_by(2).map(|i| u8::from_str_radix(&s[i..i + 2], 16).expect("hex")).collect()
}

#[test]
fn option_combinations_give_the_same_verdicts_as_typescript() {
    let doc: Value = serde_json::from_str(include_str!("../../testvectors/regino/signing-0.13.3.json")).unwrap();
    assert_eq!(doc["version"], "0.13.3");
    let anchor = PublicKey::from_bytes(&hex(&doc["anchor"])).unwrap();
    let signer = PublicKey::from_bytes(&hex(&doc["signer"])).unwrap();
    let scope = doc["scope"].as_str().unwrap();
    for t in doc["cases"].as_array().unwrap() {
        let blobs: Vec<Vec<u8>> = t["blobs"].as_array().unwrap().iter().map(hex).collect();
        let refs: Vec<&[u8]> = blobs.iter().map(|b| b.as_slice()).collect();
        let o = &t["opts"];
        let opts = ChainOptions {
            pinned: o.get("pinned").map(|p| Pinned {
                version: p["version"].as_u64().unwrap(),
                hashes: p["hashes"].as_array().unwrap().iter().map(|h| hex(h).try_into().unwrap()).collect(),
            }),
            signers: if o.get("signers").is_some() { vec![signer] } else { vec![] },
            anchors_may_sign: o.get("anchors_may_sign").and_then(Value::as_bool).unwrap_or(true),
            pinned_trusted: o.get("pinned_trusted").and_then(Value::as_bool).unwrap_or(false),
        };
        let got = sign::verify_manifest_chain_from_anchor_with(&refs, scope, &[anchor], &opts);
        let case = &t["case"];
        match t["expect"].as_str().unwrap() {
            "ok" => {
                let hashes: Vec<Vec<u8>> = got.unwrap_or_else(|e| panic!("{case}: {e:?}")).iter().map(|a| a.hash.to_vec()).collect();
                let want: Vec<Vec<u8>> = t["hashes"].as_array().unwrap().iter().map(hex).collect();
                assert_eq!(hashes, want, "{case}");
            }
            e => {
                let want = match e {
                    "untrusted" => Error::UntrustedSigner,
                    "chain" => Error::BadChain,
                    "withheld" => Error::Withheld,
                    e => panic!("{e}"),
                };
                assert_eq!(got.map(|l| l.len()), Err(want), "{case}");
            }
        }
    }
}
