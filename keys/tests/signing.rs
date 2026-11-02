//! Signatures (`regino_keys::sign`): the shared fixed vectors `testvectors/regino/signing-0.13.0.json`
//! were made by the TypeScript side (`ts/src/signing.ts`); Rust must give the same public keys,
//! fingerprints, signatures (Ed25519 is deterministic) and blobs, and the same verdicts.

use ed25519_dalek::{Signature, VerifyingKey};
use regino_keys::sign::{self, AcceptedManifest, Manifest, Member, PublicKey, SigningKey, WrapStatement};
use regino_keys::{wrap, Error, Key};
use serde_json::Value;

fn vectors() -> Value {
    serde_json::from_str(include_str!("../../testvectors/regino/signing-0.13.0.json")).expect("JSON")
}

fn hex(v: &Value) -> Vec<u8> {
    let s = v.as_str().expect("hex string");
    (0..s.len()).step_by(2).map(|i| u8::from_str_radix(&s[i..i + 2], 16).expect("hex")).collect()
}

fn to_hex(b: &[u8]) -> String {
    b.iter().map(|x| format!("{x:02x}")).collect()
}

fn seed(v: &Value) -> SigningKey {
    SigningKey::from_seed(&Key::from_bytes(hex(v).try_into().unwrap()))
}

fn key(n: u8) -> SigningKey {
    SigningKey::from_seed(&Key::from_bytes([n; 32]))
}

fn text(v: &Value) -> &str {
    v.as_str().unwrap()
}

#[test]
fn vectors_are_from_0_13_0() {
    assert_eq!(vectors()["version"], "0.13.0");
}

#[test]
fn public_keys_and_fingerprints_match_typescript() {
    let doc = vectors();
    for t in doc["keys"].as_array().unwrap() {
        let k = seed(&t["seed"]);
        assert_eq!(to_hex(k.public_key().as_bytes()), text(&t["public"]));
        assert_eq!(sign::fingerprint(&k.public_key()), text(&t["fingerprint"]));
        assert!(k.seed() == Key::from_bytes(hex(&t["seed"]).try_into().unwrap()));
    }
}

#[test]
fn derived_keys_match_typescript() {
    let doc = vectors();
    for t in doc["derive"].as_array().unwrap() {
        let master = Key::from_bytes(hex(&t["key"]).try_into().unwrap());
        let k = SigningKey::derive(&master, text(&t["app"]), text(&t["label"])).unwrap();
        assert_eq!(to_hex(k.seed().as_bytes()), text(&t["seed"]));
        assert_eq!(to_hex(k.public_key().as_bytes()), text(&t["public"]));
    }
}

#[test]
fn data_signatures_match_typescript() {
    let doc = vectors();
    for t in doc["data"].as_array().unwrap() {
        let k = seed(&t["seed"]);
        let (ctx, data, sig) = (text(&t["context"]), hex(&t["data"]), hex(&t["signature"]));
        assert_eq!(sign::sign_data(&k, ctx, &data).unwrap().to_vec(), sig);
        sign::verify_data(&k.public_key(), ctx, &data, &sig).unwrap();
        assert_eq!(sign::verify_data(&k.public_key(), &format!("{ctx}x"), &data, &sig), Err(Error::BadSignature));
        assert_eq!(sign::verify_data(&key(9).public_key(), ctx, &data, &sig), Err(Error::BadSignature));
        let mut bad = sig.clone();
        bad[0] ^= 1;
        assert_eq!(sign::verify_data(&k.public_key(), ctx, &data, &bad), Err(Error::BadSignature));
        assert_eq!(sign::verify_data(&k.public_key(), ctx, &data, &sig[..63]), Err(Error::BadSignature));
    }
}

#[test]
fn wrap_signatures_match_typescript() {
    let doc = vectors();
    for t in doc["wrap"].as_array().unwrap() {
        let k = seed(&t["seed"]);
        let (recipient, wrapped, sig) = (hex(&t["recipient"]), hex(&t["wrapped"]), hex(&t["signature"]));
        let st = WrapStatement {
            context: text(&t["context"]),
            object_id: text(&t["object_id"]),
            version: t["version"].as_u64().unwrap(),
            recipient: &recipient,
            wrapped: &wrapped,
        };
        assert_eq!(sign::sign_wrap(&k, &st).unwrap().to_vec(), sig);
        sign::verify_wrap(&k.public_key(), &st, &sig).unwrap();
        // every field is covered
        let other = [1u8; 65];
        for changed in [
            WrapStatement { context: "other", ..st },
            WrapStatement { object_id: "other", ..st },
            WrapStatement { version: st.version - 1, ..st },
            WrapStatement { recipient: &other, ..st },
            WrapStatement { wrapped: b"other", ..st },
        ] {
            assert_eq!(sign::verify_wrap(&k.public_key(), &changed, &sig), Err(Error::BadSignature));
        }
        assert_eq!(sign::verify_wrap(&key(9).public_key(), &st, &sig), Err(Error::BadSignature));
    }
}

#[test]
fn signed_rust_wrapped_key() {
    // a Rust `wrap::wrap_key` blob signed by the sender, checked before unwrapping
    let sender = SigningKey::generate().unwrap();
    let kek = Key::generate().unwrap();
    let inner = Key::generate().unwrap();
    let blob = wrap::wrap_key(&kek, &inner, b"demo/case/1").unwrap();
    let st = WrapStatement { context: "demo/case/1", object_id: "1", version: 1, recipient: b"me", wrapped: &blob };
    let sig = sign::sign_wrap(&sender, &st).unwrap();
    sign::verify_wrap(&sender.public_key(), &st, &sig).unwrap();
    assert!(wrap::unwrap_key(&kek, &blob, b"demo/case/1").unwrap() == inner);
}

fn chain_of(doc: &Value) -> Vec<Vec<u8>> {
    doc["manifest"]["chain"].as_array().unwrap().iter().map(|c| hex(&c["blob"])).collect()
}

fn anchor(doc: &Value) -> PublicKey {
    PublicKey::from_bytes(&hex(&doc["manifest"]["anchor"])).unwrap()
}

fn accepted(doc: &Value, upto: usize) -> Option<AcceptedManifest> {
    let blobs = chain_of(doc);
    let refs: Vec<&[u8]> = blobs.iter().take(upto).map(|b| b.as_slice()).collect();
    (upto > 0).then(|| sign::verify_manifest_chain(&refs, &[anchor(doc)], None).unwrap())
}

#[test]
fn manifest_chain_from_typescript_is_accepted_and_reproduced() {
    let doc = vectors();
    let m = &doc["manifest"];
    let blobs = chain_of(&doc);
    let mut prev: Option<AcceptedManifest> = None;
    for (c, blob) in m["chain"].as_array().unwrap().iter().zip(&blobs) {
        let a = sign::verify_manifest(blob, &[anchor(&doc)], prev.as_ref()).unwrap();
        assert_eq!(to_hex(&a.hash), text(&c["hash"]));
        assert_eq!(to_hex(a.signer.as_bytes()), text(&c["signer"]));
        assert_eq!(a.manifest.version, c["version"].as_u64().unwrap());
        assert_eq!(a.manifest.epoch, c["epoch"].as_u64().unwrap());
        assert_eq!(a.manifest.scope, text(&m["scope"]));
        let members: Vec<Member> = c["members"]
            .as_array()
            .unwrap()
            .iter()
            .map(|x| Member {
                id: text(&x["id"]).into(),
                role: text(&x["role"]).into(),
                admin: x["admin"].as_bool().unwrap(),
                sign: PublicKey::from_bytes(&hex(&x["sign"])).unwrap(),
                seal: hex(&x["seal"]),
            })
            .collect();
        assert_eq!(a.manifest.members, members);
        // signing the same list again (members in reverse order – they are sorted) gives the same blob
        let signer = [1u8, 2].into_iter().map(key).find(|k| k.public_key() == a.signer).unwrap();
        let mut again = a.manifest.clone();
        again.members.reverse();
        assert_eq!(&sign::sign_manifest(&signer, &again).unwrap(), blob);
        assert_eq!(sign::open_manifest(blob).unwrap(), a);
        prev = Some(a);
    }
    let refs: Vec<&[u8]> = blobs.iter().map(|b| b.as_slice()).collect();
    let last = sign::verify_manifest_chain(&refs, &[anchor(&doc)], None).unwrap();
    assert_eq!(last, prev.clone().unwrap());
    assert_eq!(sign::verify_manifest_chain(&[], &[], prev.as_ref()).unwrap(), last);
    assert_eq!(sign::verify_manifest_chain(&[], &[], None), Err(Error::BadChain));
    // continuing from an already trusted list
    let one = accepted(&doc, 1).unwrap();
    assert_eq!(sign::verify_manifest_chain(&refs[1..], &[], Some(&one)).unwrap(), last);
}

#[test]
fn refused_manifests_are_refused_for_the_same_reason() {
    let doc = vectors();
    let m = &doc["manifest"];
    for r in m["refused"].as_array().unwrap() {
        let prev = accepted(&doc, r["after"].as_u64().unwrap() as usize);
        let want = match text(&r["error"]) {
            "untrusted" => Error::UntrustedSigner,
            "chain" => Error::BadChain,
            e => panic!("{e}"),
        };
        assert_eq!(sign::verify_manifest(&hex(&r["blob"]), &[anchor(&doc)], prev.as_ref()), Err(want), "{r}");
    }
    let prev = accepted(&doc, m["rescue"]["after"].as_u64().unwrap() as usize).unwrap();
    let rescue = sign::verify_manifest(&hex(&m["rescue"]["blob"]), &[anchor(&doc)], Some(&prev)).unwrap();
    assert_eq!(rescue.signer, anchor(&doc));
    // without the anchor the coordinator could not be replaced by management
    assert_eq!(sign::verify_manifest(&hex(&m["rescue"]["blob"]), &[], Some(&prev)), Err(Error::UntrustedSigner));
}

#[test]
fn damaged_manifests_are_refused() {
    let doc = vectors();
    let blob = chain_of(&doc).remove(1);
    for i in [0, 9, 20, blob.len() / 2, blob.len() - 1] {
        let mut b = blob.clone();
        b[i] ^= 1;
        assert!(sign::open_manifest(&b).is_err(), "byte {i}");
    }
    assert_eq!(sign::open_manifest(&blob[..blob.len() - 1]), Err(Error::Format));
    assert_eq!(sign::open_manifest(b"RGN-SIG1"), Err(Error::Format));
    let mut extra = blob[..blob.len() - 64].to_vec();
    extra.extend_from_slice(&[0, 0, 0, 0]);
    extra.extend_from_slice(&blob[blob.len() - 64..]);
    assert_eq!(sign::open_manifest(&extra), Err(Error::Format));
}

fn member(id: &str, admin: bool, k: &SigningKey) -> Member {
    Member { id: id.into(), role: "member".into(), admin, sign: k.public_key(), seal: vec![] }
}

#[test]
fn manifest_rules() {
    let (a, b) = (key(1), key(2));
    let first = Manifest { scope: "demo|case|1".into(), version: 1, epoch: 0, prev: [0; 32], members: vec![member("b", true, &b)] };
    let one = sign::verify_manifest(&sign::sign_manifest(&a, &first).unwrap(), &[a.public_key()], None).unwrap();
    assert_eq!(one.manifest.member_by_key(&b.public_key()).unwrap().id, "b");
    assert!(one.manifest.member_by_key(&a.public_key()).is_none());
    let bad = |m: Manifest| sign::sign_manifest(&a, &m).unwrap_err();
    assert_eq!(bad(Manifest { version: 0, ..first.clone() }), Error::Format);
    assert_eq!(bad(Manifest { version: 2, ..first.clone() }), Error::Format); // version 2 needs a link
    assert_eq!(bad(Manifest { prev: [1; 32], ..first.clone() }), Error::Format);
    assert_eq!(bad(Manifest { version: sign::MAX_VERSION + 1, prev: [1; 32], ..first.clone() }), Error::Format);
    assert_eq!(bad(Manifest { epoch: sign::MAX_VERSION + 1, ..first.clone() }), Error::Format);
    assert_eq!(bad(Manifest { scope: String::new(), ..first.clone() }), Error::EmptyContext);
    assert_eq!(bad(Manifest { scope: "x".repeat(1025), ..first.clone() }), Error::Format);
    assert_eq!(bad(Manifest { members: vec![member("b", true, &b), member("b", false, &a)], ..first.clone() }), Error::Format);
    assert_eq!(bad(Manifest { members: vec![member("", true, &b)], ..first.clone() }), Error::EmptyContext);
    assert_eq!(bad(Manifest { members: vec![Member { seal: vec![0; 1025], ..member("b", true, &b) }], ..first.clone() }), Error::Format);
    let many: Vec<Member> = (0..1001).map(|i| member(&i.to_string(), false, &b)).collect();
    assert_eq!(bad(Manifest { members: many, ..first.clone() }), Error::Format);
    // a member that is not admin cannot sign the next list; an admin can
    let next = Manifest::next(&one, vec![member("b", true, &b), member("c", false, &key(3))]);
    assert_eq!(next.version, 2);
    assert_eq!(sign::verify_manifest(&sign::sign_manifest(&key(3), &next).unwrap(), &[a.public_key()], Some(&one)), Err(Error::UntrustedSigner));
    let two = sign::verify_manifest(&sign::sign_manifest(&b, &next).unwrap(), &[], Some(&one)).unwrap();
    // another scope with the same version and link is not a continuation
    let other = Manifest { scope: "demo|case|2".into(), ..Manifest::next(&two, vec![]) };
    assert_eq!(sign::verify_manifest(&sign::sign_manifest(&b, &other).unwrap(), &[], Some(&two)), Err(Error::BadChain));
    // the same version twice (a fork) is refused
    assert_eq!(sign::verify_manifest(&two.blob, &[], Some(&two)), Err(Error::BadChain));
}

#[test]
fn raw_edge_cases_give_the_same_verdict_as_typescript() {
    let doc = vectors();
    for t in doc["raw"].as_array().unwrap() {
        let public = hex(&t["public"]);
        let sig: [u8; 64] = hex(&t["signature"]).try_into().unwrap();
        let ok = PublicKey::from_bytes(&public).is_ok()
            && VerifyingKey::from_bytes(&public.clone().try_into().unwrap()).unwrap().verify_strict(&hex(&t["message"]), &Signature::from_bytes(&sig)).is_ok();
        assert_eq!(ok, t["valid"].as_bool().unwrap(), "{}", t["case"]);
    }
}

#[test]
fn public_keys_are_checked() {
    assert!(PublicKey::from_bytes(&[0u8; 31]).is_err());
    // identity (small order), a point of order 8, y >= p (not canonical)
    let identity = {
        let mut b = [0u8; 32];
        b[0] = 1;
        b
    };
    let order8 = hex(&Value::from("c7176a703d4dd84fba3c0b760d10670f2a2053fa2c39ccc64ec7fd7792ac03fa"));
    let mut noncanonical = [0xffu8; 32];
    noncanonical[0] = 0xee; // y = p + 1 → decodes to y = 1 (identity)
    noncanonical[31] = 0x7f;
    for k in [identity.to_vec(), order8, noncanonical.to_vec()] {
        assert_eq!(PublicKey::from_bytes(&k), Err(Error::Format), "{}", to_hex(&k));
    }
}

#[test]
fn keys_are_kept_wrapped_or_derived() {
    let master = Key::generate().unwrap();
    let k = SigningKey::generate().unwrap();
    let blob = wrap::wrap_key(&master, &k.seed(), b"demo/signing-key").unwrap();
    let again = SigningKey::from_seed(&wrap::unwrap_key(&master, &blob, b"demo/signing-key").unwrap());
    assert_eq!(again.public_key(), k.public_key());
    assert_eq!(format!("{k:?}"), "SigningKey(***)");
    let d = SigningKey::derive(&master, "demo", "share").unwrap();
    assert_eq!(d.public_key(), SigningKey::derive(&master, "demo", "share").unwrap().public_key());
    assert_ne!(d.public_key(), SigningKey::derive(&master, "demo", "center").unwrap().public_key());
    assert_ne!(d.public_key(), SigningKey::derive(&master, "other", "share").unwrap().public_key());
    for (app, label) in [("de-mo", "share"), ("Demo", "share"), ("demo", "ab"), ("demo", "Share"), ("d", "share")] {
        assert_eq!(SigningKey::derive(&master, app, label).unwrap_err(), Error::Format, "{app} {label}");
    }
    assert_eq!(sign::sign_data(&k, "", b"x").unwrap_err(), Error::EmptyContext);
    let st = WrapStatement { context: "c", object_id: "o", version: 1, recipient: b"", wrapped: b"w" };
    assert_eq!(sign::sign_wrap(&k, &st).unwrap_err(), Error::Format);
    assert_eq!(sign::sign_wrap(&k, &WrapStatement { recipient: b"r", wrapped: b"", ..st }).unwrap_err(), Error::Format);
    assert_eq!(sign::sign_wrap(&k, &WrapStatement { recipient: b"r", version: sign::MAX_VERSION + 1, ..st }).unwrap_err(), Error::Format);
    assert_eq!(sign::sign_wrap(&k, &WrapStatement { recipient: b"r", object_id: "", ..st }).unwrap_err(), Error::EmptyContext);
}

#[test]
fn malformed_manifests_give_the_same_verdict_as_typescript() {
    let doc = vectors();
    for t in doc["manifest"]["malformed"].as_array().unwrap() {
        let r = sign::open_manifest(&hex(&t["blob"]));
        if t["valid"].as_bool().unwrap() {
            r.unwrap();
        } else {
            assert!(matches!(r, Err(Error::Format | Error::EmptyContext)), "{}: {r:?}", t["case"]);
        }
    }
}
