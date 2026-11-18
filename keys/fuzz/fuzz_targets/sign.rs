//! Signed member lists and prepared messages (`sign::open_manifest`, `sign::sign_prepared`,
//! `sign::verify_manifest_chain_from_anchor_with`): any bytes, no panic; an accepted list is exactly its bytes.
#![no_main]

use libfuzzer_sys::fuzz_target;
use regino_keys::sign::{self, ChainOptions, SigningKey};
use regino_keys::Key;

fuzz_target!(|data: &[u8]| {
    // a list blob: accepted only when it re-encodes to the same bytes and its signature verifies
    if let Ok(a) = sign::open_manifest(data) {
        assert_eq!(a.blob, data);
    }
    // a prepared message: a Signer outside TypeScript signs only canonical messages of the known kinds
    let key = SigningKey::from_seed(&Key::from_bytes([7; 32]));
    let _ = sign::sign_prepared(&key, data, None);
    let _ = sign::sign_prepared(&key, data, Some("demo|"));
    // a chain: the input split into blobs at every 0xfe byte
    let blobs: Vec<&[u8]> = data.split(|b| *b == 0xfe).collect();
    let anchors = [key.public_key()];
    for opts in [ChainOptions::default(), ChainOptions { require_anchor_on_latest: true, ..ChainOptions::default() }] {
        let _ = sign::verify_manifest_chain_from_anchor_with(&blobs, "demo|x", &anchors, &opts);
    }
});
