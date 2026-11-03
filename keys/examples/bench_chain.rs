//! Benchmark (not part of the tests): a member list with 15 members and 5 versions, verified from an
//! anchor and inspected. Run: `cargo run --release -p regino-keys --example bench_chain`.

use regino_keys::sign::{self, Manifest, Member, SigningKey};
use regino_keys::Key;
use std::time::Instant;

fn key(n: u8) -> SigningKey {
    SigningKey::from_seed(&Key::from_bytes([n; 32]))
}

fn median(name: &str, runs: usize, mut f: impl FnMut()) {
    let mut t: Vec<f64> = (0..runs)
        .map(|_| {
            let s = Instant::now();
            f();
            s.elapsed().as_secs_f64() * 1000.0
        })
        .collect();
    t.sort_by(|a, b| a.partial_cmp(b).unwrap());
    println!("{name:<48} {:.3} ms (median of {runs})", t[runs / 2]);
}

fn main() {
    let scope = "bench|case|1";
    let members: Vec<Member> = (0..15u8)
        .map(|i| Member { id: format!("m{i:02}"), role: if i == 0 { "coordinator".into() } else { "member".into() }, admin: i == 0, sign: key(10 + i).public_key(), seal: vec![], seal_version: 0 })
        .collect();
    let mut blobs = vec![sign::sign_manifest(&key(1), &Manifest { scope: scope.into(), version: 1, epoch: 1, prev: [0; 32], members: members.clone() }).unwrap()];
    let mut prev = sign::open_manifest(&blobs[0]).unwrap();
    for v in 2..=5 {
        let ms = members.iter().map(|m| Member { role: format!("{}{v}", m.role), ..m.clone() }).collect();
        let b = sign::sign_manifest(&key(10), &Manifest::next(&prev, ms)).unwrap();
        prev = sign::open_manifest(&b).unwrap();
        blobs.push(b);
    }
    let refs: Vec<&[u8]> = blobs.iter().map(|b| b.as_slice()).collect();
    let anchor = key(1).public_key();
    median("verify_manifest_chain_from_anchor", 50, || {
        sign::verify_manifest_chain_from_anchor(&refs, scope, &[anchor], None).unwrap();
    });
    median("inspect_manifest_chain", 50, || {
        sign::inspect_manifest_chain(&refs, scope, None).unwrap();
    });
}
