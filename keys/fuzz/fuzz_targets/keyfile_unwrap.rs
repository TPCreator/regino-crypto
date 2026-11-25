//! Key file wraps (`keyfile::unwrap_master`, 0.22.0): any wrap, app and method, no panic; a wrap made by
//! `wrap_master` and changed anywhere is refused.
#![no_main]

use libfuzzer_sys::fuzz_target;
use regino_keys::{keyfile, Key};

fuzz_target!(|data: &[u8]| {
    let kek = Key::from_bytes([3; 32]);
    let (names, wrap) = data.split_at(data.len().min(12));
    let names = String::from_utf8_lossy(names);
    let (app, method) = names.split_once('/').unwrap_or((&names, "password"));
    let _ = keyfile::unwrap_master(&kek, wrap, app, method);
    let master = Key::from_bytes([5; 32]);
    let good = keyfile::wrap_master(&kek, &master, "fuzz", "shares").expect("wrap");
    assert_eq!(keyfile::unwrap_master(&kek, &good, "fuzz", "shares").expect("unwrap"), master);
    if let Some(&b) = data.first() {
        let mut bad = good.clone();
        let i = (b as usize) % bad.len();
        bad[i] ^= data.get(1).copied().unwrap_or(1).max(1);
        assert!(keyfile::unwrap_master(&kek, &bad, "fuzz", "shares").is_err());
    }
});
