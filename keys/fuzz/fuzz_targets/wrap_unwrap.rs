//! Wrapped keys (`wrap::unwrap_key`): any blob and context, no panic; a blob made by `wrap_key` and changed
//! anywhere is refused.
#![no_main]

use libfuzzer_sys::fuzz_target;
use regino_keys::{wrap, Key};

fuzz_target!(|data: &[u8]| {
    let kek = Key::from_bytes([3; 32]);
    let (ctx, blob) = data.split_at(data.len().min(8));
    let _ = wrap::unwrap_key(&kek, blob, ctx);
    // a genuine blob with one byte flipped at a position chosen by the input
    let inner = Key::from_bytes([5; 32]);
    let good = wrap::wrap_key(&kek, &inner, b"fuzz").expect("wrap");
    assert_eq!(wrap::unwrap_key(&kek, &good, b"fuzz").expect("unwrap"), inner);
    if let Some(&b) = data.first() {
        let mut bad = good.clone();
        let i = (b as usize) % bad.len();
        bad[i] ^= data.get(1).copied().unwrap_or(1).max(1);
        assert!(wrap::unwrap_key(&kek, &bad, b"fuzz").is_err());
    }
});
