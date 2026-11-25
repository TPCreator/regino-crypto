//! Shamir shares (`shamir::combine`): any bytes cut into shares, no panic.
#![no_main]

use libfuzzer_sys::fuzz_target;
use regino_keys::shamir;

fuzz_target!(|data: &[u8]| {
    // first byte: share length (so both the exact length and wrong lengths are reached)
    let Some((&len, rest)) = data.split_first() else { return };
    let len = (len as usize % 64).max(1);
    let parts: Vec<Vec<u8>> = rest.chunks(len).map(<[u8]>::to_vec).collect();
    let _ = shamir::combine(&parts);
    let exact: Vec<Vec<u8>> = rest.chunks(shamir::SHARE_LEN).map(<[u8]>::to_vec).collect();
    let _ = shamir::combine(&exact);
});
