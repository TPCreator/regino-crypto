//! Splitting a key into `shares` shares of which any `threshold` suffice (e.g. 2-of-3: paper, a person, a notary).
//! Shamir secret sharing over GF(256) (the blahaj crate). Fewer shares than the threshold reveal nothing about the key.
//!
//! Each share also carries an 8-byte key fingerprint (SHA-256), so a corrupted or foreign share
//! ends with an error rather than a silently wrong key. Share format: `"RGK1" | threshold | fingerprint(8) | share`,
//! where the blahaj share is `x(1) | y(KEY_LEN)` – every share of a key has the same fixed length (46 bytes).

use crate::{Error, Key, KEY_LEN};
use blahaj::{Share, Sharks};
use sha2::{Digest, Sha256};
use subtle::ConstantTimeEq;
use zeroize::Zeroizing;

const MAGIC: &[u8; 4] = b"RGK1";
/// Header: magic(4) ‖ threshold(1) ‖ fingerprint(8).
const HEADER_LEN: usize = 4 + 1 + 8;
/// Whole share: header ‖ x(1) ‖ y(KEY_LEN). Keys have one length, so shares have one length (since
/// 0.12.1 checked exactly, not just `>= header`; shares written by earlier versions have always had it).
pub const SHARE_LEN: usize = HEADER_LEN + 1 + KEY_LEN;

fn fingerprint(key: &Key) -> [u8; 8] {
    // fed in parts – no temporary copy of the key that would have to be wiped
    let h = Sha256::new().chain_update(b"regino-keys/shamir/v1").chain_update(key.as_bytes()).finalize();
    h[..8].try_into().expect("8 bytes")
}

/// Splits the key. Result: `shares` shares as bytes (convert them to words or QR codes for printing).
pub fn split(key: &Key, threshold: u8, shares: u8) -> Result<Vec<Vec<u8>>, Error> {
    if threshold < 2 || shares < threshold {
        return Err(Error::BadSplit { threshold, shares });
    }
    let fp = fingerprint(key);
    let dealer = Sharks(threshold).dealer(key.as_bytes());
    Ok(dealer
        .take(shares as usize)
        .map(|s| {
            let mut out = MAGIC.to_vec();
            out.push(threshold);
            out.extend_from_slice(&fp);
            out.extend_from_slice(&Vec::from(&s));
            debug_assert_eq!(out.len(), SHARE_LEN);
            out
        })
        .collect())
}

/// Reassembles the key from shares. At least `threshold` distinct shares of the same key are required.
/// A share of any other length than [`SHARE_LEN`] is refused (`Error::Format` for the first one,
/// `Error::BadShares` for the others), so trailing or missing bytes never reach the field arithmetic.
pub fn combine(parts: &[Vec<u8>]) -> Result<Key, Error> {
    let first = parts.first().ok_or(Error::NotEnoughShares(2))?;
    if first.len() != SHARE_LEN || &first[..4] != MAGIC {
        return Err(Error::Format);
    }
    let threshold = first[4];
    let fp: [u8; 8] = first[5..HEADER_LEN].try_into().map_err(|_| Error::Format)?;
    // x (the first share byte) -> share bytes; the same share twice counts once, but two different
    // shares with the same x cannot both be right – that is an error, not a silent choice.
    let mut seen: std::collections::BTreeMap<u8, &[u8]> = std::collections::BTreeMap::new();
    let mut shares = Vec::new();
    for p in parts {
        if p.len() != SHARE_LEN || &p[..4] != MAGIC || p[4] != threshold || p[5..HEADER_LEN] != fp {
            return Err(Error::BadShares);
        }
        let body = &p[HEADER_LEN..];
        match seen.get(&body[0]) {
            Some(prev) if *prev != body => return Err(Error::BadShares),
            Some(_) => continue,
            None => {}
        }
        shares.push(Share::try_from(body).map_err(|_| Error::Format)?);
        seen.insert(body[0], body);
    }
    if shares.len() < threshold as usize {
        return Err(Error::NotEnoughShares(threshold));
    }
    // blahaj does not wipe its own buffers (polynomials, shares); the recovered secret is wiped here
    let secret = Zeroizing::new(Sharks(threshold).recover(shares.iter()).map_err(|_| Error::BadShares)?);
    let bytes: [u8; KEY_LEN] = secret.as_slice().try_into().map_err(|_| Error::BadShares)?;
    let key = Key::from_bytes(bytes);
    // The fingerprint verifies the key – compared in constant time like any other secret-derived value.
    if !bool::from(fingerprint(&key).ct_eq(&fp)) {
        return Err(Error::BadShares);
    }
    Ok(key)
}
