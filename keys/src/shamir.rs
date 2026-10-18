//! Splitting a key into `shares` shares of which any `threshold` suffice (e.g. 2-of-3: paper, a person, a notary).
//! Shamir secret sharing over GF(256) (the blahaj crate). Fewer shares than the threshold reveal nothing about the key.
//!
//! Each share also carries an 8-byte key fingerprint (SHA-256), so a corrupted or foreign share
//! ends with an error rather than a silently wrong key. Share format: `"RGK1" | threshold | fingerprint(8) | share`.

use crate::{Error, Key, KEY_LEN};
use blahaj::{Share, Sharks};
use sha2::{Digest, Sha256};
use subtle::ConstantTimeEq;

const MAGIC: &[u8; 4] = b"RGK1";

fn fingerprint(key: &Key) -> [u8; 8] {
    let h = Sha256::digest([b"regino-keys/shamir/v1".as_slice(), key.as_bytes()].concat());
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
            out
        })
        .collect())
}

/// Reassembles the key from shares. At least `threshold` distinct shares of the same key are required.
pub fn combine(parts: &[Vec<u8>]) -> Result<Key, Error> {
    let first = parts.first().ok_or(Error::NotEnoughShares(2))?;
    if first.len() < 13 || &first[..4] != MAGIC {
        return Err(Error::Format);
    }
    let threshold = first[4];
    let fp: [u8; 8] = first[5..13].try_into().map_err(|_| Error::Format)?;
    let mut seen = std::collections::BTreeSet::new();
    let mut shares = Vec::new();
    for p in parts {
        if p.len() < 13 || &p[..4] != MAGIC || p[4] != threshold || p[5..13] != fp {
            return Err(Error::BadShares);
        }
        let s = Share::try_from(&p[13..]).map_err(|_| Error::Format)?;
        if seen.insert(p[13]) {
            shares.push(s);
        }
    }
    if shares.len() < threshold as usize {
        return Err(Error::NotEnoughShares(threshold));
    }
    let secret = Sharks(threshold).recover(shares.iter()).map_err(|_| Error::BadShares)?;
    let bytes: [u8; KEY_LEN] = secret.as_slice().try_into().map_err(|_| Error::BadShares)?;
    let key = Key::from_bytes(bytes);
    // The fingerprint verifies the key – compared in constant time like any other secret-derived value.
    if !bool::from(fingerprint(&key).ct_eq(&fp)) {
        return Err(Error::BadShares);
    }
    Ok(key)
}
