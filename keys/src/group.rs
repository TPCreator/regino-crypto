//! Short codes derived from a group key (a key of a shared case, a group key of sync) – for people to
//! compare and for stable ids that do not reveal the key. The same computation exists in TypeScript
//! (`groupKeyCode`, `groupKeyId` in `ts/src/groupKey.ts`); shared vectors
//! `testvectors/regino/group-key-0.13.1.json` guard that both give the same text.
//!
//! - [`group_key_code`]: HMAC-SHA256(HKDF-SHA256(key, no salt, info `regino group-key code v1`), context),
//!   first 80 bits as hex in groups of four ("3f2a 9c01 …") – members read it to each other to check that
//!   they hold the same key (a server cannot hand one of them another key unnoticed).
//! - [`group_key_id`]: HMAC-SHA256(HKDF-SHA256(key, no salt, info `regino group-key id v1`), label), first
//!   96 bits as 24 hex characters – a stable, key-bound id (e.g. of a fixed item slot) the server sees.
//!
//! The two derived keys are independent of each other and of any key used for sealing, so a code or an
//! id reveals nothing that helps to open data. Context and label must not be empty.

use hkdf::Hkdf;
use hmac::{Hmac, KeyInit, Mac};
use sha2::Sha256;
use zeroize::{Zeroize, Zeroizing};

use crate::Error;

fn tag(key: &[u8; 32], info: &[u8], data: &str) -> Result<[u8; 32], Error> {
    if data.is_empty() {
        return Err(Error::EmptyContext);
    }
    let mut k = Zeroizing::new([0u8; 32]);
    let (mut prk, hk) = Hkdf::<Sha256>::extract(None, key);
    prk.as_mut_slice().zeroize();
    hk.expand(info, k.as_mut()).map_err(|_| Error::Format)?;
    let mut mac = <Hmac<Sha256> as KeyInit>::new_from_slice(k.as_ref()).map_err(|_| Error::Format)?;
    mac.update(data.as_bytes());
    Ok(mac.finalize().into_bytes().into())
}

fn hex(b: &[u8]) -> String {
    b.iter().map(|x| format!("{x:02x}")).collect()
}

/// Code of a group key for comparing ("3f2a 9c01 …", 80 bits), bound to `context` (e.g. the case id).
pub fn group_key_code(key: &[u8; 32], context: &str) -> Result<String, Error> {
    let t = tag(key, b"regino group-key code v1", context)?;
    let h = hex(&t[..10]);
    Ok((0..5).map(|i| &h[i * 4..i * 4 + 4]).collect::<Vec<_>>().join(" "))
}

/// Key-bound id (24 hex characters, 96 bits) for `label` (e.g. `case slot v1|consent`).
pub fn group_key_id(key: &[u8; 32], label: &str) -> Result<String, Error> {
    Ok(hex(&tag(key, b"regino group-key id v1", label)?[..12]))
}
