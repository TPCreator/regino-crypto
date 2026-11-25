//! Key file wraps (since 0.22.0): an app's master key wrapped by a key-encrypting key for one
//! **method** – `password` (Argon2id, [`crate::kdf::derive`]), `recovery` (12 or 24 words,
//! [`crate::recovery::recovery_key`]), `shares` (a key split 2-of-3, [`crate::shamir`]),
//! `device:windows-hello` ([`crate::device::device_key`]) … Any one wrap opens the master key.
//!
//! The same bytes as TypeScript `ts/src/keyfile.ts` (`wrapMaster` / `unwrapMaster`), guarded by
//! `testvectors/regino/keyfile-0.22.0.json`. The JSON file around the wraps
//! (`{ format: "regino-keyfile", v: 1, app, kdf, words, wraps }`) is described there; apps with a Rust
//! side store the same fields with their own serializer.
//!
//! Format: `"RGK1" | nonce(12) | AES-256-GCM(master)(32 + 16)` = 64 bytes, AAD
//! `"RGK1" | "regino keyfile v1|<app>|<method>"`. App: `[a-z][a-z0-9]{1,31}`; method:
//! `[a-z][a-z0-9-]{0,31}` optionally followed by `:` and a label of the same form.

use crate::{Error, Key, KEY_LEN};
use aes_gcm::aead::{Aead, KeyInit, Payload};
use aes_gcm::Aes256Gcm;

const MAGIC: &[u8; 4] = b"RGK1";
const NONCE_LEN: usize = 12;
/// Bytes of one wrap.
pub const WRAP_LEN: usize = 4 + NONCE_LEN + KEY_LEN + 16;

fn part_ok(s: &str) -> bool {
    let b = s.as_bytes();
    !b.is_empty() && b.len() <= 32 && b[0].is_ascii_lowercase() && b.iter().all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || *c == b'-')
}

fn app_ok(app: &str) -> bool {
    let b = app.as_bytes();
    (2..=32).contains(&b.len()) && b[0].is_ascii_lowercase() && b.iter().all(|c| c.is_ascii_lowercase() || c.is_ascii_digit())
}

fn method_ok(method: &str) -> bool {
    match method.split_once(':') {
        Some((a, b)) => part_ok(a) && part_ok(b),
        None => part_ok(method),
    }
}

fn aad(app: &str, method: &str) -> Result<Vec<u8>, Error> {
    if !app_ok(app) || !method_ok(method) {
        return Err(Error::Format);
    }
    let mut a = MAGIC.to_vec();
    a.extend_from_slice(format!("regino keyfile v1|{app}|{method}").as_bytes());
    Ok(a)
}

/// Wraps `master` with `kek` for `app` and `method` with a given nonce – for test vectors only.
#[doc(hidden)]
pub fn wrap_master_with_nonce(kek: &Key, master: &Key, app: &str, method: &str, nonce: [u8; NONCE_LEN]) -> Result<Vec<u8>, Error> {
    let aad = aad(app, method)?;
    let ct = Aes256Gcm::new(kek.as_bytes().into())
        .encrypt(&nonce.into(), Payload { msg: master.as_bytes(), aad: &aad })
        .map_err(|_| Error::Decrypt)?;
    let mut out = Vec::with_capacity(WRAP_LEN);
    out.extend_from_slice(MAGIC);
    out.extend_from_slice(&nonce);
    out.extend_from_slice(&ct);
    Ok(out)
}

/// Wraps `master` with `kek` for `app` and `method` (random nonce, 64 bytes).
pub fn wrap_master(kek: &Key, master: &Key, app: &str, method: &str) -> Result<Vec<u8>, Error> {
    let mut nonce = [0u8; NONCE_LEN];
    getrandom::fill(&mut nonce).map_err(|e| Error::Random(e.to_string()))?;
    wrap_master_with_nonce(kek, master, app, method, nonce)
}

/// Opens a wrap: `Format` for an invalid app or method or damaged bytes, `Decrypt` for a wrong key,
/// another app or another method – never a different key.
pub fn unwrap_master(kek: &Key, wrap: &[u8], app: &str, method: &str) -> Result<Key, Error> {
    let aad = aad(app, method)?;
    if wrap.len() != WRAP_LEN || &wrap[..4] != MAGIC {
        return Err(Error::Format);
    }
    let nonce: &[u8; NONCE_LEN] = wrap[4..4 + NONCE_LEN].try_into().map_err(|_| Error::Format)?;
    let plain = Aes256Gcm::new(kek.as_bytes().into())
        .decrypt(nonce.into(), Payload { msg: &wrap[4 + NONCE_LEN..], aad: &aad })
        .map(zeroize::Zeroizing::new)
        .map_err(|_| Error::Decrypt)?;
    Key::from_slice(&plain)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn round_trip_and_binding() {
        let kek = Key::generate().unwrap();
        let master = Key::generate().unwrap();
        let w = wrap_master(&kek, &master, "app", "shares").unwrap();
        assert_eq!(w.len(), WRAP_LEN);
        assert_ne!(w, wrap_master(&kek, &master, "app", "shares").unwrap());
        assert_eq!(unwrap_master(&kek, &w, "app", "shares").unwrap(), master);
        assert_eq!(unwrap_master(&kek, &w, "app", "password").err(), Some(Error::Decrypt));
        assert_eq!(unwrap_master(&kek, &w, "iny", "shares").err(), Some(Error::Decrypt));
        assert_eq!(unwrap_master(&Key::generate().unwrap(), &w, "app", "shares").err(), Some(Error::Decrypt));
        let mut bad = w.clone();
        bad[0] = 0;
        assert_eq!(unwrap_master(&kek, &bad, "app", "shares").err(), Some(Error::Format));
        assert_eq!(unwrap_master(&kek, &w[..63], "app", "shares").err(), Some(Error::Format));
        assert_eq!(unwrap_master(&kek, &w, "app", "device:windows-hello").err(), Some(Error::Decrypt));
    }

    #[test]
    fn invalid_names() {
        let k = Key::generate().unwrap();
        for (app, method) in [("A", "x"), ("a", "x"), ("app_", "x"), ("app", ""), ("app", "Shares"), ("app", "a:b:c"), ("app", ":x"), ("app", "x:"), ("app", "1x")] {
            assert_eq!(wrap_master(&k, &k, app, method).err(), Some(Error::Format), "{app} {method}");
            assert_eq!(unwrap_master(&k, &[0u8; WRAP_LEN], app, method).err(), Some(Error::Format), "{app} {method}");
        }
        assert!(wrap_master(&k, &k, &"a".repeat(32), &"b".repeat(32)).is_ok());
        assert_eq!(wrap_master(&k, &k, &"a".repeat(33), "x").err(), Some(Error::Format));
        assert_eq!(wrap_master(&k, &k, "app", &"b".repeat(33)).err(), Some(Error::Format));
    }
}
