//! Key wrapping (KEK -> DEK) and data sealing. XChaCha20-Poly1305 with a random 192-bit nonce.
//!
//! Format: `magic(4) | nonce(24) | ciphertext + tag(16)`.
//! `context` (e.g. `demo/client/01J…`) is authenticated but not stored – so the wrapped key of one
//! client cannot be passed off as the key of another.
//!
//! The context must not be empty (`Error::EmptyContext`) – an empty context binds nothing.
//!
//! AAD = `magic || context`. The magic has a fixed length and the context is the only variable
//! field, so no length prefix is needed: different contexts always give different AAD (question 2 in
//! AUDIT.md). The caller must build the context itself unambiguously, e.g. `<app>/client/<id>` with
//! ids that cannot contain the separator.

use crate::{Error, Key, KEY_LEN};
use chacha20poly1305::aead::{Aead, KeyInit, Payload};
use chacha20poly1305::{XChaCha20Poly1305, XNonce};
use zeroize::Zeroizing;

const WRAP_MAGIC: &[u8; 4] = b"RGW1";
const SEAL_MAGIC: &[u8; 4] = b"RGS1";
const NONCE_LEN: usize = 24;

fn aad(magic: &[u8; 4], context: &[u8]) -> Vec<u8> {
    let mut a = magic.to_vec();
    a.extend_from_slice(context);
    a
}

fn encrypt(magic: &[u8; 4], key: &Key, plain: &[u8], context: &[u8]) -> Result<Vec<u8>, Error> {
    if context.is_empty() {
        return Err(Error::EmptyContext);
    }
    let mut nonce = [0u8; NONCE_LEN];
    getrandom::fill(&mut nonce).map_err(|e| Error::Random(e.to_string()))?;
    let cipher = XChaCha20Poly1305::new(key.as_bytes().into());
    let ct = cipher
        .encrypt(XNonce::from_slice(&nonce), Payload { msg: plain, aad: &aad(magic, context) })
        .map_err(|_| Error::Decrypt)?;
    let mut out = Vec::with_capacity(4 + NONCE_LEN + ct.len());
    out.extend_from_slice(magic);
    out.extend_from_slice(&nonce);
    out.extend_from_slice(&ct);
    Ok(out)
}

fn decrypt(magic: &[u8; 4], key: &Key, blob: &[u8], context: &[u8]) -> Result<Zeroizing<Vec<u8>>, Error> {
    if context.is_empty() {
        return Err(Error::EmptyContext);
    }
    if blob.len() < 4 + NONCE_LEN + 16 || &blob[..4] != magic {
        return Err(Error::Format);
    }
    let cipher = XChaCha20Poly1305::new(key.as_bytes().into());
    cipher
        .decrypt(XNonce::from_slice(&blob[4..4 + NONCE_LEN]), Payload { msg: &blob[4 + NONCE_LEN..], aad: &aad(magic, context) })
        .map(Zeroizing::new)
        .map_err(|_| Error::Decrypt)
}

/// Wraps the key `inner` with the key `kek`.
pub fn wrap_key(kek: &Key, inner: &Key, context: &[u8]) -> Result<Vec<u8>, Error> {
    encrypt(WRAP_MAGIC, kek, inner.as_bytes(), context)
}

/// Unwraps a key; a wrong key, different context or corruption = error, never a different key.
pub fn unwrap_key(kek: &Key, blob: &[u8], context: &[u8]) -> Result<Key, Error> {
    let plain = decrypt(WRAP_MAGIC, kek, blob, context)?;
    let bytes: [u8; KEY_LEN] = plain.as_slice().try_into().map_err(|_| Error::Format)?;
    Ok(Key::from_bytes(bytes))
}

/// Seals arbitrary data (e.g. session notes) with the client's key.
pub fn seal(key: &Key, data: &[u8], context: &[u8]) -> Result<Vec<u8>, Error> {
    encrypt(SEAL_MAGIC, key, data, context)
}

/// Opens sealed data.
pub fn open(key: &Key, blob: &[u8], context: &[u8]) -> Result<Zeroizing<Vec<u8>>, Error> {
    decrypt(SEAL_MAGIC, key, blob, context)
}
