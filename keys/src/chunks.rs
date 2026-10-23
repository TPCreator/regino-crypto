//! Large files sealed in chunks (e.g. client attachments of several GB) – constant memory,
//! random access for viewers (only the chunks that are needed are opened).
//!
//! Each chunk is sealed on its own with XChaCha20-Poly1305 and a random nonce:
//! `magic(4) | nonce(24) | ciphertext + tag(16)`, magic `RGC1`.
//!
//! AAD = `magic || context || index (u64, big endian) || last (1 byte: 0 or 1)`. The context is the
//! only variable-length field and is followed by a fixed 9 bytes, so AAD is unambiguous. Binding the
//! index and the "last chunk" flag means a chunk cannot be moved to another place in the file,
//! to another file (other context) and the file cannot be cut short or extended without detection:
//! the reader knows the number of chunks from its own record and opens the final one with
//! `last = true` (STREAM construction, Hoang–Reyhanitabar–Rogaway–Vizár 2015, with random nonces).
//!
//! [`Fingerprint`] – keyed fingerprint of the plain content (HMAC-SHA256 with a key derived from the
//! file key and context) to find duplicates of the same file under the same key without revealing
//! anything about the content to anyone without that key.

use crate::{Error, Key};
use chacha20poly1305::aead::{Aead, KeyInit, Payload};
use chacha20poly1305::XChaCha20Poly1305;
use hkdf::Hkdf;
use hmac::{Hmac, KeyInit as _, Mac};
use sha2::Sha256;
use zeroize::Zeroizing;

const MAGIC: &[u8; 4] = b"RGC1";
const NONCE_LEN: usize = 24;
/// Bytes added to every chunk (magic, nonce, tag).
pub const OVERHEAD: usize = 4 + NONCE_LEN + 16;
/// Recommended plain chunk size: 4 MiB.
pub const CHUNK_SIZE: usize = 4 * 1024 * 1024;

fn aad(context: &[u8], index: u64, last: bool) -> Vec<u8> {
    let mut a = Vec::with_capacity(4 + context.len() + 9);
    a.extend_from_slice(MAGIC);
    a.extend_from_slice(context);
    a.extend_from_slice(&index.to_be_bytes());
    a.push(u8::from(last));
    a
}

/// Number of chunks for a file of `len` bytes (an empty file has one empty chunk).
pub fn chunk_count(len: u64, chunk_size: usize) -> u64 {
    let size = chunk_size.max(1) as u64;
    len.div_ceil(size).max(1)
}

/// Seals chunk number `index` (from 0); `last` = this is the final chunk of the file.
pub fn seal_chunk(key: &Key, context: &[u8], index: u64, last: bool, data: &[u8]) -> Result<Vec<u8>, Error> {
    if context.is_empty() {
        return Err(Error::EmptyContext);
    }
    let mut nonce = [0u8; NONCE_LEN];
    getrandom::fill(&mut nonce).map_err(|e| Error::Random(e.to_string()))?;
    let cipher = XChaCha20Poly1305::new(key.as_bytes().into());
    let ct = cipher
        .encrypt(&nonce.into(), Payload { msg: data, aad: &aad(context, index, last) })
        .map_err(|_| Error::Decrypt)?;
    let mut out = Vec::with_capacity(OVERHEAD + data.len());
    out.extend_from_slice(MAGIC);
    out.extend_from_slice(&nonce);
    out.extend_from_slice(&ct);
    Ok(out)
}

/// Opens chunk number `index`; the caller says whether it expects the final chunk. Wrong key,
/// context, position, flag or corruption = error.
pub fn open_chunk(key: &Key, context: &[u8], index: u64, last: bool, blob: &[u8]) -> Result<Zeroizing<Vec<u8>>, Error> {
    if context.is_empty() {
        return Err(Error::EmptyContext);
    }
    if blob.len() < OVERHEAD || &blob[..4] != MAGIC {
        return Err(Error::Format);
    }
    let nonce: &[u8; NONCE_LEN] = blob[4..4 + NONCE_LEN].try_into().map_err(|_| Error::Format)?;
    let cipher = XChaCha20Poly1305::new(key.as_bytes().into());
    cipher
        .decrypt(nonce.into(), Payload { msg: &blob[4 + NONCE_LEN..], aad: &aad(context, index, last) })
        .map(Zeroizing::new)
        .map_err(|_| Error::Decrypt)
}

/// Keyed fingerprint of plain content, computed while the file is read chunk by chunk.
/// Same key + same context + same content = same fingerprint; without the key it says nothing.
pub struct Fingerprint(Hmac<Sha256>);

impl Fingerprint {
    pub fn new(key: &Key, context: &[u8]) -> Result<Fingerprint, Error> {
        if context.is_empty() {
            return Err(Error::EmptyContext);
        }
        let mut fk = Zeroizing::new([0u8; 32]);
        Hkdf::<Sha256>::new(None, key.as_bytes())
            .expand_multi_info(&[b"regino fingerprint v1|", context], fk.as_mut())
            .map_err(|_| Error::Format)?;
        let mac = Hmac::<Sha256>::new_from_slice(fk.as_ref()).map_err(|_| Error::Format)?;
        Ok(Fingerprint(mac))
    }
    pub fn update(&mut self, data: &[u8]) {
        self.0.update(data);
    }
    pub fn finish(self) -> [u8; 32] {
        self.0.finalize().into_bytes().into()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn key() -> Key {
        Key::from_bytes([7u8; 32])
    }

    #[test]
    fn roundtrip_and_overhead() {
        let k = key();
        let c = seal_chunk(&k, b"app/file/f1", 0, true, b"obsah suboru").unwrap();
        assert_eq!(c.len(), OVERHEAD + 12);
        assert_eq!(open_chunk(&k, b"app/file/f1", 0, true, &c).unwrap().as_slice(), b"obsah suboru");
        assert_ne!(c, seal_chunk(&k, b"app/file/f1", 0, true, b"obsah suboru").unwrap());
        let empty = seal_chunk(&k, b"app/file/f1", 0, true, b"").unwrap();
        assert_eq!(open_chunk(&k, b"app/file/f1", 0, true, &empty).unwrap().len(), 0);
    }

    #[test]
    fn chunk_cannot_move_or_truncate() {
        let k = key();
        let c1 = seal_chunk(&k, b"app/file/f1", 1, false, b"stred").unwrap();
        assert_eq!(open_chunk(&k, b"app/file/f1", 2, false, &c1).err(), Some(Error::Decrypt), "another position");
        assert_eq!(open_chunk(&k, b"app/file/f1", 1, true, &c1).err(), Some(Error::Decrypt), "file cut after this chunk");
        assert_eq!(open_chunk(&k, b"app/file/f2", 1, false, &c1).err(), Some(Error::Decrypt), "another file");
        assert_eq!(open_chunk(&Key::from_bytes([8u8; 32]), b"app/file/f1", 1, false, &c1).err(), Some(Error::Decrypt), "another key");
        let mut bad = c1.clone();
        *bad.last_mut().unwrap() ^= 1;
        assert_eq!(open_chunk(&k, b"app/file/f1", 1, false, &bad).err(), Some(Error::Decrypt));
        assert_eq!(open_chunk(&k, b"app/file/f1", 1, false, &c1[..10]).err(), Some(Error::Format));
        assert_eq!(open_chunk(&k, b"app/file/f1", 1, false, b"RGS1xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx").err(), Some(Error::Format));
        assert_eq!(seal_chunk(&k, b"", 0, true, b"x").err(), Some(Error::EmptyContext));
        assert_eq!(open_chunk(&k, b"", 0, true, &c1).err(), Some(Error::EmptyContext));
    }

    #[test]
    fn context_and_index_do_not_collide() {
        // context "a" + index 0x0100… vs. context "a\x01" + index … – AAD differ because the suffix has a fixed length
        assert_ne!(aad(b"a", 1, false), aad(b"a\x00", 1, false));
        assert_eq!(aad(b"ctx", 258, true).len(), 4 + 3 + 9);
    }

    #[test]
    fn counts() {
        assert_eq!(chunk_count(0, CHUNK_SIZE), 1);
        assert_eq!(chunk_count(1, CHUNK_SIZE), 1);
        assert_eq!(chunk_count(CHUNK_SIZE as u64, CHUNK_SIZE), 1);
        assert_eq!(chunk_count(CHUNK_SIZE as u64 + 1, CHUNK_SIZE), 2);
        assert_eq!(chunk_count(2 * 1024 * 1024 * 1024, CHUNK_SIZE), 512);
    }

    #[test]
    fn fingerprint_is_keyed_and_streaming() {
        let k = key();
        let mut a = Fingerprint::new(&k, b"app/client/c1").unwrap();
        a.update(b"ahoj ");
        a.update(b"svet");
        let mut b = Fingerprint::new(&k, b"app/client/c1").unwrap();
        b.update(b"ahoj svet");
        let fa = a.finish();
        assert_eq!(fa, b.finish());
        let mut other_key = Fingerprint::new(&Key::from_bytes([9u8; 32]), b"app/client/c1").unwrap();
        other_key.update(b"ahoj svet");
        assert_ne!(fa, other_key.finish());
        let mut other_ctx = Fingerprint::new(&k, b"app/client/c2").unwrap();
        other_ctx.update(b"ahoj svet");
        assert_ne!(fa, other_ctx.finish());
        assert!(Fingerprint::new(&k, b"").is_err());
    }
}
