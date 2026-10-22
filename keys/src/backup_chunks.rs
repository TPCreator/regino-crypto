//! Large files in backups: content-addressed chunks next to the backup (same format as
//! `ts/src/backupChunks.ts`, shared test vectors in `testvectors/regino/backup-chunks-0.11.0.json`).
//!
//! - Keys from the recovery code via HKDF-SHA256 (no salt, so the same content gets the same name in
//!   every backup): info `<app> backup chunks v1[ k128]|enc` and `…|name`.
//! - Name = hex(HMAC-SHA256(name key, content)) – 64 characters; thirty backups share one copy.
//! - File `<name>.rgb` = `RGB1 | nonce (12) | AES-256-GCM(enc key, content, AAD = "RGB1|<app>|<name>")`.
//!   Opening recomputes the name from the content (constant time).

use crate::Error;
use aes_gcm::aead::{Aead, KeyInit, Payload};
use aes_gcm::{Aes256Gcm, Nonce};
use hkdf::Hkdf;
use hmac::{Hmac, Mac};
use sha2::Sha256;
use subtle::ConstantTimeEq;
use zeroize::Zeroizing;

const MAGIC: &[u8; 4] = b"RGB1";
/// Bytes added to every chunk (magic, nonce, tag).
pub const OVERHEAD: usize = 4 + 12 + 16;

/// Keys for one application and one recovery code.
pub struct BackupChunkKeys {
    app: String,
    enc: Zeroizing<[u8; 32]>,
    name: Zeroizing<[u8; 32]>,
}

fn valid_app(app: &str) -> bool {
    let b = app.as_bytes();
    (2..=32).contains(&b.len()) && b[0].is_ascii_lowercase() && b.iter().all(|c| c.is_ascii_lowercase() || c.is_ascii_digit())
}

/// A chunk name: 64 lowercase hex characters (also safe as a file name).
pub fn valid_name(name: &str) -> bool {
    name.len() == 64 && name.bytes().all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
}

impl BackupChunkKeys {
    /// `secret` = bytes of the recovery code (16 for 12 words, 32 for 24 words).
    pub fn new(secret: &[u8], app: &str) -> Result<BackupChunkKeys, Error> {
        if !valid_app(app) || !(secret.len() == 16 || secret.len() == 32) {
            return Err(Error::Format);
        }
        let k128 = if secret.len() == 16 { " k128" } else { "" };
        let hk = Hkdf::<Sha256>::new(Some(&[]), secret);
        let mut enc = Zeroizing::new([0u8; 32]);
        let mut name = Zeroizing::new([0u8; 32]);
        hk.expand(format!("{app} backup chunks v1{k128}|enc").as_bytes(), enc.as_mut()).map_err(|_| Error::Format)?;
        hk.expand(format!("{app} backup chunks v1{k128}|name").as_bytes(), name.as_mut()).map_err(|_| Error::Format)?;
        Ok(BackupChunkKeys { app: app.to_string(), enc, name })
    }

    fn mac(&self, plain: &[u8]) -> [u8; 32] {
        let mut m = <Hmac<Sha256> as Mac>::new_from_slice(self.name.as_ref()).expect("HMAC takes any key length");
        m.update(plain);
        m.finalize().into_bytes().into()
    }

    fn aad(&self, name: &str) -> Vec<u8> {
        format!("RGB1|{}|{name}", self.app).into_bytes()
    }

    /// Name of a chunk with this content.
    pub fn name(&self, plain: &[u8]) -> String {
        self.mac(plain).iter().map(|b| format!("{b:02x}")).collect()
    }

    /// Seals a chunk; returns its name and the file contents.
    pub fn seal(&self, plain: &[u8]) -> Result<(String, Vec<u8>), Error> {
        let name = self.name(plain);
        let mut nonce = [0u8; 12];
        getrandom::fill(&mut nonce).map_err(|e| Error::Random(e.to_string()))?;
        let ct = Aes256Gcm::new(self.enc.as_ref().into())
            .encrypt(Nonce::from_slice(&nonce), Payload { msg: plain, aad: &self.aad(&name) })
            .map_err(|_| Error::Decrypt)?;
        let mut out = Vec::with_capacity(OVERHEAD + plain.len());
        out.extend_from_slice(MAGIC);
        out.extend_from_slice(&nonce);
        out.extend_from_slice(&ct);
        Ok((name, out))
    }

    /// Opens a chunk file; wrong code, damage or a chunk under another name = error.
    pub fn open(&self, name: &str, blob: &[u8]) -> Result<Zeroizing<Vec<u8>>, Error> {
        if !valid_name(name) || blob.len() < OVERHEAD || &blob[..4] != MAGIC {
            return Err(Error::Format);
        }
        let plain = Aes256Gcm::new(self.enc.as_ref().into())
            .decrypt(Nonce::from_slice(&blob[4..16]), Payload { msg: &blob[16..], aad: &self.aad(name) })
            .map(Zeroizing::new)
            .map_err(|_| Error::Decrypt)?;
        let expected: Vec<u8> = (0..32).map(|i| u8::from_str_radix(&name[2 * i..2 * i + 2], 16).unwrap_or(0)).collect();
        if !bool::from(self.mac(&plain).as_slice().ct_eq(&expected)) {
            return Err(Error::Decrypt);
        }
        Ok(plain)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn unhex(s: &str) -> Vec<u8> {
        (0..s.len() / 2).map(|i| u8::from_str_radix(&s[2 * i..2 * i + 2], 16).unwrap()).collect()
    }

    fn unb64(s: &str) -> Vec<u8> {
        const A: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
        let mut out = Vec::new();
        let (mut buf, mut bits) = (0u32, 0);
        for c in s.bytes().filter(|&c| c != b'=') {
            buf = (buf << 6) | A.iter().position(|&a| a == c).unwrap() as u32;
            bits += 6;
            if bits >= 8 {
                bits -= 8;
                out.push((buf >> bits) as u8);
            }
        }
        out
    }

    #[test]
    fn vectors_shared_with_typescript() {
        let v: serde_json::Value = serde_json::from_str(include_str!("../../testvectors/regino/backup-chunks-0.11.0.json")).unwrap();
        for t in v["chunks"].as_array().unwrap() {
            let k = BackupChunkKeys::new(&unhex(t["secret"].as_str().unwrap()), t["app"].as_str().unwrap()).unwrap();
            let plain = unb64(t["plain"].as_str().unwrap());
            let name = t["name"].as_str().unwrap();
            assert_eq!(k.name(&plain), name);
            assert_eq!(k.open(name, &unb64(t["blob"].as_str().unwrap())).unwrap().as_slice(), plain.as_slice());
        }
    }

    #[test]
    fn roundtrip_dedup_and_refusals() {
        let k = BackupChunkKeys::new(&[1u8; 16], "dovernik").unwrap();
        let (n1, b1) = k.seal(b"obsah").unwrap();
        let (n2, b2) = k.seal(b"obsah").unwrap();
        assert_eq!(n1, n2, "same content, same name");
        assert_ne!(b1, b2, "random nonce");
        assert_eq!(b1.len(), OVERHEAD + 5);
        assert_eq!(k.open(&n1, &b1).unwrap().as_slice(), b"obsah");
        let (n3, _) = k.seal(b"iny").unwrap();
        assert_eq!(k.open(&n3, &b1).err(), Some(Error::Decrypt), "chunk under another name");
        assert_eq!(BackupChunkKeys::new(&[2u8; 16], "dovernik").unwrap().open(&n1, &b1).err(), Some(Error::Decrypt));
        assert_eq!(BackupChunkKeys::new(&[1u8; 16], "demo").unwrap().open(&n1, &b1).err(), Some(Error::Decrypt));
        assert_ne!(BackupChunkKeys::new(&[1u8; 32], "dovernik").unwrap().name(b"obsah"), n1);
        let mut bad = b1.clone();
        *bad.last_mut().unwrap() ^= 1;
        assert_eq!(k.open(&n1, &bad).err(), Some(Error::Decrypt));
        assert_eq!(k.open(&n1, &b1[..10]).err(), Some(Error::Format));
        assert_eq!(k.open("../x", &b1).err(), Some(Error::Format));
        assert!(BackupChunkKeys::new(&[1u8; 20], "dovernik").is_err());
        assert!(BackupChunkKeys::new(&[1u8; 16], "Dovernik").is_err());
        assert!(valid_name(&n1) && !valid_name(&n1.to_uppercase()));
    }

    #[test]
    fn name_mismatch_with_valid_tag_is_refused() {
        let k = BackupChunkKeys::new(&[3u8; 32], "demo").unwrap();
        let fake = "0".repeat(64);
        let nonce = [0u8; 12];
        let ct = Aes256Gcm::new(k.enc.as_ref().into()).encrypt(Nonce::from_slice(&nonce), Payload { msg: b"A", aad: &k.aad(&fake) }).unwrap();
        let blob = [MAGIC.as_slice(), &nonce, &ct].concat();
        assert_eq!(k.open(&fake, &blob).err(), Some(Error::Decrypt));
    }
}
