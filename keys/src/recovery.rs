//! Key from a recovery phrase (12 or 24 words) used to wrap the master key.
//!
//! Words <-> bytes conversion is done by `@regino/crypto` (`wordsToSecret`); this module receives
//! the secret itself – 16 bytes (12 words, 128 bits) or 32 bytes (24 words, 256 bits).
//! HKDF-SHA256 turns it into a 256-bit key. The length is part of the context, so 12- and 24-word
//! phrases cannot be confused; the app name separates keys of different apps.
//! The same computation exists in TypeScript (`recoveryKey`) – a fixed-vector test guards that they match.

use hkdf::Hkdf;
use sha2::Sha256;
use zeroize::Zeroizing;

use crate::{Error, Key, KEY_LEN};

/// HKDF context, e.g. `demo recovery-key v1 k128`.
fn info(app: &str, secret_len: usize) -> Result<String, Error> {
    let ok_app = (2..=32).contains(&app.len())
        && app.as_bytes()[0].is_ascii_lowercase()
        && app.bytes().all(|b| b.is_ascii_lowercase() || b.is_ascii_digit());
    if !ok_app {
        return Err(Error::Format);
    }
    match secret_len {
        16 | 32 => Ok(format!("{app} recovery-key v1 k{}", secret_len * 8)),
        _ => Err(Error::Format),
    }
}

/// Recovery phrase secret -> key for wrapping (`wrap::wrap_key`).
pub fn recovery_key(secret: &[u8], app: &str) -> Result<Key, Error> {
    let info = info(app, secret.len())?;
    let mut out = Zeroizing::new([0u8; KEY_LEN]);
    Hkdf::<Sha256>::new(None, secret)
        .expand(info.as_bytes(), out.as_mut())
        .map_err(|_| Error::Format)?;
    Ok(Key::from_bytes(*out))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn hex(k: &Key) -> String {
        k.as_bytes().iter().map(|b| format!("{b:02x}")).collect()
    }

    #[test]
    fn fixed_vectors_match_typescript() {
        let s16: Vec<u8> = (0..16).collect();
        let s32: Vec<u8> = (0..32).collect();
        assert_eq!(hex(&recovery_key(&s16, "demo").unwrap()), VEC_12);
        assert_eq!(hex(&recovery_key(&s32, "demo").unwrap()), VEC_24);
    }

    #[test]
    fn length_and_app_change_key() {
        let s32: Vec<u8> = (0..32).collect();
        let a = recovery_key(&s32, "demo").unwrap();
        assert!(a != recovery_key(&s32[..16], "demo").unwrap());
        assert!(a != recovery_key(&s32, "other").unwrap());
    }

    #[test]
    fn rejects_bad_length_and_name() {
        assert_eq!(recovery_key(&[0u8; 20], "demo").unwrap_err(), Error::Format);
        for bad in ["", "D", "Demo", "1abc", "de-mo"] {
            assert_eq!(recovery_key(&[0u8; 16], bad).unwrap_err(), Error::Format, "{bad}");
        }
    }

    const VEC_12: &str = "4d5711cad6ba1e73e9417e9b796bce4e2f3e81b4208a436da51eaef046d55b59";
    const VEC_24: &str = "5bb59f517c2278f3c4e392fc31514a57fa04e678ec5edc0d41975d08ae4ac700";
}
