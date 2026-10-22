//! Key from a secret held by the device – for quick unlock without typing the password.
//!
//! The app gets the secret from the operating system only after the user confirms it there:
//! a **Windows Hello** signature of a fixed random challenge (a TPM-bound RSA key, PKCS#1 v1.5 –
//! deterministic, so the same challenge gives the same signature), or the output of a **passkey PRF**
//! (WebAuthn `prf` extension). The secret never leaves the app's process and is never stored.
//! HKDF-SHA256 turns it into a 256-bit key that wraps the master key (`wrap::wrap_key`) next to the
//! password and recovery wraps – the password keeps working, removing the device wrap disables quick unlock.
//!
//! The secret must have at least 32 bytes (a 2048-bit RSA signature has 256). The app name and the
//! method label are part of the HKDF info, so a Windows Hello key and a passkey key never coincide,
//! not even with the same input; the label is lowercase ASCII (e.g. `windows-hello`, `passkey-prf`).

use hkdf::Hkdf;
use sha2::Sha256;
use zeroize::Zeroizing;

use crate::{Error, Key, KEY_LEN};

/// Shortest accepted device secret (bytes).
pub const MIN_SECRET: usize = 32;

fn ok_name(s: &str, min: usize) -> bool {
    (min..=32).contains(&s.len()) && s.as_bytes()[0].is_ascii_lowercase() && s.bytes().all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-')
}

/// HKDF context, e.g. `demo device-key v1 windows-hello`.
fn info(app: &str, method: &str) -> Result<String, Error> {
    if !ok_name(app, 2) || app.contains('-') || !ok_name(method, 3) {
        return Err(Error::Format);
    }
    Ok(format!("{app} device-key v1 {method}"))
}

/// Device secret -> key for wrapping the master key (`wrap::wrap_key`).
pub fn device_key(secret: &[u8], app: &str, method: &str) -> Result<Key, Error> {
    if secret.len() < MIN_SECRET {
        return Err(Error::Format);
    }
    let info = info(app, method)?;
    let mut out = Zeroizing::new([0u8; KEY_LEN]);
    Hkdf::<Sha256>::new(None, secret)
        .expand(info.as_bytes(), out.as_mut())
        .map_err(|_| Error::Format)?;
    Ok(Key::from_bytes(*out))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::wrap;

    fn hex(k: &Key) -> String {
        k.as_bytes().iter().map(|b| format!("{b:02x}")).collect()
    }

    #[test]
    fn fixed_vector() {
        let s: Vec<u8> = (0..=255u8).collect();
        assert_eq!(hex(&device_key(&s, "demo", "windows-hello").unwrap()), VEC_HELLO);
    }

    #[test]
    fn method_app_and_secret_change_the_key() {
        let s: Vec<u8> = (0..64).collect();
        let a = device_key(&s, "demo", "windows-hello").unwrap();
        assert!(a != device_key(&s, "demo", "passkey-prf").unwrap());
        assert!(a != device_key(&s, "other", "windows-hello").unwrap());
        let mut t = s.clone();
        t[63] ^= 1;
        assert!(a != device_key(&t, "demo", "windows-hello").unwrap());
        // never the same as the recovery key of the same bytes
        assert!(device_key(&s[..32], "demo", "passkey-prf").unwrap() != crate::recovery::recovery_key(&s[..32], "demo").unwrap());
    }

    #[test]
    fn refuses_short_secret_and_bad_names() {
        assert_eq!(device_key(&[7u8; 31], "demo", "windows-hello").unwrap_err(), Error::Format);
        assert!(device_key(&[7u8; 32], "demo", "windows-hello").is_ok());
        for (app, m) in [("", "x-y"), ("Demo", "hello"), ("de-mo", "hello"), ("demo", ""), ("demo", "ab"), ("demo", "Hello"), ("demo", "hello world"), ("demo", &"a".repeat(33))] {
            assert_eq!(device_key(&[7u8; 32], app, m).unwrap_err(), Error::Format, "{app} {m}");
        }
    }

    #[test]
    fn wraps_and_unwraps_master_key() {
        let master = Key::generate().unwrap();
        let sig = vec![42u8; 256];
        let k = device_key(&sig, "demo", "windows-hello").unwrap();
        let blob = wrap::wrap_key(&k, &master, b"demo/master/device").unwrap();
        let again = device_key(&sig, "demo", "windows-hello").unwrap();
        assert!(wrap::unwrap_key(&again, &blob, b"demo/master/device").unwrap() == master);
        let wrong = device_key(&[43u8; 256], "demo", "windows-hello").unwrap();
        assert!(wrap::unwrap_key(&wrong, &blob, b"demo/master/device").is_err());
    }

    // HKDF-SHA256(ikm = 0..=255, salt = none, info = "demo device-key v1 windows-hello"), checked with Python hmac/hashlib
    const VEC_HELLO: &str = "798a6ee2d26b83644e682f57ed46bdbd4007246b5ae0ac90542fa54a68a92e32";
}
