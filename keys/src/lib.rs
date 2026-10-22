//! Keys for apps built on the regino-crypto core.
//!
//! - [`kdf`] – key from a password via Argon2id (parameters are stored with the data and can be raised).
//! - [`backup_chunks`] – large files in backups: content-addressed chunks (HMAC name, AES-256-GCM), shared by all backups.
//! - [`chunks`] – large files sealed in chunks (index and final-chunk flag authenticated) and a keyed fingerprint.
//! - [`wrap`] – wrapping a key with another key and sealing data (XChaCha20-Poly1305, version in the header).
//! - [`recovery`] – key from a recovery phrase (12 or 24 words) via HKDF-SHA256.
//! - [`device`] – key from a secret held by the device (Windows Hello signature, passkey PRF) via HKDF-SHA256 – quick unlock.
//! - [`shamir`] – splitting a key into N shares of which any K suffice (e.g. 2-of-3), with integrity check.
//!
//! Deleting data = discarding the wrapped key (crypto-shredding): without it, sealed data
//! is unreadable – in the database and in every backup made after the key was discarded.
//! A backup made before still carries the wrapped key; the app must handle such backups.

use subtle::ConstantTimeEq;
use zeroize::Zeroizing;

pub mod backup_chunks;
pub mod chunks;
pub mod device;
pub mod kdf;
pub mod recovery;
pub mod shamir;
pub mod wrap;

/// Core version – the app shows it in "About" (together with the commit from Cargo.lock).
pub const VERSION: &str = env!("CARGO_PKG_VERSION");

pub const KEY_LEN: usize = 32;

/// 256-bit key; its memory is zeroed when dropped.
pub struct Key(Zeroizing<[u8; KEY_LEN]>);

impl Key {
    pub fn generate() -> Result<Key, Error> {
        let mut b = Zeroizing::new([0u8; KEY_LEN]);
        getrandom::fill(b.as_mut()).map_err(|e| Error::Random(e.to_string()))?;
        Ok(Key(b))
    }
    pub fn from_bytes(bytes: [u8; KEY_LEN]) -> Key {
        Key(Zeroizing::new(bytes))
    }
    pub fn as_bytes(&self) -> &[u8; KEY_LEN] {
        &self.0
    }
}

impl PartialEq for Key {
    /// Constant-time comparison (`subtle`), so a wrong key is not revealed byte by byte through timing.
    fn eq(&self, other: &Self) -> bool {
        self.0.as_ref().ct_eq(other.0.as_ref()).into()
    }
}

impl std::fmt::Debug for Key {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("Key(***)")
    }
}

#[derive(Debug, thiserror::Error, PartialEq)]
pub enum Error {
    #[error("Random number generator failed: {0}")]
    Random(String),
    #[error("Invalid Argon2id parameters.")]
    KdfParams,
    #[error("Wrong key or corrupted data.")]
    Decrypt,
    #[error("Unknown or corrupted format.")]
    Format,
    #[error("The context must not be empty.")]
    EmptyContext,
    #[error("Invalid split: {threshold}-of-{shares} (2 <= threshold <= shares <= 255).")]
    BadSplit { threshold: u8, shares: u8 },
    #[error("Too few shares or duplicate shares – {0} distinct shares are required.")]
    NotEnoughShares(u8),
    #[error("Shares do not belong together or one of them is corrupted.")]
    BadShares,
}
