//! Keys for apps built on the regino-crypto core.
//!
//! - [`kdf`] – key from a password via Argon2id (parameters are stored with the data and can be raised).
//! - [`backup_code`] – 16-character backup code (Crockford Base32 + check character), keys through Argon2id.
//! - [`backup_chunks`] – large files in backups: content-addressed chunks (HMAC name, AES-256-GCM), shared by all backups.
//! - [`chunks`] – large files sealed in chunks (index and final-chunk flag authenticated) and a keyed fingerprint.
//! - [`wrap`] – wrapping a key with another key and sealing data (XChaCha20-Poly1305, version in the header).
//! - [`keyfile`] – master key wrapped per method (password, recovery phrase, shares, device), AES-256-GCM, same bytes as TypeScript.
//! - [`recovery`] – key from a recovery phrase (12 or 24 words) via HKDF-SHA256.
//! - [`device`] – key from a secret held by the device (Windows Hello signature, passkey PRF) via HKDF-SHA256 – quick unlock.
//! - [`group`] – code and id derived from a group key (comparing by phone, key-bound ids).
//! - [`sign`] – Ed25519 signatures: personal signing key, fingerprint, signed wrapped keys, signed member lists.
//! - [`shamir`] – splitting a key into N shares of which any K suffice (e.g. 2-of-3), with integrity check.
//!
//! Deleting data = discarding the wrapped key (crypto-shredding): without it, sealed data
//! is unreadable – in the database and in every backup made after the key was discarded.
//! A backup made before still carries the wrapped key; the app must handle such backups.

use subtle::ConstantTimeEq;
use zeroize::{Zeroize, Zeroizing};

pub mod backup_chunks;
pub mod backup_code;
pub mod chunks;
pub mod context;
pub mod device;
pub mod group;
pub mod kdf;
pub mod keyfile;
pub mod recovery;
pub mod shamir;
pub mod sign;
pub mod wrap;

/// Core version – the app shows it in "About" (together with the commit from Cargo.lock).
pub const VERSION: &str = env!("CARGO_PKG_VERSION");

pub const KEY_LEN: usize = 32;

/// 256-bit key; its memory is zeroed when dropped. The bytes live in one place on the heap (since 0.15.1):
/// moving or returning a `Key` moves a pointer, not copies of the key that would stay behind unwiped.
pub struct Key(Box<Zeroizing<[u8; KEY_LEN]>>);

impl Key {
    pub fn generate() -> Result<Key, Error> {
        Key::fill(|b| getrandom::fill(b).map_err(|e| Error::Random(e.to_string())))
    }

    /// Key from bytes. The argument is a copy the caller passes by value; it is wiped here, but the
    /// caller's own variable is the caller's to wipe (`Zeroizing`) – inside the core keys are written in
    /// place ([`Key::fill`]) without such copies.
    pub fn from_bytes(mut bytes: [u8; KEY_LEN]) -> Key {
        let k = Key::from_slice(&bytes).expect("32 bytes");
        bytes.zeroize();
        k
    }

    /// Key written in place by `f` into zeroed memory (nothing to wipe elsewhere).
    pub(crate) fn fill<E>(f: impl FnOnce(&mut [u8; KEY_LEN]) -> Result<(), E>) -> Result<Key, E> {
        let mut k = Key(Box::new(Zeroizing::new([0u8; KEY_LEN])));
        f(&mut k.0)?;
        Ok(k)
    }

    /// Key copied from exactly 32 bytes (`Error::Format` otherwise).
    pub(crate) fn from_slice(bytes: &[u8]) -> Result<Key, Error> {
        if bytes.len() != KEY_LEN {
            return Err(Error::Format);
        }
        Key::fill(|b| {
            b.copy_from_slice(bytes);
            Ok(())
        })
    }
    pub fn as_bytes(&self) -> &[u8; KEY_LEN] {
        &self.0
    }
}

impl PartialEq for Key {
    /// Constant-time comparison (`subtle`), so a wrong key is not revealed byte by byte through timing.
    fn eq(&self, other: &Self) -> bool {
        self.as_bytes().ct_eq(other.as_bytes()).into()
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
    #[error("Invalid signature.")]
    BadSignature,
    #[error("The signature is valid, but the signer is not trusted for this.")]
    UntrustedSigner,
    #[error("The list does not continue the one already trusted.")]
    BadChain,
    #[error("Versions of the list that were already accepted are missing (withheld).")]
    Withheld,
}
