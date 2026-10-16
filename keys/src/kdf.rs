//! Key from a password: Argon2id. Parameters and salt are stored with the wrapped key so they can be raised later.

use crate::{Error, Key, KEY_LEN};
use argon2::{Algorithm, Argon2, Params, Version};
use zeroize::Zeroizing;

/// Argon2id parameters. Default: 64 MiB, 3 passes, 1 lane (desktop; ~0.5 s).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct KdfParams {
    pub memory_kib: u32,
    pub iterations: u32,
    pub parallelism: u32,
}

impl Default for KdfParams {
    fn default() -> Self {
        KdfParams { memory_kib: 64 * 1024, iterations: 3, parallelism: 1 }
    }
}

impl KdfParams {
    /// Lower bound (OWASP 2023: 19 MiB, 2 passes) – weaker parameters are rejected.
    pub const MIN: KdfParams = KdfParams { memory_kib: 19 * 1024, iterations: 2, parallelism: 1 };

    fn check(&self) -> Result<Params, Error> {
        if self.memory_kib < Self::MIN.memory_kib || self.iterations < Self::MIN.iterations || self.parallelism == 0 {
            return Err(Error::KdfParams);
        }
        Params::new(self.memory_kib, self.iterations, self.parallelism, Some(KEY_LEN)).map_err(|_| Error::KdfParams)
    }
}

/// New random salt (16 bytes).
pub fn new_salt() -> Result<[u8; 16], Error> {
    let mut s = [0u8; 16];
    getrandom::fill(&mut s).map_err(|e| Error::Random(e.to_string()))?;
    Ok(s)
}

/// Derives a key from a password. Same password + salt + parameters = same key.
pub fn derive(password: &[u8], salt: &[u8; 16], params: KdfParams) -> Result<Key, Error> {
    let a = Argon2::new(Algorithm::Argon2id, Version::V0x13, params.check()?);
    let mut out = Zeroizing::new([0u8; KEY_LEN]);
    a.hash_password_into(password, salt, out.as_mut()).map_err(|_| Error::KdfParams)?;
    Ok(Key::from_bytes(*out))
}
