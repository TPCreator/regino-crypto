//! Key from a password: Argon2id. Parameters and salt are stored with the wrapped key so they can be raised later
//! (within [`KdfParams::MIN`] and [`KdfParams::MAX`], checked before any work).

use crate::{Error, Key, KEY_LEN};
use argon2::{Algorithm, Argon2, Params, Version};

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
    /// Upper bound (since 0.15.1): 128 MiB, 8 passes, 4 lanes – and [`KdfParams::MAX_WORK_KIB`].
    pub const MAX: KdfParams = KdfParams { memory_kib: 131072, iterations: 8, parallelism: 4 };
    /// Upper bound of `memory × passes` (KiB): 256 MiB.
    pub const MAX_WORK_KIB: u64 = 262144;

    /// Whether the parameters are within [`KdfParams::MIN`] and [`KdfParams::MAX`] (and `memory × passes`
    /// ≤ [`KdfParams::MAX_WORK_KIB`]). Checked before any work, so parameters stored next to a wrapped key
    /// or in a backup header (both can be planted) cannot start an Argon2id of gigabytes or hours.
    /// The default (64 MiB, 3 passes) and the backup-code default (32 MiB, 2 passes) are within.
    pub fn is_valid(&self) -> bool {
        (Self::MIN.memory_kib..=Self::MAX.memory_kib).contains(&self.memory_kib)
            && (Self::MIN.iterations..=Self::MAX.iterations).contains(&self.iterations)
            && (Self::MIN.parallelism..=Self::MAX.parallelism).contains(&self.parallelism)
            && u64::from(self.memory_kib) * u64::from(self.iterations) <= Self::MAX_WORK_KIB
    }

    fn check(&self) -> Result<Params, Error> {
        if !self.is_valid() {
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
    Key::fill(|out| a.hash_password_into(password, salt, out).map_err(|_| Error::KdfParams))
}

#[cfg(test)]
mod tests {
    use super::*;

    /// 0.15.1 (audit N1): parameters of a planted key file above the upper bounds are refused before any
    /// work – the same bounds as for a backup code (`backup_code::valid_params`).
    #[test]
    fn upper_bounds_before_any_work() {
        let salt = [1u8; 16];
        // memory × passes above 256 MiB (each part alone is allowed)
        for p in [
            KdfParams { memory_kib: 65536, iterations: 5, parallelism: 1 },
            KdfParams { memory_kib: 131073, iterations: 2, parallelism: 1 },
            KdfParams { memory_kib: 19456, iterations: 9, parallelism: 1 },
            KdfParams { memory_kib: 19456, iterations: 2, parallelism: 5 },
        ] {
            assert_eq!(derive(b"password", &salt, p).unwrap_err(), Error::KdfParams, "{p:?}");
        }
        assert!(derive(b"password", &salt, KdfParams::MIN).is_ok());
        assert!(KdfParams::default().check().is_ok());
    }
}
