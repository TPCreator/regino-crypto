//! Backup code of 16 characters `XXXX-XXXX-XXXX-XXXX` (since 0.15.0) – the same as
//! `ts/src/backupCode.ts`, shared vectors in `testvectors/regino/backup-code-0.15.0.json`.
//!
//! - Crockford Base32 (`0-9 A-Z` without `I L O U`), 15 data characters = 75 random bits, the 16th is a
//!   check character: `Σ α^(i+1)·vᵢ + v₁₅ = 0` in GF(32) (x⁵ + x² + 1) – every single wrong character
//!   and every swap of two different characters is detected.
//! - Reading tolerates lower case, spaces, hyphens/dashes, the QR prefix `RGC1:` and `O → 0`, `I / L → 1`;
//!   errors say what is wrong ([`CodeError`]).
//! - The secret is 10 bytes (75 bits + 5 zero bits). Keys always go through Argon2id (the code has only
//!   75 bits): a backup with a random salt and parameters from its header ([`backup_key`]), the id for a
//!   server and the keys of backup chunks with the fixed salt of the application ([`backup_code_id`],
//!   [`crate::backup_chunks::BackupChunkKeys::from_backup_code`]).
//!
//! Backups themselves (JSON, AES-256-GCM) are written in TypeScript; Rust derives the same keys.

use hkdf::Hkdf;
use sha2::{Digest, Sha256};
use zeroize::Zeroizing;

use crate::kdf::{self, KdfParams};
use crate::{Error, Key};

pub const ALPHABET: &[u8; 32] = b"0123456789ABCDEFGHJKMNPQRSTVWXYZ";
/// Characters of a code (15 data + 1 check).
pub const LENGTH: usize = 16;
/// Bytes of the secret (75 bits + 5 zero bits).
pub const BYTES: usize = 10;
/// Prefix of the QR text on the printed sheet.
pub const QR_PREFIX: &str = "RGC1:";

/// Default for new backups and the fixed parameters of the id and chunk keys: 32 MiB, 2 passes, 1 lane.
pub const DEFAULT_PARAMS: KdfParams = KdfParams { memory_kib: 32768, iterations: 2, parallelism: 1 };
/// Upper bounds accepted from a backup header: 128 MiB, 8 passes, 4 lanes, `memory × passes` ≤ 256 MiB.
/// The lower bound is [`KdfParams::MIN`] (19 MiB, 2 passes). Since 0.15.1 the same bounds apply to every
/// Argon2id of the core ([`KdfParams::MAX`], [`KdfParams::MAX_WORK_KIB`]).
pub const MAX_PARAMS: KdfParams = KdfParams::MAX;
pub const MAX_WORK_KIB: u64 = KdfParams::MAX_WORK_KIB;

/// Whether parameters (e.g. from a backup header) are within the bounds – checked before any work
/// ([`KdfParams::is_valid`]).
pub fn valid_params(p: KdfParams) -> bool {
    p.is_valid()
}

/// A lower upper bound for reading on a phone (since 0.15.1, the same as `MOBILE_BACKUP_CODE_KDF` in
/// TypeScript): 64 MiB, 8 passes, 4 lanes, `memory × passes` ≤ 128 MiB – at most 2× the work of
/// [`DEFAULT_PARAMS`], which it accepts.
pub const MOBILE_MAX_PARAMS: KdfParams = KdfParams { memory_kib: 65536, iterations: 8, parallelism: 4 };
pub const MOBILE_MAX_WORK_KIB: u64 = 131072;

/// [`valid_params`] and within [`MOBILE_MAX_PARAMS`] / [`MOBILE_MAX_WORK_KIB`] – check a header with it
/// before [`backup_key`] on a phone.
pub fn valid_params_mobile(p: KdfParams) -> bool {
    p.is_valid()
        && p.memory_kib <= MOBILE_MAX_PARAMS.memory_kib
        && p.iterations <= MOBILE_MAX_PARAMS.iterations
        && p.parallelism <= MOBILE_MAX_PARAMS.parallelism
        && u64::from(p.memory_kib) * u64::from(p.iterations) <= MOBILE_MAX_WORK_KIB
}

/// Why an input is not a backup code.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CodeError {
    /// After removing separators and the prefix the code does not have 16 characters.
    Length(usize),
    /// `index` = position among the characters of the code (0-based, separators not counted).
    UnknownChar { index: usize, ch: char },
    /// All characters are valid, but the check character does not match.
    Checksum,
}

/// The 10-byte secret of a code; its memory is zeroed when dropped.
pub struct BackupCode(Zeroizing<[u8; BYTES]>);

impl std::fmt::Debug for BackupCode {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("BackupCode(***)")
    }
}

const fn gf_tables() -> ([u8; 31], [u8; 32]) {
    let mut exp = [0u8; 31];
    let mut log = [0u8; 32];
    let mut x: u8 = 1;
    let mut i = 0;
    while i < 31 {
        exp[i] = x;
        log[x as usize] = i as u8;
        x <<= 1;
        if x & 32 != 0 {
            x ^= 0b100101;
        }
        i += 1;
    }
    (exp, log)
}
const GF: ([u8; 31], [u8; 32]) = gf_tables();

fn mul(a: u8, b: u8) -> u8 {
    if a == 0 || b == 0 {
        return 0;
    }
    GF.0[(GF.1[a as usize] as usize + GF.1[b as usize] as usize) % 31]
}

fn check_value(values: &[u8]) -> u8 {
    values.iter().enumerate().fold(0, |s, (i, &v)| s ^ mul(GF.0[i + 1], v))
}

/// Spaces (also no-break), tabs, new lines and hyphens / dashes / minus – the same set as in TypeScript.
fn is_separator(c: char) -> bool {
    matches!(
        c,
        ' ' | '\t' | '\n' | '\r' | '\u{0c}' | '\u{0b}' | '\u{a0}' | '\u{2007}' | '\u{202f}' | '-' | '\u{2010}'
            | '\u{2011}' | '\u{2012}' | '\u{2013}' | '\u{2014}' | '\u{2212}'
    )
}

fn value(c: char) -> Option<u8> {
    let up = match c {
        'a'..='z' => c.to_ascii_uppercase(),
        _ => c,
    };
    let up = match up {
        'O' => '0',
        'I' | 'L' => '1',
        _ => up,
    };
    ALPHABET.iter().position(|&a| a as char == up).map(|i| i as u8)
}

impl BackupCode {
    /// 75 random bits.
    pub fn generate() -> Result<BackupCode, Error> {
        let mut b = Zeroizing::new([0u8; BYTES]);
        getrandom::fill(b.as_mut()).map_err(|e| Error::Random(e.to_string()))?;
        b[9] &= 0xe0;
        Ok(BackupCode(b))
    }

    /// From the 10 bytes; `Error::Format` unless the last 5 bits are zero (one canonical form).
    pub fn from_bytes(bytes: [u8; BYTES]) -> Result<BackupCode, Error> {
        if bytes[9] & 0x1f != 0 {
            return Err(Error::Format);
        }
        Ok(BackupCode(Zeroizing::new(bytes)))
    }

    pub fn as_bytes(&self) -> &[u8; BYTES] {
        &self.0
    }

    /// User input (or the QR text) → code. Errors in this order: first unknown character, length, check.
    pub fn parse(input: &str) -> Result<BackupCode, CodeError> {
        let mut chars: Vec<char> = input.chars().filter(|&c| !is_separator(c)).collect();
        if chars.len() >= 5 && chars[..5].iter().collect::<String>().to_ascii_uppercase() == QR_PREFIX {
            chars.drain(..5);
        }
        let mut values = Zeroizing::new(Vec::with_capacity(LENGTH));
        for (index, &ch) in chars.iter().enumerate() {
            values.push(value(ch).ok_or(CodeError::UnknownChar { index, ch })?);
        }
        if values.len() != LENGTH {
            return Err(CodeError::Length(values.len()));
        }
        if check_value(&values[..15]) != values[15] {
            return Err(CodeError::Checksum);
        }
        let mut b = Zeroizing::new([0u8; BYTES]);
        for (i, &v) in values[..15].iter().enumerate() {
            for bit in 0..5 {
                if (v >> (4 - bit)) & 1 == 1 {
                    let n = i * 5 + bit;
                    b[n / 8] |= 0x80 >> (n % 8);
                }
            }
        }
        Ok(BackupCode(b))
    }

    fn data_values(&self) -> [u8; 15] {
        let mut out = [0u8; 15];
        for (i, o) in out.iter_mut().enumerate() {
            let bit = i * 5;
            let word = (u16::from(self.0[bit / 8]) << 8) | u16::from(self.0[bit / 8 + 1]);
            *o = ((word >> (11 - (bit % 8))) & 31) as u8;
        }
        out
    }

    fn plain(&self) -> Zeroizing<String> {
        let v = self.data_values();
        let mut s = Zeroizing::new(String::with_capacity(LENGTH));
        for &x in v.iter().chain(std::iter::once(&check_value(&v))) {
            s.push(ALPHABET[x as usize] as char);
        }
        s
    }

    /// `XXXX-XXXX-XXXX-XXXX`
    pub fn format(&self) -> Zeroizing<String> {
        let p = self.plain();
        let mut s = Zeroizing::new(String::with_capacity(LENGTH + 3));
        for (i, c) in p.chars().enumerate() {
            if i > 0 && i % 4 == 0 {
                s.push('-');
            }
            s.push(c);
        }
        s
    }

    /// `RGC1:` + 16 characters (the QR code on the sheet).
    pub fn qr_text(&self) -> Zeroizing<String> {
        Zeroizing::new(format!("{QR_PREFIX}{}", self.plain().as_str()))
    }
}

fn check_app(app: &str) -> Result<(), Error> {
    let b = app.as_bytes();
    let ok = (2..=32).contains(&b.len()) && b[0].is_ascii_lowercase() && b.iter().all(|c| c.is_ascii_lowercase() || c.is_ascii_digit());
    if ok {
        Ok(())
    } else {
        Err(Error::Format)
    }
}

/// Argon2id(code, salt, params) → 32 bytes; parameters outside the bounds → `Error::KdfParams`.
pub fn stretch(code: &BackupCode, salt: &[u8; 16], params: KdfParams) -> Result<Key, Error> {
    if !valid_params(params) {
        return Err(Error::KdfParams);
    }
    kdf::derive(code.as_bytes(), salt, params)
}

fn expand(ikm: &Key, info: &str) -> Key {
    Key::fill(|out| Hkdf::<Sha256>::new(Some(&[]), ikm.as_bytes()).expand(info.as_bytes(), out)).expect("32 bytes is a valid HKDF length")
}

/// Key of a version-3 backup: HKDF-SHA256(Argon2id(code, header salt, header parameters), `<app> backup v3 code16`)
/// – the AES-256-GCM key of `ts/src/backup.ts`.
pub fn backup_key(code: &BackupCode, salt: &[u8; 16], params: KdfParams, app: &str) -> Result<Key, Error> {
    check_app(app)?;
    Ok(expand(&stretch(code, salt, params)?, &format!("{app} backup v3 code16")))
}

/// Fixed salt of an application: SHA-256(`regino backup-code salt v1|<app>`)[0..16].
pub fn app_salt(app: &str) -> Result<[u8; 16], Error> {
    check_app(app)?;
    let d = Sha256::digest(format!("regino backup-code salt v1|{app}").as_bytes());
    let mut s = [0u8; 16];
    s.copy_from_slice(&d[..16]);
    Ok(s)
}

/// Argon2id with the fixed salt and [`DEFAULT_PARAMS`] – the same for every backup of one code and app.
pub(crate) fn base(code: &BackupCode, app: &str) -> Result<Key, Error> {
    stretch(code, &app_salt(app)?, DEFAULT_PARAMS)
}

/// Id of a code for a server: HKDF-SHA256(base, `<app> backup-code id v1`). It reveals neither the code
/// nor a key, but guesses can be tested against it offline at Argon2id cost – the server must keep it
/// like a password hash and limit the number of attempts of anyone asking by id (`AUDIT.md`, question 20).
/// For backups of version 3: the fixed salt lets one guess test every id of the application at once and the cost
/// is always [`DEFAULT_PARAMS`] (audit F-02) – new apps use [`backup_id`] with the parameters of a version-4 backup.
pub fn backup_code_id(code: &BackupCode, app: &str) -> Result<[u8; 32], Error> {
    Ok(*expand(&base(code, app)?, &format!("{app} backup-code id v1")).as_bytes())
}

// ---- version 4 (since 0.19.0, audit F-02) ----
//
// One Argon2id(code, header salt, header parameters) gives the backup key, the chunk keys
// (`BackupChunkKeys::from_backup_code_v4`) and the id for a server – so they cost what the header says and differ
// between users (a random salt, not the fixed salt of the application). Backups that share chunks share the salt
// and the parameters. The same as `ts/src/backup.ts` (version 4), `backupChunks.ts` and `backupIdForServer`.

/// Argon2id of a version-4 backup: the one input of its backup key, chunk keys and server id.
pub(crate) fn base_v4(code: &BackupCode, salt: &[u8; 16], params: KdfParams) -> Result<Key, Error> {
    stretch(code, salt, params)
}

/// Key of a version-4 backup: HKDF-SHA256(Argon2id(code, header salt, header parameters), `<app> backup v4 code16`)
/// – the AES-256-GCM key of `ts/src/backup.ts`. The AAD has the layout of version 3 with `|4|`.
pub fn backup_key_v4(code: &BackupCode, salt: &[u8; 16], params: KdfParams, app: &str) -> Result<Key, Error> {
    check_app(app)?;
    Ok(expand(&base_v4(code, salt, params)?, &format!("{app} backup v4 code16")))
}

/// Id for a server of the version-4 backups made with this salt and these parameters: HKDF-SHA256(Argon2id(code,
/// salt, params), `<app> backup-code id v2`) – `backupIdForServer` in TypeScript. It needs the salt from the header,
/// so it cannot be computed from the code alone; a guess costs the Argon2id of the header and tests only this
/// user's id. The server still keeps it like a password hash and limits attempts.
pub fn backup_id(code: &BackupCode, salt: &[u8; 16], params: KdfParams, app: &str) -> Result<[u8; 32], Error> {
    check_app(app)?;
    Ok(*expand(&base_v4(code, salt, params)?, &format!("{app} backup-code id v2")).as_bytes())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn weights_are_distinct_and_non_zero() {
        let mut seen = [false; 32];
        seen[1] = true; // the weight of the check character
        for &g in &GF.0[1..=15] {
            let w = g as usize;
            assert!(w != 0 && !seen[w]);
            seen[w] = true;
        }
        assert_eq!(mul(0, 5), 0);
        assert_eq!(mul(5, 0), 0);
        assert_eq!(mul(1, 7), 7);
    }

    #[test]
    fn every_single_error_and_swap_is_detected() {
        for _ in 0..20 {
            let code = BackupCode::generate().unwrap();
            let p: Vec<char> = code.plain().chars().collect();
            for i in 0..LENGTH {
                for &c in ALPHABET {
                    if c as char == p[i] {
                        continue;
                    }
                    let mut bad = p.clone();
                    bad[i] = c as char;
                    assert_eq!(BackupCode::parse(&bad.iter().collect::<String>()).unwrap_err(), CodeError::Checksum);
                }
                for j in i + 1..LENGTH {
                    if p[i] == p[j] {
                        continue;
                    }
                    let mut bad = p.clone();
                    bad.swap(i, j);
                    assert_eq!(BackupCode::parse(&bad.iter().collect::<String>()).unwrap_err(), CodeError::Checksum);
                }
            }
        }
    }

    #[test]
    fn roundtrip_and_canonical_secret() {
        let code = BackupCode::generate().unwrap();
        assert_eq!(code.as_bytes()[9] & 0x1f, 0);
        let again = BackupCode::parse(&code.format()).unwrap();
        assert_eq!(again.as_bytes(), code.as_bytes());
        assert_eq!(BackupCode::parse(&code.qr_text()).unwrap().as_bytes(), code.as_bytes());
        assert_eq!(BackupCode::from_bytes([0; 10]).unwrap().format().as_str(), "0000-0000-0000-0000");
        assert_eq!(BackupCode::from_bytes([0, 0, 0, 0, 0, 0, 0, 0, 0, 1]).unwrap_err(), Error::Format);
        assert_eq!(format!("{code:?}"), "BackupCode(***)");
    }

    #[test]
    fn params_bounds() {
        assert!(valid_params(DEFAULT_PARAMS) && valid_params(KdfParams::MIN));
        assert!(!valid_params(KdfParams { memory_kib: 65536, iterations: 5, parallelism: 1 }));
        assert!(!valid_params(KdfParams { memory_kib: 131073, iterations: 2, parallelism: 1 }));
        assert!(!valid_params(KdfParams { memory_kib: 32768, iterations: 2, parallelism: 5 }));
        assert!(!valid_params(KdfParams { memory_kib: u32::MAX, iterations: u32::MAX, parallelism: 1 }));
        let code = BackupCode::from_bytes([0; 10]).unwrap();
        let huge = KdfParams { memory_kib: 1 << 30, iterations: 1000, parallelism: 1 };
        assert_eq!(stretch(&code, &[0; 16], huge).unwrap_err(), Error::KdfParams);
        assert_eq!(backup_key(&code, &[0; 16], DEFAULT_PARAMS, "Bad").unwrap_err(), Error::Format);
        assert_eq!(app_salt("x").unwrap_err(), Error::Format);
    }
}
