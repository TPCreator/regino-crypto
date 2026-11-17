/**
 * Key from a password (since 0.16.0): **Argon2id**, byte for byte `regino_keys::kdf::derive` in Rust –
 * version 0x13, output 32 bytes, a random 16-byte salt and the parameters stored next to the wrapped key
 * (so they can be raised later). For apps without Rust (the web, Testurion): an administrator's password →
 * a key that wraps the master key.
 *
 * - **Password bytes:** a string is encoded as UTF-8 exactly as given – **no Unicode normalisation**, as
 *   in Rust (`derive` takes the bytes). "á" typed as one code point (NFC) and as "a" + combining accent
 *   (NFD) give different keys; an app that wants them equal normalises before calling (and does so from
 *   its first release – changing it later locks people out). A string with a lone surrogate is refused:
 *   it has no UTF-8 form (`TextEncoder` would silently turn it into U+FFFD, so two different passwords
 *   would give one key) and cannot exist as a Rust `&str`. Bytes (`Uint8Array`) are used as they are.
 * - **Empty password:** accepted, as in Rust – the length and strength of a password are the app's rule.
 * - **Parameters:** `{ m, t, p }` (memory in KiB, passes, lanes). Default 64 MiB, 3 passes, 1 lane
 *   (`KdfParams::default`, ~0.5 s on a desktop); refused **before any work** outside 19–128 MiB,
 *   2–8 passes, 1–4 lanes and `m·t` ≤ 256 MiB (`KdfParams::MIN`, `KdfParams::MAX`, `MAX_WORK_KIB`) –
 *   the same bounds as a backup code (`validBackupCodeKdf`), because stored parameters can be planted.
 * - **Salt:** exactly 16 bytes (`newPasswordSalt()`, Rust `kdf::new_salt`).
 * - The UTF-8 copy of the password made here is wiped after use; the returned key is the caller's to wipe
 *   (e.g. `fill(0)` after `recordKey`).
 * Guarded by `testvectors/regino/keys-0.11.1.json` (made by Rust) and `password-key-0.16.0.json`
 * (made by TypeScript, checked by `keys/tests/password_key_0_16_0.rs`).
 */
import { argon2idAsync } from '@noble/hashes/argon2.js';
import { MAX_BACKUP_CODE_KDF, MIN_BACKUP_CODE_KDF, validBackupCodeKdf, type BackupCodeKdf } from './backupCode';

/** Argon2id parameters: `m` memory in KiB, `t` passes, `p` lanes (as `KdfParams { memory_kib, iterations, parallelism }`). */
export type PasswordKdf = BackupCodeKdf;
/** Default for a new password: 64 MiB, 3 passes, 1 lane (`KdfParams::default()`). */
export const DEFAULT_PASSWORD_KDF: Readonly<PasswordKdf> = Object.freeze({ m: 65536, t: 3, p: 1 });
/** Lower bound (OWASP 2023: 19 MiB, 2 passes, 1 lane) – `KdfParams::MIN`. */
export const MIN_PASSWORD_KDF: Readonly<PasswordKdf> = MIN_BACKUP_CODE_KDF;
/** Upper bound: 128 MiB, 8 passes, 4 lanes and `m·t` ≤ 256 MiB – `KdfParams::MAX` and `KdfParams::MAX_WORK_KIB`. */
export const MAX_PASSWORD_KDF: Readonly<PasswordKdf & { work: number }> = MAX_BACKUP_CODE_KDF;
/** Bytes of the salt (`kdf::new_salt`). */
export const PASSWORD_SALT_BYTES = 16;
/** Bytes of the key (`regino_keys::KEY_LEN`). */
export const PASSWORD_KEY_BYTES = 32;

/** Parameters within `MIN_PASSWORD_KDF` and `MAX_PASSWORD_KDF` (`KdfParams::is_valid`). */
export function validPasswordKdf(k: unknown): k is PasswordKdf {
  return validBackupCodeKdf(k);
}

/** New random salt (16 bytes). */
export function newPasswordSalt(): Uint8Array {
  return crypto.getRandomValues(new Uint8Array(PASSWORD_SALT_BYTES));
}

// a high surrogate not followed by a low one, or a low one not preceded by a high one
const LONE_SURROGATE = /[\uD800-\uDBFF](?![\uDC00-\uDFFF])|(?<![\uD800-\uDBFF])[\uDC00-\uDFFF]/;

/**
 * Derives a 32-byte key from a password. Same password + salt + parameters = same key, here and in
 * `regino_keys::kdf::derive`. Throws (before any work) for parameters out of bounds, a salt that is not
 * 16 bytes, a password that is neither a string nor bytes, or a string with a lone surrogate.
 */
export async function passwordKey(
  password: string | Uint8Array,
  salt: Uint8Array,
  kdf: Readonly<PasswordKdf> = DEFAULT_PASSWORD_KDF,
): Promise<Uint8Array> {
  // a copy, so the values checked are the values used
  const k = kdf && typeof kdf === 'object' ? { m: kdf.m, t: kdf.t, p: kdf.p } : kdf;
  if (!validPasswordKdf(k)) throw new Error('Argon2id parameters out of bounds.');
  if (!(salt instanceof Uint8Array) || salt.length !== PASSWORD_SALT_BYTES) throw new Error('The salt must have 16 bytes.');
  let bytes: Uint8Array;
  let own = false;
  if (typeof password === 'string') {
    if (LONE_SURROGATE.test(password)) throw new Error('The password is not valid Unicode (lone surrogate).');
    bytes = new TextEncoder().encode(password);
    own = true;
  } else if (password instanceof Uint8Array) {
    bytes = password;
  } else {
    throw new Error('The password must be a string or bytes.');
  }
  try {
    return await argon2idAsync(bytes, salt, { m: k.m, t: k.t, p: k.p, dkLen: PASSWORD_KEY_BYTES, version: 0x13 });
  } finally {
    if (own) bytes.fill(0);
  }
}
