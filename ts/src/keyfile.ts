/**
 * Key file (since 0.22.0): an app's **master key** (32 random bytes) wrapped several times – by a password
 * (Argon2id, `kdf.ts`), by a recovery phrase (12 or 24 words, `recovery.ts`) and by any other key the app has
 * (a share key split 2-of-3 with `shamir.ts`, a device key from Windows Hello or a passkey PRF, …). Any one of
 * them opens the master key; the master key then wraps or seals everything else. Without a password, the
 * phrase or another key the file is worthless, so it may lie next to the data or in a backup.
 *
 * One model for every app (sharing decision 2026-11-25: Testurion `author/keyring.ts`, Dôverník `keyfile.rs`).
 * The same wrap exists in Rust (`regino_keys::keyfile`); `testvectors/regino/keyfile-0.22.0.json` (made here,
 * checked by `keys/tests/keyfile_0_22_0.rs`) guards that both give and accept the same bytes.
 *
 * - **Wrap:** `"RGK1" ‖ nonce (12) ‖ AES-256-GCM(master) (32 + 16)` = 64 bytes, AAD
 *   `"RGK1" ‖ "regino keyfile v1|<app>|<method>"`. The method names the key that wraps (`password`, `recovery`,
 *   `shares`, `device:windows-hello` …), so a wrap cannot be moved to another method or another app.
 * - **File (JSON):** `{ format: "regino-keyfile", v: 1, app, kdf: { m, t, p, salt }, words, wraps: { <method>:
 *   <base64> } }` – `kdf` and `words` only describe the `password` and `recovery` wraps. Parameters are read
 *   with the bounds of `kdf.ts` before any work (a planted file cannot make the app spend minutes).
 * - Returned keys are the caller's to wipe (`fill(0)`); keys passed in are not changed.
 */
import { b64, unb64 } from './ecdh';
import { DEFAULT_PASSWORD_KDF, newPasswordSalt, passwordKey, PASSWORD_SALT_BYTES, validPasswordKdf, type PasswordKdf } from './kdf';
import { newRecoverySecret, recoveryKey, strengthOf, type RecoveryStrength } from './recovery';

export const KEYFILE_FORMAT = 'regino-keyfile';
export const KEYFILE_VERSION = 1;
export const MASTER_KEY_BYTES = 32;
/** Bytes of one wrap: magic 4 + nonce 12 + key 32 + tag 16. */
export const KEYFILE_WRAP_BYTES = 64;

const MAGIC = new TextEncoder().encode('RGK1');
const APP = /^[a-z][a-z0-9]{1,31}$/;
const METHOD = /^[a-z][a-z0-9-]{0,31}(?::[a-z][a-z0-9-]{0,31})?$/;

export interface KeyFile {
  format: typeof KEYFILE_FORMAT;
  v: typeof KEYFILE_VERSION;
  /** App name as for `recoveryKey` (lowercase letters and digits). */
  app: string;
  /** Argon2id of the `password` wrap; `salt` base64 (16 bytes). */
  kdf: PasswordKdf & { salt: string };
  /** Words of the recovery phrase of the `recovery` wrap (12 or 24). */
  words: RecoveryStrength;
  /** Wraps of the master key by method (base64, 64 bytes each). */
  wraps: Record<string, string>;
}

function check(app: string, method: string): void {
  if (typeof app !== 'string' || !APP.test(app)) throw new Error('Invalid application name.');
  if (typeof method !== 'string' || !METHOD.test(method)) throw new Error('Invalid key file method.');
}

const key32 = (k: Uint8Array, what: string) => {
  if (!(k instanceof Uint8Array) || k.length !== MASTER_KEY_BYTES) throw new Error(`The ${what} must have 32 bytes.`);
  return k;
};

const aad = (app: string, method: string) => new Uint8Array([...MAGIC, ...new TextEncoder().encode(`regino keyfile v1|${app}|${method}`)]);

const aesKey = (kek: Uint8Array, use: KeyUsage) => crypto.subtle.importKey('raw', key32(kek, 'wrapping key') as BufferSource, 'AES-GCM', false, [use]);

/** Wraps `master` with `kek` for `app` and `method` (64 bytes). `nonce` only for test vectors. */
export async function wrapMaster(kek: Uint8Array, master: Uint8Array, app: string, method: string, nonce?: Uint8Array): Promise<Uint8Array> {
  check(app, method);
  key32(master, 'master key');
  const iv = nonce ?? crypto.getRandomValues(new Uint8Array(12));
  if (!(iv instanceof Uint8Array) || iv.length !== 12) throw new Error('The nonce must have 12 bytes.');
  const ct = await crypto.subtle.encrypt({ name: 'AES-GCM', iv: iv as BufferSource, additionalData: aad(app, method) }, await aesKey(kek, 'encrypt'), master as BufferSource);
  return new Uint8Array([...MAGIC, ...iv, ...new Uint8Array(ct)]);
}

/** Opens a wrap; null for a wrong key, another app or method, or damaged bytes. Throws only for invalid arguments. */
export async function unwrapMaster(kek: Uint8Array, wrap: Uint8Array, app: string, method: string): Promise<Uint8Array | null> {
  check(app, method);
  const k = await aesKey(kek, 'decrypt');
  if (!(wrap instanceof Uint8Array) || wrap.length !== KEYFILE_WRAP_BYTES || MAGIC.some((b, i) => wrap[i] !== b)) return null;
  try {
    return new Uint8Array(await crypto.subtle.decrypt({ name: 'AES-GCM', iv: wrap.subarray(4, 16) as BufferSource, additionalData: aad(app, method) }, k, wrap.subarray(16) as BufferSource));
  } catch {
    return null;
  }
}

const isB64 = (s: unknown, bytes: number) => {
  if (typeof s !== 'string' || !/^[A-Za-z0-9+/]*={0,2}$/.test(s)) return false;
  try {
    return unb64(s).length === bytes;
  } catch {
    return false;
  }
};

/** A key file read from JSON (text or parsed), or null if it is not one (checked before any work). */
export function parseKeyFile(input: unknown): KeyFile | null {
  let v: unknown = input;
  if (typeof input === 'string') {
    try {
      v = JSON.parse(input);
    } catch {
      return null;
    }
  }
  const f = v as Partial<KeyFile> | null;
  if (!f || typeof f !== 'object' || f.format !== KEYFILE_FORMAT || f.v !== KEYFILE_VERSION || typeof f.app !== 'string' || !APP.test(f.app)) return null;
  const k = f.kdf as Partial<KeyFile['kdf']> | undefined;
  if (!k || !validPasswordKdf({ m: k.m, t: k.t, p: k.p }) || !isB64(k.salt, PASSWORD_SALT_BYTES)) return null;
  if (f.words !== 12 && f.words !== 24) return null;
  const w = f.wraps;
  if (!w || typeof w !== 'object' || Array.isArray(w)) return null;
  for (const [m, x] of Object.entries(w)) if (!METHOD.test(m) || !isB64(x, KEYFILE_WRAP_BYTES)) return null;
  return { format: KEYFILE_FORMAT, v: KEYFILE_VERSION, app: f.app, kdf: { m: k.m!, t: k.t!, p: k.p!, salt: k.salt! }, words: f.words, wraps: { ...w } };
}

/** Opens the master key with a key for `method`; null if the file has no such wrap or the key is wrong. */
export async function unlockWithKey(file: KeyFile, method: string, kek: Uint8Array): Promise<Uint8Array | null> {
  check(file.app, method);
  return Object.hasOwn(file.wraps, method) ? unwrapMaster(kek, unb64(file.wraps[method]!), file.app, method) : null;
}

/** Opens the master key with the password (Argon2id with the file's parameters). */
export async function unlockWithPassword(file: KeyFile, password: string | Uint8Array): Promise<Uint8Array | null> {
  const kek = await passwordKey(password, unb64(file.kdf.salt), file.kdf);
  try {
    return await unlockWithKey(file, 'password', kek);
  } finally {
    kek.fill(0);
  }
}

/** Opens the master key with the recovery secret (`wordsToSecret`); a secret of the other length = null. */
export async function unlockWithRecovery(file: KeyFile, secret: Uint8Array): Promise<Uint8Array | null> {
  if (strengthOf(secret) !== file.words) return null;
  const kek = await recoveryKey(secret, file.app);
  try {
    return await unlockWithKey(file, 'recovery', kek);
  } finally {
    kek.fill(0);
  }
}

/** The file with the master key wrapped (again) by `kek` for `method`. */
export async function withKey(file: KeyFile, master: Uint8Array, method: string, kek: Uint8Array): Promise<KeyFile> {
  return { ...file, wraps: { ...file.wraps, [method]: b64(await wrapMaster(kek, master, file.app, method)) } };
}

/** The file without the wrap for `method` (e.g. quick unlock turned off). The password and the phrase stay. */
export function withoutKey(file: KeyFile, method: string): KeyFile {
  if (method === 'password' || method === 'recovery') throw new Error('The password and the recovery phrase cannot be removed.');
  const wraps = { ...file.wraps };
  delete wraps[method];
  return { ...file, wraps };
}

/** New password (new salt, optionally new parameters); the phrase and other keys keep working. */
export async function withPassword(file: KeyFile, master: Uint8Array, password: string | Uint8Array, kdf: Readonly<PasswordKdf> = file.kdf): Promise<KeyFile> {
  const salt = newPasswordSalt();
  const kek = await passwordKey(password, salt, kdf);
  try {
    return await withKey({ ...file, kdf: { m: kdf.m, t: kdf.t, p: kdf.p, salt: b64(salt) } }, master, 'password', kek);
  } finally {
    kek.fill(0);
  }
}

/**
 * Recovery phrase from a given secret (`newRecoverySecret`, e.g. made before the words were checked by the user);
 * the old phrase stops working. Throws for a secret that is not 16 or 32 bytes.
 */
export async function withRecovery(file: KeyFile, master: Uint8Array, secret: Uint8Array): Promise<KeyFile> {
  const kek = await recoveryKey(secret, file.app);
  try {
    return await withKey({ ...file, words: strengthOf(secret) }, master, 'recovery', kek);
  } finally {
    kek.fill(0);
  }
}

/** New recovery phrase: returns the file and the new secret (`secretToWords` for the sheet). The old phrase stops working. */
export async function withNewRecovery(file: KeyFile, master: Uint8Array, strength: RecoveryStrength = file.words): Promise<{ file: KeyFile; secret: Uint8Array }> {
  const secret = newRecoverySecret(strength);
  return { file: await withRecovery(file, master, secret), secret };
}

/**
 * A new key file: a new master key wrapped by the password and by a recovery phrase – a new one (`words`, default 12)
 * or the given `secret` (made earlier, e.g. after the user checked the words).
 */
export async function createKeyFile(
  app: string,
  password: string | Uint8Array,
  opts: { kdf?: Readonly<PasswordKdf>; words?: RecoveryStrength; secret?: Uint8Array } = {},
): Promise<{ file: KeyFile; master: Uint8Array; secret: Uint8Array }> {
  check(app, 'password');
  const secret = opts.secret ?? newRecoverySecret(opts.words ?? 12);
  const words = strengthOf(secret);
  const master = crypto.getRandomValues(new Uint8Array(MASTER_KEY_BYTES));
  const kdf = opts.kdf ?? DEFAULT_PASSWORD_KDF;
  const base: KeyFile = { format: KEYFILE_FORMAT, v: KEYFILE_VERSION, app, kdf: { ...kdf, salt: '' }, words, wraps: {} };
  const file = await withRecovery(await withPassword(base, master, password, kdf), master, secret);
  return { file, master, secret };
}
