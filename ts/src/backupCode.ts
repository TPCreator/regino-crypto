/**
 * Backup code (since 0.15.0): **16 characters** `XXXX-XXXX-XXXX-XXXX` for quick backups of less
 * confidential data (e.g. a teacher's portfolio). Highly confidential data stays on the 12/24-word
 * recovery code (`recovery.ts`) – see `AUDIT.md`, question 20, and the README.
 *
 * - Alphabet Crockford Base32: `0-9 A-Z` without `I L O U` (32 symbols, 5 bits each).
 * - 15 data characters = **75 random bits**; the 16th character is a check character: the syndrome
 *   `Σ wᵢ·vᵢ = 0` in GF(32) (polynomial x⁵ + x² + 1) with 16 different non-zero weights `wᵢ = α^(i+1)`
 *   for the data and `1` for the check character. Every single wrong character and every swap of two
 *   different characters is detected; random garbage passes with probability 1/32.
 * - Reading tolerates lower case, spaces, hyphens (also –, —, −), the prefix of the QR text and the
 *   look-alikes `O → 0`, `I / L → 1`; errors say exactly what is wrong (length, which character, check).
 * - The secret is 10 bytes: the 75 bits big-endian followed by 5 zero bits. Its length (10 B) is the
 *   kind of the secret everywhere in the core – words are 16 or 32 B, so the two never mix.
 * - Keys from the code always go through **Argon2id** (the code has only 75 bits, a plain HKDF would let
 *   a stolen file be tried at GPU speed): a backup uses a random 16-byte salt and parameters stored in its
 *   header (`backup.ts`, version 3); the id for a server and the keys of backup chunks use one Argon2id
 *   with a fixed salt of the application (`backupChunkKeys` of version-3 backups).
 * Same computation in Rust (`regino_keys::backup_code`), guarded by `testvectors/regino/backup-code-0.15.0.json`.
 */
import { argon2idAsync } from '@noble/hashes/argon2.js';

export const BACKUP_CODE_ALPHABET = '0123456789ABCDEFGHJKMNPQRSTVWXYZ';
/** Characters of a code (15 data + 1 check). */
export const BACKUP_CODE_LENGTH = 16;
/** Bytes of the secret of a code (75 bits + 5 zero bits). */
export const BACKUP_CODE_BYTES = 10;
/** Prefix of the QR text on the printed sheet: `RGC1:` + the 16 characters (QR alphanumeric mode). */
export const BACKUP_CODE_QR_PREFIX = 'RGC1:';

/** Argon2id parameters: `m` memory in KiB, `t` passes, `p` lanes (Argon2 version 0x13, output 32 B). */
export interface BackupCodeKdf {
  m: number;
  t: number;
  p: number;
}
/** Default for new backups and the fixed parameters of the id and chunk keys: 32 MiB, 2 passes, 1 lane. */
export const DEFAULT_BACKUP_CODE_KDF: Readonly<BackupCodeKdf> = Object.freeze({ m: 32768, t: 2, p: 1 });
/** Lower bound (OWASP: 19 MiB, 2 passes) – the same as `regino_keys::kdf::KdfParams::MIN`. */
export const MIN_BACKUP_CODE_KDF: Readonly<BackupCodeKdf> = Object.freeze({ m: 19456, t: 2, p: 1 });
/**
 * Upper bound accepted from a backup header (and when encrypting): 128 MiB, 8 passes, 4 lanes and at
 * most `m·t` = 256 MiB of work (8× the default) – a planted header must not keep a phone busy for minutes
 * or exhaust the memory of a WebView. Raising the parameters later stays within these bounds.
 */
export const MAX_BACKUP_CODE_KDF: Readonly<BackupCodeKdf & { work: number }> = Object.freeze({ m: 131072, t: 8, p: 4, work: 262144 });

/**
 * A lower upper bound for reading on a phone (since 0.15.1, `decryptBackup(…, { maxKdf })`): 64 MiB and
 * `m·t` ≤ 128 MiB – at most 2× the work of the default (measured: the default takes about 0.4 s in Node and
 * 1–1.5 s on a phone, the full `MAX_BACKUP_CODE_KDF` 4× as long with 128 MiB of memory). Backups with the
 * default parameters (every backup the core writes unless an app raises them) open with it.
 */
export const MOBILE_BACKUP_CODE_KDF: Readonly<BackupCodeKdf & { work: number }> = Object.freeze({ m: 65536, t: 8, p: 4, work: 131072 });

/** Parameters within the bounds (`max` defaults to `MAX_BACKUP_CODE_KDF`; a lower `max` only narrows them). */
export function validBackupCodeKdf(k: unknown, max: Readonly<BackupCodeKdf & { work: number }> = MAX_BACKUP_CODE_KDF): k is BackupCodeKdf {
  if (!k || typeof k !== 'object') return false;
  const { m, t, p } = k as Record<string, unknown>;
  const int = (v: unknown, lo: number, hi: number): v is number => Number.isInteger(v) && (v as number) >= lo && (v as number) <= hi;
  return (
    int(m, MIN_BACKUP_CODE_KDF.m, Math.min(max.m, MAX_BACKUP_CODE_KDF.m)) &&
    int(t, MIN_BACKUP_CODE_KDF.t, Math.min(max.t, MAX_BACKUP_CODE_KDF.t)) &&
    int(p, MIN_BACKUP_CODE_KDF.p, Math.min(max.p, MAX_BACKUP_CODE_KDF.p)) &&
    m * t <= Math.min(max.work, MAX_BACKUP_CODE_KDF.work) &&
    // Argon2 needs at least 8 KiB per lane – always true above the minimum, kept for clarity
    m >= 8 * p
  );
}

/* GF(32) with the primitive polynomial x^5 + x^2 + 1: exp/log tables of α = 2. */
const EXP: number[] = [];
const LOG: number[] = new Array(32).fill(0);
for (let i = 0, x = 1; i < 31; i++) {
  EXP.push(x);
  LOG[x] = i;
  x <<= 1;
  if (x & 32) x ^= 0b100101;
}
const mul = (a: number, b: number) => (a && b ? (EXP[((LOG[a] as number) + (LOG[b] as number)) % 31] as number) : 0);

/** Check character value of 15 data values: Σ α^(i+1)·vᵢ in GF(32). */
function checkValue(values: readonly number[]): number {
  let s = 0;
  values.forEach((v, i) => (s ^= mul(EXP[i + 1] as number, v)));
  return s;
}

/** True for a 10-byte secret whose last 5 bits are zero (the one canonical form of a code). */
export function isBackupCodeSecret(secret: unknown): secret is Uint8Array {
  return secret instanceof Uint8Array && secret.length === BACKUP_CODE_BYTES && ((secret[9] as number) & 0x1f) === 0;
}

function checkSecret(secret: Uint8Array): void {
  if (!isBackupCodeSecret(secret)) throw new Error('The backup code secret must have 10 bytes (75 bits and 5 zero bits).');
}

/** 75 random bits as a 10-byte secret. */
export function newBackupCodeSecret(): Uint8Array {
  const s = crypto.getRandomValues(new Uint8Array(BACKUP_CODE_BYTES));
  s[9] = (s[9] as number) & 0xe0;
  return s;
}

/** The 15 data values (5 bits each) of a secret. */
function dataValues(secret: Uint8Array): number[] {
  const out: number[] = [];
  for (let i = 0; i < 15; i++) {
    const bit = i * 5;
    const word = ((secret[bit >> 3] as number) << 8) | (secret[(bit >> 3) + 1] as number);
    out.push((word >> (11 - (bit & 7))) & 31);
  }
  return out;
}

/** 16 characters without hyphens. */
function plainCode(secret: Uint8Array): string {
  checkSecret(secret);
  const v = dataValues(secret);
  return [...v, checkValue(v)].map((x) => BACKUP_CODE_ALPHABET[x]).join('');
}

/** Secret → `XXXX-XXXX-XXXX-XXXX`. */
export function formatBackupCode(secret: Uint8Array): string {
  return plainCode(secret).replace(/(.{4})(?!$)/g, '$1-');
}

/** A new random code `XXXX-XXXX-XXXX-XXXX` (the secret is `parseBackupCode(code).secret`). */
export function newBackupCode(): string {
  return formatBackupCode(newBackupCodeSecret());
}

/** Text of the QR code on the printed sheet: `RGC1:` + 16 characters. */
export function backupCodeQrText(secret: Uint8Array): string {
  return BACKUP_CODE_QR_PREFIX + plainCode(secret);
}

export type BackupCodeError =
  /** after removing spaces and hyphens the code does not have 16 characters */
  | { code: 'length'; length: number }
  /** `index` = position among the characters of the code (0-based, separators not counted), `char` as typed */
  | { code: 'unknown-char'; index: number; char: string }
  /** all characters are valid, but the check character does not match (a typo or two swapped characters) */
  | { code: 'checksum' };

/** Spaces (also no-break), tabs, new lines and hyphens / dashes / minus – ignored when reading. Same set in Rust. */
const SEPARATORS = new Set([' ', '\t', '\n', '\r', '\f', '\v', '\u00a0', '\u2007', '\u202f', '-', '\u2010', '\u2011', '\u2012', '\u2013', '\u2014', '\u2212']);
/** Character → value: the alphabet in upper and lower case, and the look-alikes O → 0, I / L → 1. */
const VALUE: ReadonlyMap<string, number> = new Map([
  ...[...BACKUP_CODE_ALPHABET].flatMap((c, i) => [[c, i], [c.toLowerCase(), i]] as [string, number][]),
  ...(['O', 'o'] as const).map((c) => [c, 0] as [string, number]),
  ...(['I', 'i', 'L', 'l'] as const).map((c) => [c, 1] as [string, number]),
]);

/** Characters of the code as typed: separators removed, then the QR prefix (any case) if present. */
function codeChars(input: string): string[] {
  const chars = [...input].filter((c) => !SEPARATORS.has(c));
  return chars.slice(0, 5).join('').toUpperCase() === BACKUP_CODE_QR_PREFIX ? chars.slice(5) : chars;
}

/**
 * User input (or the QR text) → 10-byte secret and the canonical code `XXXX-XXXX-XXXX-XXXX`.
 * Order of errors: the first character outside the alphabet, then the length, then the check character.
 */
export function parseBackupCode(
  input: string,
): { ok: true; secret: Uint8Array; code: string } | { ok: false; error: BackupCodeError } {
  const chars = codeChars(input);
  const values: number[] = [];
  for (const [index, char] of chars.entries()) {
    const v = VALUE.get(char);
    if (v === undefined) return { ok: false, error: { code: 'unknown-char', index, char } };
    values.push(v);
  }
  if (values.length !== BACKUP_CODE_LENGTH) return { ok: false, error: { code: 'length', length: values.length } };
  // the check character is typed by the user, it is not a secret – a plain comparison is fine
  if (checkValue(values.slice(0, 15)) !== values[15]) return { ok: false, error: { code: 'checksum' } };
  const secret = new Uint8Array(BACKUP_CODE_BYTES);
  values.slice(0, 15).forEach((v, i) => {
    for (let b = 0; b < 5; b++) if ((v >> (4 - b)) & 1) {
      const bit = i * 5 + b;
      secret[bit >> 3] = (secret[bit >> 3] as number) | (0x80 >> (bit & 7));
    }
  });
  return { ok: true, secret, code: formatBackupCode(secret) };
}

/**
 * Whether the input is meant as a backup code rather than words: the QR prefix, or at most 4 groups that
 * together have 12 to 20 letters and digits. Used only to give a better message (`openBackup`).
 */
export function looksLikeBackupCode(input: string): boolean {
  const t = input.trim();
  if (t.toUpperCase().startsWith(BACKUP_CODE_QR_PREFIX)) return true;
  const groups = t.split(/[\s\u00a0\u2007\u202f]+/).filter(Boolean);
  const chars = codeChars(t).join('');
  return groups.length <= 4 && /^[0-9A-Za-z]{12,20}$/.test(chars);
}

const enc = new TextEncoder();
const APP = /^[a-z][a-z0-9]{1,31}$/;
function checkApp(app: string): void {
  if (!APP.test(app)) throw new Error('Invalid application name.');
}

/** (internal) Argon2id(secret, salt, kdf) → 32 bytes. The parameters must be within the bounds above. */
export async function backupCodeStretch(secret: Uint8Array, salt: Uint8Array, kdf: BackupCodeKdf): Promise<Uint8Array> {
  checkSecret(secret);
  if (!(salt instanceof Uint8Array) || salt.length !== 16) throw new Error('The salt must have 16 bytes.');
  if (!validBackupCodeKdf(kdf)) throw new Error('Argon2id parameters out of bounds.');
  return argon2idAsync(secret, salt, { m: kdf.m, t: kdf.t, p: kdf.p, dkLen: 32, version: 0x13 });
}

/** (internal) HKDF-SHA256 with an empty salt (the input is already a uniform 256-bit Argon2id output). */
export async function hkdf32(ikm: Uint8Array, info: string): Promise<Uint8Array> {
  const base = await crypto.subtle.importKey('raw', ikm as BufferSource, 'HKDF', false, ['deriveBits']);
  return new Uint8Array(await crypto.subtle.deriveBits({ name: 'HKDF', hash: 'SHA-256', salt: new Uint8Array(0), info: enc.encode(info) }, base, 256));
}

/** (internal) Fixed salt of an application: SHA-256(`regino backup-code salt v1|<app>`)[0..16]. */
export async function backupCodeAppSalt(app: string): Promise<Uint8Array> {
  checkApp(app);
  return new Uint8Array(await crypto.subtle.digest('SHA-256', enc.encode(`regino backup-code salt v1|${app}`))).slice(0, 16);
}

/**
 * (internal) Key material the same in every backup of one code and application: Argon2id with the fixed salt of the
 * application and the fixed parameters `DEFAULT_BACKUP_CODE_KDF` (part of "v1" – raising them is a v2).
 * Only HKDF outputs of it leave the core (the chunk keys of version-3 backups). The id for a server built on it
 * (`backupCodeId`, `<app> backup-code id v1`) was removed in 0.21.0 (audit F-02; no app used it) – `backupIdForServer`.
 */
export async function backupCodeBase(secret: Uint8Array, app: string): Promise<Uint8Array> {
  return backupCodeStretch(secret, await backupCodeAppSalt(app), DEFAULT_BACKUP_CODE_KDF);
}


/**
 * Salt and Argon2id parameters of a **version-4** backup (since 0.19.0, audit F-02): stored in plain in its
 * header (not secret). The backup key, the keys of its chunks and the id for a server all come from one
 * Argon2id(code, `salt`, `kdf`), so they cost what the header says and differ between users (a random salt,
 * not the fixed salt of the application). Backups that share chunks share these parameters: the app takes them
 * from its previous backup (`backupCodeParamsOf`) or keeps the ones of `newBackupCodeParams`.
 */
export interface BackupCodeParams {
  /** 16 random bytes */
  salt: Uint8Array;
  kdf: BackupCodeKdf;
}

/** Fresh parameters: a random 16-byte salt and `kdf` (default `DEFAULT_BACKUP_CODE_KDF`, within the bounds). */
export function newBackupCodeParams(kdf: Readonly<BackupCodeKdf> = DEFAULT_BACKUP_CODE_KDF): BackupCodeParams {
  const k = kdf && typeof kdf === 'object' ? { m: kdf.m, t: kdf.t, p: kdf.p } : kdf;
  if (!validBackupCodeKdf(k)) throw new Error('Argon2id parameters out of bounds.');
  return { salt: crypto.getRandomValues(new Uint8Array(16)), kdf: k };
}

/**
 * (internal) A checked copy of parameters: a 16-byte salt and bounds (`max`, default `MAX_BACKUP_CODE_KDF`) –
 * so the values checked are the values used.
 */
export function checkBackupCodeParams(
  params: unknown,
  max: Readonly<BackupCodeKdf & { work: number }> = MAX_BACKUP_CODE_KDF,
): BackupCodeParams {
  const q = params as Partial<BackupCodeParams> | null;
  const salt = q && typeof q === 'object' ? q.salt : undefined;
  if (!(salt instanceof Uint8Array) || salt.length !== 16) throw new Error('The salt must have 16 bytes.');
  const kdf = q?.kdf && typeof q.kdf === 'object' ? { m: q.kdf.m, t: q.kdf.t, p: q.kdf.p } : undefined;
  if (!validBackupCodeKdf(kdf, max)) throw new Error('Argon2id parameters out of bounds.');
  return { salt: salt.slice(), kdf };
}

/** (internal) Version 4: Argon2id(secret, params.salt, params.kdf) – the one input of every v4 key. */
export async function backupCodeBaseV4(secret: Uint8Array, params: BackupCodeParams): Promise<Uint8Array> {
  const q = checkBackupCodeParams(params);
  return backupCodeStretch(secret, q.salt, q.kdf);
}

/**
 * Id for a server of the backups made with `params` (since 0.19.0, version 4): 32 bytes,
 * HKDF-SHA256(Argon2id(code, params.salt, params.kdf), `<app> backup-code id v2`). Unlike the removed `backupCodeId` (0.15.0–0.20.0) it
 * needs the salt of the backups (it is in their header), so it cannot be computed from the code alone, and a
 * guess tested against it costs the Argon2id of the header and hits only this user's id. The server still
 * keeps it like a password hash and limits attempts. Same as `regino_keys::backup_code::backup_id`.
 */
export async function backupIdForServer(secret: Uint8Array, app: string, params: BackupCodeParams): Promise<Uint8Array> {
  checkApp(app);
  return hkdf32(await backupCodeBaseV4(secret, params), `${app} backup-code id v2`);
}
