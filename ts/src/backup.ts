/**
 * Backup encryption with a key derived from the recovery code.
 * - 12/24 words (16/32 B secret): HKDF-SHA256 (different purpose = different key) → AES-256-GCM with a
 *   random 96-bit nonce; versions 1 and 2.
 * - 16-character backup code (10 B secret, since 0.15.0, `backupCode.ts`): Argon2id with a random salt and
 *   the parameters in the header → HKDF-SHA256 → AES-256-GCM; version 3.
 * The kind of secret follows from its length, the kind of backup from its header; a secret of the other
 * kind never opens a backup (different derivation, AEAD fails).
 * WebCrypto (Windows WebView2, Android WebView, Node); Argon2id from `@noble/hashes`.
 */
/**
 * Per-application format: `<app>-backup` (e.g. "demo-backup"). The application name is required –
 * it separates both the format and the backup keys of different applications.
 */
const APP = /^[a-z][a-z0-9]{1,31}$/;
const formatOf = (app: string) => {
  if (!APP.test(app)) throw new Error('Invalid application name for the backup.');
  return `${app}-backup`;
};
/**
 * Highest version this code reads. 1 = payload only; 2 = also a plain list of chunk names (backupChunks.ts)
 * bound in the AAD; 3 = protected by a 16-character backup code (Argon2id parameters in the header,
 * optional chunk list – since 0.15.0).
 */
export const BACKUP_VERSION = 3;
/** Exactly the versions this code reads (since 0.12.1 checked as a set, not as `<= BACKUP_VERSION`). */
export const BACKUP_VERSIONS: readonly number[] = [1, 2, 3];
/** Kind of secret of a version-3 backup (the only one today): the 16-character backup code. */
export const BACKUP_CODE_SECRET = 'code16';

export interface EncryptedBackup {
  /** `<app>-backup` */
  format: string;
  version: number;
  createdAt: string;
  /** base64 */
  salt: string;
  nonce: string;
  ciphertext: string;
  /** version 2 (and 3, when there are any): sorted names of the chunks the backup uses (backupChunks.ts) */
  chunks?: string[];
  /** version 3: kind of secret, always `code16` */
  secret?: typeof BACKUP_CODE_SECRET;
  /** version 3: Argon2id parameters used with `salt` (bounds `MAX_BACKUP_CODE_KDF`) */
  kdf?: { name: 'argon2id' } & BackupCodeKdf;
}

/** Options of `encryptBackup`. */
export interface BackupOptions {
  /** Argon2id parameters for a backup code (default `DEFAULT_BACKUP_CODE_KDF`); not allowed with words. */
  kdf?: BackupCodeKdf;
}

import {
  backupCodeStretch,
  DEFAULT_BACKUP_CODE_KDF,
  hkdf32,
  isBackupCodeSecret,
  validBackupCodeKdf,
  type BackupCodeKdf,
} from './backupCode';
import { chunkListDigest } from './backupChunks';
import { b64, gcmNonce, unb64 } from './ecdh';

const enc = new TextEncoder();
const dec = new TextDecoder();

/**
 * HKDF context (info). The 24-word code (32 B) keeps the original context, so backups from
 * version 0.1.0 still open. The 12-word code (16 B) also includes its length in the context,
 * so codes of different lengths can never be mixed up.
 */
function backupInfo(secret: Uint8Array, app: string): string {
  if (secret.length === 32) return `${app} backup v1`;
  if (secret.length === 16) return `${app} backup v1 k128`;
  throw new Error('The recovery code must have 12 or 24 words.');
}

async function backupKey(secret: Uint8Array, salt: Uint8Array, app: string): Promise<CryptoKey> {
  const info = enc.encode(backupInfo(secret, app));
  const base = await crypto.subtle.importKey('raw', secret as BufferSource, 'HKDF', false, [
    'deriveKey',
  ]);
  return crypto.subtle.deriveKey(
    {
      name: 'HKDF',
      hash: 'SHA-256',
      salt: salt as BufferSource,
      info,
    },
    base,
    { name: 'AES-GCM', length: 256 },
    false,
    ['encrypt', 'decrypt'],
  );
}

/** Version 3: Argon2id(code, salt, kdf) → HKDF-SHA256 info `<app> backup v3 code16` → AES-256-GCM key. */
async function codeBackupKey(secret: Uint8Array, salt: Uint8Array, kdf: BackupCodeKdf, app: string): Promise<CryptoKey> {
  const raw = await hkdf32(await backupCodeStretch(secret, salt, kdf), `${app} backup v3 ${BACKUP_CODE_SECRET}`);
  return crypto.subtle.importKey('raw', raw as BufferSource, 'AES-GCM', false, ['encrypt', 'decrypt']);
}

/**
 * Header bound as AAD; version 2 adds the digest of the chunk list; version 3 the kind of secret, the
 * Argon2id parameters and the digest of the chunk list (of an empty list when there are no chunks).
 */
async function header(format: string, version: number, createdAt: string, chunks: string[], kdf?: BackupCodeKdf): Promise<Uint8Array> {
  if (version < 2) return enc.encode(`${format}|${version}|${createdAt}`);
  const digest = (await chunkListDigest(chunks)).digest;
  if (version < 3) return enc.encode(`${format}|${version}|${createdAt}|${digest}`);
  const k = kdf as BackupCodeKdf;
  return enc.encode(`${format}|${version}|${createdAt}|${BACKUP_CODE_SECRET}|argon2id m=${k.m} t=${k.t} p=${k.p}|${digest}`);
}

/**
 * `secret` = 16/32 B of the 12/24 words, or 10 B of a 16-character backup code (`parseBackupCode`).
 * `chunks` = names of the chunks of large files the payload refers to (backupChunks.ts); with them a words
 * backup has version 2 and lists them in plain text, so the app can delete unreferenced chunks.
 * A backup code always gives version 3 (with or without chunks); `options.kdf` raises its Argon2id cost.
 */
export async function encryptBackup(
  secret: Uint8Array,
  payload: unknown,
  createdAt: string | undefined,
  app: string,
  chunks?: string[],
  options: BackupOptions = {},
): Promise<EncryptedBackup> {
  const format = formatOf(app);
  createdAt ??= new Date().toISOString();
  const code = isBackupCodeSecret(secret);
  if (!code && options.kdf) throw new Error('Argon2id parameters are only for a backup code.');
  const kdf = code ? { ...(options.kdf ?? DEFAULT_BACKUP_CODE_KDF) } : undefined;
  if (kdf && !validBackupCodeKdf(kdf)) throw new Error('Argon2id parameters out of bounds.');
  const salt = crypto.getRandomValues(new Uint8Array(16));
  const nonce = crypto.getRandomValues(new Uint8Array(12));
  const key = kdf ? await codeBackupKey(secret, salt, kdf, app) : await backupKey(secret, salt, app);
  const list = chunks?.length ? (await chunkListDigest(chunks)).list : undefined;
  const version = kdf ? 3 : list ? 2 : 1;
  // The header is the "additional data" (AAD) – any change to it (e.g. the date) is detected on decryption.
  const aad = await header(format, version, createdAt, list ?? [], kdf);
  const ciphertext = new Uint8Array(
    await crypto.subtle.encrypt(
      { name: 'AES-GCM', iv: nonce, additionalData: aad as BufferSource },
      key,
      enc.encode(JSON.stringify(payload)),
    ),
  );
  return {
    format,
    version,
    createdAt,
    ...(kdf ? { secret: BACKUP_CODE_SECRET, kdf: { name: 'argon2id' as const, m: kdf.m, t: kdf.t, p: kdf.p } } : {}),
    salt: b64(salt),
    nonce: b64(nonce),
    ciphertext: b64(ciphertext),
    ...(list ? { chunks: list } : {}),
  };
}

export type DecryptError = 'not-backup' | 'newer-version' | 'wrong-key-or-damaged';

export async function decryptBackup<T = unknown>(
  secret: Uint8Array,
  file: unknown,
  app: string,
): Promise<{ ok: true; payload: T; createdAt: string; chunks?: string[] } | { ok: false; error: DecryptError }> {
  const f = file as Partial<EncryptedBackup> | null;
  const format = formatOf(app);
  if (
    !f ||
    f.format !== format ||
    typeof f.ciphertext !== 'string' ||
    typeof f.salt !== 'string' ||
    typeof f.nonce !== 'string' ||
    typeof f.createdAt !== 'string'
  )
    return { ok: false, error: 'not-backup' };
  // An integer above the highest known version is a newer file; anything else that is not a known
  // version (0, a fraction, NaN, a string) is not a backup of this code.
  const version = f.version;
  if (Number.isInteger(version) && (version as number) > BACKUP_VERSION) return { ok: false, error: 'newer-version' };
  if (typeof version !== 'number' || !BACKUP_VERSIONS.includes(version)) return { ok: false, error: 'not-backup' };
  // Version 3: kind of secret and Argon2id parameters within bounds, checked before any work
  // (a planted header must not start an Argon2id of gigabytes).
  const kdf = version === 3 ? f.kdf : undefined;
  if (version === 3 && (f.secret !== BACKUP_CODE_SECRET || kdf?.name !== 'argon2id' || !validBackupCodeKdf(kdf)))
    return { ok: false, error: 'not-backup' };
  // A secret of the other kind cannot open the backup (checked without deriving anything).
  if ((version === 3) !== isBackupCodeSecret(secret)) return { ok: false, error: 'wrong-key-or-damaged' };
  try {
    const salt = unb64(f.salt);
    if (salt.length !== 16) throw new Error('The salt must have 16 bytes.');
    const chunksOk = Array.isArray(f.chunks) && f.chunks.every((c) => typeof c === 'string');
    if (version === 2 && !chunksOk) throw new Error('Missing chunk list.');
    if (version === 3 && f.chunks !== undefined && !(chunksOk && (f.chunks as string[]).length)) throw new Error('Invalid chunk list.');
    const key = kdf ? await codeBackupKey(secret, salt, kdf, app) : await backupKey(secret, salt, app);
    const aad = await header(format, version, f.createdAt, f.chunks ?? [], kdf);
    const plain = await crypto.subtle.decrypt(
      { name: 'AES-GCM', iv: gcmNonce(f.nonce) as BufferSource, additionalData: aad as BufferSource },
      key,
      unb64(f.ciphertext) as BufferSource,
    );
    return {
      ok: true,
      payload: JSON.parse(dec.decode(plain)) as T,
      createdAt: f.createdAt,
      ...(version === 2 || (version === 3 && f.chunks) ? { chunks: f.chunks } : {}),
    };
  } catch {
    return { ok: false, error: 'wrong-key-or-damaged' };
  }
}
