/**
 * Backup encryption with a key derived from the recovery code.
 * - 12/24 words (16/32 B secret): HKDF-SHA256 (different purpose = different key) → AES-256-GCM with a
 *   random 96-bit nonce; versions 1 and 2.
 * - 16-character backup code (10 B secret, since 0.15.0, `backupCode.ts`): Argon2id with a random salt and
 *   the parameters in the header → HKDF-SHA256 → AES-256-GCM; version 3 (read only since 0.19.0) and
 *   **version 4** (written since 0.19.0, audit F-02): the same header, but the keys of its chunks and the id for a
 *   server come from the same salt and parameters (`BackupCodeParams`), not from the fixed salt of the application.
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
 * optional chunk list – since 0.15.0); 4 = as 3, and the chunk keys and the server id come from the header's
 * salt and parameters (since 0.19.0 – the only version written with a backup code).
 */
export const BACKUP_VERSION = 4;
/** Exactly the versions this code reads (since 0.12.1 checked as a set, not as `<= BACKUP_VERSION`). */
export const BACKUP_VERSIONS: readonly number[] = [1, 2, 3, 4];
/** Kind of secret of a version-3 and version-4 backup (the only one today): the 16-character backup code. */
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
  /** versions 3 and 4: kind of secret, always `code16` */
  secret?: typeof BACKUP_CODE_SECRET;
  /** versions 3 and 4: Argon2id parameters used with `salt` (bounds `MAX_BACKUP_CODE_KDF`) */
  kdf?: { name: 'argon2id' } & BackupCodeKdf;
}

/** Options of `encryptBackup`. */
export interface BackupOptions {
  /** Argon2id parameters for a backup code (default `DEFAULT_BACKUP_CODE_KDF`) with a fresh salt; not allowed with words. */
  kdf?: BackupCodeKdf;
  /**
   * Since 0.19.0: salt and Argon2id parameters for a backup code (`newBackupCodeParams()` or `backupCodeParamsOf`
   * of the previous backup) – the backups that share chunks share them, so their chunk keys are the same.
   * Not together with `kdf`; not allowed with words. Without it a fresh random salt is used.
   */
  params?: BackupCodeParams;
}

import {
  backupCodeStretch,
  checkBackupCodeParams,
  DEFAULT_BACKUP_CODE_KDF,
  hkdf32,
  isBackupCodeSecret,
  MAX_BACKUP_CODE_KDF,
  validBackupCodeKdf,
  type BackupCodeKdf,
  type BackupCodeParams,
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

/**
 * Versions 3 and 4: Argon2id(code, salt, kdf) → HKDF-SHA256 info `<app> backup v<version> code16` → AES-256-GCM key.
 * In version 4 the same Argon2id output also gives the chunk keys and the server id (other HKDF infos).
 */
async function codeBackupKey(secret: Uint8Array, salt: Uint8Array, kdf: BackupCodeKdf, app: string, version: 3 | 4): Promise<CryptoKey> {
  const stretched = await backupCodeStretch(secret, salt, kdf);
  const raw = await hkdf32(stretched, `${app} backup v${version} ${BACKUP_CODE_SECRET}`);
  stretched.fill(0);
  try {
    return await crypto.subtle.importKey('raw', raw as BufferSource, 'AES-GCM', false, ['encrypt', 'decrypt']);
  } finally {
    raw.fill(0);
  }
}

/**
 * Header bound as AAD; version 2 adds the digest of the chunk list; versions 3 and 4 the kind of secret, the
 * Argon2id parameters and the digest of the chunk list (of an empty list when there are no chunks).
 */
async function header(format: string, version: number, createdAt: string, chunks: string[], kdf?: BackupCodeKdf): Promise<Uint8Array> {
  if (version < 2) return enc.encode(`${format}|${version}|${createdAt}`);
  const digest = (await chunkListDigest(chunks)).digest;
  if (version < 3) return enc.encode(`${format}|${version}|${createdAt}|${digest}`);
  // versions 3 and 4: the same layout, the version number differs
  const k = kdf as BackupCodeKdf;
  return enc.encode(`${format}|${version}|${createdAt}|${BACKUP_CODE_SECRET}|argon2id m=${k.m} t=${k.t} p=${k.p}|${digest}`);
}

/**
 * `secret` = 16/32 B of the 12/24 words, or 10 B of a 16-character backup code (`parseBackupCode`).
 * `chunks` = names of the chunks of large files the payload refers to (backupChunks.ts); with them a words
 * backup has version 2 and lists them in plain text, so the app can delete unreferenced chunks.
 * A backup code always gives **version 4** (since 0.19.0; with or without chunks): `options.kdf` raises its Argon2id
 * cost, `options.params` reuses the salt and parameters of earlier backups (shared chunks, `backupChunkKeys`).
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
  if (!code && (options.kdf || options.params)) throw new Error('Argon2id parameters are only for a backup code.');
  if (options.kdf && options.params) throw new Error('Give either kdf or params, not both.');
  const kdf = code ? { ...(options.params?.kdf ?? options.kdf ?? DEFAULT_BACKUP_CODE_KDF) } : undefined;
  if (kdf && !validBackupCodeKdf(kdf)) throw new Error('Argon2id parameters out of bounds.');
  const salt = options.params ? checkBackupCodeParams(options.params).salt : crypto.getRandomValues(new Uint8Array(16));
  const nonce = crypto.getRandomValues(new Uint8Array(12));
  const key = kdf ? await codeBackupKey(secret, salt, kdf, app, 4) : await backupKey(secret, salt, app);
  const list = chunks?.length ? (await chunkListDigest(chunks)).list : undefined;
  const version = kdf ? 4 : list ? 2 : 1;
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

/** Options of `decryptBackup` (since 0.15.1). */
export interface DecryptOptions {
  /**
   * Lower upper bound of the Argon2id parameters this reader accepts from a header (e.g.
   * `MOBILE_BACKUP_CODE_KDF` on a phone); a costlier header is `not-backup`, refused before any work.
   * It only narrows `MAX_BACKUP_CODE_KDF`.
   */
  maxKdf?: Readonly<BackupCodeKdf & { work: number }>;
}

export async function decryptBackup<T = unknown>(
  secret: Uint8Array,
  file: unknown,
  app: string,
  options: DecryptOptions = {},
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
  // Versions 3 and 4: kind of secret and Argon2id parameters within bounds, checked before any work
  // (a planted header must not start an Argon2id of gigabytes).
  const codeVersion = version === 3 || version === 4;
  const kdf = codeVersion ? f.kdf : undefined;
  if (codeVersion && (f.secret !== BACKUP_CODE_SECRET || kdf?.name !== 'argon2id' || !validBackupCodeKdf(kdf, options.maxKdf)))
    return { ok: false, error: 'not-backup' };
  // A secret of the other kind cannot open the backup (checked without deriving anything).
  if (codeVersion !== isBackupCodeSecret(secret)) return { ok: false, error: 'wrong-key-or-damaged' };
  try {
    const salt = unb64(f.salt);
    if (salt.length !== 16) throw new Error('The salt must have 16 bytes.');
    // canonical only (since 0.15.1): sorted, no duplicates – the form encryptBackup writes; the AAD binds the
    // sorted unique list, so a reordered or doubled list would open and be handed to the app as it is
    const chunksOk = Array.isArray(f.chunks) && f.chunks.every((c, i, a) => typeof c === 'string' && (i === 0 || (a[i - 1] as string) < c));
    if (version === 2 && !chunksOk) throw new Error('Missing chunk list.');
    if (codeVersion && f.chunks !== undefined && !(chunksOk && (f.chunks as string[]).length)) throw new Error('Invalid chunk list.');
    const key = kdf ? await codeBackupKey(secret, salt, kdf, app, version as 3 | 4) : await backupKey(secret, salt, app);
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
      ...(version === 2 || (codeVersion && f.chunks) ? { chunks: f.chunks } : {}),
    };
  } catch {
    return { ok: false, error: 'wrong-key-or-damaged' };
  }
}

/**
 * Salt and Argon2id parameters of a version-4 backup (since 0.19.0), for its chunk keys
 * (`backupChunkKeys(code, app, params)`), the server id (`backupIdForServer`) and the next backup that shares its
 * chunks (`encryptBackup(…, { params })`). `null` for any other version or a header out of bounds (`max`, default
 * `MAX_BACKUP_CODE_KDF` – pass `MOBILE_BACKUP_CODE_KDF` on a phone). Reads only the plain header, derives nothing.
 */
export function backupCodeParamsOf(
  file: unknown,
  max: Readonly<BackupCodeKdf & { work: number }> = MAX_BACKUP_CODE_KDF,
): BackupCodeParams | null {
  const f = file as Partial<EncryptedBackup> | null;
  if (!f || typeof f !== 'object' || f.version !== 4 || f.secret !== BACKUP_CODE_SECRET || f.kdf?.name !== 'argon2id' || typeof f.salt !== 'string')
    return null;
  try {
    return checkBackupCodeParams({ salt: unb64(f.salt), kdf: f.kdf }, max);
  } catch {
    return null;
  }
}
