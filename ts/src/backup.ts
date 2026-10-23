/**
 * Backup encryption with a key derived from the recovery code.
 * HKDF-SHA256 (different purpose = different key) → AES-256-GCM with a random 96-bit nonce.
 * Everything runs on WebCrypto (Windows WebView2, Android WebView, Node) – no extra libraries.
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
/** Highest version this code reads. 1 = payload only; 2 = also a plain list of chunk names (backupChunks.ts) bound in the AAD. */
export const BACKUP_VERSION = 2;
/** Exactly the versions this code reads (since 0.12.1 checked as a set, not as `<= BACKUP_VERSION`). */
export const BACKUP_VERSIONS: readonly number[] = [1, 2];

export interface EncryptedBackup {
  /** `<app>-backup` */
  format: string;
  version: number;
  createdAt: string;
  /** base64 */
  salt: string;
  nonce: string;
  ciphertext: string;
  /** version 2: sorted names of the chunks the backup uses (backupChunks.ts) */
  chunks?: string[];
}

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

/** Header bound as AAD; version 2 adds the digest of the chunk list. */
async function header(format: string, version: number, createdAt: string, chunks: string[]): Promise<Uint8Array> {
  if (version < 2) return enc.encode(`${format}|${version}|${createdAt}`);
  return enc.encode(`${format}|${version}|${createdAt}|${(await chunkListDigest(chunks)).digest}`);
}

/**
 * `chunks` = names of the chunks of large files the payload refers to (backupChunks.ts); with them the
 * backup has version 2 and lists them in plain text, so the app can delete unreferenced chunks.
 */
export async function encryptBackup(
  secret: Uint8Array,
  payload: unknown,
  createdAt: string | undefined,
  app: string,
  chunks?: string[],
): Promise<EncryptedBackup> {
  const format = formatOf(app);
  createdAt ??= new Date().toISOString();
  const salt = crypto.getRandomValues(new Uint8Array(16));
  const nonce = crypto.getRandomValues(new Uint8Array(12));
  const key = await backupKey(secret, salt, app);
  const list = chunks?.length ? (await chunkListDigest(chunks)).list : undefined;
  const version = list ? 2 : 1;
  // The header is the "additional data" (AAD) – any change to it (e.g. the date) is detected on decryption.
  const aad = await header(format, version, createdAt, list ?? []);
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
  try {
    const salt = unb64(f.salt);
    if (salt.length !== 16) throw new Error('The salt must have 16 bytes.');
    const key = await backupKey(secret, salt, app);
    if (version >= 2 && !(Array.isArray(f.chunks) && f.chunks.every((c) => typeof c === 'string'))) throw new Error('Missing chunk list.');
    const aad = await header(format, version, f.createdAt, f.chunks ?? []);
    const plain = await crypto.subtle.decrypt(
      { name: 'AES-GCM', iv: gcmNonce(f.nonce) as BufferSource, additionalData: aad as BufferSource },
      key,
      unb64(f.ciphertext) as BufferSource,
    );
    return {
      ok: true,
      payload: JSON.parse(dec.decode(plain)) as T,
      createdAt: f.createdAt,
      ...(version >= 2 ? { chunks: f.chunks } : {}),
    };
  } catch {
    return { ok: false, error: 'wrong-key-or-damaged' };
  }
}
