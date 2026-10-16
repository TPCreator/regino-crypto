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
export const BACKUP_VERSION = 1;

export interface EncryptedBackup {
  /** `<app>-backup` */
  format: string;
  version: number;
  createdAt: string;
  /** base64 */
  salt: string;
  nonce: string;
  ciphertext: string;
}

const enc = new TextEncoder();
const dec = new TextDecoder();

function b64(bytes: Uint8Array): string {
  let s = '';
  for (const b of bytes) s += String.fromCharCode(b);
  return btoa(s);
}

function unb64(text: string): Uint8Array {
  const s = atob(text);
  const out = new Uint8Array(s.length);
  for (let i = 0; i < s.length; i++) out[i] = s.charCodeAt(i);
  return out;
}

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

export async function encryptBackup(
  secret: Uint8Array,
  payload: unknown,
  createdAt: string | undefined,
  app: string,
): Promise<EncryptedBackup> {
  const format = formatOf(app);
  createdAt ??= new Date().toISOString();
  const salt = crypto.getRandomValues(new Uint8Array(16));
  const nonce = crypto.getRandomValues(new Uint8Array(12));
  const key = await backupKey(secret, salt, app);
  // The header is the "additional data" (AAD) – any change to it (e.g. the date) is detected on decryption.
  const aad = enc.encode(`${format}|${BACKUP_VERSION}|${createdAt}`);
  const ciphertext = new Uint8Array(
    await crypto.subtle.encrypt(
      { name: 'AES-GCM', iv: nonce, additionalData: aad },
      key,
      enc.encode(JSON.stringify(payload)),
    ),
  );
  return {
    format,
    version: BACKUP_VERSION,
    createdAt,
    salt: b64(salt),
    nonce: b64(nonce),
    ciphertext: b64(ciphertext),
  };
}

export type DecryptError = 'not-backup' | 'newer-version' | 'wrong-key-or-damaged';

export async function decryptBackup<T = unknown>(
  secret: Uint8Array,
  file: unknown,
  app: string,
): Promise<{ ok: true; payload: T; createdAt: string } | { ok: false; error: DecryptError }> {
  const f = file as Partial<EncryptedBackup> | null;
  const format = formatOf(app);
  if (!f || f.format !== format || typeof f.ciphertext !== 'string')
    return { ok: false, error: 'not-backup' };
  if (typeof f.version !== 'number' || f.version > BACKUP_VERSION)
    return { ok: false, error: 'newer-version' };
  try {
    const key = await backupKey(secret, unb64(f.salt as string), app);
    const aad = enc.encode(`${format}|${f.version}|${f.createdAt}`);
    const plain = await crypto.subtle.decrypt(
      { name: 'AES-GCM', iv: unb64(f.nonce as string) as BufferSource, additionalData: aad },
      key,
      unb64(f.ciphertext) as BufferSource,
    );
    return {
      ok: true,
      payload: JSON.parse(dec.decode(plain)) as T,
      createdAt: f.createdAt as string,
    };
  } catch {
    return { ok: false, error: 'wrong-key-or-damaged' };
  }
}
