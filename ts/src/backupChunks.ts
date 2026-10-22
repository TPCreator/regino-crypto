/**
 * Large files in backups (attachments of several GB): content-addressed chunks next to the backup.
 *
 * - Two keys per application from the recovery code (HKDF-SHA256, no salt – they must be the same in
 *   every backup so that the same content gets the same name): `<app> backup chunks v1|enc` and `|name`
 *   (plus ` k128` for the 12-word code, as in backup.ts). Different info = independent from the backup key.
 * - Chunk name = HMAC-SHA256(name key, plain content), 64 hex characters. Same content = same name, so
 *   thirty backups share one copy of an unchanged file; without the code the name says nothing.
 * - Chunk file `<name>.rgb` = `RGB1 | nonce (12) | AES-256-GCM(enc key, content, AAD = "RGB1|<app>|<name>")`.
 *   On opening the name is recomputed from the content (constant time), so a chunk cannot be swapped.
 * - The backup (manifest, backup.ts) lists the names it uses in plain text and binds the list in its AAD
 *   (version 2): the app can delete unreferenced chunks without decrypting anything, and any change to the
 *   list is detected when the backup is opened.
 */
import { b64 } from './ecdh';

const enc = new TextEncoder();
const MAGIC = enc.encode('RGB1');
const NAME = /^[0-9a-f]{64}$/;
const APP = /^[a-z][a-z0-9]{1,31}$/;
export const BACKUP_CHUNK_OVERHEAD = 4 + 12 + 16;

export interface BackupChunkKeys {
  app: string;
  enc: CryptoKey;
  name: CryptoKey;
}

function info(secret: Uint8Array, app: string, purpose: 'enc' | 'name'): Uint8Array {
  if (!APP.test(app)) throw new Error('Invalid application name for the backup.');
  if (secret.length !== 32 && secret.length !== 16) throw new Error('The recovery code must have 12 or 24 words.');
  return enc.encode(`${app} backup chunks v1${secret.length === 16 ? ' k128' : ''}|${purpose}`);
}

export async function backupChunkKeys(secret: Uint8Array, app: string): Promise<BackupChunkKeys> {
  const base = await crypto.subtle.importKey('raw', secret as BufferSource, 'HKDF', false, ['deriveKey']);
  const hkdf = (purpose: 'enc' | 'name') => ({ name: 'HKDF', hash: 'SHA-256', salt: new Uint8Array(0), info: info(secret, app, purpose) as BufferSource });
  return {
    app,
    enc: await crypto.subtle.deriveKey(hkdf('enc'), base, { name: 'AES-GCM', length: 256 }, false, ['encrypt', 'decrypt']),
    name: await crypto.subtle.deriveKey(hkdf('name'), base, { name: 'HMAC', hash: 'SHA-256', length: 256 }, false, ['sign', 'verify']),
  };
}

const hex = (b: Uint8Array) => Array.from(b, (x) => x.toString(16).padStart(2, '0')).join('');
const unhex = (s: string) => Uint8Array.from(s.match(/../g)!, (h) => parseInt(h, 16));
const aad = (app: string, name: string) => enc.encode(`RGB1|${app}|${name}`);

/** Name of a chunk with this content. */
export async function backupChunkName(keys: BackupChunkKeys, plain: Uint8Array): Promise<string> {
  return hex(new Uint8Array(await crypto.subtle.sign('HMAC', keys.name, plain as BufferSource)));
}

/** Seals a chunk; returns its name and the file contents. */
export async function sealBackupChunk(keys: BackupChunkKeys, plain: Uint8Array): Promise<{ name: string; blob: Uint8Array }> {
  const name = await backupChunkName(keys, plain);
  const nonce = crypto.getRandomValues(new Uint8Array(12));
  const ct = new Uint8Array(await crypto.subtle.encrypt({ name: 'AES-GCM', iv: nonce, additionalData: aad(keys.app, name) as BufferSource }, keys.enc, plain as BufferSource));
  const blob = new Uint8Array(BACKUP_CHUNK_OVERHEAD - 16 + ct.length);
  blob.set(MAGIC, 0);
  blob.set(nonce, 4);
  blob.set(ct, 16);
  return { name, blob };
}

/** Opens a chunk file; throws on a wrong code, a damaged file or a chunk that does not belong to the name. */
export async function openBackupChunk(keys: BackupChunkKeys, name: string, blob: Uint8Array): Promise<Uint8Array> {
  if (!NAME.test(name)) throw new Error('Invalid chunk name.');
  if (blob.length < BACKUP_CHUNK_OVERHEAD || MAGIC.some((b, i) => blob[i] !== b)) throw new Error('The file is not a backup chunk.');
  let plain: Uint8Array;
  try {
    plain = new Uint8Array(await crypto.subtle.decrypt({ name: 'AES-GCM', iv: blob.slice(4, 16), additionalData: aad(keys.app, name) as BufferSource }, keys.enc, blob.slice(16) as BufferSource));
  } catch {
    throw new Error('The code does not belong to this chunk, or the chunk is damaged.');
  }
  // HMAC verify compares in constant time
  if (!(await crypto.subtle.verify('HMAC', keys.name, unhex(name) as BufferSource, plain as BufferSource))) throw new Error('The chunk does not match its name.');
  return plain;
}

/** Sorted unique list of names and its digest for the backup AAD (backup.ts, version 2). */
export async function chunkListDigest(chunks: string[]): Promise<{ list: string[]; digest: string }> {
  const list = [...new Set(chunks)].sort();
  for (const c of list) if (!NAME.test(c)) throw new Error('Invalid chunk name.');
  return { list, digest: b64(new Uint8Array(await crypto.subtle.digest('SHA-256', enc.encode(list.join('\n'))))) };
}

/**
 * A file stored in chunks inside a backup payload: any object with a `chunks` array of names (and
 * usually `name`, `mime`, `size`). The public tool finds them anywhere in the payload.
 */
export interface ChunkedFile {
  name: string;
  mime?: string;
  size?: number;
  chunks: string[];
}

export function findChunkedFiles(payload: unknown): ChunkedFile[] {
  const out: ChunkedFile[] = [];
  const walk = (v: unknown) => {
    if (Array.isArray(v)) return v.forEach(walk);
    if (!v || typeof v !== 'object') return;
    const o = v as Record<string, unknown>;
    if (Array.isArray(o.chunks) && o.chunks.length && o.chunks.every((c) => typeof c === 'string' && NAME.test(c))) {
      out.push({ name: typeof o.name === 'string' && o.name ? o.name : 'file', mime: typeof o.mime === 'string' ? o.mime : undefined, size: typeof o.size === 'number' ? o.size : undefined, chunks: o.chunks as string[] });
      return;
    }
    Object.values(o).forEach(walk);
  };
  walk(payload);
  return out;
}

/** Assembles a file from its chunks (`read` returns the chunk file by name, or null when it is missing). */
export async function assembleChunkedFile(keys: BackupChunkKeys, file: ChunkedFile, read: (name: string) => Promise<Uint8Array | null>): Promise<Uint8Array[]> {
  const parts: Uint8Array[] = [];
  for (const name of file.chunks) {
    const blob = await read(name);
    if (!blob) throw new Error(`Chunk ${name.slice(0, 12)}… is missing – select the whole chunk folder of this backup.`);
    parts.push(await openBackupChunk(keys, name, blob));
  }
  return parts;
}
