import { describe, expect, it, vi } from 'vitest';
import old from '../../testvectors/regino/backup-code-0.15.0.json';
import v from '../../testvectors/regino/backup-v4-0.19.0.json';
import { BACKUP_VERSION, backupCodeParamsOf, decryptBackup, encryptBackup } from './backup';
import {
  DEFAULT_BACKUP_CODE_KDF,
  MIN_BACKUP_CODE_KDF,
  MOBILE_BACKUP_CODE_KDF,
  backupCodeStretch,
  backupIdForServer,
  checkBackupCodeParams,
  hkdf32,
  newBackupCodeParams,
  newBackupCodeSecret,
  parseBackupCode,
  type BackupCodeParams,
} from './backupCode';
import { assembleChunkedFile, backupChunkKeys, backupChunkName, chunkListDigest, openBackupChunk, sealBackupChunk } from './backupChunks';
import { b64, unb64 } from './ecdh';
import * as index from './index';
import { openBackup } from './openBackup';
import { newRecoverySecret } from './recovery';

// Backup version 4 (0.19.0, audit F-02): the chunk keys and the server id come from the salt and Argon2id
// parameters of the backup header, not from the fixed salt of the application and the default parameters.
vi.setConfig({ testTimeout: 60_000 });

const hex = (b: Uint8Array) => Array.from(b, (x) => x.toString(16).padStart(2, '0')).join('');
const unhex = (h: string) => Uint8Array.from(h.match(/../g) ?? [], (x) => parseInt(x, 16));
const code = (text: string) => {
  const c = parseBackupCode(text);
  if (!c.ok) throw new Error(text);
  return c.secret;
};
const FAST = (): BackupCodeParams => newBackupCodeParams(MIN_BACKUP_CODE_KDF);
const data = { a: 1, text: 'čšž' };

/** Opens a version-4 file independently (Argon2id → HKDF → AES-GCM with the AAD of the derivation note). */
async function openIndependently(secret: Uint8Array, file: Record<string, unknown>, app: string): Promise<unknown> {
  const kdf = file.kdf as { m: number; t: number; p: number };
  const raw = await hkdf32(await backupCodeStretch(secret, unb64(file.salt as string), kdf), `${app} backup v4 code16`);
  const key = await crypto.subtle.importKey('raw', raw as BufferSource, 'AES-GCM', false, ['decrypt']);
  const digest = (await chunkListDigest((file.chunks as string[] | undefined) ?? [])).digest;
  const aad = `${app}-backup|4|${file.createdAt as string}|code16|argon2id m=${kdf.m} t=${kdf.t} p=${kdf.p}|${digest}`;
  const plain = await crypto.subtle.decrypt(
    { name: 'AES-GCM', iv: unb64(file.nonce as string) as BufferSource, additionalData: new TextEncoder().encode(aad) as BufferSource },
    key,
    unb64(file.ciphertext as string) as BufferSource,
  );
  return JSON.parse(new TextDecoder().decode(plain));
}

describe('backup v4 – shared vectors with Rust (backup-v4-0.19.0.json)', () => {
  it('version and the derivations', () => {
    expect(v.version).toBe('0.19.0');
    expect(BACKUP_VERSION).toBe(4);
    expect(v.keys).toHaveLength(3);
  });

  it.each(v.keys.map((k) => [k.code, k] as const))('keys and ids of %s', async (_, k) => {
    const secret = unhex(k.secret);
    const params = { salt: unhex(k.salt), kdf: k.kdf };
    const base = await backupCodeStretch(secret, params.salt, k.kdf);
    expect(hex(base)).toBe(k.argon2id);
    expect(hex(await hkdf32(base, `${v.app} backup v4 code16`))).toBe(k.backup_key);
    expect(hex(await hkdf32(base, `${v.app} backup chunks v2 code16|enc`))).toBe(k.chunk_enc);
    expect(hex(await hkdf32(base, `${v.app} backup chunks v2 code16|name`))).toBe(k.chunk_name_key);
    expect(hex(await backupIdForServer(secret, v.app, params))).toBe(k.id);
    expect(k.id).not.toBe(k.id_v1); // the version-3 id (removed in 0.21.0) was another value
    const keys = await backupChunkKeys(secret, v.app, params);
    expect(await backupChunkName(keys, new TextEncoder().encode('x'))).toBe(k.chunk_name_of_x);
    // the name key really is the HKDF output above (HMAC computed independently)
    const mac = await crypto.subtle.importKey('raw', unhex(k.chunk_name_key) as BufferSource, { name: 'HMAC', hash: 'SHA-256' }, false, ['sign']);
    expect(hex(new Uint8Array(await crypto.subtle.sign('HMAC', mac, new TextEncoder().encode('x'))))).toBe(k.chunk_name_of_x);
  });

  it.each(v.backups.map((b) => [b.name, b] as const))('whole backup: %s', async (_, b) => {
    const secret = code(b.code);
    expect(await decryptBackup(secret, b.file, v.app)).toEqual({ ok: true, payload: b.payload, createdAt: b.file.createdAt });
    expect(await openIndependently(secret, b.file, v.app)).toEqual(b.payload);
    expect(b.aad_prefix).toBe(`${v.app}-backup|4|${b.file.createdAt}|code16|argon2id m=${b.file.kdf.m} t=${b.file.kdf.t} p=${b.file.kdf.p}|`);
  });

  it('chunks shared by two backups: one salt and parameters, one chunk key', async () => {
    const c = v.chunks;
    const secret = code(c.code);
    const params = { salt: unhex(c.params.salt), kdf: c.params.kdf };
    const keys = await backupChunkKeys(secret, v.app, params);
    expect(new TextDecoder().decode(await openBackupChunk(keys, c.name, unhex(c.blob)))).toBe(c.content);
    for (const b of c.backups) {
      const p = backupCodeParamsOf(b.file);
      expect(p && { salt: hex(p.salt), kdf: p.kdf }).toEqual(c.params);
      const r = await decryptBackup(secret, b.file, v.app);
      expect(r).toEqual({ ok: true, payload: b.payload, createdAt: b.file.createdAt, chunks: [c.name] });
      expect(await openIndependently(secret, b.file, v.app)).toEqual(b.payload);
    }
    // the version-3 keys of the same code do not open the chunk
    await expect(openBackupChunk(await backupChunkKeys(secret, v.app), c.name, unhex(c.blob))).rejects.toThrow();
  });
});

describe('backup v4 – writing', () => {
  it('a backup code writes version 4; the same header as version 3, other keys', async () => {
    const secret = newBackupCodeSecret();
    const params = FAST();
    const file = await encryptBackup(secret, data, '2026-11-25T08:00:00.000Z', 'demo', undefined, { params });
    expect(file).toMatchObject({ format: 'demo-backup', version: 4, secret: 'code16', kdf: { name: 'argon2id', ...MIN_BACKUP_CODE_KDF }, salt: b64(params.salt) });
    expect(Object.keys(file).sort()).toEqual(['ciphertext', 'createdAt', 'format', 'kdf', 'nonce', 'salt', 'secret', 'version']);
    expect(await openIndependently(secret, file as unknown as Record<string, unknown>, 'demo')).toEqual(data);
    // words never write version 4 (their keys need no Argon2id)
    expect((await encryptBackup(newRecoverySecret(), data, undefined, 'demo')).version).toBe(1);
  });

  it('without params: a fresh salt per backup and the given or default parameters', async () => {
    const secret = newBackupCodeSecret();
    const a = await encryptBackup(secret, data, undefined, 'demo', undefined, { kdf: MIN_BACKUP_CODE_KDF });
    const b = await encryptBackup(secret, data, undefined, 'demo', undefined, { kdf: MIN_BACKUP_CODE_KDF });
    expect(a.salt).not.toBe(b.salt);
    expect(backupCodeParamsOf(a)?.kdf).toEqual(MIN_BACKUP_CODE_KDF);
  });

  it('refuses wrong options before any work', async () => {
    const secret = newBackupCodeSecret();
    const params = FAST();
    await expect(encryptBackup(secret, data, undefined, 'demo', undefined, { params, kdf: MIN_BACKUP_CODE_KDF })).rejects.toThrow('either kdf or params');
    await expect(encryptBackup(newRecoverySecret(), data, undefined, 'demo', undefined, { params })).rejects.toThrow('only for a backup code');
    await expect(encryptBackup(secret, data, undefined, 'demo', undefined, { params: { salt: new Uint8Array(15), kdf: MIN_BACKUP_CODE_KDF } })).rejects.toThrow('16 bytes');
    await expect(encryptBackup(secret, data, undefined, 'demo', undefined, { params: { salt: new Uint8Array(16), kdf: { m: 1024, t: 1, p: 1 } } })).rejects.toThrow('bounds');
  });

  it('the parameters are copied: changing them later does not change the backup', async () => {
    const secret = newBackupCodeSecret();
    const params = FAST();
    const salt = b64(params.salt);
    const file = await encryptBackup(secret, data, undefined, 'demo', undefined, { params });
    params.salt.fill(0);
    expect(file.salt).toBe(salt);
    expect((await decryptBackup(secret, file, 'demo')).ok).toBe(true);
  });
});

describe('backup v4 – chunk keys and server id (F-02)', () => {
  it('chunk keys come from the salt and the parameters: same params = same names, other salt or cost = other names', async () => {
    const secret = newBackupCodeSecret();
    const p1 = FAST();
    const p2 = FAST();
    const raised = { salt: p1.salt, kdf: { m: 20480, t: 2, p: 1 } };
    const x = new TextEncoder().encode('príloha');
    const n = async (p?: BackupCodeParams) => backupChunkName(await backupChunkKeys(secret, 'demo', p), x);
    const [a, a2, b, c, v3] = [await n(p1), await n({ salt: p1.salt.slice(), kdf: { ...p1.kdf } }), await n(p2), await n(raised), await n()];
    expect(a).toBe(a2);
    expect(new Set([a, b, c, v3]).size).toBe(4);
  });

  it('the server id needs the salt: other users (salts) have other ids, unlike version 3', async () => {
    const secret = newBackupCodeSecret();
    const p1 = FAST();
    const p2 = FAST();
    const id1 = await backupIdForServer(secret, 'demo', p1);
    expect(id1).toHaveLength(32);
    expect(hex(id1)).toBe(hex(await backupIdForServer(secret, 'demo', { salt: p1.salt, kdf: p1.kdf })));
    expect(hex(id1)).not.toBe(hex(await backupIdForServer(secret, 'demo', p2)));
    expect(hex(id1)).not.toBe(hex(await backupIdForServer(secret, 'other', p1)));
    // the id is HKDF of the same Argon2id as the backup key, with its own info
    const base = await backupCodeStretch(secret, p1.salt, p1.kdf);
    expect(hex(id1)).toBe(hex(await hkdf32(base, 'demo backup-code id v2')));
    await expect(backupIdForServer(secret, 'Bad', p1)).rejects.toThrow('application');
    await expect(backupIdForServer(secret, 'demo', { salt: p1.salt, kdf: { m: 1, t: 1, p: 1 } })).rejects.toThrow('bounds');
  });

  it('backupChunkKeys refuses params with words and parameters out of bounds', async () => {
    await expect(backupChunkKeys(newRecoverySecret(), 'demo', FAST())).rejects.toThrow('only for a backup code');
    await expect(backupChunkKeys(newBackupCodeSecret(), 'demo', { salt: new Uint8Array(16), kdf: { m: 2 ** 30, t: 1, p: 1 } })).rejects.toThrow('bounds');
    await expect(backupChunkKeys(newBackupCodeSecret(), 'demo', { salt: 'x' } as unknown as BackupCodeParams)).rejects.toThrow('16 bytes');
  });

  it('the Argon2id output is wiped after the chunk keys are imported', async () => {
    const real = Uint8Array.prototype.fill;
    const wiped: Uint8Array[] = [];
    const spy = vi.spyOn(Uint8Array.prototype, 'fill').mockImplementation(function (this: Uint8Array, value: number, start?: number, end?: number) {
      if (value === 0 && this.length === 32) wiped.push(this);
      return real.call(this, value, start, end);
    });
    try {
      await backupChunkKeys(newBackupCodeSecret(), 'demo', FAST());
    } finally {
      spy.mockRestore();
    }
    expect(wiped.length).toBeGreaterThanOrEqual(1);
    for (const w of wiped) expect(w.every((b) => b === 0)).toBe(true);
  });
});

describe('backup v4 – backupCodeParamsOf and newBackupCodeParams', () => {
  it('reads the salt and parameters of a version-4 header only', async () => {
    const secret = newBackupCodeSecret();
    const params = FAST();
    const file = await encryptBackup(secret, data, undefined, 'demo', ['a'.repeat(64)], { params });
    const p = backupCodeParamsOf(file);
    expect(p && hex(p.salt)).toBe(hex(params.salt));
    expect(p?.kdf).toEqual(params.kdf);
    // version 3 (the 0.15.0 vectors), words, anything else: null
    expect(backupCodeParamsOf(old.backups[0]?.file)).toBeNull();
    expect(backupCodeParamsOf(await encryptBackup(newRecoverySecret(), data, undefined, 'demo'))).toBeNull();
    for (const bad of [null, undefined, 'x', 4, { version: 4 }, { ...file, secret: 'words' }, { ...file, kdf: { ...file.kdf, name: 'scrypt' } }, { ...file, kdf: undefined }, { ...file, salt: 1 }, { ...file, salt: b64(new Uint8Array(8)) }, { ...file, salt: '***' }, { ...file, kdf: { name: 'argon2id', m: 2 ** 30, t: 1, p: 1 } }])
      expect(backupCodeParamsOf(bad), JSON.stringify(bad)).toBeNull();
    // a phone passes a lower bound
    const big = await encryptBackup(secret, data, undefined, 'demo', undefined, { kdf: { m: 131072, t: 2, p: 1 } });
    expect(backupCodeParamsOf(big)?.kdf.m).toBe(131072);
    expect(backupCodeParamsOf(big, MOBILE_BACKUP_CODE_KDF)).toBeNull();
  });

  it('newBackupCodeParams: random 16-byte salt, default or given parameters within the bounds', () => {
    const a = newBackupCodeParams();
    const b = newBackupCodeParams();
    expect(a.salt).toHaveLength(16);
    expect(hex(a.salt)).not.toBe(hex(b.salt));
    expect(a.kdf).toEqual(DEFAULT_BACKUP_CODE_KDF);
    expect(Object.isFrozen(a.kdf)).toBe(false);
    expect(newBackupCodeParams({ m: 20480, t: 3, p: 2 }).kdf).toEqual({ m: 20480, t: 3, p: 2 });
    expect(() => newBackupCodeParams({ m: 1024, t: 1, p: 1 })).toThrow('bounds');
    expect(() => newBackupCodeParams(null as unknown as typeof DEFAULT_BACKUP_CODE_KDF)).toThrow('bounds');
    // a getter cannot change the parameters after the check
    let reads = 0;
    const tricky = { get m() { return reads++ ? 2 ** 30 : 19456; }, t: 2, p: 1 };
    expect(newBackupCodeParams(tricky).kdf.m).toBe(19456);
    expect(() => checkBackupCodeParams(null)).toThrow('16 bytes');
    expect(() => checkBackupCodeParams({ salt: new Uint8Array(16), kdf: null })).toThrow('bounds');
  });

  it('public API', () => {
    expect(typeof index.newBackupCodeParams).toBe('function');
    expect(typeof index.backupIdForServer).toBe('function');
    expect(typeof index.backupCodeParamsOf).toBe('function');
  });
});

describe('backup v4 – reading older versions and the opening tool', () => {
  it('version 3 still opens, with its chunks (the 0.15.0 vectors) – in decryptBackup and in openBackup', async () => {
    const b = old.backups[0] as (typeof old.backups)[number];
    expect(await decryptBackup(code(b.code), b.file, old.app)).toEqual({ ok: true, payload: b.payload, createdAt: b.file.createdAt });
    const c = old.chunks[0] as (typeof old.chunks)[number];
    const r = await openBackup(JSON.stringify(c.backup.file), c.code);
    if (!r.ok || !r.chunkKeys) throw new Error('not opened');
    expect(r.payload).toEqual(c.backup.payload);
    const parts = await assembleChunkedFile(r.chunkKeys, r.files[0]!, async (n) => (n === c.name ? unhex(c.blob) : null));
    expect(new TextDecoder().decode(parts[0])).toBe(c.content);
  });

  it('openBackup opens a version-4 backup with its chunks (keys from the header)', async () => {
    const c = v.chunks;
    for (const b of c.backups) {
      const r = await openBackup(JSON.stringify(b.file), c.code.toLowerCase());
      if (!r.ok || !r.chunkKeys) throw new Error('not opened');
      expect(r).toMatchObject({ app: v.app, createdAt: b.file.createdAt, payload: b.payload });
      const parts = await assembleChunkedFile(r.chunkKeys, r.files[0]!, async (n) => (n === c.name ? unhex(c.blob) : null));
      expect(new TextDecoder().decode(parts[0])).toBe(c.content);
    }
    const plain = v.backups[0] as (typeof v.backups)[number];
    expect(await openBackup(JSON.stringify(plain.file), plain.code)).toEqual({ ok: true, app: v.app, createdAt: plain.file.createdAt, payload: plain.payload, files: [], chunkKeys: null });
    expect(await openBackup(JSON.stringify({ ...plain.file, version: 5 }), plain.code)).toEqual({ ok: false, message: 'The backup comes from a newer version – download a newer tool.' });
  });

  it('the app flow (Žiačik): the next backup reuses the parameters of the previous one, so no chunk is sealed again', async () => {
    const secret = newBackupCodeSecret();
    const first = FAST();
    const keys1 = await backupChunkKeys(secret, 'ziacik', first);
    const item = new TextEncoder().encode('{"sealed":"…"}');
    const c1 = await sealBackupChunk(keys1, item);
    const b1 = await encryptBackup(secret, { items: [c1.name] }, undefined, 'ziacik', [c1.name], { params: first });
    // later, maybe on another device: the parameters come from the latest backup
    const next = backupCodeParamsOf(b1) as BackupCodeParams;
    const keys2 = await backupChunkKeys(secret, 'ziacik', next);
    expect(await backupChunkName(keys2, item)).toBe(c1.name);
    const b2 = await encryptBackup(secret, { items: [c1.name] }, undefined, 'ziacik', [c1.name], { params: next });
    expect(b2.salt).toBe(b1.salt);
    expect(b2.nonce).not.toBe(b1.nonce);
    expect((await decryptBackup(secret, b2, 'ziacik')).ok).toBe(true);
  });
});
