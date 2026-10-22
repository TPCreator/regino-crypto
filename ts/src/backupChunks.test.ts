import { describe, expect, it } from 'vitest';
import v from '../../testvectors/regino/backup-chunks-0.11.0.json';
import { decryptBackup, encryptBackup } from './backup';
import { assembleChunkedFile, BACKUP_CHUNK_OVERHEAD, backupChunkKeys, backupChunkName, findChunkedFiles, openBackupChunk, sealBackupChunk } from './backupChunks';
import { unb64 } from './ecdh';
import { newRecoverySecret } from './recovery';

const te = new TextEncoder();
const hexd = (s: string) => Uint8Array.from(s.match(/../g) ?? [], (h) => parseInt(h, 16));

describe('backup chunks', () => {
  it('same content = same name in every backup; sealed differently; opens only with the code', async () => {
    const secret = newRecoverySecret();
    const k = await backupChunkKeys(secret, 'demo');
    const plain = te.encode('príloha klienta');
    const a = await sealBackupChunk(k, plain);
    const b = await sealBackupChunk(await backupChunkKeys(secret, 'demo'), plain);
    expect(a.name).toMatch(/^[0-9a-f]{64}$/);
    expect(a.name).toBe(b.name);
    expect(a.blob).not.toEqual(b.blob);
    expect(a.blob.length).toBe(plain.length + BACKUP_CHUNK_OVERHEAD);
    expect(await openBackupChunk(k, a.name, a.blob)).toEqual(plain);
    await expect(openBackupChunk(await backupChunkKeys(newRecoverySecret(), 'demo'), a.name, a.blob)).rejects.toThrow('code');
    await expect(openBackupChunk(await backupChunkKeys(secret, 'other'), a.name, a.blob)).rejects.toThrow('code');
    // name differs per application and per code
    expect(await backupChunkName(await backupChunkKeys(secret, 'other'), plain)).not.toBe(a.name);
    expect(await backupChunkName(await backupChunkKeys(newRecoverySecret(12), 'demo'), plain)).not.toBe(a.name);
  });

  it('a chunk cannot be swapped for another name or damaged', async () => {
    const k = await backupChunkKeys(newRecoverySecret(12), 'demo');
    const a = await sealBackupChunk(k, te.encode('A'));
    const b = await sealBackupChunk(k, te.encode('B'));
    await expect(openBackupChunk(k, b.name, a.blob)).rejects.toThrow();
    const bad = a.blob.slice();
    bad[bad.length - 1]! ^= 1;
    await expect(openBackupChunk(k, a.name, bad)).rejects.toThrow('damaged');
    await expect(openBackupChunk(k, a.name, a.blob.slice(0, 10))).rejects.toThrow('not a backup chunk');
    await expect(openBackupChunk(k, '../x', a.blob)).rejects.toThrow('Invalid');
    // sealed under a name that is not the HMAC of its content (only possible with the keys) – still refused
    const fake = '0'.repeat(64);
    const nonce = new Uint8Array(12);
    const ct = new Uint8Array(await crypto.subtle.encrypt({ name: 'AES-GCM', iv: nonce, additionalData: te.encode(`RGB1|demo|${fake}`) }, k.enc, te.encode('A')));
    await expect(openBackupChunk(k, fake, new Uint8Array([...te.encode('RGB1'), ...nonce, ...ct]))).rejects.toThrow('does not match');
    await expect(backupChunkKeys(new Uint8Array(20), 'demo')).rejects.toThrow('12 or 24');
    await expect(backupChunkKeys(new Uint8Array(16), 'X')).rejects.toThrow('application');
  });

  it('backup v2 lists its chunks in plain text and binds the list; v1 unchanged', async () => {
    const secret = newRecoverySecret();
    const k = await backupChunkKeys(secret, 'demo');
    const c1 = await sealBackupChunk(k, te.encode('časť 1'));
    const c2 = await sealBackupChunk(k, te.encode('časť 2'));
    const payload = { files: [{ name: 'správa.pdf', mime: 'application/pdf', size: 12, chunks: [c1.name, c2.name] }] };
    const file = await encryptBackup(secret, payload, '2026-10-22T10:00:00.000Z', 'demo', [c2.name, c1.name, c1.name]);
    expect(file.version).toBe(2);
    expect(file.chunks).toEqual([c1.name, c2.name].sort());
    expect(await decryptBackup(secret, file, 'demo')).toMatchObject({ ok: true, payload, chunks: file.chunks });
    expect(await decryptBackup(secret, { ...file, chunks: [c1.name] }, 'demo')).toEqual({ ok: false, error: 'wrong-key-or-damaged' });
    expect(await decryptBackup(secret, { ...file, chunks: undefined }, 'demo')).toEqual({ ok: false, error: 'wrong-key-or-damaged' });
    expect(await decryptBackup(secret, { ...file, version: 1 }, 'demo')).toEqual({ ok: false, error: 'wrong-key-or-damaged' });
    const plain = await encryptBackup(secret, payload, undefined, 'demo', []);
    expect(plain.version).toBe(1);
    expect('chunks' in plain).toBe(false);
    await expect(encryptBackup(secret, payload, undefined, 'demo', ['xyz'])).rejects.toThrow('chunk name');
    // assemble from the folder
    const files = findChunkedFiles({ care: { attachments: [{ id: 'a', ...payload.files[0] }, { name: 'bez', chunks: [] }, { chunks: [c1.name], name: 5, size: '1' }] } });
    expect(files).toEqual([payload.files[0], { name: 'file', mime: undefined, size: undefined, chunks: [c1.name] }]);
    const store = new Map([c1, c2].map((c) => [c.name, c.blob]));
    const parts = await assembleChunkedFile(k, files[0]!, async (n) => store.get(n) ?? null);
    expect(new TextDecoder().decode(new Uint8Array([...parts[0]!, ...parts[1]!]))).toBe('časť 1časť 2');
    store.delete(c2.name);
    await expect(assembleChunkedFile(k, files[0]!, async (n) => store.get(n) ?? null)).rejects.toThrow('missing');
  });

  it('fixed vectors (shared with Rust regino_keys::backup_chunks)', async () => {
    for (const t of v.chunks) {
      const k = await backupChunkKeys(hexd(t.secret), t.app);
      const plain = unb64(t.plain);
      expect(await backupChunkName(k, plain)).toBe(t.name);
      expect(await openBackupChunk(k, t.name, unb64(t.blob))).toEqual(plain);
    }
  });
});
