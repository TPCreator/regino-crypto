import { describe, expect, it } from 'vitest';
import { encryptBackup } from './backup';
import { assembleChunkedFile, backupChunkKeys, sealBackupChunk } from './backupChunks';
import { openBackup } from './openBackup';
import { newRecoverySecret, recoveryQrText, secretToWords } from './recovery';

// Same algorithm as version 0.1.0 (24 words, original HKDF context) – never change.
// The recovery words are Slovak by design (Slovak word list).
const OLD_WORDS =
  'aréna jednota hrad halušky krajčír pätka verbovať hudobník jedáleň satelit paroh tapeta fúra hladký defekt vŕba pinzeta dlaň veľtrh lotos bobrík úsmev kaučuk otec';
// Fixed ciphertext from version 0.1.0. Its decrypted payload is `{ note: 'stará záloha 0.1.0' }`
// ("old backup 0.1.0" in Slovak) – it is baked into the ciphertext and must stay exactly as is.
const OLD_FILE = {
  format: 'demo-backup',
  version: 1,
  createdAt: '2026-10-16T10:00:00.000Z',
  salt: '3ky5DrpRoLibTDhzJ1lnWQ==',
  nonce: 'YRWzz5JNyIGJ++sX',
  ciphertext: 'aWtwCbIkXTtoa2CgmWdnwrkaYplbGS0pRDWefz19rhegc2gIPYA2yHN0fBhtK1o=',
};
const data = { items: [{ name: 'test' }] };

describe('independent backup opening', () => {
  it('backup with large files: lists them and gives the keys to assemble them from the chunk folder', async () => {
    const secret = newRecoverySecret(12);
    const keys = await backupChunkKeys(secret, 'dovernik');
    const c = await sealBackupChunk(keys, new TextEncoder().encode('obsah prílohy'));
    const payload = { care: { attachments: [{ id: 'a1', name: 'správa.pdf', mime: 'application/pdf', size: 14, chunks: [c.name] }] } };
    const file = JSON.stringify(await encryptBackup(secret, payload, '2026-10-22T09:00:00.000Z', 'dovernik', [c.name]));
    const r = await openBackup(file, (await secretToWords(secret)).join(' '));
    if (!r.ok || !r.chunkKeys) throw new Error('not opened');
    expect(r.files).toEqual([{ name: 'správa.pdf', mime: 'application/pdf', size: 14, chunks: [c.name] }]);
    const parts = await assembleChunkedFile(r.chunkKeys, r.files[0]!, async (n) => (n === c.name ? c.blob : null));
    expect(new TextDecoder().decode(parts[0])).toBe('obsah prílohy');
  });

  it.each([12, 24] as const)('opens backups of different applications based on the header (%i words)', async (n) => {
    const secret = newRecoverySecret(n);
    const words = (await secretToWords(secret)).join(' ');
    for (const app of ['demo', 'other']) {
      const file = JSON.stringify(await encryptBackup(secret, data, '2026-10-16T09:00:00.000Z', app));
      expect(await openBackup(file, words)).toEqual({ ok: true, app, createdAt: '2026-10-16T09:00:00.000Z', payload: data, files: [], chunkKeys: null });
    }
  });

  it('understandable errors', async () => {
    const secret = newRecoverySecret();
    const words = (await secretToWords(secret)).join(' ');
    const file = JSON.stringify(await encryptBackup(secret, data, undefined, 'demo'));
    expect(await openBackup('not json', words)).toEqual({ ok: false, message: expect.stringContaining('JSON') });
    expect(await openBackup('null', words)).toEqual({ ok: false, message: expect.stringContaining('regino-crypto') });
    expect(await openBackup('{"format":"other"}', words)).toEqual({ ok: false, message: expect.stringContaining('regino-crypto') });
    expect(await openBackup(file, 'one two')).toEqual({ ok: false, message: '12 or 24 words are required, 2 entered.' });
    const bad = words.split(' ');
    bad[3] = 'xyzq';
    expect(await openBackup(file, bad.join(' '))).toEqual({ ok: false, message: expect.stringContaining('no. 4') });
    const swapped = words.split(' ');
    [swapped[0], swapped[1]] = [swapped[1] as string, swapped[0] as string];
    const r = await openBackup(file, swapped.join(' '));
    expect(r.ok).toBe(false);
    // Deterministic checksum error: a fixed secret whose swapped words fail the 4-bit checksum
    // (with the random words above the swap keeps the checksum in 1 of 16 runs).
    for (let i = 0; ; i++) {
      const w = await secretToWords(new Uint8Array(16).fill(i));
      [w[0], w[1]] = [w[1] as string, w[0] as string];
      const res = await openBackup(file, w.join(' '));
      if (!res.ok && res.message.includes('checksum')) break;
      expect(i).toBeLessThan(16);
    }
    const other = (await secretToWords(newRecoverySecret())).join(' ');
    expect(await openBackup(file, other)).toEqual({ ok: false, message: expect.stringContaining('does not belong') });
    const newer = JSON.stringify({ ...JSON.parse(file), version: 99 });
    expect(await openBackup(newer, words)).toEqual({ ok: false, message: expect.stringContaining('newer version') });
    expect(await openBackup(file, 'RGR1:AAAA')).toEqual({ ok: false, message: expect.stringContaining('QR') });
  });

  it('also opens a backup with the text from the recovery sheet QR code', async () => {
    const secret = newRecoverySecret();
    const file = JSON.stringify(await encryptBackup(secret, data, '2026-10-16T09:00:00.000Z', 'demo'));
    expect(await openBackup(file, await recoveryQrText(secret))).toMatchObject({ ok: true, payload: data });
  });

  it('12 and 24 words cannot be swapped (different key context)', async () => {
    const long = newRecoverySecret(24);
    const short = long.slice(0, 16);
    const file = JSON.stringify(await encryptBackup(long, data, undefined, 'demo'));
    expect(await openBackup(file, (await secretToWords(short)).join(' '))).toMatchObject({ ok: false });
  });

  it('an old backup from version 0.1.0 (24 words) opens', async () => {
    const r = await openBackup(JSON.stringify(OLD_FILE), OLD_WORDS);
    expect(r).toEqual({ ok: true, app: 'demo', createdAt: '2026-10-16T10:00:00.000Z', payload: { note: 'stará záloha 0.1.0' }, files: [], chunkKeys: null });
  });
});
