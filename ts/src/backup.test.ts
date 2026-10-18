import { describe, expect, it } from 'vitest';
import { decryptBackup, encryptBackup } from './backup';
import { newRecoverySecret } from './recovery';

const APP = 'demo';

const data = {
  households: [{ id: 'h1', name: 'Household' }],
  transactions: [{ payee: 'Billa', amount_cents: -2340 }],
};

describe('encrypted backup', () => {
  it('encrypts and restores with the same code', async () => {
    const secret = newRecoverySecret();
    const file = await encryptBackup(secret, data, '2026-10-13T18:00:00.000Z', APP);
    expect(file).toMatchObject({
      format: 'demo-backup',
      version: 1,
      createdAt: '2026-10-13T18:00:00.000Z',
    });
    expect(JSON.stringify(file)).not.toContain('Billa'); // nothing readable
    expect(await decryptBackup(secret, JSON.parse(JSON.stringify(file)), APP)).toEqual({
      ok: true,
      payload: data,
      createdAt: '2026-10-13T18:00:00.000Z',
    });
  });

  it('12 and 24 words; any other code length is rejected', async () => {
    for (const n of [12, 24] as const) {
      const secret = newRecoverySecret(n);
      const file = await encryptBackup(secret, data, undefined, APP);
      expect(await decryptBackup(secret, file, APP)).toMatchObject({ ok: true, payload: data });
    }
    await expect(encryptBackup(new Uint8Array(20), data, undefined, APP)).rejects.toThrow('12 or 24');
  });

  it('two backups of the same data differ (random salt and nonce)', async () => {
    const secret = newRecoverySecret();
    const a = await encryptBackup(secret, data, undefined, APP);
    const b = await encryptBackup(secret, data, undefined, APP);
    expect(a.ciphertext).not.toBe(b.ciphertext);
    expect(a.nonce).not.toBe(b.nonce);
  });

  it('a wrong code, a damaged file or a modified header do not open', async () => {
    const secret = newRecoverySecret();
    const file = await encryptBackup(secret, data, undefined, APP);
    expect(await decryptBackup(newRecoverySecret(), file, APP)).toEqual({
      ok: false,
      error: 'wrong-key-or-damaged',
    });
    const damaged = { ...file, ciphertext: file.ciphertext.slice(0, -4) + 'AAAA' };
    expect(await decryptBackup(secret, damaged, APP)).toEqual({
      ok: false,
      error: 'wrong-key-or-damaged',
    });
    const redated = { ...file, createdAt: '2020-01-01T00:00:00.000Z' };
    expect(await decryptBackup(secret, redated, APP)).toEqual({
      ok: false,
      error: 'wrong-key-or-damaged',
    });
  });

  it('foreign or newer file', async () => {
    const secret = newRecoverySecret();
    expect(await decryptBackup(secret, null, APP)).toEqual({ ok: false, error: 'not-backup' });
    expect(await decryptBackup(secret, { format: 'other' }, APP)).toEqual({
      ok: false,
      error: 'not-backup',
    });
    const file = await encryptBackup(secret, data, undefined, APP);
    expect(await decryptBackup(secret, { ...file, version: 2 }, APP)).toEqual({
      ok: false,
      error: 'newer-version',
    });
    expect(await decryptBackup(secret, { ...file, version: 'x' }, APP)).toEqual({
      ok: false,
      error: 'newer-version',
    });
  });

  it("does not open another application's backup and validates the application name", async () => {
    const secret = newRecoverySecret();
    const d = await encryptBackup(secret, data, '2026-10-16T08:00:00.000Z', 'other');
    expect(d.format).toBe('other-backup');
    expect((await decryptBackup(secret, d, 'other')).ok).toBe(true);
    expect(await decryptBackup(secret, d, APP)).toEqual({ ok: false, error: 'not-backup' });
    // a forged format does not help – the key is also derived from the application name
    expect(await decryptBackup(secret, { ...d, format: 'demo-backup' }, APP)).toEqual({ ok: false, error: 'wrong-key-or-damaged' });
    await expect(encryptBackup(secret, data, undefined, 'Bad name')).rejects.toThrow();
  });

  // Question 8: 32-byte secrets use the legacy info "<app> backup v1" (0.1.0 backups), 16-byte ones
  // "<app> backup v1 k128". The length selects the info, so a backup made with one length never
  // opens with the other – not even with the first 16 bytes of a 32-byte secret.
  it('16- and 32-byte secrets are separated', async () => {
    const long = newRecoverySecret(24);
    const short = long.slice(0, 16);
    const a = await encryptBackup(long, data, '2026-10-18T10:00:00.000Z', APP);
    const b = await encryptBackup(short, data, '2026-10-18T10:00:00.000Z', APP);
    expect(await decryptBackup(short, a, APP)).toEqual({ ok: false, error: 'wrong-key-or-damaged' });
    expect(await decryptBackup(long, b, APP)).toEqual({ ok: false, error: 'wrong-key-or-damaged' });
    expect((await decryptBackup(long, a, APP)).ok).toBe(true);
    expect((await decryptBackup(short, b, APP)).ok).toBe(true);
  });

  it('header fields must be strings, salt 16 bytes and nonce 12 bytes', async () => {
    const secret = newRecoverySecret();
    const file = await encryptBackup(secret, data, '2026-10-18T10:00:00.000Z', APP);
    for (const field of ['salt', 'nonce', 'createdAt', 'ciphertext'] as const)
      expect(await decryptBackup(secret, { ...file, [field]: 5 }, APP)).toEqual({ ok: false, error: 'not-backup' });
    const b = (n: number) => btoa(String.fromCharCode(...new Uint8Array(n)));
    expect(await decryptBackup(secret, { ...file, salt: b(15) }, APP)).toEqual({ ok: false, error: 'wrong-key-or-damaged' });
    expect(await decryptBackup(secret, { ...file, nonce: b(16) }, APP)).toEqual({ ok: false, error: 'wrong-key-or-damaged' });
  });
});
