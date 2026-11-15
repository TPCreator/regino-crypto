// Fixes after the audit of 0.15.0 (2026-11-15): each test failed before its fix (AUDIT.md § 4.5).
import { signAsync } from '@noble/ed25519';
import { describe, expect, it } from 'vitest';
import lock from '../package-lock.json';
import pkg from '../package.json';
import { decryptBackup, encryptBackup } from './backup';
import { DEFAULT_BACKUP_CODE_KDF, MOBILE_BACKUP_CODE_KDF, newBackupCodeSecret, validBackupCodeKdf } from './backupCode';
import { newRecoverySecret } from './recovery';
import { openManifest, SIGNATURE_LEN, signingPublicKey, signManifest, verifyManifest, type Member } from './signing';

const seed = (n: number) => new Uint8Array(32).fill(n);
const member = async (id: string, admin: boolean, n: number): Promise<Member> => ({ id, role: 'member', admin, sign: await signingPublicKey(seed(n)), seal: new Uint8Array(65).fill(4), sealVersion: 1 });

function replace(blob: Uint8Array, from: Uint8Array, to: Uint8Array): Uint8Array {
  const out = blob.slice();
  for (let i = 0; i + from.length <= blob.length; i++)
    if (from.every((b, j) => blob[i + j] === b)) {
      out.set(to, i);
      return out;
    }
  throw new Error('not found');
}

describe('N2: signature of a member list before the keys of its members', () => {
  it('a forged blob with a bad member key fails on the signature; a signed one on the key', async () => {
    const [a, b] = [await member('a', true, 1), await member('b', false, 2)];
    const blob = await signManifest(seed(1), { scope: 'demo|x', version: 1, epoch: 0, prev: new Uint8Array(32), members: [a, b] });
    const identity = new Uint8Array(32);
    identity[0] = 1; // small order
    const forged = replace(blob, b.sign, identity);
    await expect(openManifest(forged)).rejects.toThrow('Invalid signature of the member list.');
    await expect(verifyManifest(forged, 'demo|x', [a.sign])).rejects.toThrow('Invalid signature of the member list.');
    const msg = forged.subarray(0, forged.length - SIGNATURE_LEN);
    const signed = new Uint8Array([...msg, ...(await signAsync(msg, seed(1)))]);
    await expect(openManifest(signed)).rejects.toThrow('Not a valid member list.');
    await expect(openManifest(blob)).resolves.toBeTruthy();
  });
});

describe('N3: the chunk list of a backup only in its canonical form (sorted, no duplicates)', () => {
  const names = ['aa'.repeat(32), 'bb'.repeat(32)];
  it.each([
    ['words (version 2)', () => newRecoverySecret(12)],
    ['backup code (version 3)', newBackupCodeSecret],
  ])('%s: a reordered or doubled list is refused, the written one opens', async (_, secret) => {
    const s = secret();
    const b = await encryptBackup(s, { x: 1 }, '2026-11-15T00:00:00Z', 'demo', [names[1]!, names[0]!, names[0]!]);
    expect(b.chunks).toEqual(names);
    expect(await decryptBackup(s, b, 'demo')).toMatchObject({ ok: true, chunks: names });
    for (const chunks of [[...names].reverse(), [...names, names[0]], [names[0], names[0], names[1]]])
      expect(await decryptBackup(s, { ...b, chunks }, 'demo'), JSON.stringify(chunks)).toEqual({ ok: false, error: 'wrong-key-or-damaged' });
  });
});

describe('N6: runtime dependencies pinned exactly', () => {
  it('every dependency is an exact version, the same as in the lock file', () => {
    const locked = lock as unknown as { packages: Record<string, { version: string; dependencies?: Record<string, string> }> };
    for (const [name, range] of Object.entries(pkg.dependencies)) {
      expect(range, name).toMatch(/^\d+\.\d+\.\d+$/);
      expect(locked.packages['']?.dependencies?.[name], name).toBe(range);
      expect(locked.packages[`node_modules/${name}`]?.version, name).toBe(range);
    }
  });
});

describe('N7: a lower Argon2id bound for reading on a phone', () => {
  it('maxKdf refuses a costlier header before any work; default backups open', async () => {
    const s = newBackupCodeSecret();
    const b = await encryptBackup(s, { x: 1 }, '2026-11-15T00:00:00Z', 'demo');
    const opts = { maxKdf: MOBILE_BACKUP_CODE_KDF };
    expect(await decryptBackup(s, b, 'demo', opts)).toMatchObject({ ok: true });
    for (const kdf of [{ m: 131072, t: 2, p: 1 }, { m: 65536, t: 4, p: 1 }, { m: 32768, t: 8, p: 1 }]) {
      const t = performance.now();
      expect(await decryptBackup(s, { ...b, kdf: { name: 'argon2id', ...kdf } }, 'demo', opts), JSON.stringify(kdf)).toEqual({ ok: false, error: 'not-backup' });
      expect(performance.now() - t).toBeLessThan(100);
    }
    expect(MOBILE_BACKUP_CODE_KDF).toEqual({ m: 65536, t: 8, p: 4, work: 131072 });
    expect(validBackupCodeKdf(DEFAULT_BACKUP_CODE_KDF, MOBILE_BACKUP_CODE_KDF) && !validBackupCodeKdf({ m: 65536, t: 4, p: 1 }, MOBILE_BACKUP_CODE_KDF)).toBe(true);
  });
});
