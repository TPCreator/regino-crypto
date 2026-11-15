// Fixes after the audit of 0.15.0 (2026-11-15): each test failed before its fix (AUDIT.md § 4.5).
import { signAsync } from '@noble/ed25519';
import { describe, expect, it } from 'vitest';
import { decryptBackup, encryptBackup } from './backup';
import { newBackupCodeSecret } from './backupCode';
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
