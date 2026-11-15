// Fixes after the audit of 0.15.0 (2026-11-15): each test failed before its fix (AUDIT.md § 4.5).
import { signAsync } from '@noble/ed25519';
import { describe, expect, it } from 'vitest';
import lock from '../package-lock.json';
import pkg from '../package.json';
import { decryptBackup, encryptBackup } from './backup';
import { DEFAULT_BACKUP_CODE_KDF, MOBILE_BACKUP_CODE_KDF, newBackupCodeSecret, validBackupCodeKdf } from './backupCode';
import { newRecoverySecret } from './recovery';
import {
  confirmManifest,
  manifestConfirmationMessage,
  nextManifest,
  openManifest,
  SIGNATURE_LEN,
  signingPublicKey,
  signManifest,
  verifyManifest,
  verifyManifestChainFromAnchor,
  verifyManifestConfirmation,
  type Member,
} from './signing';

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

/** The scenario of the audit: anchor signs v1 (alice and bob admins); alice removes bob in v2 (epoch 2);
 * bob, still admin of v1, forks v2′ from v1 adding mallory; a member who restores sees only [v1, v2′]. */
async function forkScenario() {
  const scope = 'demo|case|1';
  const keys = { anchor: seed(10), alice: seed(11), bob: seed(12), mallory: seed(13), mgmt: seed(14) };
  const pub = Object.fromEntries(await Promise.all(Object.entries(keys).map(async ([k, v]) => [k, await signingPublicKey(v)]))) as Record<keyof typeof keys, Uint8Array>;
  const m = (id: 'alice' | 'bob' | 'mallory', admin: boolean): Member => ({ id, role: 'member', admin, sign: pub[id], seal: new Uint8Array(65).fill(4), sealVersion: 1 });
  const v1b = await signManifest(keys.anchor, { scope, version: 1, epoch: 1, prev: new Uint8Array(32), members: [m('alice', true), m('bob', true)] });
  const v1 = await verifyManifest(v1b, scope, [pub.anchor]);
  const v2b = await signManifest(keys.alice, { ...nextManifest(v1, [m('alice', true)]), epoch: 2 });
  const v2 = await verifyManifest(v2b, scope, [pub.anchor], v1);
  const f2b = await signManifest(keys.bob, nextManifest(v1, [m('alice', true), m('bob', true), m('mallory', true)]));
  return { scope, keys, pub, v1b, v1, v2b, v2, f2b };
}

describe('S1: the latest version signed or confirmed by an anchor (requireAnchorOnLatest)', () => {
  it('refuses the chain of a removed admin; the default keeps 0.15.0 behaviour', async () => {
    const { scope, pub, v1b, f2b } = await forkScenario();
    // the attack of the audit: accepted without the option (unchanged default)
    expect((await verifyManifestChainFromAnchor([v1b, f2b], scope, [pub.anchor])).length).toBe(2);
    await expect(verifyManifestChainFromAnchor([v1b, f2b], scope, [pub.anchor], { requireAnchorOnLatest: true })).rejects.toThrow('not trusted (the latest version is not signed or confirmed by an anchor)');
  });

  it('accepts a latest version signed by an anchor or a signer, or confirmed by one of them', async () => {
    const { scope, keys, pub, v1b, v1, v2b, v2, f2b } = await forkScenario();
    const opts = { requireAnchorOnLatest: true } as const;
    expect((await verifyManifestChainFromAnchor([v1b], scope, [pub.anchor], opts)).length).toBe(1);
    await expect(verifyManifestChainFromAnchor([v1b, v2b], scope, [pub.anchor], opts)).rejects.toThrow('latest version');
    const byAnchor = { signer: pub.anchor, signature: await confirmManifest(keys.anchor, v2) };
    expect((await verifyManifestChainFromAnchor([v1b, v2b], scope, [pub.anchor], { ...opts, confirmations: [byAnchor] })).at(-1)?.hash).toEqual(v2.hash);
    // the confirmation is for exactly that version: not for the fork, not for v1, not by bob
    await expect(verifyManifestChainFromAnchor([v1b, f2b], scope, [pub.anchor], { ...opts, confirmations: [byAnchor] })).rejects.toThrow('latest version');
    const byBob = { signer: pub.bob, signature: await confirmManifest(keys.bob, v2) };
    await expect(verifyManifestChainFromAnchor([v1b, v2b], scope, [pub.anchor], { ...opts, confirmations: [byBob] })).rejects.toThrow('latest version');
    const v1conf = { signer: pub.anchor, signature: await confirmManifest(keys.anchor, v1) };
    await expect(verifyManifestChainFromAnchor([v1b, v2b], scope, [pub.anchor], { ...opts, confirmations: [v1conf, v1conf, byBob] })).rejects.toThrow('latest version');
    // a signer (e.g. the centre's management) counts like an anchor; anchors confirm even with anchorsMaySign false
    const byMgmt = { signer: pub.mgmt, signature: await confirmManifest(keys.mgmt, v2) };
    expect((await verifyManifestChainFromAnchor([v1b, v2b], scope, [pub.anchor], { ...opts, signers: [pub.mgmt], confirmations: [byMgmt] })).length).toBe(2);
    expect((await verifyManifestChainFromAnchor([v1b, v2b], scope, [pub.anchor], { ...opts, anchorsMaySign: false, confirmations: [byAnchor] })).length).toBe(2);
    await expect(verifyManifestChainFromAnchor([v1b, v2b], scope, [pub.anchor], { ...opts, confirmations: [byMgmt] })).rejects.toThrow('latest version');
    // malformed confirmations are skipped, never accepted
    const junk = [null, { signer: 'x', signature: byAnchor.signature }, { signer: pub.anchor, signature: new Uint8Array(3) }] as never[];
    await expect(verifyManifestChainFromAnchor([v1b, v2b], scope, [pub.anchor], { ...opts, confirmations: junk })).rejects.toThrow('latest version');
    expect(await verifyManifestConfirmation(pub.anchor, v2, byAnchor.signature)).toBe(true);
    expect(await verifyManifestConfirmation(new Uint8Array(32), v2, byAnchor.signature)).toBe(false);
    expect(() => manifestConfirmationMessage(v2, new Uint8Array(32))).toThrow('Invalid signing public key.');
  });
});

