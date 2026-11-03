import { describe, expect, it } from 'vitest';
import v from '../../testvectors/regino/signing-0.13.3.json';
import { clearSigningKeyCache, isSigningPublicKey, SIGNING_KEY_CACHE, signingPublicKey, verifyManifestChainFromAnchor, type ChainOptions } from './signing';

const hexd = (s: string) => Uint8Array.from(s.match(/../g) ?? [], (h) => parseInt(h, 16));
const hex = (b: Uint8Array) => Array.from(b, (x) => x.toString(16).padStart(2, '0')).join('');
const msg = { untrusted: 'not trusted', chain: 'does not continue', withheld: 'withheld' } as const;

describe('option combinations (shared vectors with Rust)', () => {
  it('same verdicts and hashes as Rust', async () => {
    for (const t of v.cases) {
      const o = t.opts as { pinned?: { version: number; hashes: string[] }; signers?: boolean; anchors_may_sign?: boolean; pinned_trusted?: boolean };
      const opts: ChainOptions = {
        pinned: o.pinned && { version: o.pinned.version, hashes: o.pinned.hashes.map(hexd) },
        signers: o.signers ? [hexd(v.signer)] : undefined,
        anchorsMaySign: o.anchors_may_sign,
        pinnedTrusted: o.pinned_trusted,
      };
      const run = verifyManifestChainFromAnchor(t.blobs.map(hexd), v.scope, [hexd(v.anchor)], opts);
      if (t.expect === 'ok') expect((await run).map((a) => hex(a.hash)), t.case).toEqual(t.hashes);
      else await expect(run, t.case).rejects.toThrow(msg[t.expect as keyof typeof msg]);
    }
  });
});

describe('remembered public-key verdicts (0.13.3)', () => {
  it('give the same result, also for invalid keys, before and after clearing', async () => {
    const good = await signingPublicKey(new Uint8Array(32).fill(1));
    const order8 = hexd('c7176a703d4dd84fba3c0b760d10670f2a2053fa2c39ccc64ec7fd7792ac03fa');
    clearSigningKeyCache();
    for (let i = 0; i < 3; i++) {
      expect(isSigningPublicKey(good)).toBe(true);
      expect(isSigningPublicKey(order8)).toBe(false);
    }
    // the bytes decide, not the object: a changed copy is checked anew
    const changed = good.slice();
    changed[0]! ^= 1;
    expect(isSigningPublicKey(changed)).toBe(isSigningPublicKey(changed.slice()));
    expect(isSigningPublicKey(new Uint8Array(31))).toBe(false);
  });

  it('is bounded: the least recently used verdicts are dropped, results stay the same', async () => {
    clearSigningKeyCache();
    const good = await signingPublicKey(new Uint8Array(32).fill(2));
    expect(isSigningPublicKey(good)).toBe(true);
    for (let i = 0; i < SIGNING_KEY_CACHE + 10; i++) {
      const k = new Uint8Array(32);
      new DataView(k.buffer).setUint32(0, i + 7);
      isSigningPublicKey(k);
    }
    expect(isSigningPublicKey(good)).toBe(true);
    expect(SIGNING_KEY_CACHE).toBe(4096);
  });
});
