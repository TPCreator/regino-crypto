import { describe, expect, it } from 'vitest';
import v from '../../testvectors/regino/signing-0.13.2.json';
import { inspectManifestChain, nextManifest, openManifest, signManifest, verifyManifestChainFromAnchor, type ChainOptions } from './signing';

const hexd = (s: string) => Uint8Array.from(s.match(/../g) ?? [], (h) => parseInt(h, 16));
const hex = (b: Uint8Array) => Array.from(b, (x) => x.toString(16).padStart(2, '0')).join('');
const anchor = hexd(v.anchor);
const signer = hexd(v.signer);
type Pin = { version: number; hashes: string[] } | null | undefined;
const pin = (p: Pin) => (p ? { version: p.version, hashes: p.hashes.map(hexd) } : undefined);
const msg = {
  untrusted: 'not trusted',
  chain: 'does not continue',
  chain_scope: 'another object',
  withheld: 'withheld',
  signature: 'Invalid signature',
} as const;

describe('chain options (shared vectors with Rust)', () => {
  it('signers, anchorsMaySign and pinnedTrusted give the same verdicts as Rust', async () => {
    for (const t of v.from_anchor) {
      const o = t.opts as { pinned?: Pin; signers?: boolean; anchors_may_sign?: boolean; pinned_trusted?: boolean };
      const opts: ChainOptions = {
        pinned: pin(o.pinned),
        signers: o.signers ? [signer] : undefined,
        anchorsMaySign: o.anchors_may_sign,
        pinnedTrusted: o.pinned_trusted,
      };
      const run = verifyManifestChainFromAnchor(t.blobs.map(hexd), v.scope, [anchor], opts);
      if (t.expect === 'ok') expect((await run).length, t.case).toBe(t.accepted);
      else await expect(run, t.case).rejects.toThrow(msg[t.expect as keyof typeof msg]);
    }
  });

  it('pinnedTrusted without a pin changes nothing', async () => {
    const t = v.from_anchor[5]!;
    await expect(verifyManifestChainFromAnchor(t.blobs.map(hexd), v.scope, [anchor], { pinnedTrusted: true })).rejects.toThrow('no version signed by an anchor');
  });
});

describe('inspectManifestChain (structure only, no trust)', () => {
  it('same verdicts and table as Rust', async () => {
    for (const t of v.inspect) {
      const scope = t.expect === 'chain_scope' ? 'dovernik|center|12|case|01JOTHER' : v.scope;
      const run = inspectManifestChain(t.blobs.map(hexd), scope, { pinned: pin(t.pinned as Pin) });
      if (t.expect === 'ok') {
        const rows = (await run).map((r) => ({ version: r.version, epoch: r.epoch, signer: hex(r.signer), members: r.members.map((m) => m.id), hash: hex(r.hash) }));
        expect(rows).toEqual(t.rows);
        // the trusted verification refuses the same chain
        await expect(verifyManifestChainFromAnchor(t.blobs.map(hexd), scope, [anchor])).rejects.toThrow('not trusted');
      } else await expect(run, t.case).rejects.toThrow(msg[t.expect as keyof typeof msg]);
    }
    await expect(inspectManifestChain([], v.scope)).rejects.toThrow('does not continue');
    // a later version for another case, linked to version 1
    const first = hexd(v.inspect[0]!.blobs[0]!);
    const other = await signManifest(new Uint8Array(32).fill(9), { ...nextManifest(await openManifest(first), []), scope: 'x|y' });
    await expect(inspectManifestChain([first, other], v.scope)).rejects.toThrow('another object');
    await expect(inspectManifestChain(v.inspect[0]!.blobs.slice(1).map(hexd), v.scope)).rejects.toThrow('does not continue');
  });
});
