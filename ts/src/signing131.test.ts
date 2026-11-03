import { describe, expect, it } from 'vitest';
import v from '../../testvectors/regino/signing-0.13.1.json';
import { b64 } from './ecdh';
import { openSignedWrap, signedWrapForDevice, signingPublicKey, signWrap, verifyManifestChainFromAnchor, wrapMessage, type PinnedManifest } from './signing';
import { newDeviceKeys, newGroupKey, publicKeyBytes } from './sync';

const hexd = (s: string) => Uint8Array.from(s.match(/../g) ?? [], (h) => parseInt(h, 16));
const hex = (b: Uint8Array) => Array.from(b, (x) => x.toString(16).padStart(2, '0')).join('');
const fill = (n: number) => new Uint8Array(32).fill(n);
const anchor = hexd(v.anchor);

describe('chain verified from an anchor (shared vectors with Rust)', () => {
  it('same verdicts as Rust', async () => {
    const msg = { untrusted: 'not trusted', chain: /does not continue|another object/, withheld: 'withheld' } as const;
    for (const t of v.from_anchor) {
      const pinned = 'pinned' in t && t.pinned ? { version: t.pinned.version, hashes: t.pinned.hashes.map(hexd) } : undefined;
      const run = verifyManifestChainFromAnchor(t.blobs.map(hexd), v.scope, [anchor], { pinned });
      if (t.expect === 'ok') {
        const list = await run;
        expect(list.length, t.case).toBe(t.accepted);
        if (t.blobs.length > 1) list.forEach((a, i) => expect(hex(a.hash)).toBe(v.chain[i]!.hash));
      } else await expect(run, t.case).rejects.toThrow(msg[t.expect as keyof typeof msg]);
    }
  });

  it('fail-closed without anchors; bad pins and another scope are refused', async () => {
    const blobs = v.chain.map((c) => hexd(c.blob));
    await expect(verifyManifestChainFromAnchor(blobs, v.scope, [])).rejects.toThrow('not trusted');
    await expect(verifyManifestChainFromAnchor(blobs.slice(0, 2), v.scope, [])).rejects.toThrow('no version signed by an anchor');
    for (const pinned of [{ version: 2, hashes: [] }, { version: 1, hashes: [fill(0), fill(0)] }, { version: 1.5, hashes: [fill(0)] }] as PinnedManifest[])
      await expect(verifyManifestChainFromAnchor(blobs, v.scope, [anchor], { pinned })).rejects.toThrow('Invalid pinned');
    await expect(verifyManifestChainFromAnchor(blobs, 'other', [anchor])).rejects.toThrow('another object');
    // a pin of a version after the chain only reports withholding
    await expect(verifyManifestChainFromAnchor(blobs, v.scope, [anchor], { pinned: { version: 6, hashes: [fill(0)] } })).rejects.toThrow('withheld');
  });
});

describe('wrapped key for a named recipient', () => {
  it('signatures match Rust; the recipient must be the member of the list with that seal', async () => {
    const list = (await verifyManifestChainFromAnchor(v.chain.map((c) => hexd(c.blob)), v.scope, [anchor])).pop()!;
    const signer = await signingPublicKey(fill(2));
    for (const t of v.recipient) {
      const st = { context: t.context, objectId: t.object_id, version: t.version, manifest: hexd(t.manifest), recipient: hexd(t.recipient), wrapped: hexd(t.wrapped) };
      expect(hex(await signWrap(fill(2), st))).toBe(t.signature);
      expect(hex(wrapMessage(st, signer)).length).toBeGreaterThan(0);
      const signed = { v: 1, id: t.object_id, ver: t.version, m: b64(list.hash), w: t.wrapped_key, k: b64(signer), s: b64(hexd(t.signature)) };
      const dev = await newDeviceKeys(); // not the real recipient: an accepted check then fails only at unwrapping
      const run = openSignedWrap(signed, dev.privateKey, hexd(t.recipient), t.context, t.object_id, list, [], { recipientId: t.recipient_id });
      await expect(run, t.case).rejects.toThrow(t.expect === 'ok' ? 'cannot be unwrapped' : 'not a member of the list');
    }
  });

  it('opens for the named member on its device; without recipientId as before', async () => {
    const dev = await newDeviceKeys();
    const devPub = await publicKeyBytes(dev.publicKey);
    const { signManifest, openManifest } = await import('./signing');
    const scope = 'demo|case|r';
    const sign = await signingPublicKey(fill(2));
    const blob = await signManifest(fill(1), { scope, version: 1, epoch: 1, prev: new Uint8Array(32), members: [{ id: 'm', role: 'r', admin: true, sign, seal: devPub, sealVersion: 1 }] });
    const list = await openManifest(blob);
    const k = newGroupKey();
    const w = await signedWrapForDevice(k, devPub, 'c', 'case', list, fill(2));
    expect((await openSignedWrap(w, dev.privateKey, devPub, 'c', 'case', list, [], { recipientId: 'm' })).groupKey).toEqual(k);
    expect((await openSignedWrap(w, dev.privateKey, devPub, 'c', 'case', list)).groupKey).toEqual(k);
    await expect(openSignedWrap(w, dev.privateKey, devPub, 'c', 'case', list, [], { recipientId: 'x' })).rejects.toThrow('not a member');
  });
});
