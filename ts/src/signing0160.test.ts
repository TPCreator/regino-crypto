// Review 2026-11-18 (Gemini 4 Argon F-01, decision point 2): `openWriteKey` – the key an app seals new items
// with, every check always on (requireAnchorOnLatest, requireCurrentEpoch, recipientId). Rust: keys/tests/signing_0_16_0.rs.
import { describe, expect, it } from 'vitest';
import {
  confirmManifest,
  nextManifest,
  openSignedWrap,
  openWriteKey,
  signedWrapForDevice,
  signingPublicKey,
  signManifest,
  verifyManifest,
  type Member,
  type WriteKeyChain,
} from './signing';
import { newDeviceKeys, newGroupKey, publicKeyBytes } from './sync';

const seed = (n: number) => new Uint8Array(32).fill(n);
const scope = 'demo|case|7';
const ctx = 'demo|case|7|key';

/** anchor signs v1 (alice, bob admins, carol member); alice removes bob in v2 (epoch 2); bob forks v2′ from v1. */
async function scenario() {
  const keys = { anchor: seed(20), alice: seed(21), bob: seed(22), carol: seed(23), mgmt: seed(24) };
  const pub = Object.fromEntries(await Promise.all(Object.entries(keys).map(async ([k, v]) => [k, await signingPublicKey(v)]))) as Record<keyof typeof keys, Uint8Array>;
  const dev = await newDeviceKeys();
  const devPub = await publicKeyBytes(dev.publicKey);
  const m = (id: 'alice' | 'bob' | 'carol', admin: boolean, seal: Uint8Array): Member => ({ id, role: 'member', admin, sign: pub[id], seal, sealVersion: 1 });
  const other = (id: 'alice' | 'bob') => Uint8Array.of(4, ...pub[id]);
  const v1b = await signManifest(keys.anchor, { scope, version: 1, epoch: 1, prev: new Uint8Array(32), members: [m('alice', true, other('alice')), m('bob', true, other('bob')), m('carol', false, devPub)] });
  const v1 = await verifyManifest(v1b, scope, [pub.anchor]);
  const v2b = await signManifest(keys.alice, { ...nextManifest(v1, [m('alice', true, other('alice')), m('carol', false, devPub)]), epoch: 2 });
  const v2 = await verifyManifest(v2b, scope, [pub.anchor], v1);
  const f2b = await signManifest(keys.bob, nextManifest(v1, v1.manifest.members));
  const f2 = await verifyManifest(f2b, scope, [pub.anchor], v1);
  const byAnchor = { signer: pub.anchor, signature: await confirmManifest(keys.anchor, v2) };
  const chain: WriteKeyChain = { blobs: [v1b, v2b], scope, anchors: [pub.anchor], confirmations: [byAnchor] };
  return { keys, pub, dev, devPub, v1b, v1, v2b, v2, f2b, f2, byAnchor, chain };
}

describe('openWriteKey (0.16.0): the write key with every check on', () => {
  it('opens the current key for the member, from a chain whose latest version an anchor confirmed', async () => {
    const { keys, dev, devPub, v2, chain } = await scenario();
    const groupKey = newGroupKey();
    const cur = await signedWrapForDevice(groupKey, devPub, ctx, 'case7', v2, keys.alice);
    const r = await openWriteKey(cur, dev.privateKey, devPub, ctx, 'case7', 'carol', chain);
    expect(r.groupKey).toEqual(groupKey);
    expect(r.epoch).toBe(2);
    expect(r.list.hash).toEqual(v2.hash);
    expect(r.signer).toEqual(await signingPublicKey(keys.alice));
  });

  it('requireAnchorOnLatest is always on: a latest version nobody trusted confirmed, or a fork, is refused', async () => {
    const { keys, pub, dev, devPub, v1b, v2, f2b, f2, chain } = await scenario();
    const cur = await signedWrapForDevice(newGroupKey(), devPub, ctx, 'case7', v2, keys.alice);
    await expect(openWriteKey(cur, dev.privateKey, devPub, ctx, 'case7', 'carol', { ...chain, confirmations: [] })).rejects.toThrow('latest version');
    // switching it off is not possible, not even past the type
    const off = { ...chain, confirmations: [], requireAnchorOnLatest: false } as WriteKeyChain;
    await expect(openWriteKey(cur, dev.privateKey, devPub, ctx, 'case7', 'carol', off)).rejects.toThrow('latest version');
    // the removed admin's fork and a key it signed for it
    const forked = await signedWrapForDevice(newGroupKey(), devPub, ctx, 'case7', f2, keys.bob);
    await expect(openWriteKey(forked, dev.privateKey, devPub, ctx, 'case7', 'carol', { ...chain, blobs: [v1b, f2b] })).rejects.toThrow('latest version');
    // the default of openSignedWrap is unchanged: the fork's key opens there (0.15.x behaviour)
    expect((await openSignedWrap(forked, dev.privateKey, devPub, ctx, 'case7', f2)).epoch).toBe(1);
    // a signer (e.g. the centre's management) confirms like an anchor
    const byMgmt = { signer: pub.mgmt, signature: await confirmManifest(keys.mgmt, v2) };
    expect((await openWriteKey(cur, dev.privateKey, devPub, ctx, 'case7', 'carol', { ...chain, signers: [pub.mgmt], confirmations: [byMgmt] })).epoch).toBe(2);
  });

  it('requireCurrentEpoch and recipientId are always on', async () => {
    const { keys, dev, devPub, v2, chain } = await scenario();
    const old = await signedWrapForDevice(newGroupKey(), devPub, ctx, 'case7', v2, keys.alice, 1);
    await expect(openWriteKey(old, dev.privateKey, devPub, ctx, 'case7', 'carol', chain)).rejects.toThrow('another object, epoch or member list');
    // a key of an earlier epoch still opens for reading older items (openSignedWrap, defaults unchanged)
    expect((await openSignedWrap(old, dev.privateKey, devPub, ctx, 'case7', v2)).epoch).toBe(1);
    const cur = await signedWrapForDevice(newGroupKey(), devPub, ctx, 'case7', v2, keys.alice);
    await expect(openWriteKey(cur, dev.privateKey, devPub, ctx, 'case7', 'alice', chain)).rejects.toThrow('not a member of the list with this key');
    await expect(openWriteKey(cur, dev.privateKey, devPub, ctx, 'case7', 'bob', chain)).rejects.toThrow('not a member of the list with this key');
    await expect(openWriteKey(cur, dev.privateKey, devPub, ctx, 'case7', '', chain)).rejects.toThrow('recipient id is required');
    await expect(openWriteKey(cur, dev.privateKey, devPub, ctx, 'case7', undefined as unknown as string, chain)).rejects.toThrow('recipient id is required');
    await expect(openWriteKey(cur, dev.privateKey, devPub, ctx, 'case8', 'carol', chain)).rejects.toThrow('another object');
  });
});
