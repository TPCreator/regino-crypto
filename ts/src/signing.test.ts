import { signAsync } from '@noble/ed25519';
import { describe, expect, it } from 'vitest';
import v from '../../testvectors/regino/signing-0.13.0.json';
import ed25519 from '../../testvectors/wycheproof/ed25519_test.json';
import { b64, unb64 } from './ecdh';
import {
  deriveSigningKey,
  dataMessage,
  isSigningPublicKey,
  manifestFingerprint,
  manifestMessage,
  memberKeyMessage,
  seedSigner,
  signMemberKey,
  verifyMemberKey,
  wrapMessage,
  type MemberKey,
  type Signer,
  MAX_VERSION,
  memberByKey,
  newSigningKey,
  nextManifest,
  openManifest,
  openSignedWrap,
  signData,
  signedWrapForDevice,
  signingFingerprint,
  signingPublicKey,
  signManifest,
  signWrap,
  verifyData,
  verifyEd25519,
  verifyManifest,
  verifyManifestChain,
  verifyWrap,
  wrappedKeyBytes,
  type AcceptedManifest,
  type Manifest,
  type Member,
  type WrapStatement,
} from './signing';
import { newDeviceKeys, newGroupKey, publicKeyBytes, wrapForDevice, type WrappedGroupKey } from './sync';

const hexd = (s: string) => Uint8Array.from(s.match(/../g) ?? [], (h) => parseInt(h, 16));
const hex = (b: Uint8Array) => Array.from(b, (x) => x.toString(16).padStart(2, '0')).join('');
const te = new TextEncoder();
const fill = (n: number) => new Uint8Array(32).fill(n);
const pub = (n: number) => signingPublicKey(fill(n));

describe('signing keys (shared vectors with Rust)', () => {
  it('public keys and fingerprints', async () => {
    for (const t of v.keys) {
      expect(hex(await signingPublicKey(hexd(t.seed)))).toBe(t.public);
      expect(await signingFingerprint(hexd(t.public))).toBe(t.fingerprint);
    }
    expect(await signingFingerprint(hexd(v.keys[0]!.public))).toMatch(/^[0-9a-f]{4}( [0-9a-f]{4}){4}$/);
  });

  it('derived from a key the app keeps (HKDF), identical to Rust', async () => {
    for (const t of v.derive) {
      const seed = await deriveSigningKey(hexd(t.key), t.app, t.label);
      expect(hex(seed)).toBe(t.seed);
      expect(hex(await signingPublicKey(seed))).toBe(t.public);
    }
    for (const [app, label] of [['de-mo', 'share'], ['Demo', 'share'], ['demo', 'ab'], ['demo', 'Share'], ['d', 'share']] as const)
      await expect(deriveSigningKey(fill(1), app, label)).rejects.toThrow('Invalid app name');
    await expect(deriveSigningKey(new Uint8Array(31), 'demo', 'share')).rejects.toThrow('32 bytes');
  });

  it('random keys differ; a key must have 32 bytes', async () => {
    const a = newSigningKey();
    expect(a.length).toBe(32);
    expect(hex(a)).not.toBe(hex(newSigningKey()));
    expect(() => signingPublicKey(new Uint8Array(31))).toThrow('32 bytes');
    expect(() => signingPublicKey('x' as unknown as Uint8Array)).toThrow('32 bytes');
  });

  it('public key checks: small order, torsion, length', async () => {
    expect(isSigningPublicKey(await pub(1))).toBe(true);
    expect(isSigningPublicKey(hexd('01' + '00'.repeat(31)))).toBe(false); // identity
    expect(isSigningPublicKey(hexd('c7176a703d4dd84fba3c0b760d10670f2a2053fa2c39ccc64ec7fd7792ac03fa'))).toBe(false); // order 8
    expect(isSigningPublicKey(hexd(v.raw[2]!.public))).toBe(false); // torsion component
    expect(isSigningPublicKey(new Uint8Array(31))).toBe(false);
    expect(isSigningPublicKey(new Uint8Array(32).fill(0xff))).toBe(false); // y >= p
    expect(isSigningPublicKey(null as unknown as Uint8Array)).toBe(false);
    await expect(signingFingerprint(new Uint8Array(32))).rejects.toThrow('Invalid signing public key');
  });
});

describe('strict verification (same verdicts as ed25519-dalek verify_strict)', () => {
  it('edge cases where a cofactored check would accept', async () => {
    for (const t of v.raw) {
      expect(await verifyEd25519(hexd(t.public), hexd(t.message), hexd(t.signature)), t.case).toBe(t.valid);
    }
    // the plain check of the library alone would accept the torsion cases – the extra rules matter
    expect(v.raw.filter((t) => t.noble_cofactored && !t.valid).length).toBe(2);
    expect(await verifyEd25519(hexd(v.raw[0]!.public), hexd(v.raw[0]!.message), new Uint8Array(63))).toBe(false);
    // S >= L and a damaged R are false, and so is input the library would throw on
    expect(await verifyEd25519(hexd(v.raw[3]!.public), hexd(v.raw[3]!.message), hexd(v.raw[3]!.signature))).toBe(false);
    expect(await verifyEd25519(hexd(v.raw[0]!.public), 'x' as unknown as Uint8Array, hexd(v.raw[0]!.signature))).toBe(false);
    const badR = hexd(v.raw[0]!.signature);
    badR.fill(0xff, 0, 31); // R not a point
    expect(await verifyEd25519(hexd(v.raw[0]!.public), hexd(v.raw[0]!.message), badR)).toBe(false);
  });

  it('Wycheproof Ed25519', async () => {
    let n = 0;
    for (const g of ed25519.testGroups) {
      const pk = hexd(g.publicKey.pk);
      expect(isSigningPublicKey(pk)).toBe(true);
      for (const t of g.tests) {
        expect(await verifyEd25519(pk, hexd(t.msg), hexd(t.sig)), `tcId ${t.tcId}`).toBe(t.result === 'valid');
        n++;
      }
    }
    expect(n).toBeGreaterThan(100);
  });
});

describe('signed data', () => {
  it('matches Rust and is bound to key, context and data', async () => {
    for (const t of v.data) {
      const sig = await signData(hexd(t.seed), t.context, hexd(t.data));
      expect(hex(sig)).toBe(t.signature);
      const p = await signingPublicKey(hexd(t.seed));
      expect(await verifyData(p, t.context, hexd(t.data), sig)).toBe(true);
      expect(await verifyData(p, t.context + 'x', hexd(t.data), sig)).toBe(false);
      expect(await verifyData(p, t.context, te.encode('other'), sig)).toBe(false);
      expect(await verifyData(await pub(9), t.context, hexd(t.data), sig)).toBe(false);
      expect(await verifyData(new Uint8Array(32), t.context, hexd(t.data), sig)).toBe(false);
    }
  });

  it('refuses empty, too long or broken contexts and non-byte data', async () => {
    await expect(signData(fill(1), '', te.encode('x'))).rejects.toThrow('must not be empty');
    await expect(signData(fill(1), 'x'.repeat(1025), te.encode('x'))).rejects.toThrow('too long');
    await expect(signData(fill(1), '\ud800', te.encode('x'))).rejects.toThrow('not valid text');
    await expect(signData(fill(1), 'c', 'x' as unknown as Uint8Array)).rejects.toThrow('Invalid data');
  });
});

describe('signed wrapped keys', () => {
  it('signatures match Rust, cover every field, and only an admin of the accepted list may give a key', async () => {
    const lists = { v3: (await accepted(3))!, v4: (await accepted(4))! };
    const anchor = hexd(v.manifest.anchor);
    for (const t of v.wrap) {
      const list = lists[t.list as 'v3' | 'v4'];
      const st: WrapStatement = { context: t.context, objectId: t.object_id, version: t.version, manifest: hexd(t.manifest), recipient: hexd(t.recipient), wrapped: hexd(t.wrapped) };
      expect(hex(wrappedKeyBytes(t.wrapped_key))).toBe(t.wrapped);
      const sig = await signWrap(hexd(t.seed), st);
      expect(hex(sig)).toBe(t.signature);
      const signer = await signingPublicKey(hexd(t.seed));
      expect(await verifyWrap(signer, st, sig)).toBe(true);
      for (const changed of [{ context: 'other' }, { objectId: 'other' }, { version: t.version - 1 }, { manifest: new Uint8Array(32).fill(7) }, { recipient: new Uint8Array(65).fill(1) }, { wrapped: te.encode('x') }])
        expect(await verifyWrap(signer, { ...st, ...changed }, sig)).toBe(false);
      expect(await verifyWrap(await pub(9), st, sig)).toBe(false);
      expect(await verifyWrap(new Uint8Array(32), st, sig)).toBe(false);
      // the same verdict as Rust's verify_wrap_for, through openSignedWrap (checked before unwrapping)
      const signed = { v: 1, id: t.object_id, ver: t.version, m: b64(hexd(t.manifest)), w: t.wrapped_key, k: b64(signer), s: b64(sig) };
      const want = { ok: 'cannot be unwrapped', untrusted: 'not trusted', chain: 'another object' }[t.expect]!;
      const dev = await newDeviceKeys(); // not the recipient – an accepted key then fails only at unwrapping
      await expect(openSignedWrap(signed, dev.privateKey, hexd(t.recipient), t.context, t.object_id, list, [anchor]), t.note).rejects.toThrow(want);
    }
    const t = v.wrap_opaque;
    const st = { context: t.context, objectId: t.object_id, version: t.version, manifest: hexd(t.manifest), recipient: hexd(t.recipient), wrapped: hexd(t.wrapped) };
    expect(t.version).toBe(MAX_VERSION);
    expect(hex(await signWrap(hexd(t.seed), st))).toBe(t.signature);
  });

  it('earlier epochs from an admin, the handover by the signer of the list, never an epoch above the list', async () => {
    const dev = await newDeviceKeys();
    const devPub = await publicKeyBytes(dev.publicKey);
    const [x, y, mgmt] = [newSigningKey(), newSigningKey(), newSigningKey()];
    const m = async (id: string, admin: boolean, k: Uint8Array): Promise<Member> => ({ id, role: 'r', admin, sign: await signingPublicKey(k), seal: devPub, sealVersion: 1 });
    const sc = 'demo|case|h';
    const one = await verifyManifest(await signManifest(mgmt, { scope: sc, version: 1, epoch: 3, prev: new Uint8Array(32), members: [await m('x', true, x), await m('y', false, y)] }), sc, [await signingPublicKey(mgmt)]);
    const old = newGroupKey();
    const k1 = await signedWrapForDevice(old, devPub, 'c|1', 'case-h', one, x, 1);
    expect(k1.ver).toBe(1);
    expect(await openSignedWrap(k1, dev.privateKey, devPub, 'c|1', 'case-h', one)).toMatchObject({ groupKey: old, epoch: 1 });
    await expect(signedWrapForDevice(old, devPub, 'c|4', 'case-h', one, x, 4)).rejects.toThrow('above the epoch');
    const byMember = await signedWrapForDevice(old, devPub, 'c|1', 'case-h', one, y, 1);
    await expect(openSignedWrap(byMember, dev.privateKey, devPub, 'c|1', 'case-h', one)).rejects.toThrow('not trusted');
    // x hands over to y and leaves (new epoch); x signed list 2, so its keys for list 2 are accepted
    const two = await verifyManifest(await signManifest(x, { ...nextManifest(one, [await m('y', true, y)]), epoch: 4 }), sc, [], one);
    expect(memberByKey(two.manifest, await signingPublicKey(x))).toBeUndefined();
    const k4 = await signedWrapForDevice(old, devPub, 'c|4', 'case-h', two, x);
    expect((await openSignedWrap(k4, dev.privateKey, devPub, 'c|4', 'case-h', two)).epoch).toBe(4);
    // a negative or broken epoch in the envelope is refused
    await expect(openSignedWrap({ ...k4, ver: -1 }, dev.privateKey, devPub, 'c|4', 'case-h', two)).rejects.toThrow('whole number');
    await expect(openSignedWrap({ ...k4, ver: 'x' as unknown as number }, dev.privateKey, devPub, 'c|4', 'case-h', two)).rejects.toThrow('another object');
  });

  it('a Signer outside TypeScript (Rust sign_prepared) gives the same bytes as the vectors', async () => {
    const seedBytes = hexd(v.prepared.seed);
    const calls: Uint8Array[] = [];
    const rust: Signer = { publicKey: await signingPublicKey(seedBytes), sign: async (msg) => (calls.push(msg), signAsync(msg, seedBytes)) };
    for (const t of v.prepared.ok) expect(hex(await rust.sign(hexd(t.message))), t.kind).toBe(t.signature);
    // signManifest and signedWrapForDevice through the Signer reproduce the Rust vectors
    const list = (await accepted(3))!;
    const c = v.manifest.chain[3]!;
    const a4 = await openManifest(hexd(c.blob));
    expect(hex(await signManifest(rust, a4.manifest))).toBe(c.blob);
    const dev = await newDeviceKeys();
    const devPub = await publicKeyBytes(dev.publicKey);
    const signed = await signedWrapForDevice(newGroupKey(), devPub, 'c', 'case', list, rust);
    expect(hex(calls[calls.length - 1]!)).toBe(hex(wrapMessage({ context: 'c', objectId: 'case', version: 2, manifest: list.hash, recipient: devPub, wrapped: wrappedKeyBytes(signed.w) }, rust.publicKey)));
    expect((await openSignedWrap(signed, dev.privateKey, devPub, 'c', 'case', list)).signer).toEqual(rust.publicKey);
    expect(hex(manifestMessage(a4.manifest, a4.signer))).toBe(c.blob.slice(0, -128));
    expect(hex(dataMessage('dovernik|center|12|share-key', te.encode('abc')))).toBe(v.prepared.ok[0]!.message);
    const seeded = await seedSigner(seedBytes);
    expect(seeded.publicKey).toEqual(rust.publicKey);
  });

  it('statement limits', async () => {
    const st: WrapStatement = { context: 'c', objectId: 'o', version: 1, manifest: new Uint8Array(32), recipient: Uint8Array.of(1), wrapped: Uint8Array.of(2) };
    await expect(signWrap(fill(1), { ...st, recipient: new Uint8Array(0) })).rejects.toThrow('recipient');
    await expect(signWrap(fill(1), { ...st, wrapped: new Uint8Array(65537) })).rejects.toThrow('wrapped');
    await expect(signWrap(fill(1), { ...st, manifest: new Uint8Array(31) })).rejects.toThrow('list hash');
    await expect(signWrap(fill(1), { ...st, version: -1 })).rejects.toThrow('whole number');
    await expect(signWrap(fill(1), { ...st, version: 1.5 })).rejects.toThrow('whole number');
    await expect(signWrap(fill(1), { ...st, version: MAX_VERSION + 1 })).rejects.toThrow('whole number');
    await expect(signWrap(fill(1), { ...st, objectId: '' })).rejects.toThrow('must not be empty');
    expect(() => wrappedKeyBytes({ v: 2, e: 'a.b', n: 'x', c: 'y' })).toThrow('Invalid wrapped key');
    expect(() => wrappedKeyBytes({ v: 1.5, e: 'a', n: 'x', c: 'y' })).toThrow('Invalid wrapped key');
    expect(() => wrappedKeyBytes(null as unknown as WrappedGroupKey)).toThrow('Invalid wrapped key');
  });

  it('opens only from an admin of the accepted list (or an anchor), for that list and epoch, on the right device', async () => {
    const dev = await newDeviceKeys();
    const devPub = await publicKeyBytes(dev.publicKey);
    const groupKey = newGroupKey();
    const [admin, member, mgmt] = [newSigningKey(), newSigningKey(), newSigningKey()];
    const m = async (id: string, isAdmin: boolean, k: Uint8Array): Promise<Member> => ({ id, role: 'r', admin: isAdmin, sign: await signingPublicKey(k), seal: devPub, sealVersion: 1 });
    const sc = 'demo|case|1';
    const one = await verifyManifest(await signManifest(mgmt, { scope: sc, version: 1, epoch: 4, prev: new Uint8Array(32), members: [await m('a', true, admin), await m('b', false, member)] }), sc, [await signingPublicKey(mgmt)]);
    const ctx = 'demo|case|1|key|4';
    const signed = await signedWrapForDevice(groupKey, devPub, ctx, 'case-1', one, admin);
    expect(signed.v).toBe(1);
    expect(signed.ver).toBe(4);
    const got = await openSignedWrap(signed, dev.privateKey, devPub, ctx, 'case-1', one);
    expect(got.groupKey).toEqual(groupKey);
    expect(got.signer).toEqual(await signingPublicKey(admin));
    // a member who is not admin cannot give the key; management only when passed as anchor
    const byMember = await signedWrapForDevice(groupKey, devPub, ctx, 'case-1', one, member);
    await expect(openSignedWrap(byMember, dev.privateKey, devPub, ctx, 'case-1', one)).rejects.toThrow('not trusted');
    // management signed this list, so it may give its keys (as its signer), and also as anchor
    const byMgmt = await signedWrapForDevice(groupKey, devPub, ctx, 'case-1', one, mgmt);
    expect((await openSignedWrap(byMgmt, dev.privateKey, devPub, ctx, 'case-1', one)).groupKey).toEqual(groupKey);
    expect((await openSignedWrap(byMgmt, dev.privateKey, devPub, ctx, 'case-1', one, [await signingPublicKey(mgmt)])).groupKey).toEqual(groupKey);
    // another object, epoch or list
    await expect(openSignedWrap(signed, dev.privateKey, devPub, ctx, 'case-2', one)).rejects.toThrow('another object');
    const two = await verifyManifest(await signManifest(admin, { ...nextManifest(one, [await m('a', true, admin)]), epoch: 5 }), sc, [], one);
    await expect(openSignedWrap(signed, dev.privateKey, devPub, ctx, 'case-1', two)).rejects.toThrow('another object');
    // the server swaps epoch and list hash in the envelope: the signature no longer matches
    await expect(openSignedWrap({ ...signed, ver: 5, m: b64(two.hash) }, dev.privateKey, devPub, ctx, 'case-1', two)).rejects.toThrow('Invalid signature');
    // the server wraps its own key and signs with its own key: not trusted
    const forged = await signedWrapForDevice(newGroupKey(), devPub, ctx, 'case-1', one, newSigningKey());
    await expect(openSignedWrap(forged, dev.privateKey, devPub, ctx, 'case-1', one)).rejects.toThrow('not trusted');
    // the server wraps its own key but keeps the admin's name and signature
    const own = await wrapForDevice(newGroupKey(), devPub, ctx);
    await expect(openSignedWrap({ ...signed, w: own }, dev.privateKey, devPub, ctx, 'case-1', one)).rejects.toThrow('Invalid signature');
    await expect(openSignedWrap({ ...signed, s: '***' }, dev.privateKey, devPub, ctx, 'case-1', one)).rejects.toThrow('Invalid signed');
    await expect(openSignedWrap({ ...signed, v: 2 }, dev.privateKey, devPub, ctx, 'case-1', one)).rejects.toThrow('version');
    await expect(openSignedWrap(null as unknown as typeof signed, dev.privateKey, devPub, ctx, 'case-1', one)).rejects.toThrow('version');
    // another device cannot unwrap even with a valid signature
    const other = await newDeviceKeys();
    await expect(openSignedWrap(signed, other.privateKey, await publicKeyBytes(other.publicKey), ctx, 'case-1', one)).rejects.toThrow('Invalid signature');
    expect(unb64(signed.k)).toEqual(await signingPublicKey(admin));
  });

  it('a fork: two lists with the same version – keys of one branch do not open on the other, codes differ', async () => {
    const [x, y, mgmt] = [newSigningKey(), newSigningKey(), newSigningKey()];
    const m = async (id: string, k: Uint8Array): Promise<Member> => ({ id, role: 'r', admin: true, sign: await signingPublicKey(k), seal: new Uint8Array(0), sealVersion: 0 });
    const sc = 'demo|case|9';
    const one = await verifyManifest(await signManifest(mgmt, { scope: sc, version: 1, epoch: 1, prev: new Uint8Array(32), members: [await m('x', x), await m('y', y)] }), sc, [await signingPublicKey(mgmt)]);
    const a = await verifyManifest(await signManifest(x, { ...nextManifest(one, [await m('x', x)]), epoch: 2 }), sc, [], one);
    const b = await verifyManifest(await signManifest(y, { ...nextManifest(one, [await m('y', y)]), epoch: 2 }), sc, [], one);
    expect(a.manifest.version).toBe(b.manifest.version);
    expect(await manifestFingerprint(a)).not.toBe(await manifestFingerprint(b));
    expect(await manifestFingerprint(a)).toMatch(/^[0-9a-f]{4}( [0-9a-f]{4}){4}$/);
    const dev = await newDeviceKeys();
    const devPub = await publicKeyBytes(dev.publicKey);
    const k = await signedWrapForDevice(newGroupKey(), devPub, 'c', 'case-9', a, x);
    await expect(openSignedWrap(k, dev.privateKey, devPub, 'c', 'case-9', b)).rejects.toThrow('another object');
    expect((await openSignedWrap(k, dev.privateKey, devPub, 'c', 'case-9', a)).groupKey.length).toBe(32);
    await expect(manifestFingerprint({ ...a, hash: new Uint8Array(31) })).rejects.toThrow('list hash');
  });
});

describe('member keys (shared vectors with Rust)', () => {
  it('a member vouches for its sealing key: same bytes, no replay (version from the list), no other scope or member', async () => {
    const lists = { v3: (await accepted(3))!.manifest, v5: (await accepted(5))!.manifest };
    for (const t of v.member_key) {
      const mk: MemberKey = { scope: t.scope, memberId: t.member_id, version: t.version, seal: hexd(t.seal) };
      expect(hex(memberKeyMessage(mk))).toBe(t.message);
      const sig = await signMemberKey(hexd(t.seed), mk);
      expect(hex(sig)).toBe(t.signature);
      const p = await signingPublicKey(hexd(t.seed));
      const list = t.list ? lists[t.list as 'v3' | 'v5'] : undefined;
      const run = verifyMemberKey(p, mk, sig, v.manifest.scope, t.expected_member, list);
      if (t.expect === 'ok') {
        await run;
        await expect(verifyMemberKey(await pub(9), mk, sig, mk.scope, mk.memberId)).rejects.toThrow('Invalid signature');
        await expect(verifyMemberKey(p, { ...mk, seal: te.encode('x') }, sig, mk.scope, mk.memberId)).rejects.toThrow('Invalid signature');
        await expect(verifyMemberKey(p, mk, sig, mk.scope, mk.memberId, { ...lists.v5, scope: 'other' })).rejects.toThrow('another object');
      } else {
        const want = { chain: /another object|another member|not newer/, untrusted: /not signed by that member/ }[t.expect as 'chain' | 'untrusted'];
        await expect(run, t.note).rejects.toThrow(want);
      }
    }
    await expect(signMemberKey(fill(1), { scope: 's', memberId: 'm', version: 1, seal: new Uint8Array(0) })).rejects.toThrow('member key');
    await expect(signMemberKey(fill(1), { scope: 's', memberId: '', version: 1, seal: Uint8Array.of(1) })).rejects.toThrow('must not be empty');
  });
});

const equalBytesHex = (x: Uint8Array, y: Uint8Array) => hex(x) === hex(y);

const members = (c: { members: { id: string; role: string; admin: boolean; sign: string; seal: string; seal_version: number }[] }): Member[] =>
  c.members.map((m) => ({ id: m.id, role: m.role, admin: m.admin, sign: hexd(m.sign), seal: hexd(m.seal), sealVersion: m.seal_version }));

async function accepted(upto: number): Promise<AcceptedManifest | undefined> {
  if (upto === 0) return undefined;
  return verifyManifestChain(v.manifest.chain.slice(0, upto).map((c) => hexd(c.blob)), v.manifest.scope, [hexd(v.manifest.anchor)]);
}

describe('signed member lists (shared vectors with Rust)', () => {
  it('the chain is accepted and signing it again gives the same blobs', async () => {
    const anchor = hexd(v.manifest.anchor);
    let prev: AcceptedManifest | undefined;
    for (const c of v.manifest.chain) {
      const a = await verifyManifest(hexd(c.blob), v.manifest.scope, [anchor], prev);
      expect(hex(a.hash)).toBe(c.hash);
      expect(await manifestFingerprint(a)).toBe(c.fingerprint);
      expect(hex(a.signer)).toBe(c.signer);
      expect(a.manifest.version).toBe(c.version);
      expect(a.manifest.epoch).toBe(c.epoch);
      expect(a.manifest.scope).toBe(v.manifest.scope);
      expect(a.manifest.members).toEqual(members(c));
      const seeds = [fill(1), fill(2), fill(4)];
      const pubs = await Promise.all(seeds.map((x) => signingPublicKey(x)));
      const seed = seeds[pubs.findIndex((x) => equalBytesHex(x, a.signer))]!;
      const again: Manifest = { ...a.manifest, members: [...a.manifest.members].reverse() };
      expect(hex(await signManifest(seed, again))).toBe(c.blob);
      expect(await openManifest(hexd(c.blob))).toEqual(a);
      prev = a;
    }
    const all = v.manifest.chain.map((c) => hexd(c.blob));
    const sc = v.manifest.scope;
    expect(await verifyManifestChain(all, sc, [anchor])).toEqual(prev);
    expect(await verifyManifestChain([], sc, [], prev)).toEqual(prev);
    await expect(verifyManifestChain([], 'other', [], prev)).rejects.toThrow('another object');
    expect(await verifyManifestChain(all.slice(1), sc, [], await accepted(1))).toEqual(prev);
    await expect(verifyManifestChain([], sc, [])).rejects.toThrow('does not continue');
    await expect(verifyManifestChain(all, 'dovernik|center|12|case|01JOTHER', [anchor])).rejects.toThrow('another object');
  });

  it('refused lists are refused for the same reason as in Rust', async () => {
    const anchor = hexd(v.manifest.anchor);
    for (const r of v.manifest.refused) {
      const want = { untrusted: 'not trusted', chain: 'does not continue', scope: 'another object' }[r.error]!;
      await expect(verifyManifest(hexd(r.blob), v.manifest.scope, [anchor], await accepted(r.after)), r.case).rejects.toThrow(want);
    }
    // the first seal of a member (empty to a key) is accepted with a new epoch
    expect((await verifyManifest(hexd(v.manifest.first_seal.blob), v.manifest.scope, [], await accepted(v.manifest.first_seal.after))).manifest.epoch).toBe(2);
    const prev = await accepted(v.manifest.rescue.after);
    const rescue = await verifyManifest(hexd(v.manifest.rescue.blob), v.manifest.scope, [anchor], prev);
    expect(rescue.signer).toEqual(anchor);
    await expect(verifyManifest(hexd(v.manifest.rescue.blob), v.manifest.scope, [], prev)).rejects.toThrow('not trusted');
  });

  it('damaged or non-canonical blobs are refused', async () => {
    const blob = hexd(v.manifest.chain[1]!.blob);
    for (const i of [0, 9, 20, blob.length >> 1]) {
      const b = blob.slice();
      b[i]! ^= 1;
      await expect(openManifest(b), `byte ${i}`).rejects.toThrow('member list');
    }
    const sig = blob.slice();
    sig[sig.length - 1]! ^= 1;
    await expect(openManifest(sig)).rejects.toThrow('Invalid signature');
    await expect(openManifest(blob.subarray(0, blob.length - 1))).rejects.toThrow('Not a valid');
    await expect(openManifest(te.encode('RGN-SIG1'))).rejects.toThrow('Not a valid');
    await expect(openManifest('x' as unknown as Uint8Array)).rejects.toThrow('Not a valid');
    const msg = blob.subarray(0, blob.length - 64);
    const extra = new Uint8Array([...msg, 0, 0, 0, 0, ...blob.subarray(blob.length - 64)]);
    await expect(openManifest(extra)).rejects.toThrow('Not a valid');
    // a field longer than what is left
    const cut = new Uint8Array([...te.encode('RGN-SIG1'), 0, 0, 0, 99, ...new Uint8Array(64)]);
    await expect(openManifest(cut)).rejects.toThrow('Not a valid');
    const short = new Uint8Array([...te.encode('RGN-SIG1'), 0, 0, ...new Uint8Array(64)]);
    await expect(openManifest(short)).rejects.toThrow('Not a valid');
  });

  it('rules for signing and for continuing a list', async () => {
    const [a, b, c] = [fill(1), fill(2), fill(3)];
    const m = async (id: string, admin: boolean, k: Uint8Array): Promise<Member> => ({ id, role: 'member', admin, sign: await signingPublicKey(k), seal: new Uint8Array(0), sealVersion: 0 });
    const first: Manifest = { scope: 'demo|case|1', version: 1, epoch: 0, prev: new Uint8Array(32), members: [await m('b', true, b)] };
    const sc = 'demo|case|1';
    const one = await verifyManifest(await signManifest(a, first), sc, [await signingPublicKey(a)]);
    expect(memberByKey(one.manifest, await signingPublicKey(b))?.id).toBe('b');
    expect(memberByKey(one.manifest, await signingPublicKey(a))).toBeUndefined();
    const bad = (x: Partial<Manifest>) => signManifest(a, { ...first, ...x });
    await expect(bad({ version: 0 })).rejects.toThrow('version');
    await expect(bad({ version: 2 })).rejects.toThrow('version');
    await expect(bad({ prev: new Uint8Array(32).fill(1) })).rejects.toThrow('version');
    await expect(bad({ prev: new Uint8Array(31) })).rejects.toThrow('previous hash');
    await expect(bad({ epoch: MAX_VERSION + 1 })).rejects.toThrow('whole number');
    await expect(bad({ scope: '' })).rejects.toThrow('must not be empty');
    await expect(bad({ members: [await m('b', true, b), await m('b', false, a)] })).rejects.toThrow('Duplicate member id');
    await expect(bad({ members: [await m('b', true, b), await m('c', false, b)] })).rejects.toThrow('Duplicate member signing key');
    await expect(bad({ members: [await m('', true, b)] })).rejects.toThrow('must not be empty');
    await expect(bad({ members: [{ ...(await m('b', true, b)), seal: new Uint8Array(1025), sealVersion: 1 }] })).rejects.toThrow('member key');
    await expect(bad({ members: [{ ...(await m('b', true, b)), sealVersion: 1 }] })).rejects.toThrow('seal version');
    await expect(bad({ members: [{ ...(await m('b', true, b)), seal: Uint8Array.of(1) }] })).rejects.toThrow('seal version');
    await expect(bad({ members: [{ ...(await m('b', true, b)), seal: Uint8Array.of(1), sealVersion: -1 }] })).rejects.toThrow('whole number');
    await expect(bad({ members: [{ ...(await m('b', true, b)), sign: new Uint8Array(32) }] })).rejects.toThrow('member signing');
    const many = await Promise.all(Array.from({ length: 1001 }, (_, i) => m(String(i), false, fill(i % 250))));
    await expect(bad({ members: many })).rejects.toThrow('Invalid manifest');
    await expect(signManifest(a, null as unknown as Manifest)).rejects.toThrow('Invalid manifest');
    // ids are sorted by their UTF-8 bytes (as in Rust), also with a common prefix
    const sorted = await verifyManifest(await signManifest(a, { ...first, members: [await m('bb', false, c), await m('b', true, b), await m('ä', false, fill(4)), await m('\ufeffz', false, fill(5))] }), sc, [await signingPublicKey(a)]);
    expect(sorted.manifest.members.map((x) => x.id)).toEqual(['b', 'bb', 'ä', '\ufeffz']);

    const next = nextManifest(one, [await m('b', true, b), await m('c', false, c)]);
    expect(next.version).toBe(2);
    await expect(verifyManifest(await signManifest(c, next), sc, [await signingPublicKey(a)], one)).rejects.toThrow('not trusted');
    const two = await verifyManifest(await signManifest(b, next), sc, [], one);
    const other = await signManifest(b, { ...nextManifest(two, []), scope: 'demo|case|2' });
    await expect(verifyManifest(other, sc, [], two)).rejects.toThrow('another object');
    await expect(verifyManifest(other, 'demo|case|2', [], two)).rejects.toThrow('another object');
    await expect(verifyManifest(two.blob, sc, [], two)).rejects.toThrow('does not continue');
  });

  it('a removal or a changed sealing key needs a new epoch; adding does not', async () => {
    const [a, b, c] = [fill(1), fill(2), fill(3)];
    const m = async (id: string, admin: boolean, k: Uint8Array, seal = new Uint8Array(0), sealVersion = seal.length ? 1 : 0): Promise<Member> => ({ id, role: 'member', admin, sign: await signingPublicKey(k), seal, sealVersion });
    const sc = 'demo|case|e';
    const one = await verifyManifest(await signManifest(a, { scope: sc, version: 1, epoch: 4, prev: new Uint8Array(32), members: [await m('b', true, b), await m('c', false, c)] }), sc, [await signingPublicKey(a)]);
    const check = async (x: Manifest) => verifyManifest(await signManifest(b, x), sc, [], one);
    await expect(check(nextManifest(one, [await m('b', true, b)]))).rejects.toThrow('removal without a new epoch');
    expect((await check({ ...nextManifest(one, [await m('b', true, b)]), epoch: 5 })).manifest.epoch).toBe(5);
    expect((await check(nextManifest(one, [await m('b', true, b), await m('c', false, c), await m('d', false, fill(4))]))).manifest.epoch).toBe(4);
    await expect(check(nextManifest(one, [await m('b', true, b), await m('c', false, c, Uint8Array.of(1))]))).rejects.toThrow('new epoch');
    expect((await check({ ...nextManifest(one, [await m('b', true, b), await m('c', false, c, Uint8Array.of(1))]), epoch: 5 })).manifest.version).toBe(2);
    expect((await check(nextManifest(one, [await m('b', true, b), { ...(await m('c2', false, c)), role: 'x' }]))).manifest.version).toBe(2);
    // seal version: a new seal needs a higher one, an unchanged seal keeps it
    const two = await check({ ...nextManifest(one, [await m('b', true, b), await m('c', false, c, Uint8Array.of(1))]), epoch: 5 });
    const check2 = async (x: Manifest) => verifyManifest(await signManifest(b, x), sc, [], two);
    await expect(check2({ ...nextManifest(two, [await m('b', true, b), await m('c', false, c, Uint8Array.of(2), 1)]), epoch: 6 })).rejects.toThrow('seal version');
    expect((await check2({ ...nextManifest(two, [await m('b', true, b), await m('c', false, c, Uint8Array.of(2), 2)]), epoch: 6 })).manifest.epoch).toBe(6);
    await expect(check2(nextManifest(two, [await m('b', true, b), await m('c', false, c, Uint8Array.of(1), 3)]))).rejects.toThrow('seal version');
  });

  it('malformed blobs give the same verdict as in Rust', async () => {
    for (const t of v.manifest.malformed) {
      if (t.valid) expect((await openManifest(hexd(t.blob))).manifest.members.length, t.case).toBe(2);
      else if (t.case === 'duplicate signing key') await expect(openManifest(hexd(t.blob)), t.case).rejects.toThrow('Not a valid member list');
      else await expect(openManifest(hexd(t.blob)), t.case).rejects.toThrow('Not a valid member list');
    }
  });

  it('a version above 2^53 - 1 in a blob is refused', async () => {
    const blob = hexd(v.manifest.chain[0]!.blob);
    // version field: magic(8) + lp("manifest")(12) + lp(scope)
    const at = 8 + 12 + 4 + te.encode(v.manifest.scope).length + 4;
    const b = blob.slice();
    b[at] = 0xff;
    await expect(openManifest(b)).rejects.toThrow('Not a valid');
  });
});
