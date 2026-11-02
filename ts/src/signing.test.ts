import { describe, expect, it } from 'vitest';
import v from '../../testvectors/regino/signing-0.13.0.json';
import ed25519 from '../../testvectors/wycheproof/ed25519_test.json';
import { b64, unb64 } from './ecdh';
import {
  deriveSigningKey,
  isSigningPublicKey,
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
  it('signatures match Rust and cover every field', async () => {
    for (const t of v.wrap) {
      const st: WrapStatement = { context: t.context, objectId: t.object_id, version: t.version, recipient: hexd(t.recipient), wrapped: hexd(t.wrapped) };
      if (t.wrapped_key) expect(hex(wrappedKeyBytes(t.wrapped_key))).toBe(t.wrapped);
      const sig = await signWrap(hexd(t.seed), st);
      expect(hex(sig)).toBe(t.signature);
      const signer = await signingPublicKey(hexd(t.seed));
      expect(await verifyWrap(signer, st, sig)).toBe(true);
      for (const changed of [{ context: 'other' }, { objectId: 'other' }, { version: t.version - 1 }, { recipient: new Uint8Array(65).fill(1) }, { wrapped: te.encode('x') }])
        expect(await verifyWrap(signer, { ...st, ...changed }, sig)).toBe(false);
      expect(await verifyWrap(await pub(9), st, sig)).toBe(false);
      expect(await verifyWrap(new Uint8Array(32), st, sig)).toBe(false);
    }
  });

  it('statement limits', async () => {
    const st: WrapStatement = { context: 'c', objectId: 'o', version: 1, recipient: Uint8Array.of(1), wrapped: Uint8Array.of(2) };
    await expect(signWrap(fill(1), { ...st, recipient: new Uint8Array(0) })).rejects.toThrow('recipient');
    await expect(signWrap(fill(1), { ...st, wrapped: new Uint8Array(65537) })).rejects.toThrow('wrapped');
    await expect(signWrap(fill(1), { ...st, version: -1 })).rejects.toThrow('whole number');
    await expect(signWrap(fill(1), { ...st, version: 1.5 })).rejects.toThrow('whole number');
    await expect(signWrap(fill(1), { ...st, version: MAX_VERSION + 1 })).rejects.toThrow('whole number');
    await expect(signWrap(fill(1), { ...st, objectId: '' })).rejects.toThrow('must not be empty');
    expect(() => wrappedKeyBytes({ v: 2, e: 'a.b', n: 'x', c: 'y' })).toThrow('Invalid wrapped key');
    expect(() => wrappedKeyBytes({ v: 1.5, e: 'a', n: 'x', c: 'y' })).toThrow('Invalid wrapped key');
    expect(() => wrappedKeyBytes(null as unknown as WrappedGroupKey)).toThrow('Invalid wrapped key');
  });

  it('opens only from a trusted sender, for the expected object and version, on the right device', async () => {
    const dev = await newDeviceKeys();
    const devPub = await publicKeyBytes(dev.publicKey);
    const groupKey = newGroupKey();
    const sender = newSigningKey();
    const senderPub = await signingPublicKey(sender);
    const ctx = 'demo|case|1|key|2';
    const signed = await signedWrapForDevice(groupKey, devPub, ctx, 'case-1', 2, sender);
    expect(signed.v).toBe(1);
    const expect1 = { objectId: 'case-1', version: 2 };
    const got = await openSignedWrap(signed, dev.privateKey, devPub, ctx, expect1, [await pub(5), senderPub]);
    expect(got.groupKey).toEqual(groupKey);
    expect(got.signer).toEqual(senderPub);

    await expect(openSignedWrap(signed, dev.privateKey, devPub, ctx, expect1, [await pub(5)])).rejects.toThrow('not trusted');
    await expect(openSignedWrap(signed, dev.privateKey, devPub, ctx, { objectId: 'case-2', version: 2 }, [senderPub])).rejects.toThrow('another object');
    await expect(openSignedWrap(signed, dev.privateKey, devPub, ctx, { objectId: 'case-1', version: 3 }, [senderPub])).rejects.toThrow('another object');
    // the server swaps the version in the envelope: the signature no longer matches
    await expect(openSignedWrap({ ...signed, ver: 3 }, dev.privateKey, devPub, ctx, { objectId: 'case-1', version: 3 }, [senderPub])).rejects.toThrow('Invalid signature');
    // the server wraps its own key and signs with its own key: not a trusted sender
    const evil = newSigningKey();
    const forged = await signedWrapForDevice(newGroupKey(), devPub, ctx, 'case-1', 2, evil);
    await expect(openSignedWrap(forged, dev.privateKey, devPub, ctx, expect1, [senderPub])).rejects.toThrow('not trusted');
    // the server wraps its own key but keeps the sender's name and signature
    const own = await wrapForDevice(newGroupKey(), devPub, ctx);
    await expect(openSignedWrap({ ...signed, w: own }, dev.privateKey, devPub, ctx, expect1, [senderPub])).rejects.toThrow('Invalid signature');
    await expect(openSignedWrap({ ...signed, s: '***' }, dev.privateKey, devPub, ctx, expect1, [senderPub])).rejects.toThrow('Invalid signed');
    await expect(openSignedWrap({ ...signed, v: 2 }, dev.privateKey, devPub, ctx, expect1, [senderPub])).rejects.toThrow('version');
    await expect(openSignedWrap(null as unknown as typeof signed, dev.privateKey, devPub, ctx, expect1, [senderPub])).rejects.toThrow('version');
    // another device cannot unwrap even with a valid signature
    const other = await newDeviceKeys();
    await expect(openSignedWrap(signed, other.privateKey, await publicKeyBytes(other.publicKey), ctx, expect1, [senderPub])).rejects.toThrow('Invalid signature');
    const forOther = await signedWrapForDevice(groupKey, await publicKeyBytes(other.publicKey), ctx, 'case-1', 2, sender);
    await expect(openSignedWrap({ ...forOther, w: signed.w }, other.privateKey, await publicKeyBytes(other.publicKey), ctx, expect1, [senderPub])).rejects.toThrow('Invalid signature');
    expect(unb64(signed.k)).toEqual(senderPub);
    expect(b64(senderPub)).toBe(signed.k);
  });
});

const members = (c: { members: { id: string; role: string; admin: boolean; sign: string; seal: string }[] }): Member[] =>
  c.members.map((m) => ({ id: m.id, role: m.role, admin: m.admin, sign: hexd(m.sign), seal: hexd(m.seal) }));

async function accepted(upto: number): Promise<AcceptedManifest | undefined> {
  if (upto === 0) return undefined;
  return verifyManifestChain(v.manifest.chain.slice(0, upto).map((c) => hexd(c.blob)), [hexd(v.manifest.anchor)]);
}

describe('signed member lists (shared vectors with Rust)', () => {
  it('the chain is accepted and signing it again gives the same blobs', async () => {
    const anchor = hexd(v.manifest.anchor);
    let prev: AcceptedManifest | undefined;
    for (const c of v.manifest.chain) {
      const a = await verifyManifest(hexd(c.blob), [anchor], prev);
      expect(hex(a.hash)).toBe(c.hash);
      expect(hex(a.signer)).toBe(c.signer);
      expect(a.manifest.version).toBe(c.version);
      expect(a.manifest.epoch).toBe(c.epoch);
      expect(a.manifest.scope).toBe(v.manifest.scope);
      expect(a.manifest.members).toEqual(members(c));
      const seed = [fill(1), fill(2)].find((s, i) => hex(a.signer) === v.keys[i]!.public)!;
      const again: Manifest = { ...a.manifest, members: [...a.manifest.members].reverse() };
      expect(hex(await signManifest(seed, again))).toBe(c.blob);
      expect(await openManifest(hexd(c.blob))).toEqual(a);
      prev = a;
    }
    const all = v.manifest.chain.map((c) => hexd(c.blob));
    expect(await verifyManifestChain(all, [anchor])).toEqual(prev);
    expect(await verifyManifestChain([], [], prev)).toEqual(prev);
    expect(await verifyManifestChain(all.slice(1), [], await accepted(1))).toEqual(prev);
    await expect(verifyManifestChain([], [])).rejects.toThrow('does not continue');
  });

  it('refused lists are refused for the same reason as in Rust', async () => {
    const anchor = hexd(v.manifest.anchor);
    for (const r of v.manifest.refused) {
      const want = r.error === 'untrusted' ? 'not trusted' : 'does not continue';
      await expect(verifyManifest(hexd(r.blob), [anchor], await accepted(r.after))).rejects.toThrow(want);
    }
    const prev = await accepted(v.manifest.rescue.after);
    const rescue = await verifyManifest(hexd(v.manifest.rescue.blob), [anchor], prev);
    expect(rescue.signer).toEqual(anchor);
    await expect(verifyManifest(hexd(v.manifest.rescue.blob), [], prev)).rejects.toThrow('not trusted');
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
    const m = async (id: string, admin: boolean, k: Uint8Array): Promise<Member> => ({ id, role: 'member', admin, sign: await signingPublicKey(k), seal: new Uint8Array(0) });
    const first: Manifest = { scope: 'demo|case|1', version: 1, epoch: 0, prev: new Uint8Array(32), members: [await m('b', true, b)] };
    const one = await verifyManifest(await signManifest(a, first), [await signingPublicKey(a)]);
    expect(memberByKey(one.manifest, await signingPublicKey(b))?.id).toBe('b');
    expect(memberByKey(one.manifest, await signingPublicKey(a))).toBeUndefined();
    const bad = (x: Partial<Manifest>) => signManifest(a, { ...first, ...x });
    await expect(bad({ version: 0 })).rejects.toThrow('version');
    await expect(bad({ version: 2 })).rejects.toThrow('version');
    await expect(bad({ prev: new Uint8Array(32).fill(1) })).rejects.toThrow('version');
    await expect(bad({ prev: new Uint8Array(31) })).rejects.toThrow('previous hash');
    await expect(bad({ epoch: MAX_VERSION + 1 })).rejects.toThrow('whole number');
    await expect(bad({ scope: '' })).rejects.toThrow('must not be empty');
    await expect(bad({ members: [await m('b', true, b), await m('b', false, a)] })).rejects.toThrow('Duplicate');
    await expect(bad({ members: [await m('', true, b)] })).rejects.toThrow('must not be empty');
    await expect(bad({ members: [{ ...(await m('b', true, b)), seal: new Uint8Array(1025) }] })).rejects.toThrow('member key');
    await expect(bad({ members: [{ ...(await m('b', true, b)), sign: new Uint8Array(32) }] })).rejects.toThrow('member signing');
    const many = await Promise.all(Array.from({ length: 1001 }, (_, i) => m(String(i), false, b)));
    await expect(bad({ members: many })).rejects.toThrow('Invalid manifest');
    await expect(signManifest(a, null as unknown as Manifest)).rejects.toThrow('Invalid manifest');
    // ids are sorted by their UTF-8 bytes (as in Rust), also with a common prefix
    const sorted = await verifyManifest(await signManifest(a, { ...first, members: [await m('bb', false, c), await m('b', true, b), await m('ä', false, c)] }), [await signingPublicKey(a)]);
    expect(sorted.manifest.members.map((x) => x.id)).toEqual(['b', 'bb', 'ä']);

    const next = nextManifest(one, [await m('b', true, b), await m('c', false, c)]);
    expect(next.version).toBe(2);
    await expect(verifyManifest(await signManifest(c, next), [await signingPublicKey(a)], one)).rejects.toThrow('not trusted');
    const two = await verifyManifest(await signManifest(b, next), [], one);
    await expect(verifyManifest(await signManifest(b, { ...nextManifest(two, []), scope: 'demo|case|2' }), [], two)).rejects.toThrow('does not continue');
    await expect(verifyManifest(two.blob, [], two)).rejects.toThrow('does not continue');
  });

  it('malformed blobs give the same verdict as in Rust', async () => {
    for (const t of v.manifest.malformed) {
      if (t.valid) expect((await openManifest(hexd(t.blob))).manifest.members.length, t.case).toBe(2);
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
