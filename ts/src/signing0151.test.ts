// Audit S1/S2 (0.15.1): shared vectors with Rust (keys/tests/signing_0_15_1.rs) – messages, signatures, verdicts.
import { describe, expect, it } from 'vitest';
import v from '../../testvectors/regino/signing-0.15.1.json';
import {
  confirmManifest,
  manifestConfirmationMessage,
  openManifest,
  signingPublicKey,
  signManifest,
  signWrap,
  verifyManifestChainFromAnchor,
  verifyManifestConfirmation,
  verifyWrap,
  wrapMessage,
} from './signing';

const hexd = (s: string) => Uint8Array.from(s.match(/../g) ?? [], (h) => parseInt(h, 16));
const hex = (b: Uint8Array) => Array.from(b, (x) => x.toString(16).padStart(2, '0')).join('');
type Name = keyof typeof v.seeds;
const seed = (n: Name) => new Uint8Array(32).fill(v.seeds[n]);
const pub = (n: Name) => hexd(v.public[n]);
type ListName = keyof typeof v.blobs;
const list = (n: ListName) => openManifest(hexd(v.blobs[n]));

describe('signing vectors 0.15.1', () => {
  it('keys, blobs and confirmations', async () => {
    for (const n of Object.keys(v.seeds) as Name[]) expect(hex(await signingPublicKey(seed(n))), n).toBe(v.public[n]);
    for (const n of Object.keys(v.blobs) as ListName[]) {
      const a = await list(n);
      expect(hex(a.hash)).toBe(v.hashes[n]);
      const signer = (['anchor', 'alice', 'bob'] as const).find((s) => v.public[s] === hex(a.signer))!;
      expect(hex(await signManifest(seed(signer), a.manifest))).toBe(v.blobs[n]);
    }
    for (const c of v.confirmations) {
      const l = await list(c.list as ListName);
      expect(hex(manifestConfirmationMessage(l, pub(c.signer as Name)))).toBe(c.message);
      expect(hex(await confirmManifest(seed(c.signer as Name), l))).toBe(c.signature);
      expect(await verifyManifestConfirmation(pub(c.signer as Name), l, hexd(c.signature))).toBe(true);
    }
  });

  it('chains with requireAnchorOnLatest: same verdicts and hashes as Rust', async () => {
    for (const t of v.chains) {
      const o = t.opts as { require_anchor_on_latest?: boolean; signers?: Name[]; anchors_may_sign?: boolean; confirmations?: number[] };
      const run = verifyManifestChainFromAnchor(
        t.blobs.map((b) => hexd(v.blobs[b as ListName])),
        v.scope,
        [pub('anchor')],
        {
          requireAnchorOnLatest: o.require_anchor_on_latest,
          signers: o.signers?.map(pub),
          anchorsMaySign: o.anchors_may_sign,
          confirmations: o.confirmations?.map((i) => ({ signer: pub(v.confirmations[i]!.signer as Name), signature: hexd(v.confirmations[i]!.signature) })),
        },
      );
      if (t.expect === 'ok') expect((await run).map((a) => hex(a.hash)), t.case).toEqual(t.hashes);
      else await expect(run, t.case).rejects.toThrow('not trusted');
    }
  });

  it('wrap statements of two epochs (requireCurrentEpoch is checked on the epoch, the signature is the same)', async () => {
    for (const w of v.wraps) {
      const st = { context: w.context, objectId: w.object_id, version: w.version, manifest: hexd(w.manifest), recipient: hexd(w.recipient), wrapped: hexd(w.wrapped) };
      expect(hex(wrapMessage(st, pub('alice')))).toBe(w.message);
      expect(hex(await signWrap(seed('alice'), st))).toBe(w.signature);
      expect(await verifyWrap(pub('alice'), st, hexd(w.signature))).toBe(true);
      expect(w.require_current_epoch).toBe(w.version === (await list('v2')).manifest.epoch ? 'ok' : 'chain');
    }
  });
});
