// Point 5 of the decision on the review of 2026-11-18 (docs/rozhodnutia.md): a unique seal when a list is made,
// a signed key written only with wrap v2. Formats unchanged.
import { signAsync } from '@noble/ed25519';
import { afterEach, describe, expect, it, vi } from 'vitest';
import * as sync from './sync';
import { manifestMessage, openManifest, signedWrapForDevice, signingPublicKey, signManifest, verifyManifest, type Member } from './signing';

vi.mock('./sync', async (importOriginal) => {
  const real = await importOriginal<typeof import('./sync')>();
  return { ...real, wrapForDevice: vi.fn(real.wrapForDevice) };
});

const seed = (n: number) => new Uint8Array(32).fill(n);
const member = async (id: string, n: number, seal: Uint8Array): Promise<Member> => ({ id, role: 'member', admin: true, sign: await signingPublicKey(seed(n)), seal, sealVersion: seal.length > 0 ? 1 : 0 });
const list = (members: Member[]) => ({ scope: 'demo|x', version: 1, epoch: 0, prev: new Uint8Array(32), members });

describe('F-07: a unique seal when a list is made', () => {
  it('refuses two members with one non-empty seal; reads a list made before unchanged', async () => {
    const shared = [await member('a', 1, new Uint8Array(65).fill(4)), await member('b', 2, new Uint8Array(65).fill(4))];
    await expect(signManifest(seed(1), list(shared))).rejects.toThrow('Duplicate member seal key.');
    // empty seals may repeat; different seals are fine
    await expect(signManifest(seed(1), list([await member('a', 1, new Uint8Array(0)), await member('b', 2, new Uint8Array(0))]))).resolves.toBeTruthy();
    await expect(signManifest(seed(1), list([shared[0]!, await member('b', 2, new Uint8Array(65).fill(5))]))).resolves.toBeTruthy();
    // a list with a shared seal signed before 0.16.0 (the message bytes are unchanged) is still read
    const msg = manifestMessage(list(shared), await signingPublicKey(seed(1)));
    const old = new Uint8Array([...msg, ...(await signAsync(msg, seed(1)))]);
    expect((await openManifest(old)).manifest.members).toHaveLength(2);
    await expect(verifyManifest(old, 'demo|x', [await signingPublicKey(seed(1))])).resolves.toBeTruthy();
  });
});

describe('F-10: a signed key is written only with wrap v2', () => {
  afterEach(() => vi.mocked(sync.wrapForDevice).mockClear());

  it('signedWrapForDevice refuses a wrapped key of another version', async () => {
    const dev = await sync.newDeviceKeys();
    const devPub = await sync.publicKeyBytes(dev.publicKey);
    const one = await verifyManifest(await signManifest(seed(1), list([await member('a', 1, devPub)])), 'demo|x', [await signingPublicKey(seed(1))]);
    const ok = await signedWrapForDevice(sync.newGroupKey(), devPub, 'c', 'o', one, seed(1));
    expect(ok.w.v).toBe(sync.WRAP_VERSION);
    vi.mocked(sync.wrapForDevice).mockResolvedValueOnce({ ...ok.w, v: 1 });
    await expect(signedWrapForDevice(sync.newGroupKey(), devPub, 'c', 'o', one, seed(1))).rejects.toThrow('Unsupported wrapped key version.');
  });
});
