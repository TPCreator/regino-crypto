/**
 * Benchmark (not part of `npm test`): a member list with 15 members and 5 versions, verified from an
 * anchor and inspected. Run: `npm run bench`. Prints the median of each case in milliseconds.
 */
import { clearSigningKeyCache, inspectManifestChain, nextManifest, openManifest, signManifest, signingPublicKey, verifyManifestChainFromAnchor, type AcceptedManifest, type Member } from '../src/signing';

const fill = (n: number) => new Uint8Array(32).fill(n);
const scope = 'bench|case|1';

async function chain(): Promise<Uint8Array[]> {
  const members: Member[] = [];
  for (let i = 0; i < 15; i++)
    members.push({ id: `m${String(i).padStart(2, '0')}`, role: i === 0 ? 'coordinator' : 'member', admin: i === 0, sign: await signingPublicKey(fill(10 + i)), seal: new Uint8Array(0), sealVersion: 0 });
  const blobs = [await signManifest(fill(1), { scope, version: 1, epoch: 1, prev: new Uint8Array(32), members })];
  let prev: AcceptedManifest = await openManifest(blobs[0]!);
  for (let v = 2; v <= 5; v++) {
    const b = await signManifest(fill(10), nextManifest(prev, members.map((m) => ({ ...m, role: `${m.role}${v}` }))));
    blobs.push(b);
    prev = await openManifest(b);
  }
  return blobs;
}

async function median(name: string, runs: number, f: () => Promise<unknown>): Promise<void> {
  const t: number[] = [];
  for (let i = 0; i < runs; i++) {
    const s = performance.now();
    await f();
    t.push(performance.now() - s);
  }
  t.sort((a, b) => a - b);
  console.log(`${name.padEnd(48)} ${t[runs >> 1]!.toFixed(2)} ms (median of ${runs})`);
}

const blobs = await chain();
const anchor = await signingPublicKey(fill(1));
await verifyManifestChainFromAnchor(blobs, scope, [anchor]); // warm-up
await median('verifyManifestChainFromAnchor, cold key cache', 30, async () => {
  clearSigningKeyCache();
  await verifyManifestChainFromAnchor(blobs, scope, [anchor]);
});
await median('verifyManifestChainFromAnchor, warm key cache', 30, () => verifyManifestChainFromAnchor(blobs, scope, [anchor]));
await median('inspectManifestChain, warm key cache', 30, () => inspectManifestChain(blobs, scope));
