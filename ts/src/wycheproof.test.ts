import { describe, expect, it } from 'vitest';
import aesGcm from '../../testvectors/wycheproof/aes_gcm_test.json';
import hkdf from '../../testvectors/wycheproof/hkdf_sha256_test.json';
import ecdh from '../../testvectors/wycheproof/ecdh_secp256r1_ecpoint_test.json';

/**
 * Wycheproof test vectors (testvectors/wycheproof): WebCrypto, which backups are built on
 * (HKDF-SHA256 → AES-256-GCM with a 96-bit IV), must accept valid and reject invalid inputs.
 */
const hex = (s: string) => new Uint8Array((s.match(/../g) ?? []).map((x) => parseInt(x, 16)));
const toHex = (b: ArrayBuffer) =>
  Array.from(new Uint8Array(b), (x) => x.toString(16).padStart(2, '0')).join('');

interface Test {
  tcId: number;
  result: string;
  [k: string]: unknown;
}
const all = (doc: { testGroups: { tests: Test[] }[] }) => doc.testGroups.flatMap((g) => g.tests);

// PKCS#8 for a P-256 private scalar (no public key inside – WebCrypto computes it).
const pkcs8P256 = (d: Uint8Array) => {
  const prefix = hex('308141020100301306072a8648ce3d020106082a8648ce3d030107042730250201010420');
  const out = new Uint8Array(prefix.length + 32);
  out.set(prefix);
  const k = d.subarray(Math.max(0, d.length - 32)); // strip a leading 00, left-pad short scalars
  out.set(k, out.length - k.length);
  return out;
};

describe('Wycheproof', () => {
  it('ECDH P-256, raw points (sync.ts, inbox.ts) – invalid-curve and wrong-curve points rejected', async () => {
    const tests = all(ecdh as never);
    expect(tests).toHaveLength(355);
    const P256 = { name: 'ECDH', namedCurve: 'P-256' } as const;
    for (const t of tests) {
      const priv = await crypto.subtle.importKey('pkcs8', pkcs8P256(hex(t.private as string)), P256, false, ['deriveBits']);
      const shared = await crypto.subtle
        .importKey('raw', hex(t.public as string), P256, false, [])
        .then((pub) => crypto.subtle.deriveBits({ name: 'ECDH', public: pub }, priv, 256))
        .then(toHex, () => null);
      if (t.result === 'valid') expect(shared, `tcId ${t.tcId}`).toBe(t.shared);
      else if (t.result === 'invalid') expect(shared, `invalid input accepted: tcId ${t.tcId}`).toBeNull();
    }
  });

  it('AES-256-GCM (IV 96 b, tag 128 b)', async () => {
    const tests = all(aesGcm as never);
    expect(tests).toHaveLength(66);
    for (const t of tests) {
      const key = await crypto.subtle.importKey('raw', hex(t.key as string), 'AES-GCM', false, [
        'encrypt',
        'decrypt',
      ]);
      const params = { name: 'AES-GCM', iv: hex(t.iv as string), additionalData: hex(t.aad as string) };
      const sealed = (t.ct as string) + (t.tag as string);
      const opened = await crypto.subtle.decrypt(params, key, hex(sealed)).then(
        (b) => toHex(b),
        () => null,
      );
      if (t.result === 'valid') {
        expect(opened, `tcId ${t.tcId}`).toBe(t.msg);
        expect(toHex(await crypto.subtle.encrypt(params, key, hex(t.msg as string))), `tcId ${t.tcId}`).toBe(sealed);
      } else {
        expect(opened, `invalid input accepted: tcId ${t.tcId}`).toBeNull();
      }
    }
  });

  it('HKDF-SHA256', async () => {
    const tests = all(hkdf as never);
    expect(tests).toHaveLength(86);
    for (const t of tests) {
      const base = await crypto.subtle.importKey('raw', hex(t.ikm as string), 'HKDF', false, ['deriveBits']);
      const okm = await crypto.subtle
        .deriveBits(
          { name: 'HKDF', hash: 'SHA-256', salt: hex(t.salt as string), info: hex(t.info as string) },
          base,
          (t.size as number) * 8,
        )
        .then(
          (b) => toHex(b),
          () => null,
        );
      if (t.result === 'valid') expect(okm, `tcId ${t.tcId}`).toBe(t.okm);
      else expect(okm, `invalid input accepted: tcId ${t.tcId}`).toBeNull();
    }
  });
});
