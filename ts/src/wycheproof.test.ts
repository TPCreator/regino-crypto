import { describe, expect, it } from 'vitest';
import aesGcm from '../../testvectors/wycheproof/aes_gcm_test.json';
import hkdf from '../../testvectors/wycheproof/hkdf_sha256_test.json';

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

describe('Wycheproof', () => {
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
