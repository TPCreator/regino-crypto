import { getPublicKeyAsync, signAsync, utils } from '@noble/ed25519';
import { describe, expect, it } from 'vitest';
import ed25519 from '../../testvectors/wycheproof/ed25519_test.json';
import {
  certifiedKeys,
  fromBase64url,
  peekToken,
  verifyCertificate,
  verifySignature,
  verifyToken,
  verifyWithKeys,
  type Payload,
} from './signed';

const b64url = (b: Uint8Array) =>
  btoa(String.fromCharCode(...b))
    .replace(/\+/g, '-')
    .replace(/\//g, '_')
    .replace(/=+$/, '');
const hex = (s: string) => new Uint8Array((s.match(/../g) ?? []).map((x) => parseInt(x, 16)));

async function keyPair() {
  const secret = utils.randomSecretKey();
  return { secret, pub: b64url(await getPublicKeyAsync(secret)) };
}

/** Same format as the server signer: `<PREFIX>1.<json>.<sig>` over the JSON bytes. */
async function sign(prefix: string, payload: unknown, secret: Uint8Array) {
  const json = new TextEncoder().encode(JSON.stringify(payload));
  return `${prefix}1.${b64url(json)}.${b64url(await signAsync(json, secret))}`;
}

const AT = 1_792_150_000;

async function setup() {
  const root = await keyPair();
  const product = await keyPair();
  const roots = [{ kid: 'root-2026', pub: root.pub }];
  const cert = await sign(
    'RG',
    {
      v: 1,
      typ: 'cert',
      kid: 'root-2026',
      subject: { kid: 'demo-2026', product: 'demo', use: 'licence', pub: product.pub },
      nbf: AT - 10,
      exp: null,
      iat: AT - 10,
    },
    root.secret,
  );
  return { root, product, roots, cert };
}

describe('signed tokens', () => {
  it('base64url decoding', () => {
    expect(fromBase64url('AQID')).toEqual(new Uint8Array([1, 2, 3]));
    expect(fromBase64url('AQI')).toEqual(new Uint8Array([1, 2]));
    expect(fromBase64url('-_8')).toEqual(new Uint8Array([0xfb, 0xff]));
    expect(fromBase64url('')).toEqual(new Uint8Array([]));
    expect(fromBase64url('A')).toBeNull();
    expect(fromBase64url('AQ==')).toBeNull();
    expect(fromBase64url('A+B/')).toBeNull();
  });

  it('verifies a token and rejects any change', async () => {
    const k = await keyPair();
    const token = await sign('DM', { v: 1, typ: 'lic', n: 'Žltý kôň' }, k.secret);
    expect(await verifyToken(token, k.pub)).toEqual({
      prefix: 'DM',
      payload: { v: 1, typ: 'lic', n: 'Žltý kôň' },
    });
    expect(await verifyToken(` ${token}\n`, k.pub)).not.toBeNull();
    const [head, body, sig] = token.split('.') as [string, string, string];
    const other = await sign('DM', { v: 1, typ: 'lic', n: 'X' }, k.secret);
    expect(await verifyToken(`${head}.${other.split('.')[1]}.${sig}`, k.pub)).toBeNull();
    expect(await verifyToken(`XX1.${body}.${sig}`, k.pub)).not.toBeNull(); // prefix is not signed …
    expect(peekToken(`XX1.${body}.${sig}`)?.prefix).toBe('XX'); // … callers check it
    expect(await verifyToken(token, (await keyPair()).pub)).toBeNull();
  });

  it('malformed tokens and keys', async () => {
    const k = await keyPair();
    const token = await sign('DM', { a: 1 }, k.secret);
    const [, body, sig] = token.split('.') as [string, string, string];
    for (const bad of [
      '',
      'DM1.abc',
      `dm1.${body}.${sig}`,
      `D1.${body}.${sig}`,
      `DM2.${body}.${sig}`,
      `DM1.${body}.${sig}.x`,
      `DM1.${body}.AAAA`,
      `DM1.${body}+.${sig}`,
    ]) {
      expect(peekToken(bad), bad).toBeNull();
      expect(await verifyToken(bad, k.pub), bad).toBeNull();
    }
    expect(await verifyToken(token, 'AAAA')).toBeNull();
    expect(await verifyToken(token, '!')).toBeNull();
    // A 32-byte value that is not a curve point.
    expect(await verifyToken(token, b64url(new Uint8Array(32).fill(0xff)))).toBeNull();
    // Valid signature over something that is not a JSON object.
    for (const raw of ['[1]', 'null', '"x"', '{', '\xff']) {
      const json = raw === '\xff' ? new Uint8Array([0xff]) : new TextEncoder().encode(raw);
      const t = `DM1.${b64url(json)}.${b64url(await signAsync(json, k.secret))}`;
      expect(peekToken(t), raw).toBeNull();
      expect(await verifyToken(t, k.pub), raw).toBeNull();
    }
  });

  it('certificate chain: root → product key → token', async () => {
    const { product, roots, cert } = await setup();
    const key = await verifyCertificate(cert, roots, AT);
    expect(key).toEqual({ kid: 'demo-2026', product: 'demo', use: 'licence', pub: product.pub });
    const keys = await certifiedKeys([{ kid: 'demo-2026', status: 'active', cert }], roots, AT);
    expect(keys).toEqual([key]);
    const lic = await sign('DM', { v: 1, typ: 'lic', kid: 'demo-2026', product: 'demo' }, product.secret);
    const expect_ = { prefix: 'DM', product: 'demo', use: 'licence' };
    expect((await verifyWithKeys(lic, keys, expect_))?.typ).toBe('lic');
    expect(await verifyWithKeys(lic, keys, { ...expect_, prefix: 'XX' })).toBeNull();
    expect(await verifyWithKeys(lic, keys, { ...expect_, use: 'device' })).toBeNull();
    expect(await verifyWithKeys(lic, keys, { ...expect_, product: 'other' })).toBeNull();
    expect(await verifyWithKeys(lic, [], expect_)).toBeNull();
    // Signed by the right key, but claims another product or an unknown kid.
    const wrongProduct = await sign('DM', { kid: 'demo-2026', product: 'other' }, product.secret);
    expect(await verifyWithKeys(wrongProduct, keys, expect_)).toBeNull();
    const unknownKid = await sign('DM', { kid: 'demo-2027', product: 'demo' }, product.secret);
    expect(await verifyWithKeys(unknownKid, keys, expect_)).toBeNull();
    // A key without a root-signed certificate is useless, even with a matching kid.
    const rogue = await keyPair();
    const forged = await sign('DM', { kid: 'demo-2026', product: 'demo' }, rogue.secret);
    expect(await verifyWithKeys(forged, keys, expect_)).toBeNull();
    // Question 10: the prefix is not signed – a payload with typ "cert" is never a licence, even
    // if a key were (wrongly) used both as a root and as a product key.
    const certShaped = await sign('DM', { typ: 'cert', kid: 'demo-2026', product: 'demo' }, product.secret);
    expect(await verifyWithKeys(certShaped, keys, expect_)).toBeNull();
    const relabelled = cert.replace(/^RG1\./, 'DM1.');
    expect(await verifyWithKeys(relabelled, keys, expect_)).toBeNull();
  });

  it('certificates: time window, signer, shape', async () => {
    const { root, product, roots, cert } = await setup();
    const certWith = (p: Payload, prefix = 'RG', secret = root.secret) =>
      sign(
        prefix,
        {
          v: 1,
          typ: 'cert',
          kid: 'root-2026',
          subject: { kid: 'demo-2026', product: 'demo', use: 'licence', pub: product.pub },
          nbf: AT - 10,
          exp: AT + 10,
          iat: AT - 10,
          ...p,
        },
        secret,
      );
    expect(await verifyCertificate(cert, roots, AT - 11)).toBeNull(); // not yet valid
    expect(await verifyCertificate(await certWith({}), roots, AT + 10)).not.toBeNull();
    expect(await verifyCertificate(await certWith({}), roots, AT + 11)).toBeNull(); // expired
    expect(await verifyCertificate(await certWith({ exp: undefined }), roots, AT + 99)).not.toBeNull();
    const noProduct = await certWith({
      subject: { kid: 'x', use: 'webhook', pub: product.pub },
    });
    expect((await verifyCertificate(noProduct, roots, AT))?.product).toBeNull();
    for (const bad of [
      await certWith({}, 'DM'),
      await certWith({ typ: 'lic' }),
      await certWith({ kid: 'root-2025' }),
      await certWith({ nbf: '1' }),
      await certWith({ nbf: undefined }),
      await certWith({ exp: '9' }),
      await certWith({ subject: null }),
      await certWith({ subject: 'x' }),
      await certWith({ subject: { kid: 'x', use: 'licence' } }),
      await certWith({ subject: { kid: '', use: 'licence', pub: product.pub } }),
      await certWith({ subject: { kid: 'x', product: 3, use: 'licence', pub: product.pub } }),
      await certWith({}, 'RG', (await keyPair()).secret),
    ]) {
      expect(await verifyCertificate(bad, roots, AT)).toBeNull();
    }
    expect(await verifyCertificate('nonsense', roots, AT)).toBeNull();
  });

  it('key list: only root-certified, not revoked, kid must match', async () => {
    const { roots, cert } = await setup();
    const list = [
      { kid: 'demo-2026', status: 'revoked', cert },
      { kid: 'demo-2026', cert },
      { kid: 'other-kid', cert },
      { kid: 'demo-2025', cert: 'RG1.x.y' },
    ];
    expect(await certifiedKeys(list, roots, AT)).toHaveLength(1);
    expect(await certifiedKeys(list, roots, AT, ['demo-2026'])).toHaveLength(0);
    expect(await certifiedKeys(list, [], AT)).toHaveLength(0);
  });

  it('Wycheproof Ed25519: valid accepted, invalid rejected (strict RFC 8032)', async () => {
    const groups = (
      ed25519 as unknown as {
        testGroups: { publicKey: { pk: string }; tests: { tcId: number; msg: string; sig: string; result: string }[] }[];
      }
    ).testGroups;
    let n = 0;
    for (const g of groups) {
      const pub = hex(g.publicKey.pk);
      for (const t of g.tests) {
        n++;
        const ok = await verifySignature(hex(t.sig), hex(t.msg), pub);
        expect(ok, `tcId ${t.tcId}`).toBe(t.result === 'valid');
      }
    }
    expect(n).toBe(151);
  });
});
