import jsQR from 'jsqr';
import { afterEach, describe, expect, it, vi } from 'vitest';
import rust from '../../testvectors/regino/keys-0.11.1.json';
import v from '../../testvectors/regino/shamir-0.16.0.json';
import {
  SHAMIR_SHARE_LENGTH,
  SHARE_QR_PREFIX,
  combineShares,
  gfMul,
  shareFromQrText,
  shareInfo,
  shareQrText,
  splitKey,
  type ShamirError,
} from './shamir';
import { shareQrMatrix, shareQrSvg } from './sheet';

// Shamir 2 of 3 in TypeScript (0.16.0), byte for byte the same as Rust `regino_keys::shamir` (blahaj 0.7).
const hex = (b: Uint8Array) => Array.from(b, (x) => x.toString(16).padStart(2, '0')).join('');
const unhex = (h: string) => Uint8Array.from(h.match(/../g) ?? [], (x) => parseInt(x, 16));
const randomKey = () => crypto.getRandomValues(new Uint8Array(32));

/** Every subset (bit mask) of the shares. */
function* subsets<T>(all: T[]): Generator<T[]> {
  for (let mask = 1; mask < 1 << all.length; mask++) yield all.filter((_, i) => mask & (1 << i));
}

async function expectAllSubsets(shares: Uint8Array[], threshold: number, key: string): Promise<number> {
  let ok = 0;
  for (const s of subsets(shares)) {
    const r = await combineShares(s);
    if (s.length >= threshold) {
      expect(r.ok && hex(r.key)).toBe(key);
      ok++;
    } else {
      expect(r).toEqual({ ok: false, error: { code: 'not-enough-shares', threshold, count: s.length } });
    }
  }
  return ok;
}

afterEach(() => {
  vi.restoreAllMocks();
});

describe('GF(256) as in blahaj (0x11d)', () => {
  it('multiplication matches the log/exp tables of generator 2 for all 65 536 pairs', () => {
    const exp = new Array<number>(510);
    const log = new Array<number>(256).fill(0);
    for (let i = 0, x = 1; i < 255; i++) {
      exp[i] = exp[i + 255] = x;
      log[x] = i;
      x = (x << 1) ^ (x & 0x80 ? 0x11d : 0);
    }
    expect(exp[8]).toBe(0x1d); // blahaj EXP_TABLE[8]
    expect(log[0x1d]).toBe(8);
    for (let a = 0; a < 256; a++)
      for (let b = 0; b < 256; b++) {
        const want = a && b ? (exp[(log[a] as number) + (log[b] as number)] as number) : 0;
        if (gfMul(a, b) !== want) expect([a, b, gfMul(a, b)]).toEqual([a, b, want]);
      }
  });

  it('evaluates the polynomial like blahaj (highest coefficient first): [3, 2, 5] → x=1: 4, x=2: 13', async () => {
    // blahaj test `evaluator_works`; the key byte is the constant term, random bytes are drawn highest first
    vi.spyOn(crypto, 'getRandomValues').mockImplementation(<T extends ArrayBufferView | null>(a: T): T => {
      const u = a as unknown as Uint8Array;
      for (let i = 0; i < u.length; i++) u[i] = i % 2 ? 2 : 3;
      return a;
    });
    const s = await splitKey(new Uint8Array(32).fill(5), 3, 3);
    expect([...(s[0] as Uint8Array).subarray(13)]).toEqual([1, ...new Array(32).fill(4)]);
    expect([...(s[1] as Uint8Array).subarray(13)]).toEqual([2, ...new Array(32).fill(13)]);
  });
});

describe('shares made by Rust (keys-0.11.1.json)', () => {
  it.each(rust.shamir.map((c) => [`${c.threshold} of ${c.shares.length}`, c] as const))(
    '%s: every subset of at least the threshold gives the key, smaller ones are refused',
    async (_, c) => {
      expect(await expectAllSubsets(c.shares.map(unhex), c.threshold, c.key)).toBeGreaterThanOrEqual(4);
    },
  );
});

describe('shared vectors made by TypeScript (shamir-0.16.0.json, combined by Rust too)', () => {
  it('version and cases', () => {
    expect(v.version).toBe('0.16.0');
    expect(v.split).toHaveLength(5);
    expect(v.refused).toHaveLength(14);
  });

  it.each(v.split.map((c) => [c.name, c] as const))('%s', async (_, c) => {
    const shares = c.shares.map(unhex);
    shares.forEach((s) => expect(shareInfo(s)?.threshold).toBe(c.threshold));
    expect(await expectAllSubsets(shares, c.threshold, c.key)).toBeGreaterThanOrEqual(1);
  });

  it('x up to 255', () => {
    const c = v.split[4] as (typeof v.split)[number];
    expect(c.shares.map((s) => shareInfo(unhex(s))?.index)).toEqual([1, 2, 128, 254, 255]);
  });

  it.each(v.refused.map((c) => [c.name, c] as const))('refused: %s', async (_, c) => {
    expect(await combineShares(c.shares.map(unhex))).toEqual({ ok: false, error: c.ts as ShamirError });
  });

  it('the QR texts are fixed', async () => {
    for (const q of v.qr) {
      expect(await shareQrText(unhex(q.share))).toBe(q.text);
      expect(hex((await shareFromQrText(q.text)) as Uint8Array)).toBe(q.share);
    }
  });
});

describe('splitKey', () => {
  it('header: RGK1, threshold, fingerprint = SHA-256("regino-keys/shamir/v1" ‖ key)[..8], x = 1…n', async () => {
    const key = randomKey();
    const shares = await splitKey(key, 2, 3);
    const msg = new Uint8Array([...new TextEncoder().encode('regino-keys/shamir/v1'), ...key]);
    const fp = new Uint8Array(await crypto.subtle.digest('SHA-256', msg)).slice(0, 8);
    shares.forEach((s, i) => {
      expect(s).toHaveLength(SHAMIR_SHARE_LENGTH);
      expect(hex(s.subarray(0, 13))).toBe('52474b31' + '02' + hex(fp));
      expect(shareInfo(s)).toEqual({ threshold: 2, index: i + 1 });
    });
  });

  it.each([
    [2, 2],
    [2, 3],
    [3, 5],
    [4, 6],
  ])('%i of %i: random keys round-trip through every subset', async (t, n) => {
    for (let round = 0; round < 3; round++) {
      const key = randomKey();
      await expectAllSubsets(await splitKey(key, t, n), t, hex(key));
    }
  });

  it('255 shares (the most a byte x allows)', async () => {
    const key = randomKey();
    const shares = await splitKey(key, 3, 255);
    expect(shares.map((s) => s[13])).toEqual(Array.from({ length: 255 }, (_, i) => i + 1));
    const r = await combineShares([shares[254], shares[0], shares[127]] as Uint8Array[]);
    expect(r.ok && hex(r.key)).toBe(hex(key));
  });

  it('the key is not changed; two splits of one key have other random coefficients', async () => {
    const key = randomKey();
    const copy = hex(key);
    const a = await splitKey(key, 2, 3);
    const b = await splitKey(key, 2, 3);
    expect(hex(key)).toBe(copy);
    expect(hex(a[0] as Uint8Array)).not.toBe(hex(b[0] as Uint8Array));
    // shares of two splits of the same key share the header but do not fit together
    expect(await combineShares([a[0], b[1]] as Uint8Array[])).toEqual({ ok: false, error: { code: 'damaged' } });
  });

  it('the random coefficients come from crypto.getRandomValues and are wiped afterwards', async () => {
    const spy = vi.spyOn(crypto, 'getRandomValues');
    await splitKey(randomKey(), 3, 5);
    const coeffs = spy.mock.calls.at(-1)?.[0] as Uint8Array;
    expect(coeffs).toHaveLength(64);
    expect(coeffs.every((b) => b === 0)).toBe(true);
  });

  it('with zero coefficients every y is the key (the key byte is the constant term)', async () => {
    vi.spyOn(crypto, 'getRandomValues').mockImplementation(<T extends ArrayBufferView | null>(a: T): T => a);
    const key = randomKey();
    for (const s of await splitKey(key, 2, 3)) expect(hex(s.subarray(14))).toBe(hex(key));
  });

  it.each([
    ['a 31-byte key', new Uint8Array(31), 2, 3],
    ['a 33-byte key', new Uint8Array(33), 2, 3],
    ['not bytes', [...new Uint8Array(32)] as unknown as Uint8Array, 2, 3],
    ['threshold 1', new Uint8Array(32), 1, 3],
    ['threshold 0', new Uint8Array(32), 0, 3],
    ['fewer shares than the threshold', new Uint8Array(32), 3, 2],
    ['256 shares', new Uint8Array(32), 2, 256],
    ['a fractional threshold', new Uint8Array(32), 2.5, 3],
    ['NaN shares', new Uint8Array(32), 2, Number.NaN],
  ])('refuses %s', async (_, key, t, n) => {
    await expect(splitKey(key, t, n)).rejects.toThrow();
  });
});

describe('combineShares', () => {
  it('fewer distinct shares than the threshold, the same share twice', async () => {
    const [a, b] = await splitKey(randomKey(), 2, 3);
    expect(await combineShares([])).toEqual({ ok: false, error: { code: 'not-enough-shares', threshold: 2, count: 0 } });
    expect(await combineShares([a, a, a] as Uint8Array[])).toEqual({
      ok: false,
      error: { code: 'not-enough-shares', threshold: 2, count: 1 },
    });
    const r = await combineShares([a, b, a, b] as Uint8Array[]);
    expect(r.ok).toBe(true);
  });

  it('any damaged byte of y is detected (fingerprint, constant-time compare)', async () => {
    const [a, b] = await splitKey(randomKey(), 2, 3);
    for (let i = 14; i < SHAMIR_SHARE_LENGTH; i++) {
      const bad = (b as Uint8Array).slice();
      bad[i] = (bad[i] as number) ^ 0x01;
      expect(await combineShares([a, bad] as Uint8Array[])).toEqual({ ok: false, error: { code: 'damaged' } });
    }
  });

  it('a changed fingerprint, threshold or magic', async () => {
    const [a, b] = (await splitKey(randomKey(), 2, 3)) as [Uint8Array, Uint8Array];
    const fp = b.slice();
    fp[8] = (fp[8] as number) ^ 1;
    expect(await combineShares([a, fp])).toEqual({ ok: false, error: { code: 'different-keys', index: 1 } });
    const t = b.slice();
    t[4] = 3;
    expect(await combineShares([a, t])).toEqual({ ok: false, error: { code: 'different-keys', index: 1 } });
    // both changed alike: the shares agree, but the key does not match the fingerprint
    const fa = a.slice();
    fa[8] = (fa[8] as number) ^ 1;
    expect(await combineShares([fa, fp])).toEqual({ ok: false, error: { code: 'damaged' } });
    const m = b.slice();
    m[0] = 0x51;
    expect(await combineShares([a, m])).toEqual({ ok: false, error: { code: 'format', index: 1 } });
  });

  it('something other than bytes is not a share', async () => {
    const [a] = await splitKey(randomKey(), 2, 3);
    const notBytes = [...(a as Uint8Array)] as unknown as Uint8Array;
    expect(shareInfo(notBytes)).toBeNull();
    expect(await combineShares([a as Uint8Array, notBytes])).toEqual({ ok: false, error: { code: 'format', index: 1 } });
  });
});

/** QR matrix → image → jsQR, as a phone reading the printed share would. */
function scan(m: boolean[][], scale = 4, quiet = 4): string | undefined {
  const size = (m.length + 2 * quiet) * scale;
  const px = new Uint8ClampedArray(size * size * 4).fill(255);
  m.forEach((row, r) =>
    row.forEach((dark, c) => {
      if (!dark) return;
      for (let y = 0; y < scale; y++)
        for (let x = 0; x < scale; x++) {
          const i = (((r + quiet) * scale + y) * size + (c + quiet) * scale + x) * 4;
          px[i] = px[i + 1] = px[i + 2] = 0;
        }
    }),
  );
  return jsQR(px, size, size)?.data;
}

const B32 = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567';
/** Independent base32 (bit string) – to craft texts `shareQrText` would never write. */
const b32 = (bytes: Uint8Array) => {
  const bits = [...bytes].map((b) => b.toString(2).padStart(8, '0')).join('');
  let out = '';
  for (let i = 0; i < bits.length; i += 5) out += B32[parseInt(bits.slice(i, i + 5).padEnd(5, '0'), 2)];
  return out;
};
const check2 = async (s: Uint8Array) => new Uint8Array(await crypto.subtle.digest('SHA-256', s as BufferSource)).slice(0, 2);

describe('share as QR text / QR code (RGS1:)', () => {
  it('text = RGS1: + base32(share ‖ SHA-256(share)[..2]), 77 characters; reads back', async () => {
    const [s] = (await splitKey(randomKey(), 2, 3)) as [Uint8Array];
    const text = await shareQrText(s);
    expect(text).toBe(SHARE_QR_PREFIX + b32(new Uint8Array([...s, ...(await check2(s))])));
    expect(text).toMatch(/^RGS1:[A-Z2-7]{77}$/);
    expect(hex((await shareFromQrText(text)) as Uint8Array)).toBe(hex(s));
    // typed by hand: lower case, spaces, hyphens, new lines
    const typed = text.toLowerCase().replace(/(.{8})/g, '$1 - ') + '\n';
    expect(hex((await shareFromQrText(typed)) as Uint8Array)).toBe(hex(s));
  });

  it('refuses other texts, damaged texts and non-shares', async () => {
    const [s] = (await splitKey(randomKey(), 2, 3)) as [Uint8Array];
    const text = await shareQrText(s);
    const body = text.slice(5);
    const swap = (i: number) => text.slice(0, i) + (text[i] === 'A' ? 'B' : 'A') + text.slice(i + 1);
    expect(await shareFromQrText('RGR1:' + body)).toBeNull(); // a recovery code QR
    expect(await shareFromQrText(text.slice(0, -1))).toBeNull();
    expect(await shareFromQrText(text + 'A')).toBeNull();
    expect(await shareFromQrText(text.slice(0, 20) + '1' + text.slice(21))).toBeNull(); // not base32
    expect(await shareFromQrText(swap(40))).toBeNull(); // check bytes
    // last character: 4 data bits + 1 padding bit – padding 1 is not canonical
    const last = B32.indexOf(text.at(-1) as string);
    expect(await shareFromQrText(text.slice(0, -1) + B32[last ^ 1])).toBeNull();
    // correct check bytes, but not a share (x = 0)
    const x0 = s.slice();
    x0[13] = 0;
    expect(await shareFromQrText(SHARE_QR_PREFIX + b32(new Uint8Array([...x0, ...(await check2(x0))])))).toBeNull();
    await expect(shareQrText(x0)).rejects.toThrow();
    await expect(shareQrText(s.subarray(0, 45))).rejects.toThrow();
  });

  it('QR code scans back to the share; the SVG is only an image', async () => {
    const key = randomKey();
    const shares = await splitKey(key, 2, 3);
    const read = await Promise.all(
      shares.slice(1).map(async (s) => (await shareFromQrText(scan(await shareQrMatrix(s)) as string)) as Uint8Array),
    );
    const r = await combineShares(read);
    expect(r.ok && hex(r.key)).toBe(hex(key));
    const svg = await shareQrSvg(shares[0] as Uint8Array);
    expect(svg).toMatch(/^<svg [^>]*viewBox="0 0 \d+ \d+"/);
    expect(svg).not.toMatch(/href|script|http(?!:\/\/www\.w3\.org)/);
    expect(svg).toContain('aria-label="QR code of a key share"');
    expect(await shareQrSvg(shares[0] as Uint8Array, 4, 'sk')).toContain('aria-label="QR kód podielu kľúča"');
  });
});
