import { equalBytes } from './bytes';

/**
 * Splitting a 32-byte key into `shares` shares of which any `threshold` suffice (e.g. 2 of 3: paper,
 * a person, a notary) – Shamir secret sharing over GF(256), **byte for byte the same as Rust**
 * `regino_keys::shamir` (since 0.18.0): shares made here combine in Rust and the other way round
 * (fixed vectors `testvectors/regino/keys-0.11.1.json` made by Rust, `shamir-0.18.0.json` made here).
 *
 * Share format (46 bytes): `"RGK1" | threshold(1) | fingerprint(8) | x(1) | y(32)`.
 * - fingerprint = the first 8 bytes of SHA-256(`regino-keys/shamir/v1` ‖ key): a damaged share or
 *   shares of another key end with an error, never with a silently wrong key; compared in constant time,
 * - field: GF(2^8) with the reduction polynomial x^8 + x^4 + x^3 + x^2 + 1 (0x11d), as the Rust crate
 *   `blahaj` 0.7; x runs 1, 2, …, `shares`; per key byte the polynomial is
 *   `a_{t-1}·x^{t-1} + … + a_1·x + key[i]` with `a_j` uniformly random bytes (zero included, as blahaj),
 *   evaluated by Horner from the highest coefficient (the order blahaj draws them in),
 * - combining: Lagrange interpolation at x = 0 over all distinct shares given (as blahaj).
 *
 * Fewer shares than the threshold reveal nothing about the key. The multiplication with key bytes
 * is branch- and table-free (no secret-dependent memory access); divisions touch only x, which is public.
 * Random coefficients, the recovered secret and every buffer holding key bytes are wiped (`fill(0)`).
 */

const MAGIC = [0x52, 0x47, 0x4b, 0x31]; // "RGK1"
/** Header: magic(4) ‖ threshold(1) ‖ fingerprint(8). */
const HEADER_LEN = 4 + 1 + 8;
const KEY_LEN = 32;
/** Length of every share in bytes (header ‖ x ‖ y), as Rust `shamir::SHARE_LEN`. */
export const SHAMIR_SHARE_LENGTH = HEADER_LEN + 1 + KEY_LEN;
/** Domain of the key fingerprint, as Rust. */
const FINGERPRINT_DOMAIN = new TextEncoder().encode('regino-keys/shamir/v1');

/** Multiplication in GF(2^8) mod 0x11d, without branches or tables on the operands. */
export function gfMul(a: number, b: number): number {
  let p = 0;
  for (let i = 0; i < 8; i++) {
    p ^= -(b & 1) & a; // add a when the lowest bit of b is set
    a = ((a << 1) ^ (-(a >> 7) & 0x11d)) & 0xff; // a·x, reduced when the top bit was set
    b >>= 1;
  }
  return p & 0xff;
}

/** Inverse in GF(2^8): a^254 (only for public values – the x of shares). */
function gfInv(a: number): number {
  let r = 1;
  for (let e = 254, base = a; e > 0; e >>= 1, base = gfMul(base, base)) if (e & 1) r = gfMul(r, base);
  return r;
}

async function fingerprint(key: Uint8Array): Promise<Uint8Array> {
  const buf = new Uint8Array(FINGERPRINT_DOMAIN.length + key.length);
  buf.set(FINGERPRINT_DOMAIN);
  buf.set(key, FINGERPRINT_DOMAIN.length);
  try {
    return new Uint8Array(await crypto.subtle.digest('SHA-256', buf as BufferSource)).slice(0, 8);
  } finally {
    buf.fill(0);
  }
}

const isByte = (n: number, min: number) => Number.isInteger(n) && n >= min && n <= 255;

/**
 * Splits a 32-byte key into `shares` shares (46 bytes each), any `threshold` of which give the key back.
 * Throws for a key of another length, `threshold < 2`, `shares < threshold` or `shares > 255`
 * (Rust `Error::BadSplit`; there both are `u8`). The key itself is not changed or wiped.
 */
export async function splitKey(key: Uint8Array, threshold: number, shares: number): Promise<Uint8Array[]> {
  if (!(key instanceof Uint8Array) || key.length !== KEY_LEN) throw new Error('The key must have 32 bytes.');
  if (!isByte(threshold, 2) || !isByte(shares, 2) || shares < threshold)
    throw new Error(`Cannot split into ${String(shares)} shares with threshold ${String(threshold)} (2 ≤ threshold ≤ shares ≤ 255).`);
  const fp = await fingerprint(key);
  const k = threshold - 1; // random coefficients per key byte, highest degree first
  const coeffs = crypto.getRandomValues(new Uint8Array(KEY_LEN * k));
  try {
    const out: Uint8Array[] = [];
    for (let x = 1; x <= shares; x++) {
      const share = new Uint8Array(SHAMIR_SHARE_LENGTH);
      share.set(MAGIC);
      share[4] = threshold;
      share.set(fp, 5);
      share[HEADER_LEN] = x;
      for (let i = 0; i < KEY_LEN; i++) {
        let acc = 0;
        for (let j = 0; j < k; j++) acc = gfMul(acc, x) ^ (coeffs[i * k + j] as number);
        share[HEADER_LEN + 1 + i] = gfMul(acc, x) ^ (key[i] as number);
      }
      out.push(share);
    }
    return out;
  } finally {
    coeffs.fill(0);
  }
}

/** Why `combineShares` refused (the index is the position in the given array). */
export type ShamirError =
  /** not a share: wrong length, not `RGK1`, threshold below 2 or x = 0 */
  | { code: 'format'; index: number }
  /** a share of another key or another split (fingerprint or threshold differ from the first share) */
  | { code: 'different-keys'; index: number }
  /** two different shares with the same x – both cannot be right */
  | { code: 'duplicate-x'; index: number }
  /** fewer distinct shares than the threshold (`threshold` is 2 when no share was given) */
  | { code: 'not-enough-shares'; threshold: number; count: number }
  /** the shares fit together, but the result does not match the fingerprint – a share is damaged */
  | { code: 'damaged' };

/** Threshold and x (1–255, the share's number) of a share, or null if it is not a share. */
export function shareInfo(share: Uint8Array): { threshold: number; index: number } | null {
  if (
    !(share instanceof Uint8Array) ||
    share.length !== SHAMIR_SHARE_LENGTH ||
    MAGIC.some((b, i) => share[i] !== b) ||
    (share[4] as number) < 2 ||
    share[HEADER_LEN] === 0
  )
    return null;
  return { threshold: share[4] as number, index: share[HEADER_LEN] as number };
}

/**
 * Reassembles the key from shares (Rust `shamir::combine`). At least `threshold` distinct shares of the
 * same key are required; the same share given twice counts once. The caller wipes the returned key
 * when done (`fill(0)`).
 */
export async function combineShares(
  shares: readonly Uint8Array[],
): Promise<{ ok: true; key: Uint8Array } | { ok: false; error: ShamirError }> {
  const first = shares[0];
  if (!first) return { ok: false, error: { code: 'not-enough-shares', threshold: 2, count: 0 } };
  const head = shareInfo(first);
  if (!head) return { ok: false, error: { code: 'format', index: 0 } };
  const { threshold } = head;
  const fp = first.subarray(5, HEADER_LEN);
  const byX = new Map<number, Uint8Array>();
  for (const [index, s] of shares.entries()) {
    if (!shareInfo(s)) return { ok: false, error: { code: 'format', index } };
    // header fields are public (threshold, fingerprint) – an ordinary comparison is fine
    if (s[4] !== threshold || s.subarray(5, HEADER_LEN).some((b, i) => b !== fp[i]))
      return { ok: false, error: { code: 'different-keys', index } };
    const x = s[HEADER_LEN] as number;
    const prev = byX.get(x);
    if (prev) {
      if (!equalBytes(prev, s)) return { ok: false, error: { code: 'duplicate-x', index } };
      continue;
    }
    byX.set(x, s);
  }
  if (byX.size < threshold) return { ok: false, error: { code: 'not-enough-shares', threshold, count: byX.size } };

  // Lagrange basis at 0: l_i = Π_{j≠i} x_j / (x_j − x_i); x is public, so plain arithmetic is fine.
  const pts = [...byX.values()];
  const xs = pts.map((s) => s[HEADER_LEN] as number);
  const basis = xs.map((xi, i) => {
    let l = 1;
    xs.forEach((xj, j) => {
      if (j !== i) l = gfMul(l, gfMul(xj, gfInv(xj ^ xi)));
    });
    return l;
  });
  const key = new Uint8Array(KEY_LEN);
  for (let b = 0; b < KEY_LEN; b++) {
    let acc = 0;
    pts.forEach((s, i) => (acc ^= gfMul(basis[i] as number, s[HEADER_LEN + 1 + b] as number)));
    key[b] = acc;
  }
  const check = await fingerprint(key);
  if (!equalBytes(check, fp)) {
    key.fill(0);
    return { ok: false, error: { code: 'damaged' } };
  }
  return { ok: true, key };
}

/*
 * A share as text for its own QR code or for typing (since 0.18.0, TypeScript only – Rust works with
 * the bytes): "RGS1:" + base32 (A–Z, 2–7, QR alphanumeric mode) of [share(46) | 2 bytes of SHA-256(share)],
 * 77 characters after the prefix. The check bytes catch a misread or mistyped share before combining.
 */
export const SHARE_QR_PREFIX = 'RGS1:';
const B32 = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567';
const QR_BYTES = SHAMIR_SHARE_LENGTH + 2;
const QR_CHARS = Math.ceil((QR_BYTES * 8) / 5);

async function check2(share: Uint8Array): Promise<Uint8Array> {
  return new Uint8Array(await crypto.subtle.digest('SHA-256', share as BufferSource)).slice(0, 2);
}

/** QR / typing text of a share (`RGS1:…`). Throws for anything that is not a share. */
export async function shareQrText(share: Uint8Array): Promise<string> {
  if (!shareInfo(share)) throw new Error('Not a key share.');
  const raw = new Uint8Array(QR_BYTES);
  raw.set(share);
  raw.set(await check2(share), SHAMIR_SHARE_LENGTH);
  let out = SHARE_QR_PREFIX;
  let acc = 0;
  let bits = 0;
  for (const byte of raw) {
    acc = (acc << 8) | byte;
    bits += 8;
    while (bits >= 5) {
      bits -= 5;
      out += B32[(acc >> bits) & 31];
    }
    acc &= (1 << bits) - 1;
  }
  out += B32[(acc << (5 - bits)) & 31]; // 48 bytes = 384 bits: 76 full characters + 4 bits
  raw.fill(0);
  return out;
}

/**
 * Text from `shareQrText` → share bytes, or null if it is not a valid share text (other prefix, wrong
 * length, non-canonical padding, check bytes or share header wrong). Case, spaces and hyphens are ignored.
 */
export async function shareFromQrText(text: string): Promise<Uint8Array | null> {
  const t = text.toUpperCase().replace(/[\s-]+/g, '');
  if (!t.startsWith(SHARE_QR_PREFIX)) return null;
  const body = t.slice(SHARE_QR_PREFIX.length);
  if (body.length !== QR_CHARS) return null;
  const raw = new Uint8Array(QR_BYTES);
  try {
    let acc = 0;
    let bits = 0;
    let n = 0;
    for (const ch of body) {
      const v = B32.indexOf(ch);
      if (v < 0) return null;
      acc = ((acc << 5) | v) & 0xfff;
      bits += 5;
      if (bits >= 8) {
        bits -= 8;
        raw[n++] = (acc >> bits) & 0xff; // 77 characters = 385 bits: exactly 48 bytes + 1 bit
      }
    }
    // one text per share: the padding bits after the last byte must be zero
    if (acc & ((1 << bits) - 1)) return null;
    const share = raw.slice(0, SHAMIR_SHARE_LENGTH);
    if (shareInfo(share) !== null && equalBytes(await check2(share), raw.subarray(SHAMIR_SHARE_LENGTH))) return share;
    share.fill(0);
    return null;
  } finally {
    // the decoded bytes are a share: wiped on every path, also when a later character is refused (since 0.18.0)
    raw.fill(0);
  }
}
