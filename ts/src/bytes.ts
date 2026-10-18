/** Small internal helpers (not exported from the package). */

/**
 * Compares two byte arrays without an early exit, so the time does not reveal where they differ.
 * Use it for anything derived from a secret (checksums, hashes, tags). The length is not secret.
 */
export function equalBytes(a: Uint8Array, b: Uint8Array): boolean {
  if (a.length !== b.length) return false;
  let diff = 0;
  for (let i = 0; i < a.length; i++) diff |= (a[i] as number) ^ (b[i] as number);
  return diff === 0;
}

const LIMIT = 4_294_000_000; // largest multiple of 10^6 below 2^32

/**
 * Six decimal digits ("123 456") from a hash without modulo bias: 32-bit words are taken in order
 * and the first one below LIMIT is used (rejection sampling). If all eight words are rejected
 * (probability about 10^-29) the hash is hashed again – deterministic, so both devices agree.
 */
export async function sixDigits(hash: Uint8Array): Promise<string> {
  for (let h = hash; ; h = new Uint8Array(await crypto.subtle.digest('SHA-256', h as BufferSource))) {
    const view = new DataView(h.buffer, h.byteOffset, h.byteLength);
    for (let i = 0; i + 4 <= h.length; i += 4) {
      const v = view.getUint32(i);
      if (v < LIMIT) {
        const digits = String(v % 1_000_000).padStart(6, '0');
        return `${digits.slice(0, 3)} ${digits.slice(3)}`;
      }
    }
  }
}
