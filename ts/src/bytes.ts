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
