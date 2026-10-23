/**
 * PIN for switching users on a shared device (a centre, a family computer).
 * It does not protect the data – the encrypted database does that; it only prevents a member
 * from switching to the administrator.
 * PBKDF2-SHA256 hash with a random salt: "pbkdf2$<iterations>$<salt hex>$<hash hex>".
 */
import { equalBytes } from './bytes';

const ITERATIONS = 200_000;
/**
 * Upper bound for the iteration count accepted in a stored hash (and when hashing). Apps store the
 * default 200 000; a damaged or planted record with billions of iterations must not keep the device
 * busy for hours (since 0.12.1).
 */
export const MAX_PIN_ITERATIONS = 10_000_000;
const PIN = /^\d{4,8}$/;

export const validPin = (pin: string): boolean => PIN.test(pin);

const hex = (b: Uint8Array) => Array.from(b, (x) => x.toString(16).padStart(2, '0')).join('');
// The salt has always been 16 bytes and the hash SHA-256 (32 bytes) – exact lengths since 0.12.1.
const SALT_HEX = /^[0-9a-f]{32}$/;
const HASH_HEX = /^[0-9a-f]{64}$/;
// Only called on a validated hex string, so match never returns null.
const unhex = (h: string) => new Uint8Array(h.match(/../g)!.map((x) => parseInt(x, 16)));
const validIterations = (n: number) => Number.isInteger(n) && n >= 1 && n <= MAX_PIN_ITERATIONS;

async function derive(pin: string, salt: Uint8Array, iterations: number): Promise<string> {
  const base = await crypto.subtle.importKey(
    'raw',
    new TextEncoder().encode(pin),
    'PBKDF2',
    false,
    ['deriveBits'],
  );
  const bits = await crypto.subtle.deriveBits(
    { name: 'PBKDF2', hash: 'SHA-256', salt: salt as BufferSource, iterations },
    base,
    256,
  );
  return hex(new Uint8Array(bits));
}

export async function hashPin(pin: string, iterations = ITERATIONS): Promise<string> {
  if (!validPin(pin)) throw new Error('The PIN must have 4 to 8 digits.');
  if (!validIterations(iterations)) throw new Error(`Iterations must be 1 to ${MAX_PIN_ITERATIONS}.`);
  const salt = crypto.getRandomValues(new Uint8Array(16));
  return `pbkdf2$${iterations}$${hex(salt)}$${await derive(pin, salt, iterations)}`;
}

/**
 * False for a wrong PIN and for any stored value that is not exactly `pbkdf2$<1..MAX>$<32 hex>$<64 hex>`
 * – the iteration count in its one canonical form (digits, no leading zeros, as `hashPin` writes it).
 */
export async function verifyPin(pin: string, stored: string): Promise<boolean> {
  const parts = stored.split('$');
  if (parts.length !== 4) return false;
  const [kind, iter, salt, hash] = parts as [string, string, string, string];
  const iterations = Number(iter);
  if (
    kind !== 'pbkdf2' ||
    !/^[1-9]\d*$/.test(iter) ||
    !validIterations(iterations) ||
    !SALT_HEX.test(salt) ||
    !HASH_HEX.test(hash)
  )
    return false;
  if (!validPin(pin)) return false;
  const got = await derive(pin, unhex(salt), iterations);
  const enc = new TextEncoder();
  return equalBytes(enc.encode(got), enc.encode(hash));
}
