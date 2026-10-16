/**
 * PIN for switching users on a shared device (a centre, a family computer).
 * It does not protect the data – the encrypted database does that; it only prevents a member
 * from switching to the administrator.
 * PBKDF2-SHA256 hash with a random salt: "pbkdf2$<iterations>$<salt hex>$<hash hex>".
 */
const ITERATIONS = 200_000;
const PIN = /^\d{4,8}$/;

export const validPin = (pin: string): boolean => PIN.test(pin);

const hex = (b: Uint8Array) => Array.from(b, (x) => x.toString(16).padStart(2, '0')).join('');
const HEX = /^(?:[0-9a-f]{2})+$/;
// Only called on a validated hex string, so match never returns null.
const unhex = (h: string) => new Uint8Array(h.match(/../g)!.map((x) => parseInt(x, 16)));

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
  const salt = crypto.getRandomValues(new Uint8Array(16));
  return `pbkdf2$${iterations}$${hex(salt)}$${await derive(pin, salt, iterations)}`;
}

export async function verifyPin(pin: string, stored: string): Promise<boolean> {
  const [kind, iter, salt, hash] = stored.split('$');
  const iterations = Number(iter);
  if (
    kind !== 'pbkdf2' ||
    !Number.isInteger(iterations) ||
    iterations < 1 ||
    !HEX.test(salt ?? '') ||
    !hash
  )
    return false;
  if (!validPin(pin)) return false;
  const got = await derive(pin, unhex(salt!), iterations);
  // Comparison without early exit.
  let diff = got.length ^ hash.length;
  for (let i = 0; i < got.length; i++) diff |= got.charCodeAt(i) ^ (hash.charCodeAt(i) | 0);
  return diff === 0;
}
