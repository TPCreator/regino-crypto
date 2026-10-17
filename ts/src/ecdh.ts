/**
 * Shared building blocks of sync.ts and inbox.ts (internal, not exported from the package):
 * base64 and the ECDH P-256 → HKDF-SHA256 → AES-256-GCM key used to seal to a public key.
 */
const enc = new TextEncoder();

export const ECDH = { name: "ECDH", namedCurve: "P-256" } as const;

// In blocks – records and documents can have megabytes and one character at a time would be very slow.
export function b64(bytes: Uint8Array): string {
  let s = "";
  for (let i = 0; i < bytes.length; i += 0x8000)
    s += String.fromCharCode(...bytes.subarray(i, i + 0x8000));
  return btoa(s);
}

export function unb64(text: string): Uint8Array {
  const s = atob(text);
  const out = new Uint8Array(s.length);
  for (let i = 0; i < s.length; i++) out[i] = s.charCodeAt(i);
  return out;
}

/** Throws unless the key is an uncompressed P-256 point (65 bytes, 0x04 ‖ x ‖ y). */
export function checkP256Point(key: Uint8Array, what: string): void {
  if (!(key instanceof Uint8Array) || key.length !== 65 || key[0] !== 4)
    throw new Error(`Invalid ${what} public key (expected an uncompressed P-256 point).`);
}

/**
 * AES-256-GCM key from ECDH between `privateKey` and `otherPublic`, through HKDF-SHA256 with
 * salt = ephemeral public key ‖ recipient public key and the given info (version and context).
 */
export async function sealingKey(
  privateKey: CryptoKey,
  otherPublic: Uint8Array,
  ephemeralPublic: Uint8Array,
  recipientPublic: Uint8Array,
  info: string,
): Promise<CryptoKey> {
  const other = await crypto.subtle.importKey("raw", otherPublic as BufferSource, ECDH, false, []);
  const shared = await crypto.subtle.deriveBits({ name: "ECDH", public: other }, privateKey, 256);
  const base = await crypto.subtle.importKey("raw", shared, "HKDF", false, ["deriveKey"]);
  const salt = new Uint8Array(130);
  salt.set(ephemeralPublic, 0);
  salt.set(recipientPublic, 65);
  return crypto.subtle.deriveKey(
    { name: "HKDF", hash: "SHA-256", salt, info: enc.encode(info) },
    base,
    { name: "AES-GCM", length: 256 },
    false,
    ["encrypt", "decrypt"],
  );
}
