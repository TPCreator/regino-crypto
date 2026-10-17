/**
 * Sync between the devices of one group (a household, a practice): records are sealed with a
 * shared group key and the group key is wrapped separately for every device. WebCrypto only.
 *
 * - Records: HKDF-SHA256 (group key → record key) → AES-256-GCM with a random 96-bit nonce.
 *   The context (e.g. group, table and record id) is bound as additional data, so a sealed record
 *   cannot be moved to another group, table or id without being detected.
 * - Devices: an ECDH P-256 key pair per device; the private key is created non-extractable and
 *   never leaves the device. The group key is wrapped for a device with an ephemeral ECDH key,
 *   HKDF-SHA256 (salt = both public keys) → AES-256-GCM.
 * - Pairing: the new device shows its public key (e.g. as a QR code); both devices show a short
 *   code derived from it, so people can confirm that the right device was paired.
 */
export const SYNC_VERSION = 1;

const enc = new TextEncoder();
const dec = new TextDecoder();
const ECDH = { name: "ECDH", namedCurve: "P-256" } as const;

function b64(bytes: Uint8Array): string {
  let s = "";
  for (const b of bytes) s += String.fromCharCode(b);
  return btoa(s);
}

function unb64(text: string): Uint8Array {
  const s = atob(text);
  const out = new Uint8Array(s.length);
  for (let i = 0; i < s.length; i++) out[i] = s.charCodeAt(i);
  return out;
}

function checkGroupKey(key: Uint8Array): void {
  if (!(key instanceof Uint8Array) || key.length !== 32)
    throw new Error("The group key must have 32 bytes.");
}

function checkPublicKey(key: Uint8Array): void {
  if (!(key instanceof Uint8Array) || key.length !== 65 || key[0] !== 4)
    throw new Error(
      "Invalid device public key (expected an uncompressed P-256 point).",
    );
}

/** A new random group key (32 bytes). Keep it only wrapped (for devices, by the recovery key). */
export function newGroupKey(): Uint8Array {
  return crypto.getRandomValues(new Uint8Array(32));
}

/** Record key derived from the group key; derive it once and reuse it for many records. */
export async function recordKey(groupKey: Uint8Array): Promise<CryptoKey> {
  checkGroupKey(groupKey);
  const base = await crypto.subtle.importKey(
    "raw",
    groupKey as BufferSource,
    "HKDF",
    false,
    ["deriveKey"],
  );
  return crypto.subtle.deriveKey(
    {
      name: "HKDF",
      hash: "SHA-256",
      salt: new Uint8Array(32),
      info: enc.encode("sync records v1"),
    },
    base,
    { name: "AES-GCM", length: 256 },
    false,
    ["encrypt", "decrypt"],
  );
}

export interface SealedRecord {
  v: number;
  /** base64 nonce */
  n: string;
  /** base64 ciphertext with the GCM tag */
  c: string;
}

const recordAad = (context: string) =>
  enc.encode(`sync record v${SYNC_VERSION}|${context}`);

export async function sealRecord(
  key: CryptoKey,
  context: string,
  payload: unknown,
): Promise<SealedRecord> {
  const nonce = crypto.getRandomValues(new Uint8Array(12));
  const c = await crypto.subtle.encrypt(
    { name: "AES-GCM", iv: nonce, additionalData: recordAad(context) },
    key,
    enc.encode(JSON.stringify(payload)),
  );
  return { v: SYNC_VERSION, n: b64(nonce), c: b64(new Uint8Array(c)) };
}

/** Opens a sealed record; throws if the key or the context is wrong or the record was changed. */
export async function openRecord<T = unknown>(
  key: CryptoKey,
  context: string,
  sealed: SealedRecord,
): Promise<T> {
  if (!sealed || sealed.v !== SYNC_VERSION)
    throw new Error("Unsupported sync record version.");
  try {
    const plain = await crypto.subtle.decrypt(
      {
        name: "AES-GCM",
        iv: unb64(sealed.n) as BufferSource,
        additionalData: recordAad(context),
      },
      key,
      unb64(sealed.c) as BufferSource,
    );
    return JSON.parse(dec.decode(plain)) as T;
  } catch {
    throw new Error(
      "The sync record cannot be opened (wrong key, context or damaged data).",
    );
  }
}

/** A device key pair: the private key is non-extractable (it can be stored, e.g. in IndexedDB). */
export function newDeviceKeys(): Promise<CryptoKeyPair> {
  return crypto.subtle.generateKey(ECDH, false, [
    "deriveBits",
  ]) as Promise<CryptoKeyPair>;
}

/** The public key as 65 bytes (uncompressed point) – for the QR code and the server. */
export async function publicKeyBytes(
  publicKey: CryptoKey,
): Promise<Uint8Array> {
  return new Uint8Array(await crypto.subtle.exportKey("raw", publicKey));
}

export interface WrappedGroupKey {
  v: number;
  /** base64 ephemeral public key */
  e: string;
  n: string;
  c: string;
}

async function wrapKey(
  privateKey: CryptoKey,
  otherPublic: Uint8Array,
  ephemeralPublic: Uint8Array,
  devicePublic: Uint8Array,
  context: string,
): Promise<CryptoKey> {
  const other = await crypto.subtle.importKey(
    "raw",
    otherPublic as BufferSource,
    ECDH,
    false,
    [],
  );
  const shared = await crypto.subtle.deriveBits(
    { name: "ECDH", public: other },
    privateKey,
    256,
  );
  const base = await crypto.subtle.importKey("raw", shared, "HKDF", false, [
    "deriveKey",
  ]);
  const salt = new Uint8Array(130);
  salt.set(ephemeralPublic, 0);
  salt.set(devicePublic, 65);
  return crypto.subtle.deriveKey(
    {
      name: "HKDF",
      hash: "SHA-256",
      salt,
      info: enc.encode(`sync wrap v${SYNC_VERSION}|${context}`),
    },
    base,
    { name: "AES-GCM", length: 256 },
    false,
    ["encrypt", "decrypt"],
  );
}

/** Wraps the group key for one device (its public key from the pairing QR code). */
export async function wrapForDevice(
  groupKey: Uint8Array,
  devicePublic: Uint8Array,
  context: string,
): Promise<WrappedGroupKey> {
  checkGroupKey(groupKey);
  checkPublicKey(devicePublic);
  const eph = (await crypto.subtle.generateKey(ECDH, false, [
    "deriveBits",
  ])) as CryptoKeyPair;
  const ephPublic = await publicKeyBytes(eph.publicKey);
  const key = await wrapKey(
    eph.privateKey,
    devicePublic,
    ephPublic,
    devicePublic,
    context,
  );
  const nonce = crypto.getRandomValues(new Uint8Array(12));
  const c = await crypto.subtle.encrypt(
    { name: "AES-GCM", iv: nonce, additionalData: enc.encode(context) },
    key,
    groupKey as BufferSource,
  );
  return {
    v: SYNC_VERSION,
    e: b64(ephPublic),
    n: b64(nonce),
    c: b64(new Uint8Array(c)),
  };
}

/** Unwraps the group key on the device it was wrapped for; throws otherwise. */
export async function unwrapForDevice(
  wrapped: WrappedGroupKey,
  devicePrivate: CryptoKey,
  devicePublic: Uint8Array,
  context: string,
): Promise<Uint8Array> {
  if (!wrapped || wrapped.v !== SYNC_VERSION)
    throw new Error("Unsupported wrapped key version.");
  checkPublicKey(devicePublic);
  try {
    const ephPublic = unb64(wrapped.e);
    const key = await wrapKey(
      devicePrivate,
      ephPublic,
      ephPublic,
      devicePublic,
      context,
    );
    const plain = await crypto.subtle.decrypt(
      {
        name: "AES-GCM",
        iv: unb64(wrapped.n) as BufferSource,
        additionalData: enc.encode(context),
      },
      key,
      unb64(wrapped.c) as BufferSource,
    );
    return new Uint8Array(plain);
  } catch {
    throw new Error("The group key cannot be unwrapped on this device.");
  }
}

/**
 * Short pairing code (6 digits, "123 456") from a device public key. Both devices show it;
 * if the codes match, the right device was paired.
 */
export async function pairingCode(devicePublic: Uint8Array): Promise<string> {
  checkPublicKey(devicePublic);
  const h = new Uint8Array(
    await crypto.subtle.digest(
      "SHA-256",
      enc.encode(`sync pairing v${SYNC_VERSION}|${b64(devicePublic)}`),
    ),
  );
  const n =
    (((h[0] as number) << 16) | ((h[1] as number) << 8) | (h[2] as number)) %
    1_000_000;
  const digits = String(n).padStart(6, "0");
  return `${digits.slice(0, 3)} ${digits.slice(3)}`;
}

/** Base64 helpers for carrying public keys in QR codes and requests. */
export const toBase64 = b64;
export const fromBase64 = unb64;
