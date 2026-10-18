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
 *   Wrapped keys v2 (since 0.8.0) bind `sync wrap v2|<context>` both as HKDF info and as AAD;
 *   v1 (bare context as AAD) is still unwrapped.
 * - Pairing (docs/PAIRING.md): the new device shows its public key as a QR code and the existing
 *   device scans it; both show `pairingCode` – a guard against scanning the wrong screen. If an app
 *   ever lets a public key travel through a server, it must use the SAS with a commitment instead
 *   (`pairingCommitment`, `pairingSas`), which a party in the middle cannot grind.
 */
import { equalBytes, sixDigits } from "./bytes";
import { b64, checkContext, checkP256Point, ECDH, gcmNonce, sealingKey, unb64 } from "./ecdh";

/** Version of sealed records. */
export const SYNC_VERSION = 1;
/** Version of wrapped group keys written by `wrapForDevice` (v1 is still read). */
export const WRAP_VERSION = 2;

const enc = new TextEncoder();
const dec = new TextDecoder();

function checkGroupKey(key: Uint8Array): void {
  if (!(key instanceof Uint8Array) || key.length !== 32)
    throw new Error("The group key must have 32 bytes.");
}

const checkPublicKey = (key: Uint8Array) => checkP256Point(key, "device");

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
  checkContext(context, "sync");
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
  checkContext(context, "sync");
  try {
    const plain = await crypto.subtle.decrypt(
      {
        name: "AES-GCM",
        iv: gcmNonce(sealed.n) as BufferSource,
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

// v1: info `sync wrap v1|<context>`, AAD = bare context; v2: `sync wrap v2|<context>` for both.
const wrapLabel = (v: number, context: string) => `sync wrap v${v}|${context}`;
const wrapAad = (v: number, context: string) => enc.encode(v === 1 ? context : wrapLabel(v, context));

/** Wraps the group key for one device (its public key from the pairing QR code). */
export async function wrapForDevice(
  groupKey: Uint8Array,
  devicePublic: Uint8Array,
  context: string,
): Promise<WrappedGroupKey> {
  checkGroupKey(groupKey);
  checkPublicKey(devicePublic);
  checkContext(context, "sync");
  const eph = (await crypto.subtle.generateKey(ECDH, false, [
    "deriveBits",
  ])) as CryptoKeyPair;
  const ephPublic = await publicKeyBytes(eph.publicKey);
  const key = await sealingKey(eph.privateKey, devicePublic, ephPublic, devicePublic, wrapLabel(WRAP_VERSION, context));
  const nonce = crypto.getRandomValues(new Uint8Array(12));
  const c = await crypto.subtle.encrypt(
    { name: "AES-GCM", iv: nonce, additionalData: wrapAad(WRAP_VERSION, context) },
    key,
    groupKey as BufferSource,
  );
  return {
    v: WRAP_VERSION,
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
  if (!wrapped || (wrapped.v !== 1 && wrapped.v !== WRAP_VERSION))
    throw new Error("Unsupported wrapped key version.");
  const v = wrapped.v;
  checkPublicKey(devicePublic);
  checkContext(context, "sync");
  try {
    const ephPublic = unb64(wrapped.e);
    checkPublicKey(ephPublic);
    const key = await sealingKey(devicePrivate, ephPublic, ephPublic, devicePublic, wrapLabel(v, context));
    const plain = await crypto.subtle.decrypt(
      {
        name: "AES-GCM",
        iv: gcmNonce(wrapped.n) as BufferSource,
        additionalData: wrapAad(v, context),
      },
      key,
      unb64(wrapped.c) as BufferSource,
    );
    if (plain.byteLength !== 32) throw new Error("not a group key");
    return new Uint8Array(plain);
  } catch {
    throw new Error("The group key cannot be unwrapped on this device.");
  }
}

/**
 * Short pairing code (6 digits, "123 456") from the new device's public key. Both devices show it;
 * if the codes match, the right screen was scanned. Unbiased since 0.8.0 (label `sync pairing v2`),
 * so both devices must use core 0.8.0 or newer.
 *
 * Limits (AUDIT.md, question 15; docs/PAIRING.md): whoever carries the public key could try about a
 * million key pairs to find one with the same code, so this code is enough only when the existing
 * device takes the key straight from the new device's QR code. Otherwise use the SAS below.
 */
export async function pairingCode(devicePublic: Uint8Array): Promise<string> {
  checkPublicKey(devicePublic);
  return sixDigits(await sha256(`sync pairing v2|${b64(devicePublic)}`));
}

const sha256 = async (text: string) => new Uint8Array(await crypto.subtle.digest("SHA-256", enc.encode(text)));

/** A fresh random nonce (16 bytes) for one pairing attempt (`pairingCommitment`, `pairingSas`). */
export function newPairingNonce(): Uint8Array {
  return crypto.getRandomValues(new Uint8Array(16));
}

function checkNonce(nonce: Uint8Array): void {
  if (!(nonce instanceof Uint8Array) || nonce.length !== 16) throw new Error("The pairing nonce must have 16 bytes.");
}

const sasInput = (label: string, newPublic: Uint8Array, existingPublic: Uint8Array, ...nonces: Uint8Array[]) => {
  checkPublicKey(newPublic);
  checkPublicKey(existingPublic);
  nonces.forEach(checkNonce);
  return [label, b64(newPublic), b64(existingPublic), ...nonces.map(b64)].join("|");
};

/**
 * Commitment of the new device to its nonce, sent before it learns the existing device's nonce
 * (docs/PAIRING.md, SAS flow). Base64 of SHA-256 over both public keys and the nonce.
 */
export async function pairingCommitment(newPublic: Uint8Array, existingPublic: Uint8Array, newNonce: Uint8Array): Promise<string> {
  return b64(await sha256(sasInput("sync pairing commit v1", newPublic, existingPublic, newNonce)));
}

/** The existing device checks the revealed nonce against the commitment it received first. */
export async function checkPairingCommitment(
  commitment: string,
  newPublic: Uint8Array,
  existingPublic: Uint8Array,
  newNonce: Uint8Array,
): Promise<boolean> {
  let got: Uint8Array;
  try {
    got = unb64(commitment);
  } catch {
    return false;
  }
  return equalBytes(got, await sha256(sasInput("sync pairing commit v1", newPublic, existingPublic, newNonce)));
}

/**
 * Short authentication string over both public keys and both nonces (6 digits). Both devices show
 * it after the commitment was checked; a party in the middle had to commit before seeing the other
 * nonce, so it matches for it with probability 10^-6 per attempt.
 */
export async function pairingSas(
  newPublic: Uint8Array,
  existingPublic: Uint8Array,
  newNonce: Uint8Array,
  existingNonce: Uint8Array,
): Promise<string> {
  return sixDigits(await sha256(sasInput("sync pairing sas v1", newPublic, existingPublic, newNonce, existingNonce)));
}

/** Base64 helpers for carrying public keys in QR codes and requests. */
export const toBase64 = b64;
export const fromBase64 = unb64;
