/**
 * Inbox of a practice (or any recipient): people without an account – e.g. a client filling in a
 * web form or signing a document in the browser – seal data to the recipient's public key. The
 * server carries the sealed message but cannot open it; only the recipient's app can. WebCrypto only.
 *
 * - Recipient: one ECDH P-256 key pair. The private key is exported once as PKCS#8 so the app can
 *   keep it wrapped by its own keys (e.g. sealed with the group key) and use it on every device;
 *   when imported for use it is non-extractable.
 * - Message: an ephemeral ECDH P-256 key per message, HKDF-SHA256 (salt = ephemeral ‖ recipient
 *   public key, info = version and context) → AES-256-GCM with a random 96-bit nonce; the context
 *   (e.g. app, practice, form and request id) is also bound as additional data.
 * - The sender is anonymous: a message proves it was not changed, not who sent it.
 * - Fingerprint: a short fingerprint of the recipient's public key for publishing out of band (on
 *   paper, in the recipient's own app, read out by phone). The recipient's app compares it with the
 *   key the server publishes; a sender can compare it with the key the page shows. The server can
 *   serve one key to the recipient and another to senders, so only a fingerprint the sender gets
 *   from somewhere else than the server protects the sender (see AUDIT.md, question 14).
 */
import { b64, checkContext, checkP256Point, ECDH, gcmNonce, sealingKey, unb64 } from "./ecdh";

export const INBOX_VERSION = 1;

const enc = new TextEncoder();

function b64url(text: string): Uint8Array {
  return unb64(text.replace(/-/g, "+").replace(/_/g, "/").padEnd(Math.ceil(text.length / 4) * 4, "="));
}

const checkPublicKey = (key: Uint8Array) => checkP256Point(key, "inbox");

const checkInboxContext = (context: string) => checkContext(context, "inbox");

export interface InboxKeys {
  /** 65 bytes (uncompressed point) – publish it on the server, e.g. on the practice web page. */
  publicKey: Uint8Array;
  /** PKCS#8 – keep it only wrapped by the recipient's own keys, never on the server in plain form. */
  privateKey: Uint8Array;
}

/** A new inbox key pair for a recipient (a practice). */
export async function newInboxKeys(): Promise<InboxKeys> {
  const pair = (await crypto.subtle.generateKey(ECDH, true, ["deriveBits"])) as CryptoKeyPair;
  return {
    publicKey: new Uint8Array(await crypto.subtle.exportKey("raw", pair.publicKey)),
    privateKey: new Uint8Array(await crypto.subtle.exportKey("pkcs8", pair.privateKey)),
  };
}

export interface InboxPrivateKey {
  /** non-extractable */
  privateKey: CryptoKey;
  /** the matching public key, taken from the private key itself */
  publicKey: Uint8Array;
}

/** Imports the stored private key for opening messages; the public key is derived from it. */
export async function importInboxKey(pkcs8: Uint8Array): Promise<InboxPrivateKey> {
  try {
    const tmp = await crypto.subtle.importKey("pkcs8", pkcs8 as BufferSource, ECDH, true, ["deriveBits"]);
    const jwk = await crypto.subtle.exportKey("jwk", tmp);
    const publicKey = new Uint8Array(65);
    publicKey[0] = 4;
    publicKey.set(b64url(jwk.x as string), 1);
    publicKey.set(b64url(jwk.y as string), 33);
    const privateKey = await crypto.subtle.importKey("pkcs8", pkcs8 as BufferSource, ECDH, false, ["deriveBits"]);
    return { privateKey, publicKey };
  } catch {
    throw new Error("Invalid inbox private key.");
  }
}

export interface InboxMessage {
  v: number;
  /** base64 ephemeral public key */
  e: string;
  /** base64 nonce */
  n: string;
  /** base64 ciphertext with the GCM tag */
  c: string;
}

const messageKey = (
  privateKey: CryptoKey,
  otherPublic: Uint8Array,
  ephemeralPublic: Uint8Array,
  recipientPublic: Uint8Array,
  context: string,
) => sealingKey(privateKey, otherPublic, ephemeralPublic, recipientPublic, `inbox seal v${INBOX_VERSION}|${context}`);

const messageAad = (context: string) => enc.encode(`inbox message v${INBOX_VERSION}|${context}`);

/** Seals data (e.g. form answers as JSON, a signed PDF) for the owner of the inbox public key. */
export async function sealToInbox(
  recipientPublic: Uint8Array,
  context: string,
  data: Uint8Array,
): Promise<InboxMessage> {
  checkPublicKey(recipientPublic);
  checkInboxContext(context);
  if (!(data instanceof Uint8Array)) throw new Error("Inbox data must be bytes.");
  const eph = (await crypto.subtle.generateKey(ECDH, false, ["deriveBits"])) as CryptoKeyPair;
  const ephPublic = new Uint8Array(await crypto.subtle.exportKey("raw", eph.publicKey));
  const key = await messageKey(eph.privateKey, recipientPublic, ephPublic, recipientPublic, context);
  const nonce = crypto.getRandomValues(new Uint8Array(12));
  const c = await crypto.subtle.encrypt(
    { name: "AES-GCM", iv: nonce, additionalData: messageAad(context) },
    key,
    data as BufferSource,
  );
  return { v: INBOX_VERSION, e: b64(ephPublic), n: b64(nonce), c: b64(new Uint8Array(c)) };
}

/** Opens a message with the inbox private key; throws if the key or context is wrong or data changed. */
export async function openFromInbox(
  key: InboxPrivateKey,
  context: string,
  message: InboxMessage,
): Promise<Uint8Array> {
  if (!message || message.v !== INBOX_VERSION) throw new Error("Unsupported inbox message version.");
  checkInboxContext(context);
  try {
    const ephPublic = unb64(message.e);
    checkPublicKey(ephPublic);
    const k = await messageKey(key.privateKey, ephPublic, ephPublic, key.publicKey, context);
    const plain = await crypto.subtle.decrypt(
      { name: "AES-GCM", iv: gcmNonce(message.n) as BufferSource, additionalData: messageAad(context) },
      k,
      unb64(message.c) as BufferSource,
    );
    return new Uint8Array(plain);
  } catch {
    throw new Error("The inbox message cannot be opened (wrong key, context or damaged data).");
  }
}

/**
 * Fingerprint of an inbox public key ("3f2a 9c01 …", 80 bits). The recipient's app checks that the
 * key published by the server has the fingerprint of its own key; a sender who has the fingerprint
 * from the recipient directly can check the key the page shows. It does not help a sender who has
 * nothing but what the server serves.
 */
export async function inboxFingerprint(publicKey: Uint8Array): Promise<string> {
  checkPublicKey(publicKey);
  const h = new Uint8Array(
    await crypto.subtle.digest("SHA-256", enc.encode(`inbox fingerprint v${INBOX_VERSION}|${b64(publicKey)}`)),
  );
  const hex = Array.from(h.subarray(0, 10), (b) => b.toString(16).padStart(2, "0")).join("");
  return hex.match(/.{4}/g)!.join(" ");
}
