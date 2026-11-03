/**
 * Signatures (Ed25519, `@noble/ed25519`, strict RFC 8032) – so a server that carries keys between
 * people cannot pass off its own key as a colleague's, or its own group key as a new epoch. The same
 * computation exists in Rust (`regino_keys::sign`, `ed25519-dalek`); the shared fixed vectors
 * `testvectors/regino/signing-0.13.0.json` guard that both give the same bytes and accept the same
 * signatures. Model, what it protects and what not: docs/SIGNING.md.
 *
 * - Signing key: a 32-byte seed – random (`newSigningKey`), kept only wrapped by the app's own keys
 *   (like the inbox private key), or derived from a key the app keeps anyway (`deriveSigningKey`, HKDF-SHA256
 *   `<app> signing-key v1 <label>`) – then it is the same on every device and after a restore.
 * - `signingFingerprint`: "3f2a 9c01 …" (80 bits) – compared once by phone or in person, then pinned.
 * - `signData` / `verifyData`: a signature over data bound to a context.
 * - `signedWrapForDevice` / `openSignedWrap`: `wrapForDevice` plus the sender's signature over the context,
 *   object id, epoch, hash of the accepted member list, recipient public key, the sender's public key and
 *   the wrapped key; opened only from an admin of the list the recipient accepted itself.
 * - Manifests: a signed list of members (scope, version, key epoch, hash of the previous list, members
 *   with their signing and sealing keys); `verifyManifest` / `verifyManifestChain` accept a list only if
 *   it continues one already trusted and is signed by one of its admins (or by an anchor).
 *
 * Every signed message is `RGN-SIG1 || lp(kind) || lp(field) …` with `lp(x) = u32 BE length || x`.
 */
import { Point, getPublicKeyAsync, signAsync, verifyAsync } from "@noble/ed25519";
import { equalBytes } from "./bytes";
import { b64, checkContext, unb64 } from "./ecdh";
import { unwrapForDevice, wrapForDevice, type WrappedGroupKey } from "./sync";

export const SIGNATURE_LEN = 64;
export const SIGNING_KEY_LEN = 32;
export const MAX_CONTEXT = 1024;
export const MAX_NAME = 256;
export const MAX_KEY = 1024;
export const MAX_MEMBERS = 1000;
export const MAX_WRAPPED = 65536;
/** Versions and epochs are whole numbers 0 … 2^53 − 1 (the same limit in Rust). */
export const MAX_VERSION = Number.MAX_SAFE_INTEGER;
/** Version of `SignedWrappedKey`. */
export const SIGNED_WRAP_VERSION = 1;

const enc = new TextEncoder();
const MAGIC = enc.encode("RGN-SIG1");

function seed(key: Uint8Array): Uint8Array {
  if (!(key instanceof Uint8Array) || key.length !== SIGNING_KEY_LEN) throw new Error("The signing key must have 32 bytes.");
  return key;
}

/** A new random signing key (32-byte seed). Keep it only wrapped by the app's own keys; wipe with `fill(0)`. */
export function newSigningKey(): Uint8Array {
  return crypto.getRandomValues(new Uint8Array(SIGNING_KEY_LEN));
}

/**
 * Signing key derived from a key the app keeps anyway (e.g. the master key, 32 bytes) with HKDF-SHA256,
 * info `<app> signing-key v1 <label>` – identical to `regino_keys::sign::SigningKey::derive`.
 */
export async function deriveSigningKey(key: Uint8Array, app: string, label: string): Promise<Uint8Array> {
  if (!(key instanceof Uint8Array) || key.length !== 32) throw new Error("The key must have 32 bytes.");
  if (!/^[a-z][a-z0-9]{1,31}$/.test(app) || !/^[a-z][a-z0-9-]{2,31}$/.test(label)) throw new Error("Invalid app name or label.");
  const base = await crypto.subtle.importKey("raw", key as BufferSource, "HKDF", false, ["deriveBits"]);
  const bits = await crypto.subtle.deriveBits(
    { name: "HKDF", hash: "SHA-256", salt: new Uint8Array(0), info: enc.encode(`${app} signing-key v1 ${label}`) },
    base,
    256,
  );
  return new Uint8Array(bits);
}

/** The public key (32 bytes) of a signing key. */
export function signingPublicKey(key: Uint8Array): Promise<Uint8Array> {
  return getPublicKeyAsync(seed(key));
}

function point(bytes: Uint8Array): Point | null {
  try {
    return Point.fromBytes(bytes, false);
  } catch {
    return null;
  }
}

/** A canonical point of prime order (not small order, no torsion component) – the same rule as in Rust. */
export function isSigningPublicKey(key: Uint8Array): boolean {
  if (!(key instanceof Uint8Array) || key.length !== SIGNING_KEY_LEN) return false;
  // The check is a pure function of the 32 bytes and costly (torsion check = a scalar multiplication),
  // and a chain of lists repeats the same member keys in every version – remember the verdict (since 0.13.3).
  const id = b64(key);
  const known = keyCache.get(id);
  if (known !== undefined) {
    keyCache.delete(id); // least recently used goes first
    keyCache.set(id, known);
    return known;
  }
  const p = point(key);
  const ok = p !== null && !p.isSmallOrder() && p.isTorsionFree();
  keyCache.set(id, ok);
  if (keyCache.size > SIGNING_KEY_CACHE) keyCache.delete(keyCache.keys().next().value as string);
  return ok;
}

/** Most public-key verdicts kept by `isSigningPublicKey` (least recently used dropped first). */
export const SIGNING_KEY_CACHE = 4096;
const keyCache = new Map<string, boolean>();

/** Forgets the remembered public-key verdicts (tests, benchmarks); results never depend on it. */
export function clearSigningKeyCache(): void {
  keyCache.clear();
}

function checkPublic(key: Uint8Array, what = "signing"): void {
  if (!isSigningPublicKey(key)) throw new Error(`Invalid ${what} public key.`);
}

/** Short code of a public key ("3f2a 9c01 …", 80 bits of SHA-256) for comparing by phone or in person. */
export async function signingFingerprint(publicKey: Uint8Array): Promise<string> {
  checkPublic(publicKey);
  return code("regino signing fingerprint v1|", publicKey);
}

/**
 * Short code of an accepted member list ("3f2a 9c01 …", 80 bits) – members compare it with the
 * coordinator to be sure they all accepted the same list (a fork cannot be seen by the core alone).
 */
export async function manifestFingerprint(list: AcceptedManifest): Promise<string> {
  return code("regino manifest fingerprint v1|", bytes(list.hash, 32, 32, "list hash"));
}

async function code(label: string, data: Uint8Array): Promise<string> {
  const h = new Uint8Array(await crypto.subtle.digest("SHA-256", concat([enc.encode(label), data]) as BufferSource));
  const hex = Array.from(h.subarray(0, 10), (b) => b.toString(16).padStart(2, "0")).join("");
  return hex.match(/.{4}/g)!.join(" ");
}

function concat(parts: Uint8Array[]): Uint8Array {
  const out = new Uint8Array(parts.reduce((n, p) => n + p.length, 0));
  let i = 0;
  for (const p of parts) {
    out.set(p, i);
    i += p.length;
  }
  return out;
}

function u32(n: number): Uint8Array {
  const b = new Uint8Array(4);
  new DataView(b.buffer).setUint32(0, n);
  return b;
}

function u64(n: number): Uint8Array {
  if (!Number.isSafeInteger(n) || n < 0) throw new Error("A version must be a whole number from 0 to 2^53 - 1.");
  const b = new Uint8Array(8);
  new DataView(b.buffer).setBigUint64(0, BigInt(n));
  return b;
}

function message(kind: string, fields: Uint8Array[]): Uint8Array {
  const parts: Uint8Array[] = [MAGIC];
  for (const f of [enc.encode(kind), ...fields]) parts.push(u32(f.length), f);
  return concat(parts);
}

/** UTF-8 of a non-empty, well-formed string of at most `max` bytes. */
function text(s: string, max: number, what: string): Uint8Array {
  checkContext(s, what);
  const b = enc.encode(s);
  if (b.length > max || new TextDecoder("utf-8", { ignoreBOM: true }).decode(b) !== s) throw new Error(`The ${what} is too long or not valid text.`);
  return b;
}

function bytes(b: Uint8Array, min: number, max: number, what: string): Uint8Array {
  if (!(b instanceof Uint8Array) || b.length < min || b.length > max) throw new Error(`Invalid ${what}.`);
  return b;
}

/**
 * The strict Ed25519 check behind every function here (the same verdicts as Rust): the public key and R
 * must be canonical points of prime order, S < L. Apps should sign through `signData` (context-bound)
 * rather than over bare bytes.
 */
export async function verifyEd25519(publicKey: Uint8Array, msg: Uint8Array, signature: Uint8Array): Promise<boolean> {
  if (!isSigningPublicKey(publicKey) || !(signature instanceof Uint8Array) || signature.length !== SIGNATURE_LEN) return false;
  // R must be of prime order too: then the cofactored check of noble and the strict cofactorless check
  // of ed25519-dalek accept exactly the same signatures (docs/SIGNING.md).
  const r = point(signature.subarray(0, 32));
  if (!r || r.isSmallOrder() || !r.isTorsionFree()) return false;
  try {
    return await verifyAsync(signature, msg, publicKey, { zip215: false });
  } catch {
    return false;
  }
}

/**
 * Who signs: the public key and a function that signs prepared message bytes. In Dôverník the signing
 * key never leaves Rust – `sign` calls `regino_keys::sign::sign_prepared`, which checks the message
 * before it signs. `seedSigner` makes one from a seed (tests, apps without Rust).
 */
export interface Signer {
  publicKey: Uint8Array;
  sign(message: Uint8Array): Promise<Uint8Array>;
}

/** A `Signer` from a 32-byte seed. */
export async function seedSigner(key: Uint8Array): Promise<Signer> {
  const publicKey = await signingPublicKey(key);
  return { publicKey, sign: (m) => signAsync(m, key) };
}

const asSigner = async (s: Signer | Uint8Array): Promise<Signer> => (s instanceof Uint8Array ? seedSigner(s) : s);

/** The bytes `signData` signs (for a `Signer` outside TypeScript). */
export const dataMessage = (context: string, data: Uint8Array) =>
  message("data", [text(context, MAX_CONTEXT, "signing"), bytes(data, 0, Infinity, "data")]);

/** Signs data bound to a context (e.g. `dovernik|center|12|share-key`). */
export async function signData(key: Uint8Array, context: string, data: Uint8Array): Promise<Uint8Array> {
  return signAsync(dataMessage(context, data), seed(key));
}

/** Checks a signature made by `signData`; false for anything else (wrong key, context, data, malformed). */
export async function verifyData(publicKey: Uint8Array, context: string, data: Uint8Array, signature: Uint8Array): Promise<boolean> {
  return verifyEd25519(publicKey, dataMessage(context, data), signature);
}

/** What the sender of a wrapped key vouches for (the same fields as `regino_keys::sign::WrapStatement`). */
export interface WrapStatement {
  /** the context the key was wrapped under */
  context: string;
  /** what the key opens, e.g. the id of a shared case */
  objectId: string;
  /** key version or epoch */
  version: number;
  /** hash of the member list the sender accepted as the latest (`AcceptedManifest.hash`, 32 bytes) */
  manifest: Uint8Array;
  /** the recipient's public key the key was wrapped for */
  recipient: Uint8Array;
  /** the wrapped key exactly as stored (`wrappedKeyBytes` for a `WrappedGroupKey`) */
  wrapped: Uint8Array;
}

/** The bytes of a `WrappedGroupKey` that a signature covers: UTF-8 of `<v>.<e>.<n>.<c>`. */
export function wrappedKeyBytes(w: WrappedGroupKey): Uint8Array {
  if (!w || !Number.isInteger(w.v) || ![w.e, w.n, w.c].every((x) => typeof x === "string" && /^[A-Za-z0-9+/=]+$/.test(x)))
    throw new Error("Invalid wrapped key.");
  return enc.encode(`${w.v}.${w.e}.${w.n}.${w.c}`);
}

/** The bytes a sender signs for a wrapped key (`signer` = its public key) – for a `Signer` outside TypeScript. */
export const wrapMessage = (st: WrapStatement, signer: Uint8Array) =>
  message("wrap", [
    text(st.context, MAX_CONTEXT, "signing"),
    text(st.objectId, MAX_CONTEXT, "object id"),
    u64(st.version),
    bytes(st.manifest, 32, 32, "list hash"),
    bytes(st.recipient, 1, MAX_KEY, "recipient key"),
    signer,
    bytes(st.wrapped, 1, MAX_WRAPPED, "wrapped key"),
  ]);

/** The sender signs a key it wrapped for a recipient; its own public key is part of what is signed. */
export async function signWrap(key: Uint8Array, st: WrapStatement): Promise<Uint8Array> {
  return signAsync(wrapMessage(st, await signingPublicKey(key)), key);
}

/**
 * Checks the sender's signature only – not whether the sender may give this key. Apps open keys with
 * `openSignedWrap`, which also requires an admin of the accepted list.
 */
export async function verifyWrap(signer: Uint8Array, st: WrapStatement, signature: Uint8Array): Promise<boolean> {
  if (!isSigningPublicKey(signer)) return false;
  return verifyEd25519(signer, wrapMessage(st, signer), signature);
}

/** A group key wrapped for a device and signed by the sender. */
export interface SignedWrappedKey {
  v: number;
  /** object id */
  id: string;
  /** key epoch (= `epoch` of the list in `m`) */
  ver: number;
  /** base64 hash of the member list the sender accepted as the latest */
  m: string;
  w: WrappedGroupKey;
  /** base64 public key of the sender */
  k: string;
  /** base64 signature */
  s: string;
}

/**
 * `wrapForDevice` + the sender's signature over object id, the epoch and the hash of `list` – the member
 * list the sender accepted as the latest (for an invitation: the new version that lists the invitee).
 * `epoch` defaults to the list's; an earlier one gives a new member the key of an earlier epoch.
 * `signer` is a `Signer` (key kept in Rust) or a seed.
 */
export async function signedWrapForDevice(
  groupKey: Uint8Array,
  recipientPublic: Uint8Array,
  context: string,
  objectId: string,
  list: AcceptedManifest,
  signer: Signer | Uint8Array,
  epoch: number = list.manifest.epoch,
): Promise<SignedWrappedKey> {
  const who = await asSigner(signer);
  if (epoch > list.manifest.epoch) throw new Error("The epoch is above the epoch of the member list.");
  const w = await wrapForDevice(groupKey, recipientPublic, context);
  const st = { context, objectId, version: epoch, manifest: list.hash, recipient: recipientPublic, wrapped: wrappedKeyBytes(w) };
  const s = await who.sign(wrapMessage(st, who.publicKey));
  return { v: SIGNED_WRAP_VERSION, id: objectId, ver: epoch, m: b64(list.hash), w, k: b64(who.publicKey), s: b64(s) };
}

/**
 * Checks, then unwraps: the key must be for `objectId`, for the list the recipient accepted itself as
 * the latest (`list` – its hash), for an epoch not above the list's (earlier epochs are allowed: a new
 * member gets older keys too), signed by an **admin** of that list, by the **signer of that list** (a
 * coordinator handing over in this version) or by one of `anchors` (e.g. the centre's management), with
 * a valid signature. Returns the key, the signer and the epoch; throws otherwise.
 */
export async function openSignedWrap(
  signed: SignedWrappedKey,
  devicePrivate: CryptoKey,
  devicePublic: Uint8Array,
  context: string,
  objectId: string,
  list: AcceptedManifest,
  anchors: readonly Uint8Array[] = [],
  opts: { recipientId?: string } = {},
): Promise<{ groupKey: Uint8Array; signer: Uint8Array; epoch: number }> {
  if (!signed || signed.v !== SIGNED_WRAP_VERSION) throw new Error("Unsupported signed wrapped key version.");
  // since 0.13.1: the key must be for the member `recipientId` of the list, wrapped for the seal the list names
  if (opts.recipientId !== undefined && !list.manifest.members.some((m) => m.id === opts.recipientId && m.seal.length > 0 && equalBytes(m.seal, devicePublic)))
    throw new Error("The recipient is not a member of the list with this key.");
  let signer: Uint8Array;
  let sig: Uint8Array;
  let manifest: Uint8Array;
  try {
    signer = unb64(signed.k);
    sig = unb64(signed.s);
    manifest = unb64(signed.m);
  } catch {
    throw new Error("Invalid signed wrapped key.");
  }
  if (signed.id !== objectId || !(signed.ver <= list.manifest.epoch) || !equalBytes(manifest, list.hash))
    throw new Error("The signed key is for another object, epoch or member list.");
  if (!anchors.some((k) => equalBytes(k, signer)) && !equalBytes(signer, list.signer) && !memberByKey(list.manifest, signer)?.admin)
    throw new Error("The sender of the key is not trusted.");
  const st = { context, objectId, version: signed.ver, manifest, recipient: devicePublic, wrapped: wrappedKeyBytes(signed.w) };
  if (!(await verifyWrap(signer, st, sig))) throw new Error("Invalid signature of the wrapped key.");
  return { groupKey: await unwrapForDevice(signed.w, devicePrivate, devicePublic, context), signer, epoch: signed.ver };
}

/** A member of a signed list. */
export interface Member {
  /** the app's id (account id); unique in the list */
  id: string;
  /** the app's role name (e.g. `coordinator`, `member`, `external`); not interpreted here */
  role: string;
  /** may sign the next version of the list */
  admin: boolean;
  /** signing public key (32 bytes) */
  sign: Uint8Array;
  /** another public key the list vouches for, e.g. the P-256 key for `wrapForDevice`; may be empty */
  seal: Uint8Array;
  /** version of the member's statement about `seal` (`MemberKey.version`); 0 exactly when `seal` is empty */
  sealVersion: number;
}

export interface Manifest {
  /** what the list is for, e.g. `dovernik|center|12|case|<id>` */
  scope: string;
  /** 1 for the first list, then exactly +1 for every change */
  version: number;
  /** key epoch: never goes down; raise it whenever someone is removed (new items only under the new key); ≤ 2^53 − 1 */
  epoch: number;
  /** hash of the previous version (32 bytes); zeros for version 1 */
  prev: Uint8Array;
  members: Member[];
}

/** A list that passed `verifyManifest`; store `blob` to continue the chain later (`openManifest`). */
export interface AcceptedManifest {
  manifest: Manifest;
  signer: Uint8Array;
  /** SHA-256 of the blob – goes into `prev` of the next version */
  hash: Uint8Array;
  blob: Uint8Array;
}

/** The next version after `prev` with new members (scope, epoch and the chain link are taken over). */
export function nextManifest(prev: AcceptedManifest, members: Member[]): Manifest {
  const m = prev.manifest;
  return { scope: m.scope, version: m.version + 1, epoch: m.epoch, prev: prev.hash, members };
}

/** The member with this signing key, if any. */
export function memberByKey(manifest: Manifest, key: Uint8Array): Member | undefined {
  return manifest.members.find((m) => equalBytes(m.sign, key));
}

function compareBytes(a: Uint8Array, b: Uint8Array): number {
  for (let i = 0; i < Math.min(a.length, b.length); i++) if (a[i] !== b[i]) return (a[i] as number) - (b[i] as number);
  return a.length - b.length;
}

const ZERO32 = new Uint8Array(32);

/** The bytes that sign a list (`signer` = the signer's public key) – for a `Signer` outside TypeScript. */
export function manifestMessage(m: Manifest, signer: Uint8Array): Uint8Array {
  if (!m || !Array.isArray(m.members) || m.members.length > MAX_MEMBERS) throw new Error("Invalid manifest.");
  const prev = bytes(m.prev, 32, 32, "previous hash");
  if (m.version === 0 || (m.version === 1) !== equalBytes(prev, ZERO32)) throw new Error("Invalid manifest version or previous hash.");
  const members = m.members.map((x) => ({ x, id: text(x.id, MAX_NAME, "member id") }));
  members.sort((a, b) => compareBytes(a.id, b.id));
  if (members.some((e, i) => i > 0 && equalBytes(e.id, members[i - 1]!.id))) throw new Error("Duplicate member id.");
  members.forEach((e) => checkPublic(e.x.sign, "member signing"));
  const keys = new Set(members.map((e) => b64(e.x.sign)));
  if (keys.size !== members.length) throw new Error("Duplicate member signing key.");
  const fields = [text(m.scope, MAX_CONTEXT, "scope"), u64(m.version), u64(m.epoch), prev, signer, u32(members.length)];
  for (const { x, id } of members) {
    const seal = bytes(x.seal, 0, MAX_KEY, "member key");
    const sv = u64(x.sealVersion);
    if ((seal.length === 0) !== (x.sealVersion === 0)) throw new Error("The seal version must be 0 exactly for an empty seal.");
    fields.push(id, text(x.role, MAX_NAME, "role"), Uint8Array.of(x.admin ? 1 : 0), x.sign, sv, seal);
  }
  return message("manifest", fields);
}

/** Signs a list; the blob is `message || signature` and is carried as is (the server stores it opaque). */
export async function signManifest(signer: Signer | Uint8Array, manifest: Manifest): Promise<Uint8Array> {
  const who = await asSigner(signer);
  const msg = manifestMessage(manifest, who.publicKey);
  return concat([msg, await who.sign(msg)]);
}

/** A member vouches for its own sealing key (scope, its id, a version that only goes up, the key). */
export interface MemberKey {
  scope: string;
  memberId: string;
  version: number;
  seal: Uint8Array;
}

/** The bytes a member signs for its sealing key – for a `Signer` outside TypeScript. */
export const memberKeyMessage = (mk: MemberKey) =>
  message("member-key", [text(mk.scope, MAX_CONTEXT, "scope"), text(mk.memberId, MAX_NAME, "member id"), u64(mk.version), bytes(mk.seal, 1, MAX_KEY, "member key")]);

/** The member signs its own sealing key (with its signing key, a `Signer` or a seed). */
export async function signMemberKey(signer: Signer | Uint8Array, mk: MemberKey): Promise<Uint8Array> {
  return (await asSigner(signer)).sign(memberKeyMessage(mk));
}

/**
 * Checks a member's statement about its sealing key before an admin puts it into a list: for `scope` and
 * the member `memberId` the admin means; if `list` (the latest list the admin accepted for this scope) has
 * a member with that id, the version must be above its `sealVersion` (replay of an older statement) and
 * `signer` must be that member's signing key – the last version comes from the signed list, not from
 * local memory, so a new coordinator or a restored app refuses an older statement too; then the
 * signature. Throws.
 */
export async function verifyMemberKey(
  signer: Uint8Array,
  mk: MemberKey,
  signature: Uint8Array,
  scope: string,
  memberId: string,
  list?: Manifest,
): Promise<void> {
  const msg = memberKeyMessage(mk);
  if (mk.scope !== scope || (list && list.scope !== scope)) throw new Error("The member key is for another object.");
  if (mk.memberId !== memberId) throw new Error("The member key is for another member.");
  const known = list?.members.find((x) => x.id === memberId);
  if (known) {
    if (!(mk.version > known.sealVersion)) throw new Error("The member key is not newer than the one in the list.");
    if (!equalBytes(known.sign, signer)) throw new Error("The member key is not signed by that member.");
  }
  if (!(await verifyEd25519(signer, msg, signature))) throw new Error("Invalid signature of the member key.");
}

class Reader {
  constructor(private b: Uint8Array) {}
  field(): Uint8Array {
    if (this.b.length < 4) throw new Error();
    const n = new DataView(this.b.buffer, this.b.byteOffset, 4).getUint32(0);
    if (this.b.length < 4 + n) throw new Error();
    const f = this.b.subarray(4, 4 + n);
    this.b = this.b.subarray(4 + n);
    return f;
  }
  fixed(n: number): Uint8Array {
    const f = this.field();
    if (f.length !== n) throw new Error();
    return f;
  }
  text(): string {
    return new TextDecoder("utf-8", { fatal: true, ignoreBOM: true }).decode(this.field());
  }
  number(): number {
    const v = new DataView(this.fixed(8).slice().buffer).getBigUint64(0);
    if (v > BigInt(MAX_VERSION)) throw new Error();
    return Number(v);
  }
  get done(): boolean {
    return this.b.length === 0;
  }
}

/**
 * Reads a blob and checks its signature against the key named inside – **not** whether that key is
 * trusted. Only for a blob the app accepted before with `verifyManifest` and stored itself.
 */
export async function openManifest(blob: Uint8Array): Promise<AcceptedManifest> {
  let manifest: Manifest;
  let signer: Uint8Array;
  const msg = blob instanceof Uint8Array && blob.length >= MAGIC.length + SIGNATURE_LEN ? blob.subarray(0, blob.length - SIGNATURE_LEN) : null;
  try {
    if (!msg || !equalBytes(msg.subarray(0, MAGIC.length), MAGIC)) throw new Error();
    const r = new Reader(msg.subarray(MAGIC.length));
    if (r.text() !== "manifest") throw new Error();
    const scope = r.text();
    const version = r.number();
    const epoch = r.number();
    const prev = r.fixed(32).slice();
    signer = r.fixed(32).slice();
    const count = new DataView(r.fixed(4).slice().buffer).getUint32(0);
    if (count > MAX_MEMBERS) throw new Error();
    const members: Member[] = [];
    for (let i = 0; i < count; i++) {
      const id = r.text();
      const role = r.text();
      const a = r.fixed(1)[0];
      if (a !== 0 && a !== 1) throw new Error();
      const sign = r.fixed(32).slice();
      const sealVersion = r.number();
      members.push({ id, role, admin: a === 1, sign, seal: r.field().slice(), sealVersion });
    }
    if (!r.done) throw new Error();
    manifest = { scope, version, epoch, prev, members };
    checkPublic(signer);
    // canonical: encoding the decoded list again must give the same bytes (sorted ids, limits)
    if (!equalBytes(manifestMessage(manifest, signer), msg)) throw new Error();
  } catch {
    throw new Error("Not a valid member list.");
  }
  if (!(await verifyEd25519(signer, msg, blob.subarray(msg.length)))) throw new Error("Invalid signature of the member list.");
  const hash = new Uint8Array(await crypto.subtle.digest("SHA-256", blob as BufferSource));
  return { manifest, signer, hash, blob: blob.slice() };
}

/**
 * Accepts a list only if it is for `scope` (the object the app asked for) and continues what the app
 * already trusts:
 * - no `prev` (the first list the app sees for this scope): version 1, signed by one of `anchors`;
 * - `prev`: the same scope, version `prev + 1`, `prev` = hash of the previous list, epoch not lower,
 *   signed by an admin of the previous list or by one of `anchors`.
 * `anchors` are keys the app trusts for the scope by itself (pinned after comparing fingerprints).
 *
 * Two admins (or a removed admin together with a server that withholds the newer list) can sign two
 * different lists with the same version; each member accepts the first it sees. The core cannot detect
 * such a fork alone: signed wrapped keys name the list they belong to, and the app compares
 * `manifestFingerprint` of the latest list with the coordinator (docs/SIGNING.md).
 */
export async function verifyManifest(
  blob: Uint8Array,
  scope: string,
  anchors: readonly Uint8Array[],
  prev?: AcceptedManifest,
): Promise<AcceptedManifest> {
  const a = await openManifest(blob);
  const m = a.manifest;
  if (m.scope !== scope || (prev && prev.manifest.scope !== scope)) throw new Error("The member list is for another object.");
  const anchor = anchors.some((k) => equalBytes(k, a.signer));
  if (!prev) {
    if (m.version !== 1) throw new Error("The member list does not continue the one already trusted.");
    if (!anchor) throw new Error("The signer of the member list is not trusted.");
  } else {
    continues(m, prev);
    if (!anchor && !memberByKey(prev.manifest, a.signer)?.admin) throw new Error("The signer of the member list is not trusted.");
  }
  return a;
}

/** The structural rules of a next version (no trust): +1, link, epoch, seal versions. Throws. */
function continues(m: Manifest, prev: AcceptedManifest): void {
  const p = prev.manifest;
  if (m.scope !== p.scope) throw new Error("The member list is for another object.");
  if (m.version !== p.version + 1 || !equalBytes(m.prev, prev.hash) || m.epoch < p.epoch)
    throw new Error("The member list does not continue the one already trusted.");
  // someone removed, or a sealing key changed: the old key must not be used any more – new epoch
  const changed = p.members.some((old) => {
    const now = memberByKey(m, old.sign);
    return !now || !equalBytes(now.seal, old.seal);
  });
  if (changed && m.epoch <= p.epoch) throw new Error("The member list does not continue the one already trusted (removal without a new epoch).");
  // a new seal needs a higher sealVersion (no older statement brought back); an unchanged one keeps it
  const badSealVersion = p.members.some((old) => {
    const now = memberByKey(m, old.sign);
    return now !== undefined && (equalBytes(now.seal, old.seal) ? now.sealVersion !== old.sealVersion : now.sealVersion <= old.sealVersion);
  });
  if (badSealVersion) throw new Error("The member list does not continue the one already trusted (seal version).");
}

/** Follows `blobs` in order from `trusted` (or from version 1) and returns the last list. */
export async function verifyManifestChain(
  blobs: readonly Uint8Array[],
  scope: string,
  anchors: readonly Uint8Array[],
  trusted?: AcceptedManifest,
): Promise<AcceptedManifest> {
  if (trusted && trusted.manifest.scope !== scope) throw new Error("The member list is for another object.");
  let cur = trusted;
  for (const b of blobs) cur = await verifyManifest(b, scope, anchors, cur);
  if (!cur) throw new Error("The member list does not continue the one already trusted.");
  return cur;
}

/** What the app already pinned for a scope: the highest accepted version and the hashes of its last
 * versions (`hashes[i]` = hash of version `version - hashes.length + 1 + i`; one hash is enough). */
export interface PinnedManifest {
  version: number;
  hashes: readonly Uint8Array[];
}

/** Options of `verifyManifestChainFromAnchor` (0.13.2 adds `signers`, `anchorsMaySign`, `pinnedTrusted`). */
export interface ChainOptions {
  pinned?: PinnedManifest;
  /** keys that may sign any next version even when they are no admin of the previous one; not for v1 nor for the anchor requirement */
  signers?: readonly Uint8Array[];
  /** default true: anchors may sign any next version; false: an anchor counts only for the anchor requirement */
  anchorsMaySign?: boolean;
  /** the pinned versions were accepted before: matching pins meet the anchor requirement, versions up to the pin are checked only for structure */
  pinnedTrusted?: boolean;
}

const has = (keys: readonly Uint8Array[], k: Uint8Array) => keys.some((x) => equalBytes(x, k));

async function chainStructure(blobs: readonly Uint8Array[], scope: string, check?: (next: AcceptedManifest, prev: AcceptedManifest) => void): Promise<AcceptedManifest[]> {
  if (blobs.length === 0) throw new Error("The member list does not continue the one already trusted.");
  const first = await openManifest(blobs[0]!);
  if (first.manifest.scope !== scope) throw new Error("The member list is for another object.");
  if (first.manifest.version !== 1) throw new Error("The member list does not continue the one already trusted.");
  const out = [first];
  for (const b of blobs.slice(1)) {
    const next = await openManifest(b);
    const prev = out[out.length - 1]!;
    continues(next.manifest, prev);
    check?.(next, prev);
    out.push(next);
  }
  return out;
}

function checkPins(out: readonly AcceptedManifest[], p?: PinnedManifest): void {
  if (!p) return;
  const n = p.hashes.length;
  if (!Number.isSafeInteger(p.version) || n === 0 || n > p.version) throw new Error("Invalid pinned versions.");
  p.hashes.forEach((h, i) => {
    const a = out[p.version - n + i];
    if (a && !equalBytes(a.hash, h)) throw new Error("The member list does not continue the one already trusted (fork of a pinned version).");
  });
  if (out.length < p.version) throw new Error("Versions of the member list that were already accepted are missing (withheld).");
}

/**
 * Verifies a whole chain from version 1 for someone who joins or restores and has no trusted list yet
 * (identical to Rust `verify_manifest_chain_from_anchor[_with]`): version 1 is taken with its own signer;
 * every later version must continue the previous one and be signed by an admin of the previous version,
 * by one of `signers` or – unless `anchorsMaySign` is false – by an anchor; at least one version must be
 * **signed by an anchor** (that signature confirms all versions before it), otherwise nothing is accepted
 * (fail-closed). With `pinned`, a different hash for a pinned version is a fork and a chain that ends
 * before the pinned version means newer lists are withheld – both throw. With `pinnedTrusted` (the pins
 * were accepted before), matching pins meet the anchor requirement and versions up to the pin are checked
 * only for structure, signatures and links. Returns every accepted version, oldest first.
 */
export async function verifyManifestChainFromAnchor(
  blobs: readonly Uint8Array[],
  scope: string,
  anchors: readonly Uint8Array[],
  opts: ChainOptions = {},
): Promise<AcceptedManifest[]> {
  const signers = opts.signers ?? [];
  const anchorsMaySign = opts.anchorsMaySign ?? true;
  const trustedUpto = opts.pinned && opts.pinnedTrusted ? opts.pinned.version : 1;
  const out = await chainStructure(blobs, scope, (next, prev) => {
    if (next.manifest.version <= trustedUpto) return;
    const s = next.signer;
    if (!memberByKey(prev.manifest, s)?.admin && !has(signers, s) && !(anchorsMaySign && has(anchors, s)))
      throw new Error("The signer of the member list is not trusted.");
  });
  checkPins(out, opts.pinned);
  const pinMeets = opts.pinned !== undefined && opts.pinnedTrusted === true;
  if (!pinMeets && !out.some((a) => has(anchors, a.signer))) throw new Error("The signer of the member list is not trusted (no version signed by an anchor).");
  return out;
}

/** One version read by `inspectManifestChain` – **not trusted**: nobody vouched for the signers yet. */
export interface InspectedManifest {
  version: number;
  epoch: number;
  signer: Uint8Array;
  members: Member[];
  hash: Uint8Array;
}

/**
 * Structure only (since 0.13.2), for management after a restore: scope, version + 1, links, epochs and
 * seal versions, canonical blobs, signatures valid for the signer named in each blob, pins (fork,
 * withheld). **No trust in the signers** – show the table to management and let them decide; after
 * approval pin the hash of the last version and continue with `pinnedTrusted`. Never open keys with it.
 */
export async function inspectManifestChain(blobs: readonly Uint8Array[], scope: string, opts: { pinned?: PinnedManifest } = {}): Promise<InspectedManifest[]> {
  const out = await chainStructure(blobs, scope);
  checkPins(out, opts.pinned);
  return out.map((a) => ({ version: a.manifest.version, epoch: a.manifest.epoch, signer: a.signer, members: a.manifest.members, hash: a.hash }));
}
