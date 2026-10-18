import { verifyAsync } from '@noble/ed25519';

/**
 * Signed tokens `<PREFIX>1.<payload base64url>.<Ed25519 signature base64url>`, signature over the
 * payload JSON bytes. Used for licence entitlements and key certificates. Verification only: signing
 * keys never live in apps.
 *
 * Trust chain: apps ship one or more root public keys; every other signing key is accepted only with
 * a valid certificate (`RG1.…`, `typ: "cert"`) signed by a root. A key list fetched from a server is
 * therefore safe to use: it cannot add keys without a root signature.
 */

export type Payload = Record<string, unknown>;

/** A root public key (base64url, 32 bytes). */
export interface RootKey {
  kid: string;
  pub: string;
}

/** The key a certificate vouches for. */
export interface CertifiedKey {
  kid: string;
  product: string | null;
  use: string;
  pub: string;
}

/** Entry of a published key list (e.g. `/.well-known/license-keys.json`). */
export interface KeyListEntry {
  kid: string;
  status?: string;
  cert: string;
}

const CERT_PREFIX = 'RG';
const B64URL = /^[A-Za-z0-9_-]*$/;

/** base64url without padding → bytes, or null when malformed. */
export function fromBase64url(s: string): Uint8Array | null {
  if (!B64URL.test(s) || s.length % 4 === 1) return null;
  const b64 = s.replace(/-/g, '+').replace(/_/g, '/');
  const bin = atob(b64 + '='.repeat((4 - (b64.length % 4)) % 4));
  return Uint8Array.from(bin, (c) => c.charCodeAt(0));
}

function split(token: string): { prefix: string; json: Uint8Array; sig: Uint8Array } | null {
  const parts = token.trim().split('.');
  if (parts.length !== 3) return null;
  const m = /^([A-Z]{2,4})1$/.exec(parts[0] as string);
  const json = fromBase64url(parts[1] as string);
  const sig = fromBase64url(parts[2] as string);
  if (!m || !json || !sig || sig.length !== 64) return null;
  return { prefix: m[1] as string, json, sig };
}

function parse(json: Uint8Array): Payload | null {
  try {
    const v: unknown = JSON.parse(new TextDecoder('utf-8', { fatal: true }).decode(json));
    return v !== null && typeof v === 'object' && !Array.isArray(v) ? (v as Payload) : null;
  } catch {
    return null;
  }
}

/** Prefix and payload WITHOUT checking the signature – only to find `kid` and `typ`. */
export function peekToken(token: string): { prefix: string; payload: Payload } | null {
  const t = split(token);
  const payload = t && parse(t.json);
  return t && payload ? { prefix: t.prefix, payload } : null;
}

/** Ed25519 signature check with strict RFC 8032 rules; false for any malformed input. */
export async function verifySignature(
  signature: Uint8Array,
  message: Uint8Array,
  publicKey: Uint8Array,
): Promise<boolean> {
  try {
    return await verifyAsync(signature, message, publicKey, { zip215: false });
  } catch {
    return false;
  }
}

/** Verifies the signature with a public key (base64url, 32 bytes); strict RFC 8032 checks. */
export async function verifyToken(
  token: string,
  publicKey: string,
): Promise<{ prefix: string; payload: Payload } | null> {
  const t = split(token);
  const pub = fromBase64url(publicKey);
  if (!t || !pub || pub.length !== 32) return null;
  const payload = (await verifySignature(t.sig, t.json, pub)) ? parse(t.json) : null;
  return payload ? { prefix: t.prefix, payload } : null;
}

const str = (v: unknown): v is string => typeof v === 'string' && v.length > 0;
const time = (v: unknown): v is number => typeof v === 'number' && Number.isInteger(v);

/**
 * Verifies a key certificate against the built-in roots at time `at` (seconds since 1970, UTC) and
 * returns the certified key, or null.
 */
export async function verifyCertificate(
  cert: string,
  roots: readonly RootKey[],
  at: number,
): Promise<CertifiedKey | null> {
  const root = roots.find((r) => r.kid === peekToken(cert)?.payload.kid);
  const v = root ? await verifyToken(cert, root.pub) : null;
  if (!v || v.prefix !== CERT_PREFIX) return null;
  const p = v.payload;
  const s = p.subject as Payload | null | undefined;
  if (p.typ !== 'cert' || !time(p.nbf) || p.nbf > at) return null;
  if (p.exp !== null && p.exp !== undefined && (!time(p.exp) || p.exp < at)) return null;
  if (!s || typeof s !== 'object' || !str(s.kid) || !str(s.use) || !str(s.pub)) return null;
  if (s.product !== null && s.product !== undefined && !str(s.product)) return null;
  return { kid: s.kid, product: (s.product as string | undefined) ?? null, use: s.use, pub: s.pub };
}

/**
 * Keys from a key list that carry a valid certificate from one of the built-in roots. Entries marked
 * `revoked` (or listed in `revoked`) are dropped; roots inside the list itself are never trusted.
 */
export async function certifiedKeys(
  entries: readonly KeyListEntry[],
  roots: readonly RootKey[],
  at: number,
  revoked: readonly string[] = [],
): Promise<CertifiedKey[]> {
  const out: CertifiedKey[] = [];
  for (const e of entries) {
    if (e.status === 'revoked' || revoked.includes(e.kid)) continue;
    const key = await verifyCertificate(e.cert, roots, at);
    if (key && key.kid === e.kid && !revoked.includes(key.kid)) out.push(key);
  }
  return out;
}

/**
 * Verifies a token signed by a certified key for `product` and `use`: the `kid` in the payload must
 * name such a key, and `product` in the payload must match. Returns the payload or null.
 *
 * The prefix is not covered by the signature (it only names the token kind), so the payload decides:
 * a certificate payload (`typ: "cert"`) is never accepted here, even if a key were ever used both as
 * a root and as a product key (question 10).
 */
export async function verifyWithKeys(
  token: string,
  keys: readonly CertifiedKey[],
  expect: { prefix: string; product: string; use: string },
): Promise<Payload | null> {
  const kid = peekToken(token)?.payload.kid;
  const key = keys.find((k) => k.kid === kid && k.product === expect.product && k.use === expect.use);
  const v = key ? await verifyToken(token, key.pub) : null;
  if (!v || v.prefix !== expect.prefix || v.payload.product !== expect.product || v.payload.typ === 'cert') return null;
  return v.payload;
}
