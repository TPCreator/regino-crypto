/**
 * Short codes derived from a group key (a key of a shared case, a sync group key) – for people to compare
 * and for stable ids that do not reveal the key. Identical to `regino_keys::group` in Rust; shared vectors
 * `testvectors/regino/group-key-0.13.1.json`.
 *
 * - `groupKeyCode(key, context)`: HMAC-SHA256(HKDF-SHA256(key, no salt, info `regino group-key code v1`),
 *   context), first 80 bits as hex in groups of four ("3f2a 9c01 …") – members read it to each other.
 * - `groupKeyId(key, label)`: the same with info `regino group-key id v1`, first 96 bits as 24 hex
 *   characters – a stable, key-bound id the server may see (e.g. of a fixed item slot).
 */
import { checkContext } from "./ecdh";

const enc = new TextEncoder();

async function tag(key: Uint8Array, info: string, data: string): Promise<Uint8Array> {
  if (!(key instanceof Uint8Array) || key.length !== 32) throw new Error("The group key must have 32 bytes.");
  checkContext(data, "group key");
  const base = await crypto.subtle.importKey("raw", key as BufferSource, "HKDF", false, ["deriveKey"]);
  const mac = await crypto.subtle.deriveKey(
    { name: "HKDF", hash: "SHA-256", salt: new Uint8Array(0), info: enc.encode(info) },
    base,
    { name: "HMAC", hash: "SHA-256", length: 256 },
    false,
    ["sign"],
  );
  return new Uint8Array(await crypto.subtle.sign("HMAC", mac, enc.encode(data)));
}

const hex = (b: Uint8Array) => Array.from(b, (x) => x.toString(16).padStart(2, "0")).join("");

/** Code of a group key for comparing ("3f2a 9c01 …", 80 bits), bound to `context` (e.g. the case id). */
export async function groupKeyCode(key: Uint8Array, context: string): Promise<string> {
  return hex((await tag(key, "regino group-key code v1", context)).subarray(0, 10)).match(/.{4}/g)!.join(" ");
}

/** Key-bound id (24 hex characters, 96 bits) for `label` (e.g. `case slot v1|consent`). */
export async function groupKeyId(key: Uint8Array, label: string): Promise<string> {
  return hex((await tag(key, "regino group-key id v1", label)).subarray(0, 12));
}
