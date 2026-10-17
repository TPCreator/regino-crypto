import { describe, expect, it } from "vitest";
import { b64, checkP256Point, unb64 } from "./ecdh";
import { importInboxKey, openFromInbox } from "./inbox";
import { unwrapForDevice } from "./sync";
// Sealed by 0.6.0 before inbox.ts and sync.ts shared ecdh.ts – test keys only, no real data.
import v from "../../testvectors/regino/ecdh-0.6.0.json";

describe("ecdh (shared by sync and inbox)", () => {
  it("base64 round trip, also above one 32 KB block", () => {
    const big = new Uint8Array(0x8000 * 2 + 5).map((_, i) => (i * 7) & 255);
    expect(unb64(b64(big))).toEqual(big);
    expect(b64(new Uint8Array(0))).toBe("");
    expect(b64(new Uint8Array([0, 255]))).toBe("AP8=");
  });

  it("checks P-256 public keys", () => {
    expect(() => checkP256Point(new Uint8Array(64), "test")).toThrow("Invalid test public key");
    expect(() => checkP256Point(new Uint8Array(65), "test")).toThrow(/uncompressed P-256/);
  });

  it("opens an inbox message sealed by 0.6.0", async () => {
    const key = await importInboxKey(unb64(v.inbox.privateKey));
    const out = await openFromInbox(key, v.inbox.context, v.inbox.message);
    expect(new TextDecoder().decode(out)).toBe(v.inbox.plaintext);
  });

  it("unwraps a group key wrapped by 0.6.0", async () => {
    const priv = await crypto.subtle.importKey("pkcs8", unb64(v.sync.devicePrivate) as BufferSource, { name: "ECDH", namedCurve: "P-256" }, false, ["deriveBits"]);
    const group = await unwrapForDevice(v.sync.wrapped, priv, unb64(v.sync.devicePublic), v.sync.context);
    expect(b64(group)).toBe(v.sync.groupKey);
  });
});
