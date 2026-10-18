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

describe("equalBytes", () => {
  it("compares content and length", async () => {
    const { equalBytes } = await import("./bytes");
    expect(equalBytes(new Uint8Array([1, 2]), new Uint8Array([1, 2]))).toBe(true);
    expect(equalBytes(new Uint8Array([1, 2]), new Uint8Array([1, 3]))).toBe(false);
    expect(equalBytes(new Uint8Array([1, 2]), new Uint8Array([1, 2, 3]))).toBe(false);
    expect(equalBytes(new Uint8Array(0), new Uint8Array(0))).toBe(true);
  });
});

describe("gcmNonce and checkContext", () => {
  it("only 12-byte nonces and non-empty contexts", async () => {
    const { gcmNonce, checkContext } = await import("./ecdh");
    expect(gcmNonce(b64(new Uint8Array(12)))).toHaveLength(12);
    for (const n of [0, 8, 13, 16]) expect(() => gcmNonce(b64(new Uint8Array(n)))).toThrow("12 bytes");
    expect(() => checkContext("", "sync")).toThrow("sync context");
    expect(() => checkContext(5 as unknown as string, "sync")).toThrow("must not be empty");
    expect(() => checkContext("g|x", "sync")).not.toThrow();
  });

  it("sealed data with a nonce of another length is refused everywhere", async () => {
    const { newGroupKey, recordKey, sealRecord, openRecord, newDeviceKeys, publicKeyBytes, wrapForDevice } = await import("./sync");
    const { newInboxKeys, sealToInbox } = await import("./inbox");
    const n16 = b64(new Uint8Array(16));
    const key = await recordKey(newGroupKey());
    const rec = await sealRecord(key, "g|t|1", { a: 1 });
    await expect(openRecord(key, "g|t|1", { ...rec, n: n16 })).rejects.toThrow("cannot be opened");
    await expect(sealRecord(key, "", 1)).rejects.toThrow("context");
    await expect(openRecord(key, "", rec)).rejects.toThrow("context");
    const dev = await newDeviceKeys();
    const pub = await publicKeyBytes(dev.publicKey);
    const w = await wrapForDevice(newGroupKey(), pub, "g|device|d");
    await expect(unwrapForDevice({ ...w, n: n16 }, dev.privateKey, pub, "g|device|d")).rejects.toThrow("cannot be unwrapped");
    await expect(wrapForDevice(newGroupKey(), pub, "")).rejects.toThrow("context");
    await expect(unwrapForDevice(w, dev.privateKey, pub, "")).rejects.toThrow("context");
    const inbox = await newInboxKeys();
    const msg = await sealToInbox(inbox.publicKey, "c", new Uint8Array([1]));
    const k = await importInboxKey(inbox.privateKey);
    await expect(openFromInbox(k, "c", { ...msg, n: n16 })).rejects.toThrow();
  });
});
