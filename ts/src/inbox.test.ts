import { describe, expect, it } from "vitest";
import {
  importInboxKey,
  INBOX_VERSION,
  inboxFingerprint,
  newInboxKeys,
  openFromInbox,
  sealToInbox,
} from "./inbox";
import { fromBase64 } from "./sync";

const enc = new TextEncoder();
const dec = new TextDecoder();
const CTX = "dovernik|practice-1|form|req-7";

// Test vector made with version 1 (not a real key) – messages sealed today must open in future versions.
const FIXED = {
  priv: "MIGHAgEAMBMGByqGSM49AgEGCCqGSM49AwEHBG0wawIBAQQg+Ia2V57uCrSCUvmk2L2GjCsFWWRr8r+imtNthbGhBDuhRANCAAT7oq4DN4cddzkaxGmCNZyaKEuI4gCP964GttvHtyfZAypZraB2dzmebTnK7zvcopBcsB3Fcr90GxHm++8ps6r2",
  pub: "BPuirgM3hx13ORrEaYI1nJooS4jiAI/3rga228e3J9kDKlmtoHZ3OZ5tOcrvO9yikFywHcVyv3QbEeb77ymzqvY=",
  m: {
    v: 1,
    e: "BA1JDmyBcQ8g+TD1pCF5xXkeDAftWRqh08dsM8i67laRFKl2u/fK95XLZKSQlWpPQ1cB/lJF2Ql6rNG2KlbbxXM=",
    n: "qiZfJ1eUIuVVC4b9",
    c: "5Cy8vmP140KtHsVt+iiSnnOtySNs+1ROkc4afjFT9fY+DcXhPN0oSwW9nYs=",
  },
};

describe("inbox", () => {
  it("seal with the public key, open with the stored private key", async () => {
    const keys = await newInboxKeys();
    expect(keys.publicKey.length).toBe(65);
    const msg = await sealToInbox(keys.publicKey, CTX, enc.encode('{"lieky":"nechcem odpovedať"}'));
    expect(msg.v).toBe(INBOX_VERSION);
    expect(atob(msg.c)).not.toContain("lieky");
    const key = await importInboxKey(keys.privateKey);
    expect(key.publicKey).toEqual(keys.publicKey);
    expect(key.privateKey.extractable).toBe(false);
    expect(dec.decode(await openFromInbox(key, CTX, msg))).toBe('{"lieky":"nechcem odpovedať"}');
  });

  it("a fresh ephemeral key and nonce for every message", async () => {
    const { publicKey } = await newInboxKeys();
    const a = await sealToInbox(publicKey, CTX, enc.encode("x"));
    const b = await sealToInbox(publicKey, CTX, enc.encode("x"));
    expect(a.e).not.toBe(b.e);
    expect(a.n).not.toBe(b.n);
    expect(a.c).not.toBe(b.c);
  });

  it("large documents and empty data", async () => {
    const keys = await newInboxKeys();
    const key = await importInboxKey(keys.privateKey);
    const pdf = new Uint8Array(3 * 1024 * 1024);
    for (let i = 0; i < pdf.length; i += 65536) crypto.getRandomValues(pdf.subarray(i, i + 65536));
    const out = await openFromInbox(key, CTX, await sealToInbox(keys.publicKey, CTX, pdf));
    // Compare hashes – toEqual compares 3 MB element by element and takes tens of seconds.
    const sha = async (b: Uint8Array) => new Uint8Array(await crypto.subtle.digest("SHA-256", b as BufferSource));
    expect(out.length).toBe(pdf.length);
    expect(await sha(out)).toEqual(await sha(pdf));
    expect((await openFromInbox(key, CTX, await sealToInbox(keys.publicKey, CTX, new Uint8Array()))).length).toBe(0);
  });

  it("opens a message sealed by version 1 (fixed test vector)", async () => {
    const key = await importInboxKey(fromBase64(FIXED.priv));
    expect(key.publicKey).toEqual(fromBase64(FIXED.pub));
    expect(dec.decode(await openFromInbox(key, CTX, FIXED.m))).toBe('{"area":"stres a vyhorenie"}');
  });

  it("wrong context, wrong key, changed data or version is refused", async () => {
    const key = await importInboxKey(fromBase64(FIXED.priv));
    const other = await importInboxKey((await newInboxKeys()).privateKey);
    const err = /cannot be opened/;
    await expect(openFromInbox(key, CTX + "x", FIXED.m)).rejects.toThrow(err);
    await expect(openFromInbox(other, CTX, FIXED.m)).rejects.toThrow(err);
    const flip = (s: string) => {
      const b = fromBase64(s);
      b[b.length - 1] = (b[b.length - 1] as number) ^ 1;
      let t = "";
      for (const x of b) t += String.fromCharCode(x);
      return btoa(t);
    };
    await expect(openFromInbox(key, CTX, { ...FIXED.m, c: flip(FIXED.m.c) })).rejects.toThrow(err);
    await expect(openFromInbox(key, CTX, { ...FIXED.m, n: flip(FIXED.m.n) })).rejects.toThrow(err);
    // the nonce must have exactly 12 bytes (checked before WebCrypto is asked)
    for (const n of ["elevenbytes", "thirteenbytes", ""])
      await expect(openFromInbox(key, CTX, { ...FIXED.m, n: btoa(n) }), `${n.length} bytes`).rejects.toThrow(err);
    await expect(openFromInbox(key, CTX, { ...FIXED.m, e: flip(FIXED.m.e) })).rejects.toThrow(err);
    await expect(openFromInbox(key, CTX, { ...FIXED.m, e: btoa("short") })).rejects.toThrow(err);
    await expect(openFromInbox(key, CTX, { ...FIXED.m, v: 2 })).rejects.toThrow(/version/);
    await expect(openFromInbox(key, CTX, null as never)).rejects.toThrow(/version/);
    await expect(openFromInbox(key, "", FIXED.m)).rejects.toThrow(/context/);
  });

  it("bad inputs when sealing and importing", async () => {
    const { publicKey } = await newInboxKeys();
    await expect(sealToInbox(new Uint8Array(65), CTX, enc.encode("x"))).rejects.toThrow(/public key/);
    await expect(sealToInbox(publicKey.subarray(0, 33), CTX, enc.encode("x"))).rejects.toThrow(/public key/);
    await expect(sealToInbox("x" as never, CTX, enc.encode("x"))).rejects.toThrow(/public key/);
    await expect(sealToInbox(publicKey, "", enc.encode("x"))).rejects.toThrow(/context/);
    await expect(sealToInbox(publicKey, 1 as never, enc.encode("x"))).rejects.toThrow(/context/);
    await expect(sealToInbox(publicKey, CTX, "text" as never)).rejects.toThrow(/bytes/);
    await expect(importInboxKey(new Uint8Array(10))).rejects.toThrow(/Invalid inbox private key/);
  });

  it("fingerprint is stable and differs between keys", async () => {
    const fp = await inboxFingerprint(fromBase64(FIXED.pub));
    expect(fp).toMatch(/^[0-9a-f]{4}( [0-9a-f]{4}){4}$/);
    expect(await inboxFingerprint(fromBase64(FIXED.pub))).toBe(fp);
    expect(await inboxFingerprint((await newInboxKeys()).publicKey)).not.toBe(fp);
    await expect(inboxFingerprint(new Uint8Array(3))).rejects.toThrow(/public key/);
  });
});
