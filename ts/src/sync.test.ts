import { describe, expect, it } from "vitest";
import { b64, sealingKey } from "./ecdh";
import {
  fromBase64,
  newDeviceKeys,
  newGroupKey,
  openRecord,
  checkPairingCommitment,
  newPairingNonce,
  pairingCode,
  pairingCommitment,
  pairingSas,
  publicKeyBytes,
  recordKey,
  sealRecord,
  SYNC_VERSION,
  toBase64,
  unwrapForDevice,
  wrapForDevice,
  WRAP_VERSION,
} from "./sync";
import { sixDigits } from "./bytes";
// Made by 0.8.0 – test keys only (wrapped key v2, pairing code, SAS).
import v8 from "../../testvectors/regino/sync-0.8.0.json";

describe("sync records", () => {
  it("seal and open with the same key and context", async () => {
    const key = await recordKey(newGroupKey());
    const sealed = await sealRecord(key, "g1|items|42", {
      amount: -2340,
      text: "Pekáreň",
    });
    expect(sealed.v).toBe(SYNC_VERSION);
    expect(sealed.c).not.toContain("Pek");
    expect(await openRecord(key, "g1|items|42", sealed)).toEqual({
      amount: -2340,
      text: "Pekáreň",
    });
    // A fresh nonce every time.
    expect((await sealRecord(key, "x", 1)).n).not.toBe(
      (await sealRecord(key, "x", 1)).n,
    );
  });

  it("wrong context, wrong key, changed data or version is refused", async () => {
    const group = newGroupKey();
    const key = await recordKey(group);
    const sealed = await sealRecord(key, "g1|items|42", { a: 1 });
    await expect(openRecord(key, "g1|items|43", sealed)).rejects.toThrow(
      "cannot be opened",
    );
    await expect(
      openRecord(await recordKey(newGroupKey()), "g1|items|42", sealed),
    ).rejects.toThrow("cannot be opened");
    const bytes = fromBase64(sealed.c);
    bytes[0] = (bytes[0] as number) ^ 1;
    await expect(
      openRecord(key, "g1|items|42", { ...sealed, c: toBase64(bytes) }),
    ).rejects.toThrow("cannot be opened");
    await expect(
      openRecord(key, "g1|items|42", { ...sealed, v: 2 }),
    ).rejects.toThrow("version");
    await expect(
      openRecord(key, "g1|items|42", null as unknown as typeof sealed),
    ).rejects.toThrow("version");
    // The same group key always gives the same record key.
    expect(
      await openRecord(await recordKey(group), "g1|items|42", sealed),
    ).toEqual({ a: 1 });
  });

  it("the group key must have 32 bytes", async () => {
    await expect(recordKey(new Uint8Array(16))).rejects.toThrow("32 bytes");
    await expect(recordKey("x" as unknown as Uint8Array)).rejects.toThrow(
      "32 bytes",
    );
    expect(newGroupKey()).toHaveLength(32);
  });
});

describe("device keys", () => {
  it("wrap the group key for a device and unwrap it there only", async () => {
    const group = newGroupKey();
    const phone = await newDeviceKeys();
    const phonePublic = await publicKeyBytes(phone.publicKey);
    expect(phonePublic).toHaveLength(65);
    const wrapped = await wrapForDevice(group, phonePublic, "g1|device|d2");
    expect(
      await unwrapForDevice(
        wrapped,
        phone.privateKey,
        phonePublic,
        "g1|device|d2",
      ),
    ).toEqual(group);

    const other = await newDeviceKeys();
    const otherPublic = await publicKeyBytes(other.publicKey);
    await expect(
      unwrapForDevice(wrapped, other.privateKey, otherPublic, "g1|device|d2"),
    ).rejects.toThrow("cannot be unwrapped");
    await expect(
      unwrapForDevice(wrapped, phone.privateKey, phonePublic, "g2|device|d2"),
    ).rejects.toThrow("cannot be unwrapped");
    await expect(
      unwrapForDevice({ ...wrapped, v: 9 }, phone.privateKey, phonePublic, "x"),
    ).rejects.toThrow("version");
    await expect(
      unwrapForDevice(
        null as unknown as typeof wrapped,
        phone.privateKey,
        phonePublic,
        "x",
      ),
    ).rejects.toThrow("version");
  });

  it("the private key cannot be exported", async () => {
    const k = await newDeviceKeys();
    expect(k.privateKey.extractable).toBe(false);
    await expect(
      crypto.subtle.exportKey("pkcs8", k.privateKey),
    ).rejects.toThrow();
  });

  it("invalid public keys and group keys are refused", async () => {
    const k = await newDeviceKeys();
    const pub = await publicKeyBytes(k.publicKey);
    await expect(
      wrapForDevice(newGroupKey(), new Uint8Array(33), "x"),
    ).rejects.toThrow("public key");
    const bad = pub.slice();
    bad[0] = 2;
    await expect(wrapForDevice(newGroupKey(), bad, "x")).rejects.toThrow(
      "public key",
    );
    await expect(wrapForDevice(new Uint8Array(31), pub, "x")).rejects.toThrow(
      "32 bytes",
    );
    await expect(
      unwrapForDevice(
        { v: SYNC_VERSION, e: "", n: "", c: "" },
        k.privateKey,
        new Uint8Array(65),
        "x",
      ),
    ).rejects.toThrow("public key");
    await expect(pairingCode(new Uint8Array(3))).rejects.toThrow("public key");
  });

  it("a wrapped key with an invalid ephemeral key or a plaintext that is not a key is refused", async () => {
    const phone = await newDeviceKeys();
    const phonePublic = await publicKeyBytes(phone.publicKey);
    const wrapped = await wrapForDevice(newGroupKey(), phonePublic, "g1|device|d2");
    // Ephemeral key of the wrong length or not an uncompressed point – refused before ECDH.
    await expect(
      unwrapForDevice({ ...wrapped, e: toBase64(new Uint8Array(33)) }, phone.privateKey, phonePublic, "g1|device|d2"),
    ).rejects.toThrow("cannot be unwrapped");
    const compressed = fromBase64(wrapped.e);
    compressed[0] = 2;
    await expect(
      unwrapForDevice({ ...wrapped, e: toBase64(compressed) }, phone.privateKey, phonePublic, "g1|device|d2"),
    ).rejects.toThrow("cannot be unwrapped");
    // A blob sealed correctly for this device but carrying 16 bytes instead of a 32-byte group key.
    const eph = (await crypto.subtle.generateKey({ name: "ECDH", namedCurve: "P-256" }, false, ["deriveBits"])) as CryptoKeyPair;
    const ephPublic = await publicKeyBytes(eph.publicKey);
    const key = await sealingKey(eph.privateKey, phonePublic, ephPublic, phonePublic, `sync wrap v${SYNC_VERSION}|g1|device|d2`);
    const nonce = crypto.getRandomValues(new Uint8Array(12));
    const c = await crypto.subtle.encrypt(
      { name: "AES-GCM", iv: nonce, additionalData: new TextEncoder().encode("g1|device|d2") },
      key,
      new Uint8Array(16),
    );
    await expect(
      unwrapForDevice({ v: SYNC_VERSION, e: b64(ephPublic), n: b64(nonce), c: b64(new Uint8Array(c)) }, phone.privateKey, phonePublic, "g1|device|d2"),
    ).rejects.toThrow("cannot be unwrapped");
  });

  it("wrapped keys are v2 and bind the version label; v1 still opens", async () => {
    const phone = await newDeviceKeys();
    const pub = await publicKeyBytes(phone.publicKey);
    const group = newGroupKey();
    const w = await wrapForDevice(group, pub, "g|device|d");
    expect(w.v).toBe(WRAP_VERSION);
    expect(WRAP_VERSION).toBe(2);
    // the same blob claimed as v1 (bare context as AAD, v1 HKDF info) does not open
    await expect(unwrapForDevice({ ...w, v: 1 }, phone.privateKey, pub, "g|device|d")).rejects.toThrow("cannot be unwrapped");
    await expect(unwrapForDevice({ ...w, v: 3 }, phone.privateKey, pub, "g|device|d")).rejects.toThrow("version");
    // fixed v2 vector made by 0.8.0
    const priv = await crypto.subtle.importKey("pkcs8", fromBase64(v8.wrap.devicePrivate) as BufferSource, { name: "ECDH", namedCurve: "P-256" }, false, ["deriveBits"]);
    const g = await unwrapForDevice(v8.wrap.wrapped, priv, fromBase64(v8.wrap.devicePublic), v8.wrap.context);
    expect(toBase64(g)).toBe(v8.wrap.groupKey);
  });

  it("pairing code v2 matches the fixed vector (unbiased digits)", async () => {
    expect(await pairingCode(fromBase64(v8.pairingCode.devicePublic))).toBe(v8.pairingCode.code);
  });

  it("six digits: rejection sampling, re-hash when every word is rejected", async () => {
    expect(await sixDigits(new Uint8Array(32))).toBe("000 000");
    const high = new Uint8Array(32).fill(0xff); // every 32-bit word >= 4 294 000 000 → re-hash
    const again = new Uint8Array(await crypto.subtle.digest("SHA-256", high));
    expect(await sixDigits(high)).toBe(await sixDigits(again));
    const first = new Uint8Array(32).fill(0xff);
    first.set([0, 0, 0x30, 0x39], 4); // second word = 12345
    expect(await sixDigits(first)).toBe("012 345");
  });

  it("SAS with a commitment: both devices agree, a changed nonce or key is caught", async () => {
    const n = await publicKeyBytes((await newDeviceKeys()).publicKey);
    const e = await publicKeyBytes((await newDeviceKeys()).publicKey);
    const nN = newPairingNonce();
    const nE = newPairingNonce();
    expect(nN).toHaveLength(16);
    // 1. new device commits, 2. existing device sends its nonce, 3. new device reveals its nonce
    const commit = await pairingCommitment(n, e, nN);
    expect(await checkPairingCommitment(commit, n, e, nN)).toBe(true);
    const sas = await pairingSas(n, e, nN, nE);
    expect(sas).toMatch(/^\d{3} \d{3}$/);
    expect(await pairingSas(n.slice(), e.slice(), nN.slice(), nE.slice())).toBe(sas);
    // a party in the middle that reveals another nonce, or swapped keys, fails the commitment
    const other = newPairingNonce();
    expect(await checkPairingCommitment(commit, n, e, other)).toBe(false);
    expect(await checkPairingCommitment(commit, e, n, nN)).toBe(false);
    expect(await checkPairingCommitment("***", n, e, nN)).toBe(false);
    expect(await pairingSas(n, e, nN, other)).not.toBe(sas);
    await expect(pairingSas(n, e, new Uint8Array(15), nE)).rejects.toThrow("16 bytes");
    await expect(pairingCommitment(n, new Uint8Array(65), nN)).rejects.toThrow("public key");
    // fixed vector made by 0.8.0
    const s = v8.sas;
    const [vn, ve, vnn, vne] = [s.newPublic, s.existingPublic, s.newNonce, s.existingNonce].map(fromBase64) as [Uint8Array, Uint8Array, Uint8Array, Uint8Array];
    expect(await pairingCommitment(vn, ve, vnn)).toBe(s.commitment);
    expect(await pairingSas(vn, ve, vnn, vne)).toBe(s.sas);
  });

  it("pairing code: 6 digits, the same on both devices, different for another key", async () => {
    const a = await publicKeyBytes((await newDeviceKeys()).publicKey);
    const b = await publicKeyBytes((await newDeviceKeys()).publicKey);
    const code = await pairingCode(a);
    expect(code).toMatch(/^\d{3} \d{3}$/);
    expect(await pairingCode(a.slice())).toBe(code);
    expect(await pairingCode(b)).not.toBe(code);
  });
});
