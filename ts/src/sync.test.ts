import { describe, expect, it } from "vitest";
import { b64, sealingKey } from "./ecdh";
import {
  fromBase64,
  newDeviceKeys,
  newGroupKey,
  openRecord,
  pairingCode,
  publicKeyBytes,
  recordKey,
  sealRecord,
  SYNC_VERSION,
  toBase64,
  unwrapForDevice,
  wrapForDevice,
} from "./sync";

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

  it("pairing code: 6 digits, the same on both devices, different for another key", async () => {
    const a = await publicKeyBytes((await newDeviceKeys()).publicKey);
    const b = await publicKeyBytes((await newDeviceKeys()).publicKey);
    const code = await pairingCode(a);
    expect(code).toMatch(/^\d{3} \d{3}$/);
    expect(await pairingCode(a.slice())).toBe(code);
    expect(await pairingCode(b)).not.toBe(code);
  });
});
