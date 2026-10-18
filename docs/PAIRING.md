# Pairing a device for sync (`ts/src/sync.ts`)

What the core provides, what an app must do around it, and how the first app using it (Gazda,
household finances) does it. This page is in scope of the security review (AUDIT.md, question 15).

## Roles

- **Group**: the devices of one household or practice. They share a random 32-byte **group key**
  (`newGroupKey`); records are sealed with a key derived from it (`recordKey`, `sealRecord`).
- **Existing device**: already holds the group key.
- **New device**: has no key yet. It creates an ECDH P-256 key pair (`newDeviceKeys`); the private key
  is non-extractable and stays on the device (e.g. in IndexedDB).
- **Server**: stores and forwards blobs it cannot open. It is **not trusted** with the new device's
  public key.

## Requirement: the public key travels out of band

`wrapForDevice(groupKey, devicePublic, context)` seals the group key to whatever public key it is
given. If an attacker's key is given, the attacker gets the group key. The core therefore requires
that the existing device obtains the new device's public key **directly from the new device**, not
from the server or any party the server can influence. The intended way is a QR code shown by the new
device and scanned by the existing device.

The 6-digit `pairingCode(devicePublic)` does **not** replace this. It is six digits of a hash of the
key alone; a key pair with a given code is found in about 10^6 attempts. It exists so that a person
can notice they scanned the wrong screen (another device in the room), not to detect a malicious
server. If an app ever lets the key travel through the server, it must use a different confirmation
(a short authentication string over both keys with a commitment, or a long fingerprint), and this
page and `SYNC_VERSION` must change.

## Flow (as implemented in Gazda, core pinned to 0.5.0)

1. **New device** generates its key pair and shows a QR code
   `GZSYNC1:<deviceId>:<publicKey base64>` with the 6-digit `pairingCode(publicKey)` under it.
2. **Existing device** scans the QR code with its camera. It computes `pairingCode` from the scanned
   key itself and asks "Does the code X match?". The person compares the two screens and confirms.
3. Only after the confirmation the existing device calls
   `wrapForDevice(groupKey, publicKey, "<group>|device|<deviceId>")` and posts `{device, wrapped}`
   to the server as an invitation. An invitation is valid for 15 minutes and can be collected once.
4. **New device** polls the server for its invitation, calls
   `unwrapForDevice(wrapped, privateKey, publicKey, "<group>|device|<deviceId>")`, downloads the
   sealed records, opens them with `openRecord` under the context `<group>|event|<id>`, and only then
   replaces its local data in one transaction. An error anywhere leaves local data untouched.

The server sees the device id and the wrapped blob. It never sees the public key or the group key.
Device tokens are stored on the server as SHA-256 hashes.

## What an auditor may want to check

- That the context strings bind group and device id so an invitation cannot be redirected to another
  device or group (AAD and HKDF info in `wrapForDevice`; AUDIT.md question 17 on the AAD label).
- That `unwrapForDevice` rejects an ephemeral key that is not an uncompressed P-256 point and a
  plaintext that is not 32 bytes (added in 0.7.0).
- Whether the QR transport plus the 6-digit confirmation is sufficient against an attacker in the
  same room (shoulder-surfing the QR gives only the public key, which is public by design).
- The invitation lifetime and single collection on the server side (out of scope of this repository,
  described here for context).
