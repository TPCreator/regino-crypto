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
server. Since 0.8.0 the digits are unbiased (rejection sampling, label `sync pairing v2`), so both
devices must run core 0.8.0 or newer – an app should put its core version into the pairing QR code
and refuse a mismatch instead of showing two different codes.

## When a key travels through a server: SAS with a commitment (since 0.8.0)

If an app cannot scan a QR code (two devices in different places, a desktop without a camera) and
the public keys have to travel through the server, it must use the short authentication string
(SAS) below instead of `pairingCode`. It is the numeric comparison of Bluetooth LE Secure
Connections / ZRTP: the new device commits to a random nonce before it learns the other nonce, so a
party in the middle cannot search for keys or nonces that give the same digits; each attempt
succeeds with probability 10^-6 and fails visibly.

| Step | New device (N) | Server | Existing device (E) |
|---|---|---|---|
| 1 | `newDeviceKeys`, sends `pubN` | forwards | receives `pubN` |
| 2 | receives `pubE` | forwards | sends `pubE` (its own device key) |
| 3 | `nN = newPairingNonce()`, sends `C = pairingCommitment(pubN, pubE, nN)` | forwards | stores `C` |
| 4 | receives `nE` | forwards | only after `C` arrived: `nE = newPairingNonce()`, sends `nE` |
| 5 | sends `nN` | forwards | `checkPairingCommitment(C, pubN, pubE, nN)` must be `true`, else abort |
| 6 | shows `pairingSas(pubN, pubE, nN, nE)` | | shows `pairingSas(pubN, pubE, nN, nE)` |
| 7 | the person confirms on **both** devices that the six digits are equal | | then `wrapForDevice(groupKey, pubN, …)` |

Rules: a fresh nonce for every attempt (never reuse after a failed or cancelled attempt); E must
not send `nE` before it holds `C`; N must not reveal `nN` before it holds `nE`; three failed
attempts in a row should lock pairing for a while and tell the user someone may be interfering.
Fixed vectors for the commitment and the SAS: `testvectors/regino/sync-0.8.0.json`.

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
  device or group. Since 0.8.0 wrapped keys are v2: `sync wrap v2|<context>` is both the HKDF info
  and the AAD (v1 – AAD = bare context – is still unwrapped; question 17).
- That `unwrapForDevice` rejects an ephemeral key that is not an uncompressed P-256 point and a
  plaintext that is not 32 bytes (added in 0.7.0).
- Whether the QR transport plus the 6-digit confirmation is sufficient against an attacker in the
  same room (shoulder-surfing the QR gives only the public key, which is public by design).
- The SAS flow above (commitment order, nonce length 128 bits, 6 digits) for apps that move keys
  through a server.
- The invitation lifetime and single collection on the server side (out of scope of this repository,
  described here for context).
