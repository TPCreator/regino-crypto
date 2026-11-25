# Device vault – data key on the device, a short PIN only as a gate (since 0.20.0)

`ts/src/deviceVault.ts`. Why: an app must never turn a 4–8-digit PIN into the key of its data (audit validation
2026-11-25, V-02 and L-04: 13–27 bits protect a stolen file for hours). Maintainer's decision 2026-11-25: "the PIN is
nowhere the source of a key". Design taken over from app-core `docs/deviceVault.md`, now one format in the core.

## Pieces
| Piece | API | Note |
|---|---|---|
| data key | `createDeviceVault(deviceKey, app, { mode, pin?, kdf? })` → `{ dataKey, envelope }` | 32 random bytes; the app keeps it in memory only and wipes it on lock |
| device key from the OS | `deviceKeyFromSecret(secret, app, method)` | Windows Hello signature, DPAPI / Credential Manager, Android Keystore, Keychain secret (≥ 32 B); = Rust `device::device_key` |
| device key from a passkey | `passkeyPrfInput(app, label?)`, `passkeyPrfExtension(input)`, `passkeyPrfEnabled(cred)`, `passkeyPrfOutput(cred)`, `deviceKeyFromPasskey(output, app)` | WebAuthn `prf` extension; works in a browser, so the PIN is only a gate there too |
| device key in a plain browser | `newBrowserDeviceKey()` | non-extractable `CryptoKey` in IndexedDB; a copy of the browser profile contains it → mode `factor` |
| envelope | `wrapDeviceVault(deviceKey, app, dataKey, opts)`, `openDeviceVault(deviceKey, envelope, app, pin?, { attempts, now })` | JSON `regino-device-vault` v1 |
| attempt limit | `pinAttemptAllowed(state, now)`, `afterPinAttempt(state, ok, now)` | 5 free failures, then 30 s doubling up to 1 h; `openDeviceVault` checks and returns the new state |

## Modes
| Mode | Inside (under the device key) | To open | Use with |
|---|---|---|---|
| `gate` | data key + PIN hash (`hashPin`, PBKDF2) | device key; PIN checked with the attempt limit | a device key from the OS or a passkey |
| `factor` | data key sealed by Argon2id(PIN 8–12 digits) → HKDF → AES-GCM | device key **and** PIN | `newBrowserDeviceKey` (no passkey PRF) |
| `none` | data key | device key | data without a PIN |

The device layer is opened first: without the right device key (`device-mismatch`) no PIN is tried or counted. The
mode is bound in the AAD (`regino-device-vault|1|<app>|<mode>`), so an envelope cannot be relabelled to a weaker mode.

## Passkey flow (browser)
1. Registration: `navigator.credentials.create({ publicKey: { …, extensions: passkeyPrfExtension(await passkeyPrfInput(app)) } })`;
   if `passkeyPrfEnabled(cred)` is false, use `newBrowserDeviceKey()` and mode `factor`.
2. Sign-in: `navigator.credentials.get({ publicKey: { …, extensions: passkeyPrfExtension(input) } })`, then
   `deviceKeyFromPasskey(passkeyPrfOutput(cred), app)` (wipes the output) → `openDeviceVault(key, envelope, app, pin)` in mode `gate`.
3. More passkeys (a second device, a security key) = more envelopes of the same data key (`wrapDeviceVault`).

## Not protected
An unlocked app and code in its window; with the OS keystore, someone using the **same OS account** who can ask
the OS for the secret; the attempt counter is the app's state (whoever can roll back its storage resets it – the
cryptographic protection is the device key). Losing every device key loses the data – keep a recovery route
(12 words, or data from the server).
