# regino-crypto

Encryption core for apps that protect sensitive personal data. Published so anyone can verify how the data is protected.

*Slovensky: šifrovacie jadro pre aplikácie s citlivými osobnými údajmi, zverejnené, aby si ktokoľvek mohol overiť, ako sú údaje chránené.*

| Part | What it does |
|---|---|
| `vault/` (Rust, `regino-vault`) | Encrypted local database – SQLite + **SQLCipher (AES-256)**, key in the OS keystore (Windows Credential Manager), safe backup writes |
| `keys/` (Rust, `regino-keys`) | **Argon2id** (key from password), **XChaCha20-Poly1305** (key wrapping and data sealing with authenticated context), **Shamir 2-of-3** (key splitting with integrity check), **recovery-code key** (HKDF-SHA256, identical to the TypeScript side), **device key** for quick unlock (Windows Hello / passkey PRF secret → HKDF-SHA256) |
| `ts/` (TypeScript, `@regino/crypto`) | Recovery code – **12 Slovak words** by default (128 bits), optionally **24 words** (256 bits), with checksum; **printable recovery sheet** with QR code (data only, no address, generated offline), encrypted backups (**HKDF-SHA256 → AES-256-GCM**), PIN for switching users, **sync between devices** (records sealed with a group key, group key wrapped per device with ECDH P-256, pairing code, SAS with a commitment for pairing through a server), **inbox** (people without an account – e.g. a client filling in a form or signing a document in the browser – seal data to a practice's public key; the server carries it but cannot open it) |

## How it fits together (example)

```
password ──Argon2id──► password key ──┐
recovery code (12/24 words) ──────────┼─ wraps ─► master key ─ wraps ─► client key ─ seals ─► client records
2 of 3 shares (paper / person / notary) ┘
```
- Deleting a client = discarding the client's wrapped key → its records become unreadable in the database and in every backup made **after** the deletion. A backup made earlier still contains the wrapped key, so after deleting a client the app writes a fresh backup and discards the older ones (`regino_vault::backups::discard_backups_before`), and tells the user that copies made elsewhere still contain the client (see `AUDIT.md`, question 16).
- Changing the password = re-wrapping the master key; data is not re-encrypted.
- No single share of the "2 of 3" opens anything on its own – not even the one held by the operator.

## How to verify that an app really uses this core

1. **Open your backup independently:** download [`tools/open-backup.html`](tools/open-backup.html) (a single file that runs offline in the browser), select a backup from the app and enter your 12 or 24 words (or a photo of the QR code from the recovery sheet). If it opens, the app encrypts with this public code. The file is built from the sources in `ts/` and an automated check ensures it does not differ from them.
2. **Version in the app:** the "About" screen shows the core version and commit, e.g. "regino-crypto 0.3.0 (1a2b3c4)" – compare it with the [releases](https://github.com/TPCreator/regino-crypto/releases).
3. **Software bill of materials (SBOM):** every release of the core and of the app comes with a machine-readable list of all libraries (CycloneDX) and SHA-256 checksums.

## Audit
Material for an independent security review (scope, threat model, parameters, questions): [AUDIT.md](AUDIT.md).
Known findings from a pre-audit review and their status: [`audits/`](audits/).

## Rules
- Only well-reviewed libraries (RustCrypto, SQLCipher, WebCrypto) – no home-grown cryptography.
- Format version in the header of every wrapped key and backup.
- Tests on every change (`cargo test --workspace`, `npx vitest run --coverage` in `ts/` with 100 % coverage enforced for the TypeScript part; Rust coverage is not measured yet).
- Independent security audit before production use.

## Security
Please report vulnerabilities privately – see [SECURITY.md](SECURITY.md).

## License
**MIT OR Apache-2.0**, at your option. See [LICENSE-MIT](LICENSE-MIT) and [LICENSE-APACHE](LICENSE-APACHE).

## Changelog

- **0.10.0 (2026-10-22):** **New:** `regino_keys::chunks` – large files sealed in chunks of 4 MiB (constant memory, viewers open only the chunks they need): XChaCha20-Poly1305 per chunk, AAD `RGC1 || context || index (u64 BE) || last`, so a chunk cannot be moved, swapped between files, and a file cannot be cut short (STREAM construction with random nonces); `Fingerprint` – HMAC-SHA256 of the plain content with a key derived by HKDF from the file key and context, to find duplicates under the same key. New dependency `hmac` 0.12 (RustCrypto, already used inside `hkdf`). Nothing existing changes.
- **0.9.0 (2026-10-22):** **New:** `regino_keys::device::device_key` – key from a secret held by the device (a Windows Hello signature of a fixed challenge, or a passkey PRF output; at least 32 bytes) via HKDF-SHA256 with `<app> device-key v1 <method>` as info, for quick unlock: the app wraps the master key with it next to the password and recovery wraps. Fixed vector checked against an independent HKDF. Nothing existing changes.
- **0.8.1 (2026-10-18):** after a second independent review. Release: the SBOM tools are pinned exactly (cargo-cyclonedx 0.5.9 `--locked`, cyclonedx-npm 6.0.1 as a locked devDependency – the previous floating `@4` had a known shell-injection advisory). `regino_vault::Key::to_hex` and the key `PRAGMA` are built in one pre-sized wiped string. AUDIT.md: test keys in `testvectors/regino/` are on purpose, exact bias of the v1 pairing code, two `Key` types on purpose. No API or format change – apps pinned to 0.8.0 need not move.
- **0.8.0 (2026-10-18):** self-review of the 17 audit questions – each now has our answer and a status in `AUDIT.md` section 4. **Fixed:** constant-time checks of the Shamir key fingerprint, the PIN hash and the recovery checksums; wrapped group keys **v2** (`sync wrap v2|<context>` as HKDF info and AAD; v1 is still unwrapped); the pairing code is unbiased (`sync pairing v2` – both devices need 0.8.0); backups `fsync` the directory, never prune the file just written and clean stale temporary files; `verifyWithKeys` never accepts a certificate payload; **a kid revoked anywhere in a key list is dropped everywhere** (another entry with the same kid used to bring it back). After an independent review: AES-GCM nonces must be 12 bytes and backup header fields strings with a 16-byte salt; empty contexts are refused in `sync.ts` and `wrap.rs` (`Error::EmptyContext`); Shamir hashes the key without a copy, wipes the recovered secret and refuses two different shares with the same x; backups use block base64; the vault refuses NaN/±Inf on read. AUDIT.md: key hierarchy with the apps' payloads, rules for contexts, questions split into "please confirm" and "for the auditor". **New:** SAS with a commitment for pairing through a server (`newPairingNonce`, `pairingCommitment`, `checkPairingCommitment`, `pairingSas`, `WRAP_VERSION`; flow in `docs/PAIRING.md`); `regino_vault::backups::discard_backups_before` for deleting older backups after a client is deleted. **Decided:** 12 words stay the default; no per-backup key epoch. New tests and fixed vectors (`testvectors/regino/sync-0.8.0.json`). Backups, recovery codes, wrapped keys (`RGW1`/`RGS1`), records and inbox messages from earlier versions open unchanged.
- **0.7.0 (2026-10-18):** pre-audit review. `unwrapForDevice` refuses an ephemeral key that is not an uncompressed P-256 point and a result that is not 32 bytes. Corrected claims: deleting a client does not remove its data from backups made earlier; the practice's inbox fingerprint check does not protect the sender by itself; 100 % coverage is the TypeScript part. New `docs/PAIRING.md` and `docs/INBOX.md` (what an app must do around `sync.ts` and `inbox.ts`), `audits/` with the findings and their status, AUDIT.md questions 15–17. `Key::eq` compares with `subtle::ConstantTimeEq` instead of a hand-written loop. SECURITY.md with a fallback contact and a disclosure timeline; Dependabot for actions, npm and Cargo. CI: `npm ci`, `cargo --locked`, release build with a read-only token. No format or API change; wrapped keys, records and inbox messages from 0.5.0/0.6.0 open unchanged.
- **0.6.0 (2026-10-17):** inbox (`inbox.ts`): a recipient key pair (ECDH P-256, private key exported once as PKCS#8 for the app to keep wrapped, imported non-extractable), messages sealed to the public key with an ephemeral ECDH key + HKDF-SHA256 → AES-256-GCM and the context bound as additional data, key fingerprint so the practice can publish it out of band and a sender can check the key the server shows (the server itself can serve a different key to senders than to the practice – see `AUDIT.md`). For web forms and documents signed in the browser (Dôverník). WebCrypto only, no new libraries.
- **0.5.0 (2026-10-17):** sync between devices (`sync.ts`): group key, records sealed with HKDF-SHA256 → AES-256-GCM and the context bound as additional data, device key pairs (ECDH P-256, non-extractable private key), group key wrapped for a device (ephemeral ECDH + HKDF-SHA256 → AES-256-GCM), 6-digit pairing code. WebCrypto only, no new libraries.
- **0.4.0 (2026-10-16):** verification of signed tokens (`signed.ts`): Ed25519 via `@noble/ed25519` (strict RFC 8032), key certificates from built-in root keys, key lists, Wycheproof Ed25519 vectors. Vault: `cipher_memory_security` left off (crashed on Windows, see `AUDIT.md`).
- **0.3.0 (2026-10-16):** the app name for backups is **required** (`encryptBackup(secret, payload, createdAt, app)`, `decryptBackup(secret, file, app)`) – the default value was removed; the `<app>-backup` format and the keys are unchanged, old backups open with the same app name. Audit preparation: `AUDIT.md`, Wycheproof test vectors, cargo-deny and npm audit in CI.
- **0.2.0 (2026-10-16):** recovery code of 12 words (default) or 24 words; recovery sheet with QR code (`recoverySheetHtml`, `recoveryQrSvg`); `wordsToSecret` also accepts the text from the QR code; `recoveryKey` / `regino_keys::recovery::recovery_key`; the `open-backup.html` tool accepts 12 or 24 words and a photo of the QR code. **Backups and 24-word codes from 0.1.0 remain valid** (tested with a fixed backup from 0.1.0).
- **0.1.0 (2026-10-16):** first release.
