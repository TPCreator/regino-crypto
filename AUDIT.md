# Security review brief – regino-crypto

*Contact and vulnerability reporting: [SECURITY.md](SECURITY.md).*

**Brief for version 0.8.0 (18 October 2026).** Proposed commit for the
review: a signed tag `audit-<date>` on `main`, created when the engagement starts (so that line
references in the report stay verifiable). Known findings from a pre-audit review, with their status,
are listed in [`audits/`](audits/) – please do not spend time re-discovering them. Before the
engagement we answered our own 17 questions (section 4): where we could, we fixed the code; where a
decision was ours, we made it; the rest is **our answer for you to verify** rather than an open
question. Changes since the first draft of this brief:

| Version | Added | Files |
|---|---|---|
| 0.4.0 | verification of signed licence tokens and key certificates (Ed25519) | `ts/src/signed.ts` |
| 0.5.0 | sync between devices: sealed records, group key wrapped per device (ECDH P-256), pairing code | `ts/src/sync.ts` |
| 0.6.0 | inbox: people without an account (a web form, a document signed in the browser) seal data to a recipient's public key | `ts/src/inbox.ts` |
| 0.7.0 | pre-audit review: `unwrapForDevice` validates the ephemeral key and the result; corrected claims; `docs/PAIRING.md`, `docs/INBOX.md`; findings and status in `audits/` | `ts/src/sync.ts`, `docs/`, `audits/` |
| 0.8.0 | self-review of questions 1–17: constant-time checks, wrapped group keys v2, unbiased pairing code, SAS with commitment for pairing through a server, backups (directory `fsync`, never prune the new file, `discard_backups_before`), licence verification never accepts a certificate payload; new tests and fixed vectors | `keys/src/shamir.rs`, `ts/src/bytes.ts`, `ts/src/sync.ts`, `ts/src/signed.ts`, `vault/src/backups.rs`, `docs/PAIRING.md` |

This document scopes an independent security review of **regino-crypto**, an encryption core
shared by several offline-first apps that store sensitive personal data – including
special-category data under GDPR art. 9. License: MIT OR Apache-2.0. The code is public so users
can verify our claims.

## 1. What to review

| Component | Language | Files | Purpose |
|---|---|---|---|
| `keys/` (`regino-keys`) | Rust | `kdf.rs`, `wrap.rs`, `recovery.rs`, `shamir.rs`, `lib.rs` | password KDF, key wrapping and sealing, recovery-code key, 2-of-3 key splitting |
| `vault/` (`regino-vault`) | Rust | `lib.rs`, `keystore.rs`, `backups.rs` | encrypted local SQLite (SQLCipher), DB key in the OS keystore, backup file writing |
| `ts/` (`@regino/crypto`) | TypeScript (WebCrypto, `@noble/ed25519`) | `backup.ts`, `recovery.ts`, `openBackup.ts`, `pin.ts`, `sheet.ts`, `signed.ts`, `sync.ts`, `inbox.ts`, `ecdh.ts` (shared by sync and inbox) | encrypted backups, recovery phrase (12/24 Slovak words, QR), user-switch PIN, printable recovery sheet, verification of signed licence tokens and key certificates, sync between devices (sealed records, per-device wrapped group key, pairing code), inbox (anonymous senders seal data to a recipient's public key) |
| `tools/open-backup.html` | built from `ts/tools/` | | public offline tool that opens any backup with the recovery phrase |
| `docs/PAIRING.md`, `docs/INBOX.md` | documentation | | how an app must pair a device around `sync.ts` (the public key travels by QR code, not through the server) and how a practice publishes its inbox key and fingerprint around `inbox.ts` – the protocols the auditor should read with the code |

Size: about 1 600 lines of non-test code. The commit to review is fixed when the engagement starts
(apps pin the core to a commit; see `Cargo.toml` / `package.json` of the apps).

**Out of scope:** the apps that use the core, the Android storage plugin
(`@capacitor-community/sqlite`, SQLCipher on Android), the sync server and transport (only the
sealing in `sync.ts` and `inbox.ts` is in scope), the web page that delivers the inbox code to the browser, OS keystore
internals, and third-party crates except whether we use them correctly.

## 2. Threat model

Assets: personal financial records; special-category personal data (e.g. health); recovery secrets; keys.

| Attacker | Capability | Expected outcome |
|---|---|---|
| Finder or thief of a locked device / disk image | reads files at rest | DB and backups unreadable without the OS-keystore key or the recovery phrase |
| Anyone who obtains a backup file (OneDrive, Google Drive, e-mail) | offline attack on the file | cannot decrypt, cannot alter it undetected (incl. header fields) |
| The app operator | runs future sync and server, publishes the apps | never able to decrypt user data; no single 2-of-3 share opens a key |
| Another member of a shared household device | uses the app UI | PIN only stops switching to another user; it is **not** a data-protection boundary |
| The server in the middle of an inbox (web form → practice) | stores and forwards sealed messages, serves the practice's public key | cannot read messages sealed to the practice's real key. **Not protected by the core alone:** the server can serve its own public key to senders while showing the practice its real key, so the practice's fingerprint check does not notice it; a sender is protected only if they get the fingerprint from the practice out of band (printed, in person, by phone) and compare it – see question 14 and finding 2 in `audits/` (a server that serves malicious page code is out of scope) |
| The sync server during pairing | stores and forwards the wrapped group key; would like to learn or substitute the new device's public key | with QR transport it never sees the public key: the existing device scans it from the new device's QR code, and the 6-digit `pairingCode` only catches a mix-up. If an app moves keys through the server it must use the SAS with a commitment (since 0.8.0): a party in the middle succeeds with probability 10^-6 per attempt and fails visibly otherwise (`docs/PAIRING.md`, question 15) |
| Wrong context / swapped blobs | substitutes one client's wrapped key or sealed record for another | rejected (context is authenticated) |

**Not protected:** malware or an attacker inside the unlocked user session; coerced unlock;
side channels on the user's own device beyond what the libraries provide.

## 3. Cryptographic design

| Function | Construction | Parameters / format |
|---|---|---|
| Local DB (Windows) | SQLCipher 4 via `rusqlite` (`bundled-sqlcipher-vendored-openssl`), raw key `PRAGMA key = "x'…'"` | 256-bit random key from `getrandom`, stored in Windows Credential Manager (DPAPI) via `keyring-core`; `cipher_memory_security` left OFF (see question 11); WAL; `rekey` re-encrypts the file |
| Backups | HKDF-SHA256 → AES-256-GCM (WebCrypto) | IKM = recovery secret (16 or 32 B); salt 16 B random per backup; info `"<app> backup v1"` (32 B secret, legacy) or `"<app> backup v1 k128"` (16 B); IV 96 b random; AAD = `"<app>-backup|<version>|<createdAt>"`; JSON `{format, version, createdAt, salt, nonce, ciphertext}` (base64) |
| Recovery phrase | BIP-39-like on a fixed Slovak 2048-word list | 128-bit secret + 4-bit checksum = 12 words (default since 0.2.0), or 256 + 8 = 24 words; checksum = leading bits of SHA-256; first 4 letters identify a word, diacritics optional; QR text `RGR1:` + base32(secret ‖ SHA-256[0..2]) |
| Recovery key (to wrap a master key) | HKDF-SHA256, no salt | info `"<app> recovery-key v1 k128|k256"`; identical in Rust (`recovery_key`) and TS (`recoveryKey`), guarded by fixed cross-language vectors |
| Key wrapping / sealing | XChaCha20-Poly1305 (RustCrypto `chacha20poly1305`) | nonce 192 b random; blob `magic(4) ‖ nonce(24) ‖ ct ‖ tag(16)`, magic `RGW1` (wrap) / `RGS1` (seal); AAD = `magic ‖ context`, context not stored (e.g. `<app>/client/<id>`) |
| Password KDF | Argon2id v1.3 (RustCrypto `argon2`) | default m = 64 MiB, t = 3, p = 1; minimum enforced m = 19 MiB, t = 2; salt 16 B; parameters stored by the caller next to the wrapped key |
| Key splitting | Shamir over GF(256) (`blahaj` 0.6) | share `RGK1 ‖ threshold ‖ fingerprint(8) ‖ share`; fingerprint = SHA-256(`"regino-keys/shamir/v1"` ‖ key)[0..8] to reject foreign or damaged shares |
| Signed tokens (licences) | Ed25519 verify only (`@noble/ed25519` 3.2.0, strict RFC 8032, `zip215: false`) | token `PREFIX1.<payload b64url>.<sig b64url>`, signature over the JSON bytes; apps ship root public keys, every other key needs a root-signed certificate (`RG1.…`, `typ: cert`, `nbf`/`exp`); a fetched key list cannot add keys; caller checks prefix, `product`, `use`; revoked kids dropped |
| Sync (records, wrapped group key, pairing) | HKDF-SHA256 → AES-256-GCM; ECDH P-256 + HKDF-SHA256 → AES-256-GCM (WebCrypto) | records: info `"sync records v1"`, zero salt, IV 96 b random, AAD `"sync record v1\|<context>"`; wrapped group key **v2** (since 0.8.0): HKDF salt = ephemeral ‖ device public key, info and AAD `"sync wrap v2\|<context>"` (v1: info `"sync wrap v1\|…"`, AAD = bare context, still read); pairing code: SHA-256(`"sync pairing v2\|"` ‖ base64(key)) → 6 digits by rejection sampling; SAS: commitment SHA-256(`"sync pairing commit v1\|"`…) and SHA-256(`"sync pairing sas v1\|"` ‖ both keys ‖ both 128-bit nonces) → 6 digits (`docs/PAIRING.md`) |
| Inbox (anonymous sender → recipient) | ECDH P-256 + HKDF-SHA256 → AES-256-GCM (WebCrypto) | recipient key pair, private key exported once as PKCS#8 (the app keeps it wrapped), imported non-extractable; per message an ephemeral key; HKDF salt = ephemeral ‖ recipient public key (65 + 65 B), info `"inbox seal v1|<context>"`; IV 96 b random; AAD `"inbox message v1|<context>"`; JSON `{v, e, n, c}` (base64); fingerprint = SHA-256(`"inbox fingerprint v1|"` ‖ base64(public key))[0..10] |
| User-switch PIN | PBKDF2-SHA256 (WebCrypto) | 4–8 digits, 200 000 iterations, salt 16 B; stored `pbkdf2$iter$salt$hash`; offline brute force is trivial by design (UI barrier only) |

Randomness: OS CSPRNG (`getrandom`, `crypto.getRandomValues`). Rust secrets use `zeroize`;
JavaScript cannot reliably wipe memory. No home-grown primitives.

## 4. Our answers – please verify

Status: **fixed** (code changed, with tests), **decided** (our design decision, implemented),
**verified** (we checked it and added a test; please confirm), **for the auditor** (our view; we
would like your opinion). Test names are in `keys/tests/`, `vault/tests/` and `ts/src/*.test.ts`.

| # | Question | Our answer | Status |
|---|---|---|---|
| 1 | Other comparisons of secrets or tags that should be constant-time? | `Key::eq` (since 0.7.0) and the Shamir key fingerprint check (`shamir::combine`) use `subtle::ConstantTimeEq`; in TypeScript the PIN hash, the recovery checksum and the QR check bytes go through `equalBytes` (no early exit). AEAD tags are checked inside RustCrypto and WebCrypto. The remaining comparisons are on public data: magic bytes, thresholds, the share fingerprint (stored in every share), lengths. | fixed – please check we missed nothing |
| 2 | AAD in `wrap.rs` is `magic ‖ context` without a length prefix – ambiguity? | No: the magic has a fixed length (4 B) and the context is the only variable field, so different contexts always give different AAD and a blob cannot move between `RGW1`/`RGS1` or between contexts, even prefixes of each other (`aad_binds_magic_and_whole_context`). A length prefix would add a format version without a security gain, so the format stays `RGW1`/`RGS1`. The caller builds the context unambiguously (documented in `wrap.rs`). | verified |
| 3 | HKDF without salt for the recovery key | The IKM is a uniformly random 128- or 256-bit secret, so HKDF-Extract with the default (zero) salt is the RFC 5869 §3.1 case "salt not available"; the app name and the secret length are in `info`, so keys of different apps and lengths are separated. | for the auditor |
| 4 | Is 128 bits (12 words) an adequate default for backups kept for years? | **Decided: 12 words stay the default.** 128-bit random IKM through HKDF-SHA256 to an AES-256 key gives 128-bit classical security; a quantum search (Grover) would still need about 2^64 sequential evaluations of HKDF + AES-GCM, which we consider out of reach for the lifetime of the data (it is NIST post-quantum category 1, the AES-128 level). 24 words stay available (`newRecoverySecret(24)`) for apps or users who want a margin; the app chooses. | decided |
| 5 | 64-bit Shamir fingerprint as a verifier of a 256-bit key | A holder of fewer shares than the threshold learns the fingerprint, i.e. at most 64 bits about the key; the remaining search is about 2^192 SHA-256 evaluations. The fingerprint is domain-separated (`regino-keys/shamir/v1`). We consider it acceptable. | for the auditor |
| 6 | `blahaj` randomness and coefficient sampling | Coefficients are drawn with `rand::distributions::Uniform::new_inclusive(0, 255)` from `rand::thread_rng()` (ChaCha12, reseeded from the OS) – zero included, so the `sharks` bias is gone; the secret is the constant term and x starts at 1. Test `shamir_coefficients_are_uniform_including_zero` checks the distribution of the share at x = 1. Notes: GF(256) uses log/exp tables (not constant-time) and blahaj does not zeroize its polynomial buffers; splitting runs once, locally, on the user's device. | verified |
| 7 | SQLCipher: raw-key `PRAGMA`, key check, WAL, `rekey` | The `PRAGMA key` string is a `Zeroizing<String>` (rusqlite copies it into a C string for the call; that copy is not wiped). A wrong key is detected by `SELECT count(*) FROM sqlite_master` and nothing is written. The `-wal` file holds encrypted pages only (`wal_file_is_encrypted`); `rekey` works in WAL mode with uncheckpointed data and the old key no longer opens (`rekey_in_wal_mode`). | verified |
| 8 | Legacy backup info for 32-byte secrets – weakness from mixing lengths? | The secret length selects the info (`… backup v1` for 32 B, `… backup v1 k128` for 16 B) and is itself the IKM length, so a backup made with one length never opens with the other, not even with the first 16 bytes of a 32-byte secret (`16- and 32-byte secrets are separated`). The fixed 0.1.0 backup still opens. | verified |
| 9 | `backups.rs`: path traversal, temp file + `fsync` + rename, pruning | Names (prefix included) allow only letters, digits, `-`, `_` (`prefix_with_path_is_rejected`). Fixed in 0.8.0: the directory is `fsync`ed after the rename (Unix), the file just written is never pruned even if the clock went back (`new_backup_is_never_pruned_even_if_it_sorts_first`), stale `.<name>.tmp` files of the app are removed. | fixed |
| 10 | `signed.ts`: certificate checks, unsigned prefix, `kid` lookup | `nbf ≤ at ≤ exp`, the certificate `kid` must match the list entry, revoked kids are dropped, roots are never taken from the list. The `kid` lookup only selects the key that is then used to verify. The prefix is not covered by the signature, so the payload decides: since 0.8.0 `verifyWithKeys` never accepts a payload with `typ: "cert"`, also a re-prefixed certificate. A future token version may sign the prefix too. | verified (hardened) |
| 11 | Integrity of `tools/open-backup.html` | CI rebuilds it from `ts/` and fails on any difference; every release attaches it with `SHA256SUMS.txt`, so a user can compare the hash of the file they run with the release. | verified |
| 12 | `cipher_memory_security` OFF | With it ON, Windows refused to lock more memory (`VirtualLock` error 1453) and the process crashed. Without it, freed SQLite memory (decrypted pages) is neither wiped nor locked against paging; key buffers are wiped. An attacker who can read process memory or the page file of the unlocked session is outside our threat model; we recommend full-disk encryption (BitLocker) to users. Is there a safer setup we missed? | for the auditor |
| 13 | `sync.ts`: nonces, zero HKDF salt, P-256, pairing-code bias, context binding | Fixed in 0.8.0: the pairing code is unbiased (rejection sampling, label `sync pairing v2`). Our view on the rest: random 96-bit nonces under one record key stay far below 2^32 messages per group; the zero salt is the same case as question 3 (uniform 256-bit group key); P-256 for WebView support; `sync record v1\|<context>` as AAD binds group, table and id when the app puts them into the context. | fixed (bias) / for the auditor (rest) |
| 14 | `inbox.ts`: HKDF salt/info, PKCS#8 export, page code, 80-bit fingerprint | Salt = ephemeral ‖ recipient key and the context in both info and AAD bind each message to one recipient and one purpose. The PKCS#8 export is needed so that all devices of a practice can open messages (finding 8). In Dôverník the form shows the fingerprint of the key it uses, the practice prints it on a leaflet, the app checks the published key every 6 h and the form script has SRI (finding 2, closed). 80 bits: finding a second key with a given fingerprint takes about 2^80 work. | for the auditor |
| 15 | Pairing: is QR + 6-digit code enough, or a SAS over both keys with a commitment? | **Decided:** QR transport + `pairingCode` stays the way for devices side by side (the key never passes the server). For apps that move keys through a server the core now provides a SAS with a commitment (`newPairingNonce`, `pairingCommitment`, `checkPairingCommitment`, `pairingSas`), the numeric-comparison flow of Bluetooth LE Secure Connections; the flow and its rules are in `docs/PAIRING.md`, fixed vectors in `testvectors/regino/sync-0.8.0.json`. | decided |
| 16 | Crypto-shredding vs. older backups – a per-backup key epoch? | **Decided: no key epoch.** A backup must open with the recovery phrase alone (that is its purpose after a lost device), so every key it needs is either derivable from the phrase or stored in it – an epoch cannot make an old backup unreadable without making it unrecoverable. Instead: `regino_vault::backups::discard_backups_before` (write a fresh backup after deleting a client, then discard older ones) and the app tells the user that copies made elsewhere still contain the client. Test `shredding_reaches_only_backups_made_after_deletion` shows exactly this. | decided |
| 17 | `unwrapForDevice`: version label in the wrapped-key AAD? | Yes, since 0.8.0 wrapped group keys are v2: `sync wrap v2\|<context>` is both the HKDF info and the AAD; v1 blobs (bare context as AAD) are still unwrapped and the fixed 0.6.0 vector keeps passing. | fixed |

## 5. Existing assurance

- Tests on every change: `cargo test --workspace`, `cd ts && npx vitest run --coverage` (100 % line, branch and function coverage enforced for the TypeScript part; Rust coverage is not measured yet).
- Fixed cross-language vectors (Rust ↔ TS) for the recovery key; snapshot of the word list.
- **Wycheproof** vectors (`testvectors/wycheproof/`): XChaCha20-Poly1305, AES-256-GCM (96-bit IV), HKDF-SHA256, Ed25519, ECDH P-256 with raw points (incl. invalid-curve and wrong-curve attacks) – valid inputs accepted, invalid rejected.
- Fixed format vectors that must keep opening in future versions: a backup made by 0.1.0, an inbox message and a v1 wrapped group key made by 0.6.0, a v2 wrapped group key, a pairing code and a SAS made by 0.8.0 (`testvectors/regino/`).
- **cargo-deny** (`deny.toml`): RustSec advisories, yanked crates, license allow-list, crates.io only. **npm audit** for `ts/`.
- CI actions pinned to commit hashes, read-only token, `npm ci` and `cargo --locked` against the committed lockfiles. Releases attach CycloneDX SBOMs and SHA-256 checksums; the release build runs with a read-only token and only the upload step has write access.

## 6. How to build and test

```sh
cargo test --workspace --locked   # Rust (keys, vault; SQLCipher builds from source)
cargo clippy --workspace --all-targets --locked -- -D warnings
cargo deny check                  # needs cargo-deny
cd ts && npm ci && npx vitest run --coverage && npx tsc --noEmit
npm run build:tool                # rebuilds tools/open-backup.html
```

## 7. What we expect from the review

A written report with findings rated by severity and concrete fixes; a short retest of our fixes;
and permission to publish the report (or a summary) in [`audits/`](audits/) in this repository, with a
signed tag marking the retested commit.
