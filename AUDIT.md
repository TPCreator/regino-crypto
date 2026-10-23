# Security review brief – regino-crypto

*Contact and vulnerability reporting: [SECURITY.md](SECURITY.md).*

**Brief for version 0.8.1 (18 October 2026).** Proposed commit for the
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
| 0.8.1 | second review: SBOM tools pinned exactly in the release, `to_hex` / key `PRAGMA` without unwiped copies; no API or format change | `.github/workflows/release.yml`, `vault/src/lib.rs` |
| 0.10.0 | large files in chunks: XChaCha20-Poly1305 per 4 MiB chunk, AAD `RGC1 \|\| context \|\| index (u64 BE) \|\| last` (STREAM with random nonces – no reordering, swapping or truncation); keyed fingerprint HMAC-SHA256 with an HKDF-derived key for deduplication under one key | `keys/src/chunks.rs` |
| 0.11.0 | backup chunks: HKDF-SHA256 keys from the recovery code (`<app> backup chunks v1[ k128]\|enc` / `\|name`), name = HMAC-SHA256(content), file `RGB1 ‖ nonce(12) ‖ AES-256-GCM` with AAD `RGB1\|<app>\|<name>`, name re-checked on open; backup v2 lists its chunks in plain text and binds SHA-256 of the sorted list in the AAD; durable chunk writes and age-limited garbage collection. Please check: deterministic names reveal equality of content between backups of one user (by design, for deduplication) and nothing without the code; a changed plain list is detected on opening but could make the app delete chunks (availability only – an attacker with write access could delete them anyway) | `ts/src/backupChunks.ts`, `ts/src/backup.ts`, `keys/src/backup_chunks.rs`, `vault/src/backup_chunks.rs` |
| 0.11.1 | from an AI-assisted review of client deletion and replay (`audits/2026-10-22-ai-review.md`): `secure_delete` on in `Vault::open`, `Vault::compact()` (`wal_checkpoint(TRUNCATE)` + `VACUUM` + truncate) for the app to call after deleting sensitive rows, `Error::Busy`; documentation now states that freshness, order, replay/rollback protection and tombstones are the app's duty (section 3.3, threat model). No format change | `vault/src/lib.rs`, `vault/tests/vault.rs`, `ts/src/sync.ts`, `audits/` |
| 0.12.0 | dependencies updated, API/format unchanged: `argon2` 0.5→0.6, `chacha20poly1305` 0.10→0.11, `aes-gcm` 0.10→0.11, `sha2` 0.10→0.11, `hkdf` 0.12→0.13, `hmac` 0.12→0.13 (one `digest` 0.11 / `aead` 0.6 generation, `hybrid-array` instead of `generic-array`), `blahaj` 0.6→0.7 (only `rand` 0.8→0.10 inside; field tables and share layout identical), `getrandom` 0.3→0.4; TypeScript 7 (dev); CI actions. Code: nonces passed as fixed-size arrays, HMAC keys via `KeyInit::new_from_slice` – no change to what is computed. New compatibility test with vectors made by 0.11.1 (wrap, seal, chunks, fingerprint, Argon2id, HKDF keys, Shamir shares) | `keys/Cargo.toml`, `vault/Cargo.toml`, `Cargo.lock`, `keys/src/wrap.rs`, `keys/src/chunks.rs`, `keys/src/backup_chunks.rs`, `keys/tests/compat_0_11_1.rs`, `testvectors/regino/keys-0.11.1.json`, `.github/workflows/` |
| 0.12.1 | hardening after an external AI review (section 4.3): Shamir shares must have exactly 46 bytes (`SHARE_LEN`); `keystore::rekey` + `finish_rekey` change the database key and the keystore entry through a pending entry, so a crash in between never leaves a key that opens nothing (second review, section 4.4: `Vault::open` reports `WrongKey` only for SQLITE_NOTADB, a file that cannot be read is `Error::Sql`; `finish_rekey` drops the pending entry only after the main key has opened the file and decides nothing without the file; `Error::RekeyIncomplete` after the file was re-encrypted); QR recovery text only in canonical base32 (29 or 55 characters, zero padding bits); backup `version` exactly 1 or 2 (`BACKUP_VERSIONS`); PIN hash: 1 ≤ iterations ≤ 10 000 000 (`MAX_PIN_ITERATIONS`) without leading zeros, salt 16 B and hash 32 B exactly; certificates must have `v: 1`; `verifyWithKeys` states that time is the caller's and takes an optional `at` (`nbf`/`exp`); `peekToken` no longer exported. **No format change** – every fixed vector and `compat_0_11_1` pass untouched | `keys/src/shamir.rs`, `vault/src/lib.rs`, `vault/src/keystore.rs`, `ts/src/recovery.ts`, `ts/src/backup.ts`, `ts/src/pin.ts`, `ts/src/signed.ts`, tests |
| 0.9.0 | device key for quick unlock: HKDF-SHA256 from a secret the OS releases after the user confirms (Windows Hello signature of a fixed challenge, passkey PRF), info `<app> device-key v1 <method>`, at least 32 bytes; wraps the master key next to the password and recovery wraps | `keys/src/device.rs` |

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
| Replay or rollback: a sync server, a storage location or a backup copy returns an older – genuine – sealed record, wrapped key or state | substitutes a blob that was valid once for the current one, withholds newer ones, brings back a deleted record or an abandoned group key | **Not protected by the core alone:** the AEAD proves what a blob is and where it belongs, not when; an old blob under the right context still opens. The app must carry freshness, order and deletions in its own payloads – section 3.3 |
| Remains of deleted rows in the local database file and its WAL – together with the database key, e.g. after a later compromise of the OS keystore | reads the file with the key | Inside the live database file and WAL (since 0.11.1): `secure_delete` zeroes deleted content inside the pages at delete time; `Vault::compact()`, which the app calls after deleting sensitive data, truncates the WAL and rebuilds the file, so old page versions and free pages are no longer in the live file or WAL. **Out of scope:** remains at the file-system level – blocks released by truncating the WAL or the file are freed, not overwritten (old WAL frames, free pages from before 0.11.1 that were never zeroed), SSD wear levelling and remapped blocks, shadow copies / snapshots / backups of the disk. They are ciphertext under the database key, so with the key they can be decrypted; we recommend full-disk encryption (question 7 + 12). Without the key the remains are ciphertext like everything else |

**Not protected:** malware or an attacker inside the unlocked user session; coerced unlock;
side channels on the user's own device beyond what the libraries provide.

## 3. Cryptographic design

| Function | Construction | Parameters / format |
|---|---|---|
| Local DB (Windows) | SQLCipher 4 via `rusqlite` (`bundled-sqlcipher-vendored-openssl`), raw key `PRAGMA key = "x'…'"` | 256-bit random key from `getrandom`, stored in Windows Credential Manager (DPAPI) via `keyring-core`; `cipher_memory_security` left OFF (see question 11); WAL; `secure_delete` ON and `compact()` = `wal_checkpoint(TRUNCATE)` + `VACUUM` after sensitive deletions (since 0.11.1); `rekey` re-encrypts the file – through `keystore::rekey` (pending entry `<user>.pending` → `PRAGMA rekey` → main entry → pending removed) and `keystore::finish_rekey` at startup, so a crash between the file and the keystore leaves a key that opens the file; a pending entry is discarded only after the main key has opened the file, and `Vault::open` reports `WrongKey` only for SQLITE_NOTADB – a file that cannot be read is `Error::Sql`, never taken for a wrong key (since 0.12.1) |
| Backups | HKDF-SHA256 → AES-256-GCM (WebCrypto) | IKM = recovery secret (16 or 32 B); salt 16 B random per backup; info `"<app> backup v1"` (32 B secret, legacy) or `"<app> backup v1 k128"` (16 B); IV 96 b random; AAD = `"<app>-backup|<version>|<createdAt>"`; JSON `{format, version, createdAt, salt, nonce, ciphertext}` (base64) |
| Recovery phrase | BIP-39-like on a fixed Slovak 2048-word list | 128-bit secret + 4-bit checksum = 12 words (default since 0.2.0), or 256 + 8 = 24 words; checksum = leading bits of SHA-256; first 4 letters identify a word, diacritics optional; QR text `RGR1:` + base32(secret ‖ SHA-256[0..2]) |
| Recovery key (to wrap a master key) | HKDF-SHA256, no salt | info `"<app> recovery-key v1 k128|k256"`; identical in Rust (`recovery_key`) and TS (`recoveryKey`), guarded by fixed cross-language vectors |
| Key wrapping / sealing | XChaCha20-Poly1305 (RustCrypto `chacha20poly1305`) | nonce 192 b random; blob `magic(4) ‖ nonce(24) ‖ ct ‖ tag(16)`, magic `RGW1` (wrap) / `RGS1` (seal); AAD = `magic ‖ context`, context not stored (e.g. `<app>/client/<id>`) |
| Password KDF | Argon2id v1.3 (RustCrypto `argon2`) | default m = 64 MiB, t = 3, p = 1; minimum enforced m = 19 MiB, t = 2; salt 16 B; parameters stored by the caller next to the wrapped key |
| Key splitting | Shamir over GF(256) (`blahaj` 0.7) | share `RGK1 ‖ threshold ‖ fingerprint(8) ‖ share`; fingerprint = SHA-256(`"regino-keys/shamir/v1"` ‖ key)[0..8] to reject foreign or damaged shares |
| Signed tokens (licences) | Ed25519 verify only (`@noble/ed25519` 3.2.0, strict RFC 8032, `zip215: false`) | token `PREFIX1.<payload b64url>.<sig b64url>`, signature over the JSON bytes; apps ship root public keys, every other key needs a root-signed certificate (`RG1.…`, `typ: cert`, `nbf`/`exp`); a fetched key list cannot add keys; caller checks prefix, `product`, `use`; revoked kids dropped |
| Sync (records, wrapped group key, pairing) | HKDF-SHA256 → AES-256-GCM; ECDH P-256 + HKDF-SHA256 → AES-256-GCM (WebCrypto) | records: info `"sync records v1"`, zero salt, IV 96 b random, AAD `"sync record v1\|<context>"`; wrapped group key **v2** (since 0.8.0): HKDF salt = ephemeral ‖ device public key, info and AAD `"sync wrap v2\|<context>"` (v1: info `"sync wrap v1\|…"`, AAD = bare context, still read); pairing code: SHA-256(`"sync pairing v2\|"` ‖ base64(key)) → 6 digits by rejection sampling; SAS: commitment SHA-256(`"sync pairing commit v1\|"`…) and SHA-256(`"sync pairing sas v1\|"` ‖ both keys ‖ both 128-bit nonces) → 6 digits (`docs/PAIRING.md`) |
| Inbox (anonymous sender → recipient) | ECDH P-256 + HKDF-SHA256 → AES-256-GCM (WebCrypto) | recipient key pair, private key exported once as PKCS#8 (the app keeps it wrapped), imported non-extractable; per message an ephemeral key; HKDF salt = ephemeral ‖ recipient public key (65 + 65 B), info `"inbox seal v1|<context>"`; IV 96 b random; AAD `"inbox message v1|<context>"`; JSON `{v, e, n, c}` (base64); fingerprint = SHA-256(`"inbox fingerprint v1|"` ‖ base64(public key))[0..10] |
| User-switch PIN | PBKDF2-SHA256 (WebCrypto) | 4–8 digits, 200 000 iterations, salt 16 B; stored `pbkdf2$iter$salt$hash`; offline brute force is trivial by design (UI barrier only) |

Randomness: OS CSPRNG (`getrandom`, `crypto.getRandomValues`). Rust secrets use `zeroize`;
JavaScript cannot reliably wipe memory. No home-grown primitives.

### 3.1 Key hierarchy and what the apps put into each format

```
Rust (regino-keys), e.g. Dôverník – keys/ and the app's key file
  password ──Argon2id──► password KEK ──┐ RGW1 "dovernik/master/password"
  recovery secret ─HKDF (recovery_key)──┤
   (16/32 B, 12/24 words)   RGW1 "…/master/recovery"   │
  device secret ─HKDF (device_key)──────┼─► MASTER KEY ── RGW1 "dovernik/client/<id>" ──► client key ── RGS1 "dovernik/<kind>/<client>/<record>" ──► record
   (Windows Hello signature, optional) RGW1 "…/master/windows-hello"            (one key per client; delete = discard the RGW1 blob)
                                                       ├─ RGW1 "dovernik/db" ──► SQLCipher DB key (also kept in the OS keystore)
                                                       └─ RGS1 "dovernik/recovery-secret" ──► recovery secret (so the app can back up without asking for the words)

regino-vault: SQLCipher key – 32 random bytes, stored in the OS keystore (Windows Credential Manager); the app may also keep it wrapped as above.

ts/ backup.ts – NOT through the master key:
  recovery secret ──HKDF-SHA256(salt 16 B random, info "<app> backup v1[ k128]")──► AES-256-GCM key ──► backup file

ts/ sync.ts (Gazda):
  group key (32 B random) ──HKDF "sync records v1"──► record key ──AES-GCM, AAD "sync record v1|<context>"──► sealed record
  group key ──ECDH P-256 + HKDF "sync wrap v2|<context>"──► wrapped for each device

ts/ inbox.ts (Dôverník forms): sender ──ephemeral ECDH P-256 + HKDF "inbox seal v1|<context>"──► message to the practice's inbox key
  (the inbox private key is kept sealed by the app's master key)
```

**Payloads in the apps today** (needed to judge question 16):

| App | `encryptBackup` payload | `sealRecord` payload |
|---|---|---|
| Dôverník (core 0.6.0) | `PracticeData` as **plain JSON**: settings, clients, appointments, invoices, **notes decrypted to text**, the activity log, and the inbox private key (PKCS#8, base64). No RGS1/RGW1 blobs: the backup is protected only by the backup key from the recovery secret. Locally the notes are RGS1 blobs under per-client keys. | not used |
| Gazda (core 0.5.0) | all tables as **plain JSON**, device-only settings (sync group key, device keys) left out | a `SyncEvent` as plain JSON (table, primary key, operation, row) |

So in both apps a backup made before a client was deleted contains that client's data in plain JSON
under the backup key; deleting the client reaches only later backups – hence
`discard_backups_before` and the app's duty to say that copies elsewhere still contain the client.

**Two `Key` types on purpose.** `regino_keys::Key` (keys that wrap and seal) and `regino_vault::Key`
(the SQLCipher database key) are separate types, so a database key cannot be passed where a wrapping
key is expected by mistake and vice versa; the app converts explicitly (Dôverník unwraps the DB key
with `regino-keys` and hands its bytes to `regino-vault`). Both wipe their memory on drop. We may
unify them later; for now the separation is deliberate.

### 3.2 Contexts (domain separation)

Every sealed or wrapped object is bound to a context string (AAD, and HKDF info where a key is
derived). Rules for apps:

1. **Never empty** – refused by the core (`Error::EmptyContext`, `checkContext`).
2. **Fields joined by one fixed separator per format:** `/` for regino-keys blobs (`RGW1`/`RGS1`), `|`
   for the TypeScript formats (sync, inbox). Both conventions stay because existing data depends on
   them; the core adds its own label (`RGW1`, `RGS1`, `sync record v1|`, `sync wrap v2|`,
   `inbox message v1|`), so the two families never meet.
3. **No field may contain the separator.** Ids are ULIDs or base64url (`[A-Za-z0-9_-]`); the app
   validates them before building a context (Dôverník: `check_id` in `crates/core/src/records.rs`).
4. **Fixed shape per purpose:** the first field names the app or the group, the second the purpose
   (`client`, `note`, `event`, `device`, `request`, …), then a fixed number of ids. Two purposes never
   share a shape, e.g. `dovernik/client/<id>` vs. `dovernik/<kind>/<client>/<record>`.
5. If a field could ever contain arbitrary text, the app must length-prefix it instead (none does today).

### 3.3 What the core does not provide: freshness, order, deletion

The core authenticates content and context (AEAD with the context as AAD, and in HKDF info where a
key is derived) – nothing more. A sealed record, wrapped key, backup or chunk that was valid once
stays valid: the core has no notion of time, order or revocation, so it cannot tell a current blob
from an older genuine one, notice a withheld update, or know that a record was deleted. **These are
the app's duty**; the auditor should look for them in the apps, not here:

1. **Order and rollback:** a monotonic version in the sealed payload and the hash of the previous
   state (prev-hash chain), so a device can check that the state it receives follows the one it last
   saw; a per-device **high-water mark** (the highest version accepted so far) that refuses anything
   older, kept where a server cannot reset it.
2. **Key rotation:** a rotation **epoch** in every payload and in the context of wrapped group keys,
   increased on every rotation; a device refuses to "rotate" back into a group key it has abandoned.
3. **Deletion:** **tombstones** (a sealed record that says "deleted", kept at least as long as any
   copy could come back) rather than mere absence, so an older state cannot resurrect a deleted
   record; locally `secure_delete` and `compact()` (section 3), for backups `discard_backups_before`
   and the user's awareness of copies elsewhere (question 16).
4. **What the user sees:** show the creation time bound in the AAD (`createdAt` of a backup) and
   the device and epoch of the other state in a conflict, so a person can recognise an old state.
5. **Removing a device (revocation):** a `SealedRecord` carries no epoch and a `WrappedGroupKey`
   cannot be revoked – by design, the format stays as it is. The app rotates the group key when a
   device is removed: Dôverník seals a *rotate notice* under the **old** group key (context
   `dovernik|sync|<old group>|rotate-notice`, with the new group id, the epoch and hashes of the new
   wrapped keys), wraps the new key for every remaining device (context
   `dovernik|sync|<new group>|rotate|<device id>`), carries `epoch`,
   `old_groups` and `removed_devices` in every sealed state and refuses a notice whose epoch does not
   increase. **Known remainder:** the removed device still holds the old group key; together with a
   server that keeps or replays old blobs it can read everything sealed under that key before the
   rotation (and nothing after). That is inherent to end-to-end encryption without a trusted server
   and is accepted; what the core guarantees is only that the new key never reaches the removed device.

Open for the auditor (from `audits/2026-10-22-ai-review.md`): should the core offer an optional
freshness envelope (sequence, epoch, previous-state hash bound in the AAD) so that each app does not
build its own?

## 4. Our answers – please verify

Two parts. **4.1** are questions we answered ourselves; please only confirm. **4.2** are the
questions we would like your opinion on; each says what we did and what we think. Status: **fixed**
(code changed, with tests), **decided** (our design decision, implemented), **verified** (checked,
with a test). Question numbers are kept from earlier versions of this brief; tests are in
`keys/tests/`, `vault/tests/` and `ts/src/*.test.ts`.

### 4.1 Our answer – please only confirm

| # | Question | Our answer | Status |
|---|---|---|---|
| 1 | Other comparisons of secrets or tags that should be constant-time? | AEAD tags are checked inside RustCrypto and WebCrypto. `Key::eq` (`subtle`) is used only in tests. The remaining comparisons of secret-derived values are constant-time since 0.8.0: the Shamir key fingerprint in `shamir.rs` (`subtle`), the recovery checksum and the QR check bytes in `recovery.ts` and the PIN hash in `pin.ts` (`equalBytes`). Everything else compared is public (magic bytes, thresholds, share headers, lengths). | fixed |
| 3 | HKDF without salt for the recovery key | The IKM is a uniformly random 128- or 256-bit secret, which is the RFC 5869 §3.1 case where a salt is optional; app name and secret length are in `info`. | verified |
| 4 | 128 bits (12 words) as the default | A product decision rather than an audit question: 12 words stay the default (128-bit security; about 2^64 sequential quantum evaluations even with Grover), 24 words are available (`newRecoverySecret(24)`). | decided |
| 5 | 64-bit Shamir fingerprint as a verifier of a 256-bit key | It tells a holder of fewer shares than the threshold at most 64 bits about the key; about 2^192 work remains. Domain-separated (`regino-keys/shamir/v1`). | verified |
| 8 | Legacy backup info for 32-byte secrets | The secret length selects both the IKM length and the info, so a backup never opens with a secret of the other length, not even the first 16 bytes of a 32-byte one (`16- and 32-byte secrets are separated`); the fixed 0.1.0 backup still opens. Since 0.8.0 the header fields must be strings, the salt 16 B and the nonce 12 B. | verified |
| 11 | Integrity of `tools/open-backup.html` | CI rebuilds it from `ts/` and fails on `git diff`; each release attaches it with `SHA256SUMS.txt`. | verified |

### 4.2 Questions for the auditor

| # | Question | What we did / our view | Status |
|---|---|---|---|
| 2 + 17 | **AAD and unambiguous contexts.** Is `magic ‖ context` (Rust) and `sync wrap v2\|<context>` / `sync record v1\|<context>` / `inbox message v1\|<context>` (TS) with the context rules in 3.2 sufficient? | Magic and labels have a fixed form and the context is the only variable field, so different contexts give different AAD (`aad_binds_magic_and_whole_context`); a length prefix would add nothing as long as apps follow 3.2. Wrapped group keys are v2 since 0.8.0 (label in HKDF info and AAD; v1 still read). Empty contexts are refused everywhere since 0.8.0. | fixed (v2, empty) – please review the rules |
| 6 | **Memory hygiene of Shamir.** | blahaj 0.7 draws coefficients uniformly from 0..=255 (`Uniform::new_inclusive`, `rand::rng()` – in 0.6 `thread_rng`), zero included (`shamir_coefficients_are_uniform_including_zero`). blahaj does not zeroize its polynomials and share buffers; we hash the key without a copy and wrap the recovered secret in `Zeroizing` (0.8.0). GF(256) uses log/exp tables (not constant-time); splitting runs once, locally. Is that acceptable? | verified – your opinion |
| 7 + 12 | **SQLCipher: raw key, WAL, `rekey`, `cipher_memory_security`.** | The `PRAGMA key` string is `Zeroizing` (rusqlite's C-string copy is not). Wrong key → `sqlite_master` check fails with SQLITE_NOTADB → `WrongKey`, nothing written; any other failure of that check (locked file, I/O error) is `Error::Sql`, so nothing that decides about keys mistakes it for a wrong key (`unreadable_file_is_not_reported_as_a_wrong_key`). The `-wal` file holds encrypted pages (`wal_file_is_encrypted`); `rekey` works in WAL mode (`rekey_in_wal_mode`). `cipher_memory_security` is OFF: with it ON Windows failed `VirtualLock` (error 1453) and the process crashed; freed SQLite pages are therefore not wiped or locked against paging, key buffers are. We recommend full-disk encryption. Since 0.11.1 `secure_delete` is ON (`secure_delete_is_on_after_open`) and `compact()` truncates the WAL and rebuilds the file after sensitive deletions – this covers the live file and WAL only; blocks freed by the truncation are not overwritten and stay in the file system's free space, on the SSD or in shadow copies (encrypted under the database key), which is one more reason for full-disk encryption (`compact_truncates_wal_and_shrinks_the_file`; `secure_delete_leaves_no_deleted_text_in_a_plaintext_file` shows the effect on a plaintext file, with a control run); between compactions the remains of deleted rows are zeroed inside encrypted pages. Is there a safer setup? | verified – your opinion |
| 9 | **`backups.rs`** | Names (prefix included) allow only `[A-Za-z0-9_-]` and the app's extension (`prefix_with_path_is_rejected`). Since 0.8.0: `fsync` of the file and, on Unix, of the directory after the rename; the file just written is never pruned (`new_backup_is_never_pruned_even_if_it_sorts_first`); stale `.<name>.tmp` files removed; `discard_backups_before`. | fixed – please review |
| 10 | **`signed.ts`** | `nbf ≤ at ≤ exp`; the certificate `kid` must match the list entry; roots never come from the list; since 0.8.0 a kid revoked anywhere in the list is dropped everywhere (it was dropped only for that entry) and `verifyWithKeys` never accepts a `typ: "cert"` payload, because the prefix is not signed. | fixed – please review |
| 13a | **Pairing code bias (fixed).** | Up to 0.7.0 the code was `(24-bit value) mod 10^6`: 2^24 = 16 777 216, so the codes 000 000–777 215 occurred with weight 17 and the rest with weight 16 (about 6 % more likely). Since 0.8.0 (`sync pairing v2`) 32-bit words are rejection-sampled below 4 294 000 000, so all codes are equally likely. | fixed |
| 13 | **One record key per group, random 96-bit IVs on many devices.** | All devices of a group seal with the same record key and pick random IVs independently; there is no counter or key rotation. A collision needs about 2^48 records for probability 2^-1 (birthday bound), and stays below 2^-33 for 2^32 records; a household or practice writes far fewer. The zero HKDF salt is the case of question 3 (finding 6). Is a limit or rotation needed? | your opinion |
| 14 | **Inbox.** | Salt = ephemeral ‖ recipient key, context in info and AAD; PKCS#8 export so all devices of a practice can open messages (finding 8); 80-bit fingerprint. Dôverník shows the fingerprint in the form, prints it, checks the published key every 6 h and loads the form script with SRI (finding 2, closed; `docs/INBOX.md`). | your opinion |
| 15 | **Pairing.** | QR transport + `pairingCode` (unbiased since 0.8.0) for devices side by side; for keys through a server a SAS with a commitment (`pairingCommitment`, `checkPairingCommitment`, `pairingSas`), flow in `docs/PAIRING.md`, fixed vectors. | decided – please review the SAS flow |
| 16 | **Crypto-shredding vs. older backups.** | No key epoch: a backup must open with the recovery phrase alone, so anything it needs is derivable from the phrase or inside it; today's backups are plain JSON under the backup key (3.1). Instead `discard_backups_before` and the app's duty to tell the user about copies elsewhere (`shredding_reaches_only_backups_made_after_deletion`). | decided – your opinion |

### 4.3 External AI review (2026-10-23) – what was fixed in 0.12.1

An AI assistant reviewed the repository on the maintainer's computer (possibly an older checkout);
every point was first checked against 0.12.0 and the apps that use the core (Dôverník, Gazda;
Žiačik and regino-obchod do not use it). Status: **fixed** in 0.12.1, **already** = was already so
(in an earlier version), **as designed** = deliberately different, documented.

| Point | Status | Note |
|---|---|---|
| `shamir.rs`: hash the key without `concat()` (unwiped copy) | already (0.8.0) | `Sha256::new().chain_update(label).chain_update(key)` |
| `shamir.rs`: recovered secret in `Zeroizing` | already (0.8.0) | |
| `shamir.rs`: fingerprint compared in constant time | already (0.8.0) | `subtle::ConstantTimeEq` |
| `shamir.rs`: exact share length instead of `len < 13` | **fixed** | `SHARE_LEN` = 46 for every share (checked against the 2-of-3 and 3-of-5 vectors of 0.11.1); first share → `Error::Format`, others → `Error::BadShares` |
| `wrap.rs`: refuse an empty context with `Error::Format` | already (0.8.0), as designed | refused since 0.8.0 with its own `Error::EmptyContext` (a programming error, not corrupt data); both apps have run on that rule since, so no data with an empty context exists |
| `Vault::rekey` + `store_key` not atomic | **fixed** | `keystore::rekey` (pending entry → rekey → main entry → remove pending) and `keystore::finish_rekey` at startup; neither app calls `rekey` today (Dôverník also keeps the DB key wrapped in its key file; Gazda never changes the key), so this is for the day they do |
| `recovery.ts`: exact base32 length and zero padding bits | **fixed** | 29 / 55 characters, padding bits must be zero; fixed QR texts added as vectors, the 0.1.0 backup and all existing QR tests pass |
| `backup.ts`: `version` exactly a supported one, salt 16 B, nonce 12 B | **fixed** (version) / already (salt, nonce since 0.8.0) | `BACKUP_VERSIONS = [1, 2]`; an integer above 2 is `newer-version`, anything else `not-backup` (`'x'` used to be reported as newer) |
| `sync.ts`, `inbox.ts`: nonce exactly 12 B; empty context in `sync.ts` | already (0.8.0) | `gcmNonce` and `checkContext` in `ecdh.ts` are used by both; explicit tests added |
| `pin.ts`: upper bound on iterations, exact salt and hash length | **fixed** | `MAX_PIN_ITERATIONS` = 10 000 000 (apps store 200 000), salt 32 hex, hash 64 hex, exactly four fields; also enforced by `hashPin` |
| `signed.ts`: `verifyCertificate` requires `v: 1` | **fixed** | the format has always had `v: 1` (regino-obchod `LICENCIE-TOKENY.md`) |
| `signed.ts`: `verifyWithKeys` – expiry is the caller's | **fixed** (docs + optional `at`) | licence tokens have no `exp` by design (`valid_to` + `grace_days` decide); optional `at` checks `nbf`/`exp` when present; without `at` nothing changes for the apps |
| `signed.ts`: `peekToken` | **fixed** (removed) | no app used it; internal only (to pick the `kid`), nothing read without a signature is exported |
| `SealedRecord`: device revocation / epoch | as designed | format unchanged; the app's duty and the known remainder are in section 3.3 item 5 |

### 4.4 Second review of 0.12.1 (2026-10-23) – fixed before the merge

An independent review of the 0.12.1 changes themselves (pull request #28) found:

| Point | Status | Note |
|---|---|---|
| `finish_rekey` dropped the pending entry on **any** failure to open: `Vault::open` reported `WrongKey` for every failed `sqlite_master` check (locked file, I/O error, damaged file), so a crash after the re-encryption plus a locked file at the next start would have discarded the only working key | **fixed** (high) | `Vault::open`: `WrongKey` only for SQLITE_NOTADB, every other failure is `Error::Sql` (`unreadable_file_is_not_reported_as_a_wrong_key`); `finish_rekey` drops the pending entry only after the **main** key has opened the file and otherwise returns the error with both entries kept (`finish_rekey_keeps_pending_key_when_the_file_cannot_be_read`, `finish_rekey_drops_nothing_when_neither_key_opens_the_file`). Both apps map `WrongKey` explicitly and everything else through a wildcard arm, so the narrower `WrongKey` changes nothing for them |
| `rekey`: an error after `PRAGMA rekey` (keystore write) looked like a failed change although the file already had the new key | **fixed** (medium) | `Error::RekeyIncomplete`, with the rule in the API docs: the change is not failed, do not try the old or another key, restart (`finish_rekey` promotes the pending entry) or call `finish_rekey` – `rekey_incomplete_is_completed_by_finish_rekey` |
| `finish_rekey` dropped the pending entry when `db_path` did not exist (wrong path, database kept elsewhere) | **fixed** (medium) | without the file nothing is decided: the pending entry stays and `false` is returned; the docs say to call it for every database with that database's exact path |
| the pending entry as a new target in the Credential Manager | noted (low) | whoever can write the pending entry can overwrite the main entry too (same store, same access rights), so the pending entry adds no attack the main entry did not already allow; a planted pending key is promoted only if it opens the file, i.e. only with a key the attacker already has |
| `pin.ts`: an iteration count with leading zeros (`0200000`) was accepted | **fixed** (low) | one canonical spelling, `^[1-9]\d*$`; `hashPin` has always written the plain number (Gazda stores `200000`) |
| section 3.3 item 5: name the rotation contexts | **fixed** (docs) | `…|rotate-notice` for the notice, `…|rotate|<device id>` for the wrapped key |

## 5. Existing assurance

- Tests on every change: `cargo test --workspace`, `cd ts && npx vitest run --coverage` (100 % line, branch and function coverage enforced for the TypeScript part; Rust coverage is not measured yet).
- Fixed cross-language vectors (Rust ↔ TS) for the recovery key; snapshot of the word list.
- **Wycheproof** vectors (`testvectors/wycheproof/`): XChaCha20-Poly1305, AES-256-GCM (96-bit IV), HKDF-SHA256, Ed25519, ECDH P-256 with raw points (incl. invalid-curve and wrong-curve attacks) – valid inputs accepted, invalid rejected.
- The fixed vectors in `testvectors/regino/` (`ecdh-0.6.0.json`, `sync-0.8.0.json`) contain private keys **on purpose**: they are test keys generated only for these vectors (to show that messages and wrapped keys made by older versions still open), never used anywhere else – not a leak.
- Fixed vectors made by 0.11.1 with the previous dependency generation (`testvectors/regino/keys-0.11.1.json`, `keys/tests/compat_0_11_1.rs`): wrapped key, sealed data, chunks, fingerprint, Argon2id and HKDF keys, Shamir shares – a dependency update must open them unchanged.
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
