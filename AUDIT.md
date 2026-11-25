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
| 0.14.0 | additions only: recovery code in English – a second word list, the unchanged BIP-39 English list (MIT; SHA-256 of `english.txt` checked by a test); `secretToWords` / `wordsToSecret` take a language (default Slovak = behaviour of 0.13.x), `wordsToSecretAuto` recognises the list from the words and refuses a code valid in two lists (`ambiguous`, with both candidates); the language changes only the words – secret, checksum, QR text and keys are the same (question 19); `open-backup.html` opens both | `ts/src/recovery.ts`, `ts/src/wordlist-en.ts`, `ts/src/sheet.ts`, `ts/src/openBackup.ts`, `ts/src/recoveryEn.test.ts`, `keys/tests/recovery_en_0_14_0.rs`, `testvectors/regino/recovery-en-0.14.0.json` |
| 0.15.1 | fixes after an AI-assisted review of 0.15.0 (section 4.5), **no change of formats** – every vector of 0.15.0 and earlier passes unchanged: Argon2id for a password with the same upper bounds as for a backup code, checked before any work; the signature of a member list checked before the keys of its members; a backup's chunk list only in canonical form; a damaged backup chunk of the same size is rewritten (`put_chunk_verified`); `zeroize` in the AEAD and Argon2id crates and `Key` without copies; `qrcode-generator` pinned exactly; optional lower Argon2id bound for reading on a phone (`MOBILE_BACKUP_CODE_KDF`); two new opt-in checks for apps: the latest list version signed or confirmed by an anchor (`requireAnchorOnLatest`, new statement kind `manifest-confirm`) and only the key of the list's own epoch (`requireCurrentEpoch`) | `keys/src/kdf.rs`, `keys/src/sign.rs`, `keys/src/lib.rs`, `keys/Cargo.toml`, `keys/src/backup_code.rs`, `vault/src/backup_chunks.rs`, `ts/src/signing.ts`, `ts/src/backup.ts`, `ts/src/backupCode.ts`, `ts/package.json`, `testvectors/regino/signing-0.15.1.json` |
| 0.16.0 | after two advisory AI reviews of 0.15.1 (section 4.6), **no change of formats or defaults**: `openWriteKey` / `verify_write_key` for the key an app seals new items with (`requireAnchorOnLatest`, `requireCurrentEpoch`, `recipientId` always on); `signed.ts` with the strict `verifyEd25519`; `gc_chunks` stops on an unreadable hand-made copy; unique non-empty `seal` when a list is signed; signed keys written only with wrap v2; `split_zeroizing` / `combine_zeroizing`; `BadValue` for invalid UTF-8 in the vault; fuzzing and Rust coverage in CI | `keys/src/sign.rs`, `keys/src/shamir.rs`, `keys/fuzz/`, `vault/src/backup_chunks.rs`, `vault/src/lib.rs`, `ts/src/signing.ts`, `ts/src/signed.ts`, `.github/workflows/ci.yml` |
| 0.17.0 | after validating an external audit of 0.16.1 (section 4.7, `docs/validacia-auditu-2026-11-25.md`), **no change of formats**: the vault's authorizer refuses `PRAGMA key`/`rekey`/`hexrekey`/`cipher_*` and changes of `secure_delete` through `exec`/`run`/`all`; `structuredContext` / `context::structured` (length-prefixed contexts, shared vectors); `verifyWithKeysAt` with a required time; `MAX_MANIFEST_LEN` before decoding a member list; safe names, MIME and depth in `findChunkedFiles` | `vault/src/lib.rs`, `vault/Cargo.toml`, `keys/src/context.rs`, `keys/src/sign.rs`, `ts/src/context.ts`, `ts/src/signed.ts`, `ts/src/signing.ts`, `ts/src/backupChunks.ts`, `testvectors/regino/context-0.17.0.json` |
| 0.15.0 | additions only: **16-character backup code** for quick backups of less confidential data – Crockford Base32, 15 data characters (75 bits) + a GF(32) check character (every single wrong character and every swap detected), tolerant reading (case, spaces, dashes, O→0, I/L→1, QR prefix `RGC1:`) with exact errors; keys only through **Argon2id** (`@noble/hashes` 2.4.0 in TS, RustCrypto `argon2` in Rust): backup **version 3** with a random 16-byte salt and the parameters in the header (default 32 MiB, t = 2, p = 1; bounds 19–128 MiB, t 2–8, p 1–4, m·t ≤ 256 MiB checked before any work), then HKDF-SHA256 → AES-256-GCM; id for a server and backup-chunk keys from one Argon2id with a fixed salt of the application; `openBackup` / `open-backup.html` take either kind; versions 1 and 2 and all vectors unchanged (question 20) | `ts/src/backupCode.ts`, `ts/src/backup.ts`, `ts/src/backupChunks.ts`, `ts/src/openBackup.ts`, `ts/src/sheet.ts`, `keys/src/backup_code.rs`, `keys/src/backup_chunks.rs`, `keys/tests/backup_code_0_15_0.rs`, `testvectors/regino/backup-code-0.15.0.json` |
| 0.13.4 | maintenance, no change of formats: `rusqlite` 0.40→0.42 (`libsqlite3-sys` 0.40, bundled SQLCipher 4.14.0→4.20.0 on SQLite 3.51.3→3.54.1, still vendored OpenSSL) – fixes RUSTSEC-2026-0459 / CVE-2026-119375 (uninitialised page-cache memory with a crafted `-wal` of another page size); databases written by 0.13.3 open unchanged (the apps' upgrade fixtures pass). Backup chunks, from an AI-assisted review (12 Nov 2026): `referenced_chunks` / `gc_chunks` also honour backups copied by hand in the backup folder whose names do not match the pattern (`… - Copy.<ext>`) – their chunks are no longer collected (an unreadable file of that kind is skipped; a damaged backup with a proper name still stops gc); `put_chunk` writes a chunk again when the existing file has another size (truncated or empty file) instead of trusting it forever | `vault/Cargo.toml`, `Cargo.lock`, `vault/src/lib.rs`, `vault/src/backup_chunks.rs` |
| 0.13.3 | performance only, no change of formats or verdicts: TypeScript remembers the verdict of `isSigningPublicKey` for up to 4096 keys (LRU by key bytes; pure function), benchmark `ts/bench/chain.ts` and `keys/examples/bench_chain.rs` (15 members × 5 versions: TS 115 ms → 35 ms cold / 16 ms warm, Rust 4.4 ms); rules for chain options in `docs/SIGNING.md` (anchors not in `signers`, pin the highest version, keep pins encrypted); more vectors `signing-0.13.3.json` (signers + pinnedTrusted, anchorsMaySign = false + signers, partly wrong pins, pin above the chain, signers cannot start a chain) | `ts/src/signing.ts`, `ts/bench/`, `keys/examples/`, `keys/tests/signing_0_13_3.rs`, `ts/src/signing133.test.ts`, `docs/SIGNING.md` |
| 0.13.2 | additions only: options of the chain from an anchor (`ChainOptions` / `verify_manifest_chain_from_anchor_with`: `signers` may sign any next version, `anchors_may_sign = false` limits anchors to the anchor requirement, `pinned_trusted` lets matching pins meet the anchor requirement – versions up to the pin are checked only structurally, versions above it by admin / signers / anchor); `inspect_manifest_chain` (structure only, no trust – a table for management after a restore, untrusted until approved). Defaults keep 0.13.1; vectors `signing-0.13.2.json` | `keys/src/sign.rs`, `ts/src/signing.ts`, `keys/tests/signing_0_13_2.rs`, `ts/src/signing132.test.ts` |
| 0.13.1 | additions only: `group_key_code` / `group_key_id` (HKDF-SHA256 info `regino group-key code v1` / `id v1` → HMAC-SHA256 over context or label, 80 / 96 bits); `verify_manifest_chain_from_anchor` (v1 with its own signer, admins after that, at least one version signed by an anchor – fail-closed –, pins: fork → `BadChain`, shorter chain → new `Error::Withheld`); `verify_wrap_for_recipient` / `openSignedWrap(…, { recipientId })` (recipient = member of the list with that seal); the `sign_prepared` prefix applies to `wrap` context, `manifest` scope and `member-key` scope too. Vectors `group-key-0.13.1.json`, `signing-0.13.1.json`; nothing existing changes | `keys/src/group.rs`, `keys/src/sign.rs`, `ts/src/groupKey.ts`, `ts/src/signing.ts`, `keys/tests/signing_0_13_1.rs`, `ts/src/groupKey.test.ts`, `ts/src/signing131.test.ts` |
| 0.13.0 | **signatures (Ed25519)** for apps that carry keys between people through a server: personal signing key (random and wrapped, or HKDF-SHA256 from the master key `<app> signing-key v1 <label>`), 80-bit fingerprint, context-bound data signatures, the sender's signature over a wrapped key (context, object id, epoch, hash of the accepted member list, recipient key, signer key, wrapped bytes; epoch ≤ the list's; accepted only from an admin or the signer of the recipient's accepted list or an anchor), a member's statement about its own sealing key (`member-key`: scope, id, version, key; checked against the expected member id and the `seal_version` in the accepted list – replay refused), `sign_prepared` (Rust signs only canonical messages of known kinds naming its own key, `data` optionally only under a context prefix – for apps that keep the key in Rust; TS takes a `Signer`), signed member lists with a hash chain (expected scope in every step, version +1, `prev` = SHA-256 of the previous blob, signed by an admin of the previous list or an anchor, a higher epoch when someone is removed or a sealing key changes – the first seal included –, a higher `seal_version` per member for a new seal, unique ids and signing keys). Also: `shamir::combine` refuses a threshold below 2 (`Error::Format`). Message encoding `RGN-SIG1 ‖ lp(kind) ‖ lp(field)…`. Rust `ed25519-dalek` 3.0 `verify_strict`, TS `@noble/ed25519` 3.2.0 (`zip215: false`) – public keys and `R` must be of prime order, so both give the same verdict; shared vectors made by TS and reproduced byte for byte by Rust (question 18, `docs/SIGNING.md`). Nothing existing changes | `keys/src/sign.rs`, `ts/src/signing.ts`, `keys/tests/signing.rs`, `ts/src/signing.test.ts`, `testvectors/regino/signing-0.13.0.json`, `docs/SIGNING.md` |
| 0.9.0 | device key for quick unlock: HKDF-SHA256 from a secret the OS releases after the user confirms (Windows Hello signature of a fixed challenge, passkey PRF), info `<app> device-key v1 <method>`, at least 32 bytes; wraps the master key next to the password and recovery wraps | `keys/src/device.rs` |

This document scopes an independent security review of **regino-crypto**, an encryption core
shared by several offline-first apps that store sensitive personal data – including
special-category data under GDPR art. 9. License: MIT OR Apache-2.0. The code is public so users
can verify our claims.

## 1. What to review

| Component | Language | Files | Purpose |
|---|---|---|---|
| `keys/` (`regino-keys`) | Rust | `kdf.rs`, `backup_code.rs`, `wrap.rs`, `recovery.rs`, `shamir.rs`, `sign.rs`, `lib.rs` | password KDF, key wrapping and sealing, recovery-code key, 2-of-3 key splitting, Ed25519 signatures (signing key, signed wrapped keys, signed member lists) |
| `vault/` (`regino-vault`) | Rust | `lib.rs`, `keystore.rs`, `backups.rs` | encrypted local SQLite (SQLCipher), DB key in the OS keystore, backup file writing |
| `ts/` (`@regino/crypto`) | TypeScript (WebCrypto, `@noble/ed25519`, `@noble/hashes` for Argon2id since 0.15.0) | `backup.ts`, `backupCode.ts`, `recovery.ts`, `openBackup.ts`, `pin.ts`, `sheet.ts`, `signed.ts`, `sync.ts`, `inbox.ts`, `signing.ts`, `ecdh.ts` (shared by sync and inbox) | encrypted backups, recovery phrase (12/24 words from the Slovak or, since 0.14.0, the BIP-39 English list; QR), user-switch PIN, printable recovery sheet, verification of signed licence tokens and key certificates, sync between devices (sealed records, per-device wrapped group key, pairing code), inbox (anonymous senders seal data to a recipient's public key), signatures (the same as `sign.rs`) |
| `tools/open-backup.html` | built from `ts/tools/` | | public offline tool that opens any backup with the recovery phrase |
| `docs/PAIRING.md`, `docs/INBOX.md`, `docs/SIGNING.md` | documentation | | how an app must pair a device around `sync.ts` (the public key travels by QR code, not through the server) and how a practice publishes its inbox key and fingerprint around `inbox.ts` – the protocols the auditor should read with the code |

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
| A server that carries keys between people (shared case, centre) | serves a false public key of a member, a false new group key, a changed member list, an older list | since 0.13.0, with signatures: lists are accepted only for the expected scope and as a continuation of the trusted one by hash, signed by its admin or an anchor; wrapped keys only from an admin of the recipient's accepted list (or an anchor) and for the expected object, epoch, list and recipient. **Not protected:** the first fingerprint comparison of an anchor or an outside person, withholding of newer lists, **forks** (two admins, or a removed admin with a server withholding the newer list, sign different lists of the same version – limited by binding keys to the list hash and comparing `manifestFingerprint` with the coordinator), an admin's compromised device (`docs/SIGNING.md`) |
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
| Backups with a backup code (since 0.15.0) | Argon2id v1.3 (TS `@noble/hashes` 2.4.0, Rust `argon2` 0.6) → HKDF-SHA256 → AES-256-GCM | code = 16 Crockford Base32 characters, 75-bit secret (10 B, 5 zero bits) + check character Σ α^(i+1)·vᵢ + v₁₅ = 0 in GF(32), x⁵+x²+1; **version 3**: `secret: "code16"`, `kdf: {name: "argon2id", m, t, p}`, salt 16 B random, Argon2id output 32 B → HKDF info `"<app> backup v3 code16"`; IV 96 b random; AAD `"<app>-backup\|3\|<createdAt>\|code16\|argon2id m=<m> t=<t> p=<p>\|<SHA-256 of the sorted chunk list>"`; default m = 32 MiB, t = 2, p = 1; accepted 19 MiB ≤ m ≤ 128 MiB, 2 ≤ t ≤ 8, 1 ≤ p ≤ 4, m·t ≤ 256 MiB (checked before deriving); **id for a server** and **chunk keys**: base = Argon2id(code, SHA-256(`"regino backup-code salt v1\|<app>"`)[0..16], 32 MiB, 2, 1) → HKDF info `"<app> backup-code id v1"` / `"<app> backup chunks v1 code16\|enc\|name"` |
| Recovery phrase | BIP-39-like on a fixed Slovak 2048-word list (default) or, since 0.14.0, the BIP-39 English list | 128-bit secret + 4-bit checksum = 12 words (default since 0.2.0), or 256 + 8 = 24 words; checksum = leading bits of SHA-256; first 4 letters identify a word (an English word of 3 letters is typed whole), diacritics optional; the list changes only the words; QR text `RGR1:` + base32(secret ‖ SHA-256[0..2]) |
| Recovery key (to wrap a master key) | HKDF-SHA256, no salt | info `"<app> recovery-key v1 k128|k256"`; identical in Rust (`recovery_key`) and TS (`recoveryKey`), guarded by fixed cross-language vectors |
| Key wrapping / sealing | XChaCha20-Poly1305 (RustCrypto `chacha20poly1305`) | nonce 192 b random; blob `magic(4) ‖ nonce(24) ‖ ct ‖ tag(16)`, magic `RGW1` (wrap) / `RGS1` (seal); AAD = `magic ‖ context`, context not stored (e.g. `<app>/client/<id>`) |
| Password KDF | Argon2id v1.3 (RustCrypto `argon2`) | default m = 64 MiB, t = 3, p = 1; minimum enforced m = 19 MiB, t = 2; salt 16 B; parameters stored by the caller next to the wrapped key |
| Key splitting | Shamir over GF(256) (`blahaj` 0.7) | share `RGK1 ‖ threshold ‖ fingerprint(8) ‖ share`; fingerprint = SHA-256(`"regino-keys/shamir/v1"` ‖ key)[0..8] to reject foreign or damaged shares |
| Signed tokens (licences) | Ed25519 verify only (`@noble/ed25519` 3.2.0, strict RFC 8032, `zip215: false`) | token `PREFIX1.<payload b64url>.<sig b64url>`, signature over the JSON bytes; apps ship root public keys, every other key needs a root-signed certificate (`RG1.…`, `typ: cert`, `nbf`/`exp`); a fetched key list cannot add keys; caller checks prefix, `product`, `use`; revoked kids dropped |
| Sync (records, wrapped group key, pairing) | HKDF-SHA256 → AES-256-GCM; ECDH P-256 + HKDF-SHA256 → AES-256-GCM (WebCrypto) | records: info `"sync records v1"`, zero salt, IV 96 b random, AAD `"sync record v1\|<context>"`; wrapped group key **v2** (since 0.8.0): HKDF salt = ephemeral ‖ device public key, info and AAD `"sync wrap v2\|<context>"` (v1: info `"sync wrap v1\|…"`, AAD = bare context, still read); pairing code: SHA-256(`"sync pairing v2\|"` ‖ base64(key)) → 6 digits by rejection sampling; SAS: commitment SHA-256(`"sync pairing commit v1\|"`…) and SHA-256(`"sync pairing sas v1\|"` ‖ both keys ‖ both 128-bit nonces) → 6 digits (`docs/PAIRING.md`) |
| Inbox (anonymous sender → recipient) | ECDH P-256 + HKDF-SHA256 → AES-256-GCM (WebCrypto) | recipient key pair, private key exported once as PKCS#8 (the app keeps it wrapped), imported non-extractable; per message an ephemeral key; HKDF salt = ephemeral ‖ recipient public key (65 + 65 B), info `"inbox seal v1|<context>"`; IV 96 b random; AAD `"inbox message v1|<context>"`; JSON `{v, e, n, c}` (base64); fingerprint = SHA-256(`"inbox fingerprint v1|"` ‖ base64(public key))[0..10] |
| Signatures (since 0.13.0) | Ed25519 – Rust `ed25519-dalek` 3.0 `verify_strict`, TS `@noble/ed25519` 3.2.0 (`zip215: false`) | seed 32 B random (kept wrapped) or HKDF-SHA256(key, no salt, `<app> signing-key v1 <label>`); public keys must be canonical, not small order, torsion-free; TS also requires `R` of prime order (= dalek's verdict); message `"RGN-SIG1" ‖ lp(kind) ‖ lp(field)…` (`lp` = u32 BE length), kinds `data` (context, data), `wrap` (context, object id, version u64, list hash 32 B, recipient key, signer key, wrapped), `member-key` (scope, member id, version u64, seal key); manifest members also carry `seal_version` (u64, 0 for an empty seal), `manifest` (scope, version, epoch, prev 32 B, signer, count, members sorted by id: id, role, admin, signing key (unique), seal key); texts kept exactly (U+FEFF not stripped); numbers ≤ 2^53 − 1; manifest blob = message ‖ signature, hash = SHA-256(blob); fingerprint = SHA-256(`"regino signing fingerprint v1\|"` ‖ key)[0..10] |
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
  backup code (16 characters, 75 bits) ──Argon2id(salt 16 B random, m/t/p in the header)──HKDF "<app> backup v3 code16"──► AES-256-GCM key ──► backup file (v3)
  backup code ──Argon2id(fixed salt of the app)──► base ──HKDF "<app> backup-code id v1"──► id for a server; ──HKDF "<app> backup chunks v1 code16|…"──► chunk keys

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
| 18 | **Signatures (0.13.0, additions 0.13.1, 0.13.2).** | Encoding with length prefixes and a kind per purpose; the `wrap` statement signs epoch, list hash, recipient and signer key, and apps accept a key (epoch ≤ the list's) only from an admin or the signer of the list they accepted themselves (`verify_wrap_for`, `openSignedWrap`); members vouch for their sealing keys with a versioned `member-key` statement whose last version is the `seal_version` in the signed list (not local memory); `sign_prepared` signs only canonical messages of known kinds naming its own key; strict (dalek) and cofactored (noble) checks agree because public keys and `R` must be of prime order (two torsion vectors that a plain cofactored check accepts are refused on both sides; Wycheproof on both sides); member lists: expected scope in every step (also version 1), chain by hash, version +1, epoch not lower, and higher when a signing key is missing or a seal changed (enforced), signed by an admin of the trusted list or an anchor; **forks are not detected by the core – each member accepts the first list of a version (since 0.13.1 a joining or restoring member verifies the whole chain from an anchor-signed version and its own pins: fork of a pinned version and withholding are refused; 0.13.2: `pinned_trusted` – is it acceptable that matching pins replace the anchor requirement, and that `inspect_manifest_chain` (no trust) is shown to management for a manual decision?), keys are bound to the list, apps compare the list code with the coordinator (after an independent review of PR #30); the signing key may be derived from the master key. Model and limits in `docs/SIGNING.md`. | new – please review |
| 19 | **Recovery code in two languages (0.14.0).** | The English list is the BIP-39 list, so an English code is also a well-formed BIP-39 mnemonic of the same entropy; we never use the BIP-39 seed – the secret goes into HKDF exactly as with Slovak words (same `recovery_key`, backup keys and QR text). With an explicit language (default Slovak) nothing changes. `wordsToSecretAuto` decodes with each list and accepts only when exactly one gives known words and a valid checksum; otherwise `ambiguous` with the candidates (the caller tries each, AEAD decides – `open-backup.html` does so). Such codes exist only when every word is known in both lists: 254 four-letter prefixes and 84 whole English words are shared, so for a random English code typed in full about (84/2048)^12 · 1/16 ≈ 2^-59 (typed as prefixes ≈ 2^-40); a constructed example is in the vectors. Is refusing (instead of preferring one list) the right choice, and is it acceptable that a user could mistake the English code for a wallet seed (or enter a wallet seed into the app – it would only open nothing)? | new – please review |
| 20 | **16-character backup code (0.15.0) – offline guessing.** | *Threat:* a stolen backup file (cloud, e-mail, a lost USB stick) or a stolen server database with ids lets an attacker try codes offline; each guess costs one Argon2id. *Space:* 75 bits = 3.8·10²² codes (we gave up 5 of 80 bits for the check character: typos in a code typed by hand are far more likely than a 32× faster attack matters, and a mistyped code would otherwise only say "wrong code" after a second of Argon2id). *Cost per guess* at the default 32 MiB, t = 2: 0.04 s in Rust and 0.39 s in Node on one core of a 2.3 GHz Xeon (`npm run bench:code`, `cargo run --release -p regino-keys --example bench_backup_code`); a phone WebView about 1–1.5 s. A GPU is limited by memory bandwidth (≈ 200 MB moved per guess): an RTX 4090-class card does at most about 5 000 guesses/s; we assume 10⁴/s. *Time:* on average 2⁷⁴ / 10⁴ s ≈ 6·10¹⁰ GPU-years; a million GPUs ≈ 60 000 years (at about 0.5 € per GPU-hour ≈ 3·10¹⁴ €). Without Argon2id (HKDF only, ~10¹⁰ tries/s) it would be ≈ 6·10⁴ GPU-years, which is why the code never goes through plain HKDF. *Ids:* the salt of the id is fixed per application (the server must find the id without knowing anything else), so with N stolen ids the first hit needs on average 2⁷⁴ / N guesses – for N = 10⁵ still ≈ 6·10⁵ GPU-years; the server must store ids like password hashes and **limit attempts** of anyone asking by id (online guessing – e.g. a few per minute per address, with a lockout). Chunk names (HMAC under keys from the same base) allow the same multi-target test if the chunks of many users are in one place and the content of a chunk is known. *Why it is enough:* for less confidential, quick backups (a teacher's portfolio in Žiačik, later Gazda) the margin is many orders of magnitude above any realistic attacker, and parameters can be raised in the header later without changing the code. *Fixed parameters of the id and the chunk keys:* `backupCodeId` and `backupChunkKeys` (Rust `backup_code_id`, `BackupChunkKeys::from_backup_code`) always use one Argon2id with the fixed salt of the application and the **fixed** default parameters (32 MiB, t = 2, p = 1) – they cannot come from a header, because every backup of one code must give the same id and chunk names. Raising the header parameters therefore raises the cost of guessing against a backup file only, not against stolen ids or chunk names; raising those would be a new derivation (new info and vectors), not a parameter change. *Bounds when reading (0.15.1, audit N7):* measured worst case allowed by the header bounds (m·t = 256 MiB) is 4× the default – about 1.6 s in Node and 4–6 s on a phone, with 128 MiB of memory in the WebView. A planted header can only cost that time (it opens nothing), but 128 MiB can exceed what a low-end Android WebView gives a page; apps on a phone therefore read with **`decryptBackup(…, { maxKdf: MOBILE_BACKUP_CODE_KDF })`** (Rust `backup_code::valid_params_mobile`): 64 MiB, m·t ≤ 128 MiB = at most 2× the default, refused before any work as `not-backup`. Every backup with the default parameters (all the core writes unless an app raises them; no app does) opens with it; the format and the general bounds (vectors of 0.15.0) are unchanged. *Why Dôverník stays on 12/24 words:* special-category data kept for many years, where the margin must not depend on Argon2id parameters and future hardware – 128 bits are out of reach of any offline attack without a KDF at all. *Mixing kinds:* the length of the secret (10 B vs 16/32 B) is its kind; a code backup is version 3 with `secret: "code16"`, a secret of the other kind is refused before any derivation, the words API refuses a 10-byte secret. Is giving up 5 bits for a check character the right trade, and are the bounds (≤ 128 MiB, m·t ≤ 256 MiB; on a phone ≤ 64 MiB, m·t ≤ 128 MiB) right for a header an attacker may plant? | new – please review (mobile bound added in 0.15.1) |

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

### 4.5 AI-assisted review of 0.15.0 (2026-11-15) – what was fixed in 0.15.1

An AI-assisted review (Fable, run by the maintainer) of `888a7e8` (0.15.0) with its own test programs.
Every point has a test that failed before the fix (`keys/tests/audit_0_15_1.rs`, `ts/src/audit0151.test.ts`,
the vault test `damaged_chunk_of_the_same_size_is_rewritten`), one commit per point. **No format changed:**
backups, codes, wrapped keys, signatures and every fixed vector of 0.15.0 and earlier pass unchanged.
Status: **fixed** (default behaviour changed, with a test), **added** (new opt-in check – the default keeps
0.15.0; the app turns it on), **documented**.

| Point | Status | Note |
|---|---|---|
| N1 – Argon2id for a password had no upper bound (`kdf::KdfParams::check`): a planted key file could start an Argon2id of gigabytes or hours | **fixed** | `KdfParams::MAX` (128 MiB, 8 passes, 4 lanes) and `MAX_WORK_KIB` (m·t ≤ 256 MiB), `KdfParams::is_valid`, checked before any work – the same bounds as `backup_code::valid_params`; the default (64 MiB, 3 passes) and `MIN` are within. No TypeScript equivalent (TS has no password KDF; the PIN is bounded since 0.12.1) |
| N2 – member list checked before its signature (`openManifest` / `open_manifest`): up to 1000 point decodings for a forged blob | **fixed** | structure, canonical form and the signer's key, then the signature, then the members' keys; same verdicts, only a blob with both a bad signature and a bad member key now reports the signature (`BadSignature`) |
| N3 – the chunk list of a backup was not required in canonical form (`decryptBackup`): the AAD binds the sorted unique list, so a reordered or doubled list opened and was returned as it was in the file | **fixed** | a list that is not strictly sorted is `wrong-key-or-damaged` before any key derivation; `encryptBackup` has always written the sorted unique list and every existing vector is sorted |
| N4 – `put_chunk` kept an existing chunk of the right size even when damaged | **fixed** | kept only when its bytes equal the blob; new `put_chunk_verified(dir, name, blob, intact)` keeps an intact file by the app's check (`BackupChunkKeys::open`), so a chunk sealed again with a fresh nonce does not rewrite it |
| N5 – `chacha20poly1305`, `aes-gcm`, `argon2` without the `zeroize` feature; `Key::from_bytes` copies by value | **fixed** | the feature is on for all three (no new crates in `Cargo.lock`); `regino_keys::Key` keeps its bytes in one heap place (`Box<Zeroizing<…>>`), the core writes keys in place (`Key::fill`, `Key::from_slice`); `Key::from_bytes` keeps its signature for the apps and wipes its argument |
| N6 – `qrcode-generator` with a caret range | **fixed** | `2.0.4` exactly; a test checks that every runtime dependency is exact and the same in the lock file |
| N7 – question 20: chunk keys and id have fixed parameters; a lower bound for phones | **documented**, **added** | question 20 says the id and the chunk keys always use the fixed default (32 MiB, 2 passes), never a header; measured worst case of the header bounds (4× the default, 128 MiB); optional `decryptBackup(…, { maxKdf: MOBILE_BACKUP_CODE_KDF })` / Rust `valid_params_mobile` (64 MiB, m·t ≤ 128 MiB); the general bounds and the 0.15.0 vectors are unchanged, default backups open |
| N8 – `signing133.test.ts` "is bounded" exceeded the 5 s test limit on a busy machine | **fixed** | 60 s limit for that test |
| S1 – a chain continued by a removed admin: anchor signs v1 (Alice, Bob admins), Alice removes Bob in v2, Bob signs v2′ continuing v1; a member who restores without pins gets `[v1, v2′]` and accepts it | **added** | `requireAnchorOnLatest` / `require_anchor_on_latest`: the latest version must be signed by an anchor or one of `signers`, or confirmed by one of them (`confirmManifest`, new kind `manifest-confirm`: scope, version, hash, key); shared vectors `signing-0.15.1.json`; `docs/SIGNING.md`. Off by default: management has to confirm each version a coordinator signs, which is the app's decision |
| S2 – a genuine key of an earlier epoch accepted as if current (`openSignedWrap` allows `ver ≤ epoch` on purpose, for new members) | **added** | `openSignedWrap(…, { requireCurrentEpoch: true })` / `verify_wrap_for_with(…, WrapOptions { require_current_epoch: true, .. })` for the key an app seals new items with; older keys (to read older items) are opened without it |

### 4.6 AI-assisted review of 0.15.1 (2026-11-18) – what changed in 0.16.0

Two advisory AI reviews of `37beca2` (0.15.1): Gemini 4 Argon and, as a second opinion, Mistral Large 4
(`docs/audit/argon-posudok-2026-11-18.md`, `docs/audit/mistral-posudok-2026-11-18.md`, each claim checked in the
code). Nothing found allows reading a backup or other data without the code or a key. The maintainer accepted
points 1–5 of the recommendations (`docs/rozhodnutia.md`, 2026-11-18); one commit per point, each with tests.
**No format changed:** backups, codes, wrapped keys, signatures, sealed records and every fixed vector of 0.15.1
and earlier open unchanged; **defaults are unchanged** (the write key is a new function).

| Point | Finding | Status | Note |
|---|---|---|---|
| 1 | (d)1 – no fuzzing and no coverage for Rust | **added** | `keys/fuzz` (cargo-fuzz): `sign` (member lists, prepared messages, chains), `shamir_combine`, `backup_code_parse`, `wrap_unwrap`; CI job `fuzz` (60 s per target) and `coverage` (`cargo llvm-cov`, at least 95 % of lines; 97.2 % measured) |
| 2 | F-01 – `requireCurrentEpoch`, `requireAnchorOnLatest` and `recipientId` are opt-in | **added** | `openWriteKey` / `sign::verify_write_key`: the key an app seals new items with, the chain from version 1 with `requireAnchorOnLatest`, the key of the latest list's epoch, for the member `recipientId` – always on, cannot be switched off. Defaults of `openSignedWrap` / `verify_wrap_for` stay (older keys for reading). Apps that seal new items with a signed group key call it |
| 3 | F-03 – `signed.ts` accepted a torsion component in A or R | **fixed** | `verifySignature` (tokens, key certificates) uses `verifyEd25519` – the verdicts of `ed25519-dalek` `verify_strict`; Wycheproof Ed25519 unchanged. Only malleability before (built-in honest roots) |
| 4 | F-04 – `gc_chunks` skipped a hand-made copy of a backup that could not be read and deleted its chunks | **fixed** | an I/O error (locked by an antivirus or a sync client, no access) stops the collection; a copy that is gone or not JSON is skipped as before |
| 5 | F-07 – no unique `seal` in a member list | **fixed** (when made) | `signManifest` / `sign_manifest` refuse two members with one non-empty seal; reading, the message bytes and `sign_prepared` are unchanged (lists signed before open as before) |
| 5 | F-10 – a signed key could carry wrap v1 | **fixed** (when written) | `signedWrapForDevice` writes only v2; reading unchanged |
| 5 | F-06 – Shamir shares without `Zeroizing` | **added** | `shamir::split_zeroizing` / `combine_zeroizing`; `split` / `combine` unchanged |
| 5 | F-08 – `from_utf8_lossy` in `regino-vault` | **fixed** | invalid UTF-8 in a TEXT column is `Error::BadValue` |
| 5 | (a)3 – AES-GCM random nonces under a fixed key | **documented** | at most 2³² seals per key at `sealRecord`, `sealBackupChunk`, `BackupChunkKeys::seal` |
| 5 | (e)1 – caret ranges of Rust dependencies | **documented** | README rule: apps keep the versions of `Cargo.lock` of the core |
| – | F-02 – chunk keys and id with a fixed salt and parameters | **postponed** | random salt for chunk keys only with a future format (backup v4); question 20 unchanged |

### 4.7 External audit of 0.16.1 (2026-11-25) – validated, what changed in 0.17.0

An external audit (Devin) of `main` 97518c5 reported F-01 … F-06 and L-01 … L-08. We checked every claim independently
in the code and in the seven apps that use the core; the verdicts, the app × duty table, our own findings (V-01 … V-07)
and the proposed format changes are in [`docs/validacia-auditu-2026-11-25.md`](docs/validacia-auditu-2026-11-25.md), the
tasks for the apps in [`docs/plan-aplikacie-2026-11-25.md`](docs/plan-aplikacie-2026-11-25.md).

| Finding | Verdict | Status |
|---|---|---|
| F-01 freshness / order / replay is the app's duty | confirmed | design; proposal `sync record v2` (epoch, seq, prev in the AAD); app tasks |
| F-02 chunk keys and `backupCodeId` with a fixed salt and the default Argon2id | confirmed | postponed to backup v4 (as decided 2026-11-18) |
| F-03 forks / older APIs for the write key | confirmed | `openWriteKey` / `verify_write_key` exist since 0.16.0; app tasks |
| F-04 server pairing protected by a 6-digit SAS only | confirmed | app tasks (lockout); proposal: pairing state machine, optional longer SAS |
| F-05 inbox key trusted from the server | confirmed | proposal inbox v2 (key signed by the practice); app tasks |
| F-06 swap, `cipher_memory_security`, `compact` not forensic | confirmed | documented; full-disk encryption as a condition for art. 9 data (app tasks) |
| L-01 context structure on the caller | confirmed | **fixed**: `structuredContext` / `context::structured` |
| L-02 one AES-GCM record key per group, 2³² not enforced | confirmed | documented; proposal `sync record v2` |
| L-03 chunk names reveal equal content | confirmed | by design |
| L-04 16-character code accepted for any payload | confirmed (an app feeds a 4–8-digit PIN into it, V-02) | proposal `sensitivity` option; app tasks |
| L-05 `verifyWithKeys` checks time only with `at` | confirmed | **fixed**: `verifyWithKeysAt` (time required) |
| L-06 manifest parsed before the signature | partly (member keys were already after it) | **fixed**: `MAX_MANIFEST_LEN` |
| L-07 recursion and file name in the download page | confirmed | **fixed**: depth 64, `safeFileName`, MIME check |
| L-08 raw SQL through the vault | confirmed, **medium**: `PRAGMA hexrekey` re-encrypted the file under a chosen key, `secure_delete` could be turned off (V-01) | **fixed**: authorizer in `Vault::open` |

## 5. Existing assurance

- Tests on every change: `cargo test --workspace`, `cd ts && npx vitest run --coverage` (100 % line, branch and function coverage enforced for the TypeScript part; since 0.16.0 Rust coverage with `cargo llvm-cov`, at least 95 % of lines enforced). Since 0.16.0 fuzzing of the Rust parsers (`keys/fuzz`, 60 s per target on every change).
- Fixed cross-language vectors (Rust ↔ TS) for the recovery key and, since 0.13.0, for signatures (`testvectors/regino/signing-0.13.0.json`: keys, derived keys, fingerprints, data and wrap signatures, a manifest chain with refused and malformed lists, torsion edge cases); snapshot of the Slovak word list; SHA-256 of the English list equal to the BIP-39 `english.txt`, BIP-39 test vectors and shared vectors for English codes (`testvectors/regino/recovery-en-0.14.0.json`, since 0.14.0). Since 0.15.0 the backup code (`testvectors/regino/backup-code-0.15.0.json`): accepted spellings and refused inputs with their exact errors, Argon2id outputs, backup keys, ids, a whole backup and a chunk made by TypeScript and opened by Rust (`keys/tests/backup_code_0_15_0.rs`); the RFC 9106 Argon2id vector for both libraries.
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
