# Security review brief – regino-crypto

*Contact and vulnerability reporting: [SECURITY.md](SECURITY.md).*

This document scopes an independent security review of **regino-crypto**, an encryption core
shared by several offline-first apps that store sensitive personal data – including
special-category data under GDPR art. 9. License: MIT OR Apache-2.0. The code is public so users
can verify our claims.

## 1. What to review

| Component | Language | Files | Purpose |
|---|---|---|---|
| `keys/` (`regino-keys`) | Rust | `kdf.rs`, `wrap.rs`, `recovery.rs`, `shamir.rs`, `lib.rs` | password KDF, key wrapping and sealing, recovery-code key, 2-of-3 key splitting |
| `vault/` (`regino-vault`) | Rust | `lib.rs`, `keystore.rs`, `backups.rs` | encrypted local SQLite (SQLCipher), DB key in the OS keystore, backup file writing |
| `ts/` (`@regino/crypto`) | TypeScript (WebCrypto, `@noble/ed25519`) | `backup.ts`, `recovery.ts`, `openBackup.ts`, `pin.ts`, `sheet.ts`, `signed.ts`, `sync.ts` | encrypted backups, recovery phrase (12/24 Slovak words, QR), user-switch PIN, printable recovery sheet, verification of signed licence tokens and key certificates, sync between devices (sealed records, per-device wrapped group key, pairing code) |
| `tools/open-backup.html` | built from `ts/tools/` | | public offline tool that opens any backup with the recovery phrase |

Size: about 1 250 lines of non-test code. The commit to review is fixed when the engagement starts
(apps pin the core to a commit; see `Cargo.toml` / `package.json` of the apps).

**Out of scope:** the apps that use the core, the Android storage plugin
(`@capacitor-community/sqlite`, SQLCipher on Android), the sync server and transport (only the
sealing in `sync.ts` is in scope), OS keystore
internals, and third-party crates except whether we use them correctly.

## 2. Threat model

Assets: personal financial records; special-category personal data (e.g. health); recovery secrets; keys.

| Attacker | Capability | Expected outcome |
|---|---|---|
| Finder or thief of a locked device / disk image | reads files at rest | DB and backups unreadable without the OS-keystore key or the recovery phrase |
| Anyone who obtains a backup file (OneDrive, Google Drive, e-mail) | offline attack on the file | cannot decrypt, cannot alter it undetected (incl. header fields) |
| The app operator | runs future sync and server, publishes the apps | never able to decrypt user data; no single 2-of-3 share opens a key |
| Another member of a shared household device | uses the app UI | PIN only stops switching to another user; it is **not** a data-protection boundary |
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
| User-switch PIN | PBKDF2-SHA256 (WebCrypto) | 4–8 digits, 200 000 iterations, salt 16 B; stored `pbkdf2$iter$salt$hash`; offline brute force is trivial by design (UI barrier only) |

Randomness: OS CSPRNG (`getrandom`, `crypto.getRandomValues`). Rust secrets use `zeroize`;
JavaScript cannot reliably wipe memory. No home-grown primitives.

## 4. Questions we would like answered

1. `Key::eq` in `keys/src/lib.rs` compares with an OR-fold. Is that constant-time enough, or should we use `subtle`?
2. AAD in `wrap.rs` is `magic ‖ context` without a length prefix. Any ambiguity risk across callers?
3. HKDF without salt for the recovery key (IKM is uniformly random) – acceptable?
4. Is a 128-bit recovery secret (12 words) an adequate default for backups that may sit in cloud storage for years? (24 words remain available.)
5. The 64-bit Shamir fingerprint is a verifier of the key – acceptable given a 256-bit random key?
6. `blahaj` randomness and coefficient sampling for Shamir (the original `sharks` crate had a coefficient bias issue).
7. SQLCipher usage: raw-key `PRAGMA` built as a zeroized string, key check via `sqlite_master`, WAL files, `rekey` safety.
8. Backup format: legacy info string for 32-byte secrets (kept so backups from version 0.1.0 open) – any weakness from mixing both lengths?
9. `backups.rs`: name validation against path traversal, temp file + `fsync` + rename, pruning to the newest N.
10. `signed.ts`: certificate checks (time window, kid binding, revocation) and whether the unsigned token prefix or the `kid` lookup before verification opens any confusion between keys or products.
11. Integrity of the public tool `tools/open-backup.html` (CI checks that it matches the sources).
12. `cipher_memory_security` is OFF (the SQLCipher default). With it ON, Windows refused to lock more
    memory (`VirtualLock` error 1453, working-set quota) and the process crashed with a stack overflow.
    Without it, freed SQLite memory (e.g. decrypted page cache) is not wiped or locked against paging;
    key buffers are still wiped by SQLCipher and `zeroize`. Is this acceptable, or is there a safer setup?
13. `sync.ts`: AES-256-GCM with random 96-bit nonces under one record key per group (the number of
    records per key stays far below 2^32); HKDF with a zero salt for the record key; ECDH P-256
    (not X25519, for WebView support) with salt = ephemeral ‖ device public key; the pairing code
    is 6 digits from SHA-256 (slight modulo bias). Is the context binding (`sync record v1|…` as AAD)
    sufficient against moving records between groups, tables or ids?

## 5. Existing assurance

- Tests on every change: `cargo test --workspace`, `cd ts && npx vitest run --coverage` (100 % coverage enforced).
- Fixed cross-language vectors (Rust ↔ TS) for the recovery key; snapshot of the word list.
- **Wycheproof** vectors (`testvectors/wycheproof/`): XChaCha20-Poly1305, AES-256-GCM (96-bit IV), HKDF-SHA256, Ed25519 – valid inputs accepted, invalid rejected.
- **cargo-deny** (`deny.toml`): RustSec advisories, yanked crates, license allow-list, crates.io only. **npm audit** for `ts/`.
- CI actions pinned to commit hashes, read-only token. Releases attach CycloneDX SBOMs and SHA-256 checksums.

## 6. How to build and test

```sh
cargo test --workspace            # Rust (keys, vault; SQLCipher builds from source)
cargo clippy --workspace --all-targets -- -D warnings
cargo deny check                  # needs cargo-deny
cd ts && npm install && npx vitest run --coverage && npx tsc --noEmit
npm run build:tool                # rebuilds tools/open-backup.html
```

## 7. What we expect from the review

A written report with findings rated by severity and concrete fixes; a short retest of our fixes;
and permission to publish the report (or a summary) next to this repository.
