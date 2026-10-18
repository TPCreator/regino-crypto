# Pre-audit review, October 2026 – findings and status

An informal review of `v0.6.0` (no written report) before a paid independent audit. The list below is
our record of the findings, re-verified against the code, with what we changed. Each open item is
meant to become a GitHub issue labelled `pre-audit-review`; the texts below are the issue drafts.
Severities are ours. A formal auditor should treat these as known and start from question 15–17 in
[AUDIT.md](../AUDIT.md) for the open ones.

| # | Severity | Where | Finding | Status |
|---|---|---|---|---|
| 1 | High | `ts/src/sync.ts` `pairingCode` | 6-digit code over the new device's key alone is forgeable by whoever carries the key | **mitigated**: the app scans the key from the QR code directly, the server never carries it; requirement written down in `docs/PAIRING.md` |
| 2 | High | `ts/src/inbox.ts` `inboxFingerprint`, AUDIT.md threat model | fingerprint check by the practice does not protect the sender from a server serving a swapped key | open – protocol, documented |
| 3 | High | `ts/src/sync.ts` `unwrapForDevice` | ephemeral public key and plaintext length not validated | **fixed** |
| 4 | High | README, `keys/src/lib.rs`, `keys/tests/keys.rs` | "unreadable in all backups too" is false for backups made before the key was discarded; the test only checks a wrong key | docs **fixed**, test and app behaviour open |
| 5 | Medium | `ts/src/sync.ts` `wrapForDevice` | AAD is the bare context, records use `sync record v1\|context` | open – next format version |
| 6 | Medium | `ts/src/sync.ts` `recordKey` | HKDF with a zero salt for the record key | open – question 13 for the auditor |
| 7 | Low | `ts/src/sync.ts` `pairingCode` | modulo bias of the 6-digit code | open – subsumed by 1 |
| 8 | Low | `ts/src/inbox.ts` `newInboxKeys` | the inbox private key is exported as PKCS#8 and lives wrapped in every device of a practice | open – question 14 for the auditor |
| 9 | Low | README, AUDIT.md | "100 % coverage" is true for TypeScript only, Rust coverage is not measured | docs **fixed**, measurement open |
| 10 | Low | `.github/workflows/*` | `npm install` instead of `npm ci`, `cargo` without `--locked`, release build and upload in one job with a write token | **fixed** |

Not findings but clarified in the same review and now recorded in AUDIT.md: the frozen commit for
the audit is a signed tag, and the protocol around the primitives (pairing, inbox key delivery) is
in scope as far as this repository documents it.

---

## 1. Pairing code is forgeable by the party carrying the key (High, open)

**Where:** `ts/src/sync.ts`, `pairingCode(devicePublic)`; docs in `sync.ts` header and AUDIT.md.

**What:** the code is six decimal digits of SHA-256 over the new device's public key only. The
existing device gets that key from wherever the app transports it (the sync server, a link). A party
in that path can generate P-256 key pairs until one has the same six digits (about 10^6 attempts,
seconds on a laptop), substitute it, and both devices show the same code. The existing device then
wraps the group key for the attacker's key. The code therefore only catches an accidental mix-up.

**Fix options (app + core):**
- The existing device scans the new device's QR code (the full 65-byte key) and never takes the key
  from the server. Then the code is only a confirmation and the current function is adequate.
- Or a short authentication string over *both* public keys with a commitment from the new device
  (as in ZRTP or Signal safety numbers), so neither side can grind the code after seeing the other key.
- Or show a long fingerprint (≥ 80 bits, like `inboxFingerprint`) and ask the user to compare it.

**Status:** the only app using sync (Gazda) already does the first option: the existing device
scans the new device's QR code, the public key never passes through the server, and the 6-digit code
is only a confirmation that the right screen was scanned. The limit is documented in the
`pairingCode` doc comment, the `sync.ts` header, the AUDIT.md threat model (row "sync server during
pairing"), question 15, and the requirement for apps is now in [`docs/PAIRING.md`](../docs/PAIRING.md).
The function is unchanged. **Open for the auditor:** whether QR transport plus the 6-digit
confirmation is enough; a SAS over both keys only if an app ever moves the key through the server.

## 2. Inbox fingerprint does not protect the sender (High, open)

**Where:** `ts/src/inbox.ts`, `inboxFingerprint`; AUDIT.md threat model row "server in the middle".

**What:** the brief claimed "a swapped public key is noticed by the practice app via the
fingerprint". The practice's app only sees the key the server shows *the practice*. The server can
serve its own key to senders (the web form) and the real key to the practice, read every message and
re-seal it to the practice's key. The fingerprint helps only when the *sender* compares the key the
page shows with a fingerprint obtained from the practice out of band.

**Fix (app + web, documented in the core):**
- The practice publishes the fingerprint out of band: printed on forms and letters, in the practice's
  own app shown to a client in person, read out by phone.
- The sender's page displays the fingerprint of the key it is about to use and asks the client to
  compare it when they have one.
- Longer term: pin the key in the client's browser after the first visit, or deliver the key inside a
  practice-signed object (`signed.ts` already verifies Ed25519 certificates).

**Done now:** threat model row rewritten, `inbox.ts` comments corrected, README wording corrected,
question 14 extended. **Open:** `docs/INBOX.md` describing key delivery and the fingerprint flow, and
the sender-side UI in the private web repository.

## 3. `unwrapForDevice` did not validate the ephemeral key or the result (High, fixed)

**Where:** `ts/src/sync.ts`, `unwrapForDevice`.

**What:** `openFromInbox` checked the ephemeral key with `checkP256Point`; `unwrapForDevice` passed
`wrapped.e` straight to ECDH and returned whatever AES-GCM decrypted, so a blob with a plaintext of
another length would have been accepted as a "group key". WebCrypto rejects points off the curve on
import, so the practical impact was a confusing error rather than a key-recovery attack, but the two
paths were inconsistent.

**Fixed in this branch:** the ephemeral key must be an uncompressed P-256 point and the plaintext
must be exactly 32 bytes; otherwise "The group key cannot be unwrapped on this device." Tests cover a
33-byte key, a compressed point and a correctly sealed 16-byte plaintext. Question 17 asks the
auditor whether the wrapped-key AAD should also carry a version label (see 5).

## 4. Crypto-shredding claim ignored existing backups (High, docs fixed)

**Where:** README "How it fits together", `keys/src/lib.rs` module docs, test
`discarding_client_key_shreds_data` in `keys/tests/keys.rs`.

**What:** "its records become unreadable, in all backups too" is only true for backups made after the
wrapped key was discarded. Every backup made before still contains the client's wrapped key, and the
master key (recovery phrase) opens it. The test only shows that the master key cannot open a record
sealed with the client key directly, which is a property of AEAD, not of deletion.

**Done now:** README and module docs say so explicitly; question 16 for the auditor. **Open:**
- extend the Rust test to build a "backup" (master key + wrapped client key + sealed record), discard
  the wrapped key and show the new backup cannot open the record while the old one can;
- in the apps: when a client is deleted, delete or re-create the local backups and tell the user that
  cloud copies made earlier still contain the data;
- consider a per-backup key epoch in the core if the auditor thinks it is worth it.

## 5. Wrapped-key AAD has no version label (Medium, open)

**Where:** `ts/src/sync.ts`, `wrapForDevice` / `unwrapForDevice`: `additionalData: enc.encode(context)`.

**What:** records bind `sync record v1|<context>`, the wrapped group key binds the bare `context`.
Different keys (record key vs. ECDH-derived wrap key) mean no confusion between the two today, but a
future format that reuses a context string would have no version separation.

**Fix:** with the next `SYNC_VERSION` use `sync wrap v2|<context>` as AAD (the HKDF info already
carries `sync wrap v1|`). Keep accepting v1 blobs. Tracked as question 17.

## 6. Zero HKDF salt for the record key (Medium, open question)

Already question 13 in AUDIT.md. The group key is uniformly random, so a zero salt is the RFC 5869
"salt not provided" case. Left for the auditor; no change.

## 7. Modulo bias in the pairing code (Low, open)

`(h[0..3] as 24-bit integer) % 1_000_000` is slightly biased. Irrelevant next to finding 1; fix
together with it (rejection sampling or 32 bits).

## 8. Inbox private key as PKCS#8 on every device (Low, open question)

By design: all devices of a practice must open messages, so the key is exported once and kept wrapped
by the app's keys. Question 14. No change; a hardware-backed or per-device inbox key would be an
app-level redesign.

## 9. Coverage claim (Low, docs fixed)

"100 % coverage" is enforced by `vitest` for `ts/src` only. README and AUDIT.md now say so.
**Open:** add `cargo llvm-cov` to CI for `keys/` and `vault/` and publish the number.

## 10. CI and release hygiene (Low, fixed)

- `npm ci` instead of `npm install` in CI and release (fails on a lockfile drift).
- `cargo clippy`, `cargo test` with `--locked` (fails if `Cargo.lock` would change).
- Release split into a `build` job (read-only token, `persist-credentials: false`) that produces the
  artefacts and a `publish` job that only downloads them and uploads to the release with
  `contents: write`.
