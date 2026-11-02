# Signatures: signing keys, signed wrapped keys, signed member lists (since 0.13.0)

`keys/src/sign.rs` (`regino_keys::sign`, `ed25519-dalek`) and `ts/src/signing.ts` (`@regino/crypto`,
`@noble/ed25519`) – the same API and the same bytes on both sides, guarded by the shared fixed vectors
`testvectors/regino/signing-0.13.0.json`. This page is in scope of the security review (AUDIT.md,
question 18).

## Why

Before 0.13.0 the core had only anonymous sealing to a public key (`wrapForDevice`, `sealToInbox`). An
app that lets a server carry keys between **people** – a team sharing one encrypted case, a centre and
its members – had one defence against a server that substitutes keys: people comparing a fingerprint
(by phone, in person) every time a key appeared or changed. Three gaps remained:

1. the server hands a member a **false public key of a colleague** (the member would wrap the case key
   for the attacker) – detected only if the fingerprint is compared again after every change;
2. the server hands a member a **false new case key** (a new epoch after someone was removed) – nothing
   says who made it;
3. the server **changes the member list** (adds itself, swaps a key, drops the coordinator) – nothing
   says who decided it.

With signatures the comparison happens **once per person** (their signing key), and everything that
person later vouches for – their own sealing key, a key they wrapped for someone, a new member list – is
checked by the app automatically.

## Building blocks

| Function (Rust / TS) | What it does |
|---|---|
| `SigningKey::generate` / `newSigningKey` | 32 random bytes (Ed25519 seed). The app keeps them only **wrapped** by its own keys – Rust `wrap::wrap_key(kek, &key.seed(), context)`, TS sealed like the inbox private key (`Practice.setCenterKey` in Dôverník). |
| `SigningKey::derive` / `deriveSigningKey` | Seed = HKDF-SHA256(key, no salt, info `<app> signing-key v1 <label>`), from a key the app keeps anyway (the master key). The same key on every device of the person and after a restore from backup, nothing new to store or back up. |
| `public_key` / `signingPublicKey` | 32-byte public key. |
| `fingerprint` / `signingFingerprint` | `3f2a 9c01 …` – the first 80 bits of SHA-256(`regino signing fingerprint v1\|` ‖ key), hex in groups of four. A server would need about 2^80 key generations to find another key with the same code. |
| `sign_data` / `signData`, `verify_data` / `verifyData` | Signature over data bound to a non-empty context. |
| `sign_wrap` / `signWrap`, `verify_wrap` / `verifyWrap` | The sender's signature over a wrapped key (`WrapStatement`: context, object id, version, recipient public key, the sender's own public key, the wrapped bytes). |
| `signedWrapForDevice`, `openSignedWrap` (TS) | `wrapForDevice` + signature; on opening: the sender must be one of the given trusted keys, object id and version must be the expected ones, the signature must be valid – only then is the key unwrapped. |
| `sign_manifest` / `signManifest` | A signed member list (below). |
| `verify_manifest` / `verifyManifest`, `verify_manifest_chain` / `verifyManifestChain` | Accept a list only if it continues one already trusted. |
| `open_manifest` / `openManifest` | Read a blob the app accepted earlier and stored itself (checks format and signature, not trust). |
| `verifyEd25519` (TS) | The strict check behind all of the above. |

## Formats (exact bytes)

Every signed message is

```
"RGN-SIG1" ‖ lp(kind) ‖ lp(field1) ‖ lp(field2) …        lp(x) = u32 big-endian length ‖ x
```

so no two different field lists give the same bytes, and a signature of one kind is never valid as
another kind (`kind` is `data`, `wrap` or `manifest`). Numbers are u64 big-endian, at most 2^53 − 1
(the largest whole number TypeScript holds exactly; refused above it on both sides).

| Kind | Fields |
|---|---|
| `data` | context (UTF-8, 1–1024 B), data |
| `wrap` | context, object id (1–1024 B), version (u64), recipient public key (1–1024 B), signer public key (32 B), wrapped (1–65 536 B) |
| `manifest` | scope (1–1024 B), version (u64, ≥ 1), epoch (u64), prev (32 B), signer public key (32 B), member count (u32, ≤ 1000), then per member sorted by the UTF-8 bytes of the id: id (1–256 B, unique), role (1–256 B), admin (1 B: 0 or 1), signing key (32 B), seal key (0–1024 B) |

- A `WrappedGroupKey` (TS) is signed as the UTF-8 of `<v>.<e>.<n>.<c>` (`wrappedKeyBytes`); a Rust
  `wrap::wrap_key` blob as its bytes.
- `SignedWrappedKey` (TS, JSON): `{ v: 1, id, ver, w: WrappedGroupKey, k: base64 signer key, s: base64 signature }`.
- A manifest **blob** is `message ‖ signature (64 B)`; the server stores and returns it opaque. Its
  hash is SHA-256(blob) and goes into `prev` of the next version. Reading a blob re-encodes the decoded
  list and requires the same bytes (sorted ids, no trailing data, limits) – one list has one blob.

## Verification: the same verdict in Rust and TypeScript

Rust uses `VerifyingKey::verify_strict` (cofactorless, rejects small-order `R` and `A`, `S < L`,
canonical `R`). `@noble/ed25519` with `zip215: false` checks the cofactored equation. These differ only
for points with a small-order (torsion) component, so the core removes that case on both sides:

- a **public key** must be a canonical encoding of a point of prime order: not of small order and
  torsion-free (`PublicKey::from_bytes`, `isSigningPublicKey`); honest keys always are;
- in TypeScript **R** must also be of prime order (`verifyEd25519`); dalek's cofactorless check implies it.

With `A` and `R` in the prime-order subgroup both equations accept exactly the same signatures. The
vectors contain two signatures that a plain cofactored check accepts (a torsion component in `R`, and
in `A`) – both sides refuse them – plus Wycheproof `ed25519_test.json` on both sides.

## Member lists and the chain rule

A manifest says: for **scope** (e.g. `dovernik|center|12|case|<id>`), **version** n, key **epoch** e,
following the list with hash **prev**, the members are …, each with a signing key, an optional sealing
key (the P-256 key used by `wrapForDevice`) and a flag **admin** (may sign the next version). Roles are
the app's own words; the core does not interpret them.

`verify_manifest(blob, anchors, prev)` accepts:

- **no `prev`** (first list the app sees for this scope): version 1 (prev = 32 zero bytes), signed by
  one of `anchors`;
- **with `prev`**: same scope, version = prev + 1, `prev` = hash of the trusted list, epoch not lower,
  signed by an **admin of the trusted list** or by an **anchor**.

`anchors` are keys the app trusts for the scope on its own – pinned after a fingerprint comparison
(e.g. the centre's management). An anchor may sign any next version, so a list whose admins all left
can still be continued (by management, recorded in the app's log). A second list with the same
version as the trusted one is refused (a fork is not a continuation). The app stores the last accepted
blob (`AcceptedManifest.blob`) and continues from it with `verify_manifest_chain`.

## What it protects

| Attack by the server (or someone controlling it) | With 0.13.0 |
|---|---|
| Hands a member a false public key of a colleague | Keys come from a signed list (or from a key the colleague signed with `sign_data`); a key not signed by a trusted signer is refused – no repeated phone comparison needed |
| Hands a false new case key (new epoch) | `openSignedWrap` refuses a key not signed by a trusted member, or signed for another object, version or recipient |
| Adds itself or a key of its own to the member list, removes the coordinator, swaps keys | The list must be signed by an admin of the previous list or an anchor and chain to it by hash |
| Replays an older list as if it were newer | Versions must increase by exactly one from what the app accepted; an older or forked list is refused |
| Moves a signed wrapped key to another case, epoch or recipient | All of them are signed; a mismatch is refused |
| Crafts a signature valid in one implementation and not in the other | Same verdict on both sides (above), tested |

## What it does NOT protect

- **The first contact.** Somebody has to compare a fingerprint once – of the anchor (management, the
  centre) and of every person whose key is not vouched for by a list the app already trusts (an
  external member). A server that sits in the middle of that first comparison is not stopped by any
  signature.
- **Withholding.** The server can stop delivering newer lists or keys (a member then keeps seeing the
  last list it accepted). The app shows the version and time of the last list and the coordinator's
  view; the core cannot know that something newer exists (AUDIT.md section 3.3).
- **A signer's own device.** Whoever controls an admin's unlocked app can sign what the admin could.
  Removing the admin in a new list (and a new key epoch) stops further signatures being accepted.
- **What a removed member already saw.** A signature does not take back a key someone already had; the
  app must rotate the key epoch and seal new items under the new key (as before).
- **Content.** Signatures prove who vouched for a key or a list, not that items are confidential or
  fresh – sealing, versions in payloads and high-water marks remain the app's job.
- **Time.** No timestamps are signed by the core; an app that needs them puts them into the data it
  signs (`sign_data`) or into its sealed payloads.
- **Non-repudiation towards third parties.** Signatures are meant for members checking each other, not
  as evidence for a court; the key is personal but derived or stored by the app.

## How Dôverník is expected to use it (shared case, `docs/NAVRH-SPOLOCNY-SPIS.md` section 12)

- **Personal signing key:** `deriveSigningKey(practiceMasterKey, 'dovernik', 'share')` – the same on
  both computers of a therapist and after a restore, so colleagues do not have to compare again after a
  restore (today the sharing key is regenerated). The therapist signs its own P-256 sharing key:
  `signData(seed, 'dovernik|center|<centre>|share-key', sharePub)`; colleagues verify it with the pinned
  signing key instead of comparing `shareFingerprint` again.
- **Centre key / management:** the centre's member list is a manifest (scope `dovernik|center|<centre>`)
  signed by management (admins); the management keys are the anchors every member pins once when
  joining the centre (fingerprint comparison, like `center_key_pin` today). A new key of the centre
  (2-of-3) is wrapped with `signedWrapForDevice` by management and accepted only with a management
  signature.
- **Shared case:** a manifest per case (scope `dovernik|center|<centre>|case|<case>`), version 1 signed
  by the coordinator who creates it. The app checks version 1 with `verifyManifest(blob, [creator])`,
  where the creator's key comes from the accepted centre list (or, for a case of another centre, from a
  pinned key), and every later version with `verifyManifest(blob, management, prev)` – anchors are
  passed per call, so the creator is not an anchor for ever. Every new epoch of the case key is wrapped for each member
  with `signedWrapForDevice(caseKey, member.seal, context, caseId, epoch, signerSeed)` and opened with
  `openSignedWrap(…, { objectId: caseId, version: manifest.epoch }, admins and members of the accepted list)`.
  The `fwd` chain and the case code stay as an extra check. Threats 2, 3 and 4 in the design and the
  residual risk "server together with a removed member forges the next epoch" are closed by the
  signatures: the removed member is no admin of the new list and cannot sign a key the others accept.
- **External member:** not in the centre's list, so the coordinator compares the external member's
  **signing** fingerprint by phone or in person once (instead of the device code), then adds them to
  the case manifest (role `external`, not admin) with their sealing key. The external member pins the
  coordinator's signing key the same way (both read their codes), and uses it as anchor for the case.
- **Invitations:** an invitation is (1) the new manifest version that lists the invitee and (2) the case
  key wrapped for the invitee's sealing key with `signedWrapForDevice`. The invitee accepts the chain
  from version 1 with its anchors (management, or the pinned coordinator for an external) and opens the
  key only if it was signed by a member of that list.

## For the auditor

- The message encoding (length-prefixed fields, kinds) and whether anything should be added to the
  `wrap` statement (we sign the recipient key and the signer key, not a timestamp).
- The equivalence argument for strict (dalek) vs. cofactored (noble) verification with prime-order
  `A` and `R`, and the two torsion vectors.
- The chain rule: anchors may sign any next version; `epoch` may not go down; forks are refused.
- Deriving the signing key from the master key (HKDF with a separate label) vs. a random wrapped key.
