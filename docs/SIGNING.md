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
| `SigningKey::derive` / `deriveSigningKey` | Seed = HKDF-SHA256(key, no salt, info `<app> signing-key v1 <label>`), from a key the app keeps anyway (the master key). The same key on every device of the person and after a restore from backup, nothing new to store or back up. A derived key is replaced by deriving with a **new label** (e.g. `share-2`) – then colleagues compare the new fingerprint once. |
| `public_key` / `signingPublicKey` | 32-byte public key. |
| `fingerprint` / `signingFingerprint` | `3f2a 9c01 …` – the first 80 bits of SHA-256(`regino signing fingerprint v1\|` ‖ key), hex in groups of four. A server would need about 2^80 key generations to find another key with the same code. |
| `sign_data` / `signData`, `verify_data` / `verifyData` | Signature over data bound to a non-empty context. |
| `sign_wrap` / `signWrap`, `verify_wrap` / `verifyWrap` | The sender's signature over a wrapped key (`WrapStatement`: context, object id, version (epoch), **hash of the member list the sender accepted as the latest**, recipient public key, the sender's own public key, the wrapped bytes). `verify_wrap` checks the signature only. |
| `verify_wrap_for` (Rust), `signedWrapForDevice` / `openSignedWrap` (TS) | What apps use: the key must name the list the **recipient** accepted itself as the latest (its hash) and that list's epoch, the sender must be an **admin** of that list (or a passed anchor), the signature must be valid – only then is the key unwrapped. A member who is not admin cannot give a key. |
| `manifest_fingerprint` / `manifestFingerprint` | `3f2a 9c01 …` – code of an accepted list (80 bits of SHA-256(`regino manifest fingerprint v1\|` ‖ hash)), compared with the coordinator to detect a fork. |
| `sign_manifest` / `signManifest` | A signed member list (below). |
| `verify_manifest` / `verifyManifest`, `verify_manifest_chain` / `verifyManifestChain` | Accept a list only if it is for the **expected scope** and continues one already trusted. |
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
| `wrap` | context, object id (1–1024 B), version (u64), list hash (32 B), recipient public key (1–1024 B), signer public key (32 B), wrapped (1–65 536 B) |
| `manifest` | scope (1–1024 B), version (u64, ≥ 1), epoch (u64), prev (32 B), signer public key (32 B), member count (u32, ≤ 1000), then per member sorted by the UTF-8 bytes of the id: id (1–256 B, unique), role (1–256 B), admin (1 B: 0 or 1), signing key (32 B, unique in the list), seal key (0–1024 B) |

Texts are UTF-8 exactly as given – a leading U+FEFF is kept, not stripped, on both sides.

- A `WrappedGroupKey` (TS) is signed as the UTF-8 of `<v>.<e>.<n>.<c>` (`wrappedKeyBytes`); a Rust
  `wrap::wrap_key` blob as its bytes.
- `SignedWrappedKey` (TS, JSON): `{ v: 1, id, ver, m: base64 list hash, w: WrappedGroupKey, k: base64 signer key, s: base64 signature }`.
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
in `A`) – both sides refuse them –, non-canonical `R` encodings (y ≥ p, x = 0 with the sign bit),
`S + L`, an identity `R`, plus Wycheproof `ed25519_test.json` on both sides.

## Member lists and the chain rule

A manifest says: for **scope** (e.g. `dovernik|center|12|case|<id>`), **version** n, key **epoch** e,
following the list with hash **prev**, the members are …, each with a signing key (unique in the list),
an optional sealing key (the P-256 key used by `wrapForDevice`) and a flag **admin** (may sign the next
version and give keys). Roles are the app's own words; the core does not interpret them.

`verify_manifest(blob, scope, anchors, prev)` accepts:

- always: the list is for **`scope`** – the object the app asked for (and `prev`, if given, too). A list
  of case A is never accepted as a list of case B, not even as version 1 signed by the same coordinator;
- **no `prev`** (first list the app sees for this scope): version 1 (prev = 32 zero bytes), signed by
  one of `anchors`;
- **with `prev`**: version = prev + 1, `prev` = hash of the trusted list, epoch not lower, signed by an
  **admin of the trusted list** or by an **anchor**.

`anchors` are keys the app trusts for the scope on its own – pinned after a fingerprint comparison
(e.g. the centre's management) – and are passed per call. An anchor may sign any next version, so a
list whose admins all left can still be continued (by management, recorded in the app's log). The app
stores the last accepted blob (`AcceptedManifest.blob`) and continues from it with
`verify_manifest_chain`.

**Epoch:** the key epoch of the object. It never goes down (refused); the app **raises it whenever
someone is removed** and seals new items only under the key of the new epoch – keeping it is allowed
(adding a member needs no new key). Maximum 2^53 − 1.

**Forks.** The chain rule cannot stop two lists with the same version: two admins may each sign their
own version n + 1, or a removed admin X signs a version n + 1′ while the server withholds the real
n + 1 that removed X – a member who never saw n + 1 accepts n + 1′. Each member accepts the first list
it sees for a version and refuses the other afterwards, so the members split. What limits the damage:

- a wrapped key names the list (`WrapStatement::manifest`) and is accepted only for the list the
  recipient accepted itself (`verify_wrap_for`, `openSignedWrap`) – keys of one branch do not open on
  the other, so X's branch never gets a key from the honest admins and vice versa;
- the app shows the code of the latest list (`manifest_fingerprint`) and asks members to compare it
  with the coordinator when they join, when a key epoch changes and whenever the app finds a second
  list with a version it already has (the server must keep and return all lists; a member who gets a
  different blob for a known version raises an alarm);
- an admin is removed together with a new key epoch, and the removal is made by the coordinator or
  management, whose view other members can compare.

## What it protects

| Attack by the server (or someone controlling it) | With 0.13.0 |
|---|---|
| Hands a member a false public key of a colleague | Signing and sealing keys come from a signed list; a key not in a list signed by a trusted signer is refused – no repeated phone comparison needed |
| Hands a false new case key (new epoch) | `openSignedWrap` refuses a key not signed by an admin of the recipient's accepted list (or an anchor), or signed for another object, epoch, list or recipient |
| Hands a list of another case (e.g. by the same coordinator) | Refused: the scope is checked in every step, also for version 1 |
| Adds itself or a key of its own to the member list, removes the coordinator, swaps keys | The list must be signed by an admin of the previous list or an anchor and chain to it by hash |
| Replays an older list as if it were newer | Versions must increase by exactly one from what the app accepted; an older list, or another list with a version the app already has, is refused. A fork the member sees first is **not** detected by the core (see Forks) |
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
- **Forks** (two lists with the same version, above): only limited by binding keys to the list and by
  comparing the list code with the coordinator.
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
  restore. To replace it (a leaked master key is replaced anyway) derive with a new label.
- **The P-256 sharing key goes into the `seal` field of the member's entry** in the centre's (and the
  case's) signed list – the list gives it an identity (member id) and a version, so a server cannot
  bring back an older sharing key: a new sharing key (e.g. after a restore) means a new list version
  signed by management or the coordinator. Do **not** rely on a bare `signData` over the key – it has
  no version and could be replayed; if a member must vouch for its own key outside a list, sign
  `<member id>|<version>|<key>` with context `dovernik|center|<centre>|share-key` and keep the highest
  version seen.
- **Centre key / management:** the centre's member list is a manifest (scope `dovernik|center|<centre>`,
  sealing keys of members in `seal`) signed by management (admins); the management keys are the anchors every member pins once when
  joining the centre (fingerprint comparison, like `center_key_pin` today). A new key of the centre
  (2-of-3) is wrapped with `signedWrapForDevice` by management and accepted only with a management
  signature.
- **Shared case:** a manifest per case (scope `dovernik|center|<centre>|case|<case>`), version 1 signed
  by the coordinator who creates it. The app checks version 1 with `verifyManifest(blob, caseScope, [creator])`,
  where the creator's key comes from the accepted centre list (or, for a case of another centre, from a
  pinned key), and every later version with `verifyManifest(blob, caseScope, management, prev)` –
  `caseScope` is the case the user opened, anchors are passed per call, so the creator is not an anchor
  for ever. Every new epoch of the case key is wrapped for each member by an **admin** (coordinator) with
  `signedWrapForDevice(caseKey, member.seal, context, caseId, acceptedList, signerSeed)` and opened with
  `openSignedWrap(…, caseId, acceptedList, management)` – only admins of the list the member itself
  accepted, or management, can give it. Removing someone = new list version **and** new epoch. The
  `fwd` chain and the case code stay as an extra check; the app shows `manifestFingerprint` of the
  latest list in the case detail for comparing with the coordinator. Threats 2, 3 and 4 in the design
  are closed by the signatures. The residual risk "server together with a removed member forges the
  next epoch" is reduced, not closed: a removed **non-admin** member cannot sign anything others
  accept; a removed **admin** could sign a fork (version n + 1′) for members who did not yet see the
  removal – keys of that branch are bound to it, and comparing the list code with the coordinator
  reveals it (see Forks).
- **External member:** not in the centre's list, so the coordinator compares the external member's
  **signing** fingerprint by phone or in person once (instead of the device code), then adds them to
  the case manifest (role `external`, not admin) with their sealing key. The external member pins the
  coordinator's signing key the same way (both read their codes), and uses it as anchor for the case
  (and compares the list code once after joining).
- **Invitations:** an invitation is (1) the new manifest version that lists the invitee and (2) the case
  key wrapped for the invitee's sealing key with `signedWrapForDevice`. The invitee accepts the chain
  from version 1 with its anchors (management, or the pinned coordinator for an external) for the
  scope of the case it was invited to, and opens the key only if it names that latest list and was
  signed by an admin of it.

## For the auditor

- The message encoding (length-prefixed fields, kinds) and whether anything should be added to the
  `wrap` statement (we sign the recipient key and the signer key, not a timestamp).
- The equivalence argument for strict (dalek) vs. cofactored (noble) verification with prime-order
  `A` and `R`, and the two torsion vectors.
- The chain rule: scope checked in every step; anchors may sign any next version; `epoch` may not go
  down; forks are not detected by the core – keys are bound to the list hash and apps compare the list
  code (is that sufficient, or should lists be countersigned by members?).
- Deriving the signing key from the master key (HKDF with a separate label) vs. a random wrapped key.
