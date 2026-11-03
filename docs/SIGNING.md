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
| `verify_wrap_for` (Rust), `signedWrapForDevice` / `openSignedWrap` (TS) | What apps use: the key must name the list the **recipient** accepted itself as the latest (its hash) and an epoch **not above** that list's epoch (earlier epochs are allowed, so a new member gets the older keys signed too – no separate key ring), the sender must be an **admin** of that list, the **signer of that list** (a coordinator who hands over in that version) or a passed anchor, the signature must be valid – only then is the key unwrapped. A member who is not admin cannot give a key. `openSignedWrap` returns the epoch. |
| `sign_member_key` / `signMemberKey`, `verify_member_key` / `verifyMemberKey` | A member vouches for its own sealing key (`MemberKey`: scope, member id, version, seal key) with its signing key. Verification takes the expected scope, the **expected member id** and the latest accepted list: the version must be above that member's `seal_version` **in the list** (replay refused even for a new coordinator or after a restore – nothing is kept only locally), and the signer must be that member's signing key. |
| `Signer`, `seedSigner` (TS), `dataMessage` / `wrapMessage` / `manifestMessage` / `memberKeyMessage` (TS), `sign_prepared` (Rust) | Signing outside TypeScript: `signManifest`, `signedWrapForDevice` and `signMemberKey` take a `Signer` (`{ publicKey, sign(message) }`) or a seed. The message builders return the bytes to sign; `sign_prepared` in Rust signs only a well-formed, canonical message of a known kind that names its own key as the signer, and a `data` message only with a context under an allowed prefix when one is given (Dôverník: `dovernik|`). |
| `manifest_fingerprint` / `manifestFingerprint` | `3f2a 9c01 …` – code of an accepted list (80 bits of SHA-256(`regino manifest fingerprint v1\|` ‖ hash)), compared with the coordinator to detect a fork. |
| `sign_manifest` / `signManifest` | A signed member list (below). |
| `verify_manifest` / `verifyManifest`, `verify_manifest_chain` / `verifyManifestChain` | Accept a list only if it is for the **expected scope** and continues one already trusted. |
| `open_manifest` / `openManifest` | Read a blob the app accepted earlier and stored itself (checks format and signature, not trust). |
| `verify_manifest_chain_from_anchor` / `verifyManifestChainFromAnchor` (0.13.1) | For someone who joins or restores without a trusted list: the whole chain from version 1, which is taken with its own signer; every later version must continue the previous one; at least one version must be **signed by an anchor** (its signature confirms all earlier versions through `prev`), otherwise nothing is accepted (fail-closed). With `pinned` (`{ version, hashes }` – the hashes of the last versions up to `version` the app accepted before; one is enough): another hash for a pinned version is a fork (`BadChain`), a chain shorter than the pinned version is withheld (Rust `Error::Withheld`). Returns all accepted versions. |
| `ChainOptions` / `verify_manifest_chain_from_anchor_with` (Rust), options of `verifyManifestChainFromAnchor` (TS) (0.13.2) | Defaults keep 0.13.1. **`signers`**: keys that may sign any next version even when they are no admin of the previous one (e.g. management keys from the accepted centre list) – not for v1 nor for the anchor requirement. **`anchorsMaySign`** (default true): with false an anchor only meets the anchor requirement (e.g. by signing v1, vouching for what came before through `prev`); later versions are signed by an admin of the previous version or one of `signers`. **`pinnedTrusted`**: the pinned versions were accepted before – matching pins meet the anchor requirement and versions up to the pin are checked only for structure, signatures and links; versions above the pin need an admin of the previous version, `signers` or (with `anchorsMaySign`) an anchor. Fork → `BadChain`, withheld → `Withheld`, stranger above the pin → `UntrustedSigner`. |
| `inspect_manifest_chain` / `inspectManifestChain` (0.13.2) | **Structure only, no trust**: scope, version + 1, links, epochs, seal versions, canonical blobs, signatures valid for the signer named in each blob, pins (fork, withheld); bad signature → `BadSignature`. Returns `{ version, epoch, signer, members, hash }` per version for a table management looks at after a restore. **The result is not trustworthy until someone approves it** – it must never be used to accept keys; after approval the app pins the hash of the last version and continues with `pinnedTrusted`. |
| `verify_wrap_for_recipient` (Rust), `openSignedWrap(…, { recipientId })` (TS) (0.13.1) | In addition to the checks above: the recipient must be the member `recipientId` of the list and its `seal` must be the key the wrapped key is for. |
| `group_key_code` / `groupKeyCode`, `group_key_id` / `groupKeyId` (0.13.1) | From a group key (e.g. the case key): a code for comparing by phone (80 bits, `3f2a 9c01 …`, HMAC-SHA256 over a context with a key from HKDF-SHA256 info `regino group-key code v1`) and a key-bound id of 24 hex characters (info `regino group-key id v1`, HMAC over a label). Independent of the sealing keys; replaces the use of `backupChunkName` for these purposes. |
| `verifyEd25519` (TS) | The strict check behind all of the above. |

## Formats (exact bytes)

Every signed message is

```
"RGN-SIG1" ‖ lp(kind) ‖ lp(field1) ‖ lp(field2) …        lp(x) = u32 big-endian length ‖ x
```

so no two different field lists give the same bytes, and a signature of one kind is never valid as
another kind (`kind` is `data`, `wrap`, `manifest` or `member-key`). Numbers are u64 big-endian, at most 2^53 − 1
(the largest whole number TypeScript holds exactly; refused above it on both sides).

| Kind | Fields |
|---|---|
| `data` | context (UTF-8, 1–1024 B), data |
| `wrap` | context, object id (1–1024 B), version (u64), list hash (32 B), recipient public key (1–1024 B), signer public key (32 B), wrapped (1–65 536 B) |
| `member-key` | scope (1–1024 B), member id (1–256 B), version (u64), seal key (1–1024 B) |
| `manifest` | scope (1–1024 B), version (u64, ≥ 1), epoch (u64), prev (32 B), signer public key (32 B), member count (u32, ≤ 1000), then per member sorted by the UTF-8 bytes of the id: id (1–256 B, unique), role (1–256 B), admin (1 B: 0 or 1), signing key (32 B, unique in the list), seal version (u64; 0 exactly when the seal is empty), seal key (0–1024 B) |

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
  **admin of the trusted list** or by an **anchor**; and if a signing key of the trusted list is missing
  (someone removed) or a member's `seal` changed, the epoch must be **higher** (`BadChain` otherwise);
  a changed `seal` also needs a higher `seal_version`, an unchanged one the same. The **first seal**
  of a member (empty → a key) counts as a change: it needs a new epoch and a seal version ≥ 1.

`anchors` are keys the app trusts for the scope on its own – pinned after a fingerprint comparison
(e.g. the centre's management) – and are passed per call. An anchor may sign any next version, so a
list whose admins all left can still be continued (by management, recorded in the app's log). The app
stores the last accepted blob (`AcceptedManifest.blob`) and continues from it with
`verify_manifest_chain`.

**Epoch:** the key epoch of the object. It never goes down (refused). The core **requires a higher
epoch whenever someone is removed or a sealing key changes** (above); adding members or changing roles
may keep it. The app seals new items only under the key of the latest epoch and wraps the new key for
the remaining members. Maximum 2^53 − 1.

**Handing over coordination** works in one version: the old coordinator signs version n + 1 in which
the new coordinator is admin and it may be absent itself; because it signed n + 1, its wrapped keys
for n + 1 are still accepted (`verify_wrap_for` allows the list's signer). The new coordinator signs
everything after that.

The outgoing coordinator **knows the key of the new epoch** it created in n + 1 (it wrapped it). If it
must really be excluded from what follows, the new coordinator rotates the epoch once more in n + 2
(a new key wrapped only for the remaining members) and items from then on are sealed under that key.

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
  management, whose view other members can compare;
- (0.13.1) a member who joins or restores verifies the whole chain with
  `verify_manifest_chain_from_anchor` and passes the versions it pinned before: a fork of a pinned
  version or a withheld newer list is refused instead of accepted silently;
- (0.13.2) after a restore without any trusted list, management can look at the chain with
  `inspect_manifest_chain` (a table of versions, signers and members – **untrusted** until they approve
  it); once approved, the app pins the last hash and verifies later updates with `pinned_trusted`, so
  the anchor need not sign again.

**Rules for the chain options (after the review of 0.13.2):**

- **Anchors are not put into `signers`.** `signers` may sign any next version; an anchor there would
  sign later versions even with `anchors_may_sign = false` and so undo that choice. Keep the two sets
  disjoint (management keys that should sign every version go into `signers`, the key that vouches for
  the chain into `anchors`).
- **Pin the highest accepted version** – one hash, of the latest version, is enough (the `prev` links
  fix all earlier ones); pinning an older version leaves the versions above it to the trust rules.
- **Keep pins encrypted** (sealed in the app's own database with its keys, never in plain files or on
  the server): with `pinned_trusted` a pin replaces the anchor requirement, so whoever can write a pin
  can make the app trust a chain.
- `signers` never start a chain: version 1 is taken with its own signer and the anchor requirement still
  applies; a chain signed at version 1 by a key from `signers` (and not an anchor) is refused unless a
  later version is signed by an anchor or a trusted pin matches.

**Performance (0.13.3):** the check of a signing public key (canonical point, not of small order,
torsion-free – a scalar multiplication) is a pure function of its 32 bytes; TypeScript remembers the
verdict for the last 4096 keys (`SIGNING_KEY_CACHE`, `clearSigningKeyCache`), because a chain of lists
repeats the same member keys in every version. Results never depend on the cache. Each version of a
chain is decoded, re-encoded (canonical check) and its signature verified exactly once. Benchmark
(`npm run bench` in `ts/`, `cargo run --release -p regino-keys --example bench_chain`): 15 members ×
5 versions – TypeScript 115 ms before, 35 ms with an empty cache and 16 ms with a warm one; Rust 4.4 ms
(no cache – it would need shared mutable state in the library for a gain of a few milliseconds).

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

- **Personal signing key – derived and used only in Rust:** the master key never leaves Rust, so the
  Tauri side derives `SigningKey::derive(&master, "dovernik", "share")` – the same on both computers of
  a therapist and after a restore – and exposes one command that calls `sign::sign_prepared`. TypeScript
  never sees a seed: it builds the message (`wrapMessage`, `manifestMessage`, `memberKeyMessage`) inside
  `signManifest` / `signedWrapForDevice` / `signMemberKey` with a `Signer` whose `sign` calls that
  command, and does all **verifying** itself. The command calls `sign_prepared(&key, msg,
  Some("dovernik|"))`, which refuses anything that is not a canonical message of a known kind naming
  this key as the signer, and (since 0.13.1 for every kind) a `data` context, `wrap` context, `manifest`
  scope or `member-key` scope outside `dovernik|…`. This is **not** a guard against the
  web view itself: code running there can still get any statement of these kinds signed (a list, a
  wrapped key, a member key); it only stops the command from signing arbitrary bytes or messages of other
  protocols. The app keeps the web view's code trusted (no remote content, CSP). To replace the key,
  derive with a new label.
- **The P-256 sharing key goes into the `seal` field of the member's entry** in the centre's (and the
  case's) signed list. The member first vouches for it with `signMemberKey({ scope, memberId, version,
  seal })`; an admin puts a `seal` into a list **only after `verifyMemberKey(signer, statement, sig,
  scope, memberId, acceptedList)`** – the version must be above that member's `sealVersion` in the
  accepted list, and the new list carries the statement's version as `sealVersion`. A new sharing key
  (e.g. after a restore) therefore needs a new statement and a new list version with a new epoch; a
  server cannot bring back an older key, not even to a new coordinator or a restored app, because the
  last version is in the signed list. The first sharing key of a member is a change as well (new
  epoch). A bare `signData` over the key is not used (no version, could be replayed).
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
  `signedWrapForDevice(caseKey, member.seal, context, caseId, acceptedList, rustSigner)` and opened with
  `openSignedWrap(…, caseId, acceptedList, management)` – only admins (or the signer) of the list the
  member itself accepted, or management, can give it. A new member also gets the keys of earlier
  epochs, each signed: `signedWrapForDevice(oldKey, …, acceptedList, rustSigner, oldEpoch)`. Removing
  someone = new list version **and** new epoch (enforced by the core). The
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
  scope of the case it was invited to, and opens the keys (current and earlier epochs) only if they
  name that latest list and were signed by an admin or the signer of it.

## For the auditor

- The message encoding (length-prefixed fields, kinds) and whether anything should be added to the
  `wrap` statement (we sign the recipient key and the signer key, not a timestamp).
- The equivalence argument for strict (dalek) vs. cofactored (noble) verification with prime-order
  `A` and `R`, and the two torsion vectors.
- The chain rule: scope checked in every step; anchors may sign any next version; `epoch` may not go
  down; forks are not detected by the core – keys are bound to the list hash and apps compare the list
  code (is that sufficient, or should lists be countersigned by members?).
- Deriving the signing key from the master key (HKDF with a separate label) vs. a random wrapped key.
- `sign_prepared`: parsing and rebuilding the message (known kind, field count, own key as signer,
  canonical manifest, optional `data` prefix) limits a signing command exposed to the web view to these
  statements – is that the right boundary?
- The epoch rule (removal or changed seal ⇒ higher epoch) and wraps of earlier epochs bound to the
  latest list.
