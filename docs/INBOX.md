# Inbox: a sender without an account seals data to a practice (`ts/src/inbox.ts`)

What the core provides, what it cannot provide, what an app and its web page must do around it, and
how the first app using it (Dôverník, documents and forms for practices) does it. In scope of the
security review (AUDIT.md, question 14).

## Roles

- **Recipient (practice)**: owns one ECDH P-256 inbox key pair (`newInboxKeys`). The private key is
  exported once as PKCS#8 and kept sealed by the app's own keys, so every device of the practice can
  open messages (`importInboxKey`, `openFromInbox`). The public key (65 bytes) is published.
- **Sender (client)**: a person without an account, in a browser, filling in a form or signing a
  document. The page seals the data to the practice's public key (`sealToInbox`) with a fresh
  ephemeral key per message and the context bound as additional data.
- **Server**: publishes the practice's public key, serves the page and its JavaScript, stores and
  forwards sealed messages. It cannot open a message sealed to the practice's real key.

## What the core guarantees, and what it cannot

- A message sealed to key *K* can be opened only with the private key of *K*, only under the same
  context, and any change to it is detected.
- The core cannot tell the sender **whose** key *K* is. If the server gives the sender its own key,
  the server reads the message and can re-seal it to the practice; the practice's own fingerprint
  check (comparing the key the server shows *the practice* with its own) does not see this, because
  the server can show different keys to different parties.
- The page's JavaScript comes from the same server. A server that serves malicious code can leak the
  form before sealing, whatever key is used. **A sender therefore trusts the server completely unless
  the key and the code are checked against something obtained elsewhere.** This must be said plainly
  in the product; the inbox protects against the server's storage and transport being read
  (database leak, backups, hosting staff, a later breach), not against a server that is actively
  hostile at the moment the form is filled in.

## What an app must do around the core

1. **Publish the fingerprint out of band.** `inboxFingerprint(publicKey)` gives 80 bits as
   `"3f2a 9c01 …"`. The practice shows it in its own app and prints it on its paper material (forms,
   letters, a leaflet in the waiting room). The sender's page shows the fingerprint of the key it is
   about to use, with a sentence "compare with the fingerprint your practice gave you".
2. **The practice checks what the server publishes.** After publishing the key and on every download
   of messages the app fetches the practice's public page or profile as a client would and compares
   the published key with its own. A mismatch is shown to the practice and messages are not treated
   as confidential.
3. **Protect the page code.** Serve the form script from a separate static origin or with subresource
   integrity (SRI), publish the hash of the built script next to the sources (as this repository does
   for `tools/open-backup.html`), and check in CI that the served script is built from the pinned
   core commit.
4. **Longer term:** deliver the inbox public key inside an object signed by the practice (the core
   already verifies Ed25519 certificates in `signed.ts`), so a client who has the practice's root key
   or a previous visit's pinned key can verify a new key.

## Flow (as implemented in Dôverník, core pinned to 0.6.0)

1. The practice turns on its page: the app calls `newInboxKeys`, seals the private key with the
   app's master key in its database, and publishes the public key to the API (`PUT /v1/practice`).
2. The practice's page is rendered by the same server; the public key is put into the page
   configuration. The form script (built from this repository's `ts/`) calls
   `sealToInbox(publicKey, "dovernik|request|<rid>", JSON of the answers)`; the request id `rid` is
   generated in the browser.
3. The practice's app downloads the sealed request and opens it with `openFromInbox`.
4. **Not yet done (October 2026):** `inboxFingerprint` is not used anywhere; the client does not see a
   fingerprint, the practice does not print one, and the app does not compare the published key with
   its own. The app's plan is steps 1 and 2 above; step 3 is a recommendation for the web side.

## What an auditor may want to check

- Whether the HKDF salt (ephemeral ‖ recipient public key) and info (`inbox seal v1|<context>`) plus
  the AAD (`inbox message v1|<context>`) bind the message to the recipient and context tightly enough.
- Whether an 80-bit fingerprint, compared by a person, is adequate, and how the page should present it.
- The PKCS#8 export of the inbox private key and its storage sealed by the app's keys on every device
  of a practice.
- The recommendations in "What an app must do" against the threat of a hostile server at form time.
