//! Signatures (Ed25519, `ed25519-dalek`, strict RFC 8032 verification) – so a server that carries keys
//! between people cannot pass off its own key as a colleague's, or its own group key as a new epoch.
//! The same computation exists in TypeScript (`ts/src/signing.ts`, `@noble/ed25519`); the shared fixed
//! vectors `testvectors/regino/signing-0.13.0.json` guard that both give the same bytes. Model, what it
//! protects and what not: `docs/SIGNING.md`.
//!
//! - [`SigningKey`] – a personal signing key: 32 random bytes ([`SigningKey::generate`]) kept wrapped like
//!   any other key (`wrap::wrap_key` of [`SigningKey::seed`]), or derived from a key the app already keeps
//!   (the master key) with HKDF-SHA256 ([`SigningKey::derive`]) – then it is the same on every device of
//!   the person and after a restore, without being stored anywhere.
//! - [`fingerprint`] – a short code of a public key ("3f2a 9c01 …", 80 bits) people compare by phone or
//!   in person once, then pin.
//! - [`sign_data`] / [`verify_data`] – a signature over data bound to a context.
//! - [`sign_wrap`] / [`verify_wrap_for`] – the sender's signature over a key wrapped for a recipient
//!   (context, object id, epoch, hash of the accepted member list, recipient public key, the sender's
//!   public key and the wrapped bytes); accepted only from an admin of the list the recipient accepted.
//! - [`Manifest`] – a signed list of members (scope, version, key epoch, hash of the previous list,
//!   members with their public keys); [`verify_manifest`] / [`verify_manifest_chain`] accept a list only if
//!   it continues one already trusted and is signed by one of its admins (or by an anchor).
//!
//! - [`sign_member_key`] / [`verify_member_key`] – a member vouches for its own sealing key (versioned).
//! - [`sign_prepared`] – signs a message built elsewhere (TypeScript `Signer`), only if it is canonical,
//!   of a known kind and names this key as the signer – so the signing key can stay in Rust.
//!
//! Every signed message is `RGN-SIG1 || lp(kind) || lp(field) …` with `lp(x) = u32 BE length || x`:
//! fields are never ambiguous, and a signature of one kind can never be taken for another.

use ed25519_dalek::{Signature, Signer, VerifyingKey};
use hkdf::Hkdf;
use sha2::{Digest, Sha256};
use zeroize::{Zeroize, Zeroizing};

use crate::{Error, Key, KEY_LEN};

const MAGIC: &[u8; 8] = b"RGN-SIG1";
/// Length of a signature (bytes).
pub const SIGNATURE_LEN: usize = 64;
/// Length of a public key (bytes).
pub const PUBLIC_KEY_LEN: usize = 32;
/// Longest context, scope or object id (bytes of UTF-8).
pub const MAX_CONTEXT: usize = 1024;
/// Longest member id or role (bytes of UTF-8).
pub const MAX_NAME: usize = 256;
/// Longest additional public key of a member (e.g. its P-256 sealing key) or recipient key.
pub const MAX_KEY: usize = 1024;
/// Most members in one list.
pub const MAX_MEMBERS: usize = 1000;
/// Largest wrapped key in a [`WrapStatement`].
pub const MAX_WRAPPED: usize = 65536;
/// Largest version or epoch: 2^53 − 1 (the largest whole number TypeScript holds exactly).
pub const MAX_VERSION: u64 = (1 << 53) - 1;

/// A personal Ed25519 signing key; its memory is zeroed when dropped.
pub struct SigningKey(ed25519_dalek::SigningKey);

/// An Ed25519 public key – checked to be a valid point that is not of small order.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct PublicKey([u8; PUBLIC_KEY_LEN]);

impl SigningKey {
    /// A new random signing key. Keep it only wrapped: `wrap::wrap_key(kek, &key.seed(), context)`.
    pub fn generate() -> Result<SigningKey, Error> {
        Ok(SigningKey::from_seed(&Key::generate()?))
    }

    /// The signing key from its 32-byte seed (e.g. just unwrapped with `wrap::unwrap_key`).
    pub fn from_seed(seed: &Key) -> SigningKey {
        SigningKey(ed25519_dalek::SigningKey::from_bytes(seed.as_bytes()))
    }

    /// The seed – the only thing to store (wrapped).
    pub fn seed(&self) -> Key {
        let bytes = Zeroizing::new(self.0.to_bytes());
        Key::from_bytes(*bytes)
    }

    /// Signing key derived from a key the app keeps anyway (e.g. the master key) with HKDF-SHA256,
    /// info `<app> signing-key v1 <label>` (app: lowercase letters and digits; label: lowercase letters,
    /// digits and `-`, e.g. `share`). The same key and label give the same signing key on every device;
    /// a new label (e.g. `share-2`) gives a new, unrelated signing key – the way to replace a derived key.
    pub fn derive(key: &Key, app: &str, label: &str) -> Result<SigningKey, Error> {
        if !crate::device::ok_name(app, 2) || app.contains('-') || !crate::device::ok_name(label, 3) {
            return Err(Error::Format);
        }
        let mut seed = Zeroizing::new([0u8; KEY_LEN]);
        // the PRK is wiped here; the HMAC state inside `Hkdf` is wiped on drop (`hmac`/`sha2` feature `zeroize`)
        let (mut prk, hk) = Hkdf::<Sha256>::extract(None, key.as_bytes());
        prk.as_mut_slice().zeroize();
        hk.expand(format!("{app} signing-key v1 {label}").as_bytes(), seed.as_mut()).map_err(|_| Error::Format)?;
        Ok(SigningKey(ed25519_dalek::SigningKey::from_bytes(&seed)))
    }

    pub fn public_key(&self) -> PublicKey {
        PublicKey(self.0.verifying_key().to_bytes())
    }

    fn sign_message(&self, message: &[u8]) -> [u8; SIGNATURE_LEN] {
        self.0.sign(message).to_bytes()
    }
}

impl std::fmt::Debug for SigningKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("SigningKey(***)")
    }
}

impl PublicKey {
    /// Refuses bytes that are not a canonical point or are a point of small order (`Error::Format`).
    pub fn from_bytes(bytes: &[u8]) -> Result<PublicKey, Error> {
        let b: [u8; PUBLIC_KEY_LEN] = bytes.try_into().map_err(|_| Error::Format)?;
        let k = VerifyingKey::from_bytes(&b).map_err(|_| Error::Format)?;
        // canonical encoding only (the TypeScript side refuses y >= p as well); no small-order point and
        // no torsion component – with torsion-free keys the strict check here and the cofactored check
        // of `@noble/ed25519` accept exactly the same signatures (docs/SIGNING.md)
        let p = k.to_edwards();
        if k.is_weak() || !p.is_torsion_free() || p.compress().to_bytes() != b {
            return Err(Error::Format);
        }
        Ok(PublicKey(b))
    }

    pub fn as_bytes(&self) -> &[u8; PUBLIC_KEY_LEN] {
        &self.0
    }

    fn verify_message(&self, message: &[u8], signature: &[u8]) -> Result<(), Error> {
        let sig: [u8; SIGNATURE_LEN] = signature.try_into().map_err(|_| Error::BadSignature)?;
        let key = VerifyingKey::from_bytes(&self.0).map_err(|_| Error::BadSignature)?;
        key.verify_strict(message, &Signature::from_bytes(&sig)).map_err(|_| Error::BadSignature)
    }
}

/// Short code of a public key for comparing by phone or in person: the first 80 bits of
/// SHA-256(`regino signing fingerprint v1|` || key) as hex in groups of four ("3f2a 9c01 …").
pub fn fingerprint(key: &PublicKey) -> String {
    code(b"regino signing fingerprint v1|", key.as_bytes())
}

fn code(label: &[u8], bytes: &[u8]) -> String {
    let mut h = Sha256::new();
    h.update(label);
    h.update(bytes);
    let d = h.finalize();
    let hex: Vec<String> = d[..10].chunks(2).map(|c| format!("{:02x}{:02x}", c[0], c[1])).collect();
    hex.join(" ")
}

fn lp(out: &mut Vec<u8>, field: &[u8]) {
    out.extend_from_slice(&(field.len() as u32).to_be_bytes());
    out.extend_from_slice(field);
}

fn message(kind: &str, fields: &[&[u8]]) -> Vec<u8> {
    let mut m = MAGIC.to_vec();
    lp(&mut m, kind.as_bytes());
    for f in fields {
        lp(&mut m, f);
    }
    m
}

fn text(s: &str, max: usize) -> Result<&[u8], Error> {
    if s.is_empty() {
        return Err(Error::EmptyContext);
    }
    if s.len() > max {
        return Err(Error::Format);
    }
    Ok(s.as_bytes())
}

fn data_message(context: &str, data: &[u8]) -> Result<Vec<u8>, Error> {
    Ok(message("data", &[text(context, MAX_CONTEXT)?, data]))
}

/// Signs data bound to a context (e.g. `dovernik|center|12|share-key`); empty context = `Error::EmptyContext`.
pub fn sign_data(key: &SigningKey, context: &str, data: &[u8]) -> Result<[u8; SIGNATURE_LEN], Error> {
    Ok(key.sign_message(&data_message(context, data)?))
}

/// Checks a signature made by [`sign_data`]; `Error::BadSignature` for anything else.
pub fn verify_data(key: &PublicKey, context: &str, data: &[u8], signature: &[u8]) -> Result<(), Error> {
    key.verify_message(&data_message(context, data)?, signature)
}

/// What the sender of a wrapped key vouches for. `wrapped` is the wrapped key exactly as stored – for
/// a TypeScript `WrappedGroupKey` the UTF-8 of `<v>.<e>.<n>.<c>` (`wrappedKeyBytes` in `signing.ts`),
/// for a Rust `wrap::wrap_key` blob its bytes.
#[derive(Clone, Copy, Debug)]
pub struct WrapStatement<'a> {
    /// The context the key was wrapped under (the same string as for wrapping).
    pub context: &'a str,
    /// What the key opens (e.g. the id of a shared case).
    pub object_id: &'a str,
    /// Key version or epoch.
    pub version: u64,
    /// [`AcceptedManifest::hash`] of the member list the sender had accepted as the latest when it wrapped
    /// the key – the recipient takes the key only for the list it accepted itself (forks show up).
    pub manifest: [u8; 32],
    /// The recipient's public key the key was wrapped for (e.g. 65-byte P-256 point).
    pub recipient: &'a [u8],
    pub wrapped: &'a [u8],
}

fn wrap_message(st: &WrapStatement, signer: &PublicKey) -> Result<Vec<u8>, Error> {
    if st.version > MAX_VERSION || st.recipient.is_empty() || st.recipient.len() > MAX_KEY || st.wrapped.is_empty() || st.wrapped.len() > MAX_WRAPPED {
        return Err(Error::Format);
    }
    let version = st.version.to_be_bytes();
    Ok(message(
        "wrap",
        &[text(st.context, MAX_CONTEXT)?, text(st.object_id, MAX_CONTEXT)?, &version, &st.manifest, st.recipient, signer.as_bytes(), st.wrapped],
    ))
}

/// The sender signs a key it wrapped for a recipient; its own public key is part of what is signed.
pub fn sign_wrap(key: &SigningKey, st: &WrapStatement) -> Result<[u8; SIGNATURE_LEN], Error> {
    Ok(key.sign_message(&wrap_message(st, &key.public_key())?))
}

/// Checks the sender's signature only – **not** whether the sender may give this key. Apps use
/// [`verify_wrap_for`]; this is for keys outside a member list.
pub fn verify_wrap(signer: &PublicKey, st: &WrapStatement, signature: &[u8]) -> Result<(), Error> {
    signer.verify_message(&wrap_message(st, signer)?, signature)
}

/// The recipient checks a wrapped key against the member list it accepted itself as the latest:
/// the statement must name that list (`manifest` = its hash) and an epoch not above the list's (`version`
/// ≤ epoch – a new member also gets the keys of earlier epochs, signed), the signer must be an **admin** of
/// that list, the **signer of that list** (so a coordinator who hands over in that version can still give
/// its keys) or one of `anchors`, and the signature must be valid. `Error::BadChain` when the statement is
/// for another list or a later epoch, `Error::UntrustedSigner` when the signer may not give it.
pub fn verify_wrap_for(
    list: &AcceptedManifest,
    anchors: &[PublicKey],
    signer: &PublicKey,
    st: &WrapStatement,
    signature: &[u8],
) -> Result<(), Error> {
    if st.manifest != list.hash || st.version > list.manifest.epoch {
        return Err(Error::BadChain);
    }
    if !anchors.contains(signer) && list.signer != *signer && !list.manifest.member_by_key(signer).is_some_and(|m| m.admin) {
        return Err(Error::UntrustedSigner);
    }
    verify_wrap(signer, st, signature)
}

/// A member vouches for its own sealing key: scope, its member id, a version that only goes up, the key.
/// Signed with the member's signing key; an admin puts a `seal` into a list only with a valid statement of
/// a higher version than the one it saw before (docs/SIGNING.md).
#[derive(Clone, Copy, Debug)]
pub struct MemberKey<'a> {
    pub scope: &'a str,
    pub member_id: &'a str,
    pub version: u64,
    pub seal: &'a [u8],
}

fn member_key_message(mk: &MemberKey) -> Result<Vec<u8>, Error> {
    if mk.version > MAX_VERSION || mk.seal.is_empty() || mk.seal.len() > MAX_KEY {
        return Err(Error::Format);
    }
    Ok(message("member-key", &[text(mk.scope, MAX_CONTEXT)?, text(mk.member_id, MAX_NAME)?, &mk.version.to_be_bytes(), mk.seal]))
}

/// The member signs its own sealing key.
pub fn sign_member_key(key: &SigningKey, mk: &MemberKey) -> Result<[u8; SIGNATURE_LEN], Error> {
    Ok(key.sign_message(&member_key_message(mk)?))
}

/// Checks a member's statement about its sealing key before an admin puts it into a list:
/// - for `scope` and for the member `member_id` the admin means (`Error::BadChain` otherwise);
/// - if `list` (the latest list the admin accepted for this scope) has a member with that id: the version
///   must be above its `seal_version` (replay of an older statement – `Error::BadChain`) and `signer` must
///   be that member's signing key (`Error::UntrustedSigner`); the last version comes from the signed list,
///   not from local memory, so a new coordinator or a restored app refuses an older statement too;
/// - a valid signature of `signer` (`Error::BadSignature`).
pub fn verify_member_key(
    signer: &PublicKey,
    mk: &MemberKey,
    signature: &[u8],
    scope: &str,
    member_id: &str,
    list: Option<&Manifest>,
) -> Result<(), Error> {
    let msg = member_key_message(mk)?;
    if mk.scope != scope || mk.member_id != member_id || list.is_some_and(|l| l.scope != scope) {
        return Err(Error::BadChain);
    }
    if let Some(m) = list.and_then(|l| l.members.iter().find(|m| m.id == member_id)) {
        if mk.version <= m.seal_version {
            return Err(Error::BadChain);
        }
        if &m.sign != signer {
            return Err(Error::UntrustedSigner);
        }
    }
    signer.verify_message(&msg, signature)
}

/// Signs a message prepared elsewhere (e.g. by the TypeScript side: `wrapMessage`, `manifestMessage`,
/// `memberKeyMessage`, `dataMessage`) – for apps that keep the signing key in Rust. The message must be a
/// well-formed `RGN-SIG1` message of a known kind with the right number of fields; a `wrap` or `manifest`
/// must name this key as the signer, and a `manifest` must decode to a valid list; a `data` message must
/// have a context starting with `data_prefix` when one is given (Dôverník: `dovernik|`). Anything else is
/// refused (`Error::Format`). This limits what a caller can get signed to statements of these kinds – it is
/// still a signing service for any such statement the caller builds, so the app decides which
/// statements to send (docs/SIGNING.md).
pub fn sign_prepared(key: &SigningKey, message: &[u8], data_prefix: Option<&str>) -> Result<[u8; SIGNATURE_LEN], Error> {
    if message.get(..MAGIC.len()) != Some(&MAGIC[..]) {
        return Err(Error::Format);
    }
    let mut r = Reader(&message[MAGIC.len()..]);
    let kind = r.field()?;
    let mut fields = Vec::new();
    while !r.0.is_empty() {
        fields.push(r.field()?);
    }
    let me = key.public_key();
    let again = match (kind, fields.as_slice()) {
        (b"data", [ctx, data]) => {
            let ctx = std::str::from_utf8(ctx).map_err(|_| Error::Format)?;
            if data_prefix.is_some_and(|p| !ctx.starts_with(p)) {
                return Err(Error::Format);
            }
            data_message(ctx, data)?
        }
        (b"wrap", [ctx, id, ver, list, recipient, signer, wrapped]) => {
            if *signer != me.as_bytes() {
                return Err(Error::Format);
            }
            let st = WrapStatement {
                context: std::str::from_utf8(ctx).map_err(|_| Error::Format)?,
                object_id: std::str::from_utf8(id).map_err(|_| Error::Format)?,
                version: u64::from_be_bytes((*ver).try_into().map_err(|_| Error::Format)?),
                manifest: (*list).try_into().map_err(|_| Error::Format)?,
                recipient,
                wrapped,
            };
            wrap_message(&st, &me)?
        }
        (b"member-key", [scope, id, ver, seal]) => member_key_message(&MemberKey {
            scope: std::str::from_utf8(scope).map_err(|_| Error::Format)?,
            member_id: std::str::from_utf8(id).map_err(|_| Error::Format)?,
            version: u64::from_be_bytes((*ver).try_into().map_err(|_| Error::Format)?),
            seal,
        })?,
        (b"manifest", _) => {
            let (manifest, signer) = decode_manifest(message)?;
            if signer != me {
                return Err(Error::Format);
            }
            manifest.message(&me)?
        }
        _ => return Err(Error::Format),
    };
    // canonical: rebuilding the message from its fields must give the same bytes
    if again != message {
        return Err(Error::Format);
    }
    Ok(key.sign_message(message))
}

/// A member of a signed list.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Member {
    /// The app's id of the member (account id); unique in the list.
    pub id: String,
    /// The app's role name (e.g. `coordinator`, `member`, `external`); not interpreted here.
    pub role: String,
    /// May sign the next version of the list.
    pub admin: bool,
    /// The member's signing key.
    pub sign: PublicKey,
    /// Another public key of the member the list vouches for, e.g. its P-256 key for wrapping
    /// (`wrapForDevice`); may be empty.
    pub seal: Vec<u8>,
    /// Version of the member's statement about `seal` ([`MemberKey::version`]); 0 exactly when `seal` is
    /// empty. A new `seal` in the next list needs a higher version (and a new epoch).
    pub seal_version: u64,
}

/// A list of members of a shared object (a case, a centre), signed by an admin of the previous version.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Manifest {
    /// What the list is for, e.g. `dovernik|center|12|case|<id>`.
    pub scope: String,
    /// 1 for the first list, then exactly +1 for every change.
    pub version: u64,
    /// Key epoch of the object: never goes down; the app raises it whenever someone is removed (and seals
    /// new items only under the key of the new epoch). At most [`MAX_VERSION`].
    pub epoch: u64,
    /// [`AcceptedManifest::hash`] of the previous version; 32 zero bytes for version 1.
    pub prev: [u8; 32],
    /// Sorted by id when signed.
    pub members: Vec<Member>,
}

/// A list that passed [`verify_manifest`]: the list, who signed it, its hash and the signed blob
/// (store the blob to continue the chain later; [`open_manifest`] reads it back).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AcceptedManifest {
    pub manifest: Manifest,
    pub signer: PublicKey,
    /// SHA-256 of the whole blob – goes into `prev` of the next version.
    pub hash: [u8; 32],
    pub blob: Vec<u8>,
}

impl Manifest {
    /// The next version after `prev` with new members (scope, epoch and the chain link are taken over).
    pub fn next(prev: &AcceptedManifest, members: Vec<Member>) -> Manifest {
        Manifest {
            scope: prev.manifest.scope.clone(),
            version: prev.manifest.version + 1,
            epoch: prev.manifest.epoch,
            prev: prev.hash,
            members,
        }
    }

    /// The member with this signing key, if any.
    pub fn member_by_key(&self, key: &PublicKey) -> Option<&Member> {
        self.members.iter().find(|m| &m.sign == key)
    }

    fn message(&self, signer: &PublicKey) -> Result<Vec<u8>, Error> {
        if self.version == 0 || self.version > MAX_VERSION || self.epoch > MAX_VERSION || (self.version == 1) != (self.prev == [0u8; 32]) || self.members.len() > MAX_MEMBERS {
            return Err(Error::Format);
        }
        let mut members: Vec<&Member> = self.members.iter().collect();
        members.sort_by(|a, b| a.id.as_bytes().cmp(b.id.as_bytes()));
        if members.windows(2).any(|w| w[0].id == w[1].id) {
            return Err(Error::Format);
        }
        // one signing key belongs to one member only
        let mut keys: Vec<&[u8; 32]> = members.iter().map(|m| m.sign.as_bytes()).collect();
        keys.sort();
        if keys.windows(2).any(|w| w[0] == w[1]) {
            return Err(Error::Format);
        }
        let version = self.version.to_be_bytes();
        let epoch = self.epoch.to_be_bytes();
        let count = (members.len() as u32).to_be_bytes();
        let seal_versions: Vec<[u8; 8]> = members.iter().map(|m| m.seal_version.to_be_bytes()).collect();
        let mut fields: Vec<&[u8]> = vec![text(&self.scope, MAX_CONTEXT)?, &version, &epoch, &self.prev, signer.as_bytes(), &count];
        for (m, sv) in members.iter().zip(&seal_versions) {
            if m.seal.len() > MAX_KEY || m.seal_version > MAX_VERSION || m.seal.is_empty() != (m.seal_version == 0) {
                return Err(Error::Format);
            }
            fields.extend_from_slice(&[text(&m.id, MAX_NAME)?, text(&m.role, MAX_NAME)?, if m.admin { &[1u8][..] } else { &[0u8][..] }, m.sign.as_bytes(), sv, &m.seal]);
        }
        Ok(message("manifest", &fields))
    }
}

/// Signs a list; the blob is `message || signature` and is carried as is (the server stores it opaque).
pub fn sign_manifest(key: &SigningKey, manifest: &Manifest) -> Result<Vec<u8>, Error> {
    let mut blob = manifest.message(&key.public_key())?;
    let sig = key.sign_message(&blob);
    blob.extend_from_slice(&sig);
    Ok(blob)
}

struct Reader<'a>(&'a [u8]);

impl<'a> Reader<'a> {
    fn field(&mut self) -> Result<&'a [u8], Error> {
        let len = u32::from_be_bytes(self.0.get(..4).ok_or(Error::Format)?.try_into().map_err(|_| Error::Format)?) as usize;
        let end = len.checked_add(4).ok_or(Error::Format)?;
        let f = self.0.get(4..end).ok_or(Error::Format)?;
        self.0 = &self.0[end..];
        Ok(f)
    }
    fn fixed<const N: usize>(&mut self) -> Result<[u8; N], Error> {
        self.field()?.try_into().map_err(|_| Error::Format)
    }
    fn text(&mut self) -> Result<String, Error> {
        String::from_utf8(self.field()?.to_vec()).map_err(|_| Error::Format)
    }
}

/// Reads a blob and checks its signature against the key named inside – **not** whether that key is
/// trusted. Only for a blob the app accepted before with [`verify_manifest`] and stored itself.
pub fn open_manifest(blob: &[u8]) -> Result<AcceptedManifest, Error> {
    if blob.len() < MAGIC.len() + SIGNATURE_LEN {
        return Err(Error::Format);
    }
    let (msg, sig) = blob.split_at(blob.len() - SIGNATURE_LEN);
    let (manifest, signer) = decode_manifest(msg)?;
    signer.verify_message(msg, sig)?;
    Ok(AcceptedManifest { manifest, signer, hash: Sha256::digest(blob).into(), blob: blob.to_vec() })
}

/// The list and its signer from a `manifest` message (without the signature); canonical only.
fn decode_manifest(msg: &[u8]) -> Result<(Manifest, PublicKey), Error> {
    if msg.get(..MAGIC.len()) != Some(&MAGIC[..]) {
        return Err(Error::Format);
    }
    let mut r = Reader(&msg[MAGIC.len()..]);
    if r.field()? != b"manifest" {
        return Err(Error::Format);
    }
    let scope = r.text()?;
    let version = u64::from_be_bytes(r.fixed()?);
    let epoch = u64::from_be_bytes(r.fixed()?);
    let prev: [u8; 32] = r.fixed()?;
    let signer = PublicKey::from_bytes(r.field()?)?;
    let count = u32::from_be_bytes(r.fixed()?) as usize;
    if count > MAX_MEMBERS {
        return Err(Error::Format);
    }
    let mut members = Vec::with_capacity(count);
    for _ in 0..count {
        let id = r.text()?;
        let role = r.text()?;
        let admin = match r.field()? {
            [0] => false,
            [1] => true,
            _ => return Err(Error::Format),
        };
        let sign = PublicKey::from_bytes(r.field()?)?;
        let seal_version = u64::from_be_bytes(r.fixed()?);
        members.push(Member { id, role, admin, sign, seal: r.field()?.to_vec(), seal_version });
    }
    if !r.0.is_empty() {
        return Err(Error::Format);
    }
    let manifest = Manifest { scope, version, epoch, prev, members };
    // canonical: encoding the decoded list again must give the same bytes (sorted ids, limits)
    if manifest.message(&signer)? != msg {
        return Err(Error::Format);
    }
    Ok((manifest, signer))
}

/// A new list version must raise the epoch when a signing key of the previous version is missing or a
/// member's `seal` changed (`Error::BadChain` otherwise); adding members may keep it. A changed `seal`
/// also needs a higher `seal_version`, an unchanged one the same (`Error::BadChain`).
///
/// Accepts a list only if it is for `scope` (the object the app asked for) and continues what the app
/// already trusts:
/// - `prev = None` (the first list the app sees for this scope): version 1, signed by one of `anchors`;
/// - `prev = Some(p)`: `p` for the same scope, version `p + 1`, `prev` = hash of `p`, epoch not lower, signed by
///   an admin of `p` or by one of `anchors`.
///
/// `anchors` are keys the app trusts for the scope by itself (pinned after comparing [`fingerprint`]s,
/// e.g. the centre's management). `Error::UntrustedSigner` when the signature is valid but the signer
/// may not sign this list, `Error::BadChain` when it does not continue `prev`.
///
/// Two admins (or a removed admin together with a server that withholds the newer list) can sign two
/// different lists with the same version; each member accepts the first it sees. The core cannot detect
/// such a fork alone – wrapped keys name the list (`WrapStatement::manifest`), and the app compares the
/// code of the latest list ([`manifest_fingerprint`]) with the coordinator (docs/SIGNING.md).
pub fn verify_manifest(blob: &[u8], scope: &str, anchors: &[PublicKey], prev: Option<&AcceptedManifest>) -> Result<AcceptedManifest, Error> {
    let a = open_manifest(blob)?;
    let m = &a.manifest;
    if m.scope != scope || prev.is_some_and(|p| p.manifest.scope != scope) {
        return Err(Error::BadChain);
    }
    let anchor = anchors.contains(&a.signer);
    match prev {
        None => {
            if m.version != 1 {
                return Err(Error::BadChain);
            }
            if !anchor {
                return Err(Error::UntrustedSigner);
            }
        }
        Some(p) => {
            if m.version != p.manifest.version + 1 || m.prev != p.hash || m.epoch < p.manifest.epoch {
                return Err(Error::BadChain);
            }
            // someone removed, or a sealing key changed: the old key must not be used any more – new epoch
            let removed_or_changed = p.manifest.members.iter().any(|old| m.member_by_key(&old.sign).is_none_or(|new| new.seal != old.seal));
            if removed_or_changed && m.epoch <= p.manifest.epoch {
                return Err(Error::BadChain);
            }
            // a new seal needs a higher seal_version (no older statement brought back); an unchanged one keeps it
            let bad_seal_version = p.manifest.members.iter().any(|old| {
                m.member_by_key(&old.sign).is_some_and(|new| if new.seal == old.seal { new.seal_version != old.seal_version } else { new.seal_version <= old.seal_version })
            });
            if bad_seal_version {
                return Err(Error::BadChain);
            }
            if !anchor && !p.manifest.member_by_key(&a.signer).is_some_and(|x| x.admin) {
                return Err(Error::UntrustedSigner);
            }
        }
    }
    Ok(a)
}

/// Follows `blobs` in order from `trusted` (or from version 1 when `None`) and returns the last list.
/// An empty chain returns `trusted` itself (`Error::BadChain` if there is none).
pub fn verify_manifest_chain(blobs: &[&[u8]], scope: &str, anchors: &[PublicKey], trusted: Option<&AcceptedManifest>) -> Result<AcceptedManifest, Error> {
    if trusted.is_some_and(|t| t.manifest.scope != scope) {
        return Err(Error::BadChain);
    }
    let mut cur = trusted.cloned();
    for b in blobs {
        cur = Some(verify_manifest(b, scope, anchors, cur.as_ref())?);
    }
    cur.ok_or(Error::BadChain)
}

/// Short code of an accepted list ("3f2a 9c01 …", 80 bits of SHA-256(`regino manifest fingerprint v1|` ||
/// hash)) – members compare it with the coordinator to be sure they all accepted the same list.
pub fn manifest_fingerprint(list: &AcceptedManifest) -> String {
    code(b"regino manifest fingerprint v1|", &list.hash)
}
