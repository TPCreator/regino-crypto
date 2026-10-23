//! Database key in the OS keystore (Windows: Windows Credential Manager / DPAPI).
//! The key never leaves the device and is never written to a file or a log.
//!
//! Changing the key: `Vault::rekey` and the keystore entry are two separate writes, so a crash
//! between them would leave a keystore entry that no longer opens the file. [`rekey`] orders the
//! writes through a pending entry (`<user>.pending`) and [`finish_rekey`], called at startup,
//! completes or discards an interrupted change – at every point one of the two entries opens the
//! database, and an entry is only ever discarded after the other one has proven to open the file.
//! Apps that keep the database key wrapped elsewhere as well (Dôverník: in its key file) can also
//! recover from there; apps with the keystore as the only copy (Gazda) must use these two.

use crate::{Error, Key, Vault, KEY_LEN};
use keyring_core::{Entry, Error as KsError};
use std::path::Path;
use zeroize::Zeroizing;

/// Sets the OS keystore as the default store. Called once at app startup.
#[cfg(windows)]
pub fn init_platform_store() -> Result<(), Error> {
    let store =
        windows_native_keyring_store::Store::new().map_err(|e| Error::KeyStore(e.to_string()))?;
    keyring_core::set_default_store(store);
    Ok(())
}

/// Returns the key from the keystore; if there is none yet (first run), creates a new random one and stores it.
/// `created` is true for a new key – the database is then new (or has lost its key).
pub fn load_or_create_key(service: &str, user: &str) -> Result<(Key, bool), Error> {
    let entry = Entry::new(service, user).map_err(ks)?;
    match entry.get_secret() {
        Ok(bytes) => Ok((key_from_keystore(bytes)?, false)),
        Err(KsError::NoEntry) => {
            let key = Key::generate()?;
            entry.set_secret(key.as_bytes()).map_err(ks)?;
            Ok((key, true))
        }
        Err(e) => Err(ks(e)),
    }
}

/// A key read from the keystore; any other length than `KEY_LEN` is a damaged entry.
fn key_from_keystore(bytes: Vec<u8>) -> Result<Key, Error> {
    let bytes = Zeroizing::new(bytes);
    if bytes.len() != KEY_LEN {
        return Err(Error::KeyStore("key in the keystore has the wrong length".into()));
    }
    let mut arr = Zeroizing::new([0u8; KEY_LEN]);
    arr.copy_from_slice(&bytes);
    Ok(Key::from_bytes(arr))
}

/// Stores a new key. To change the key of an open database use [`rekey`], which also re-encrypts the
/// file and survives a crash in between; `store_key` alone is for apps that keep the key elsewhere
/// too (e.g. refreshing the keystore from a key file).
pub fn store_key(service: &str, user: &str, key: &Key) -> Result<(), Error> {
    Entry::new(service, user)
        .map_err(ks)?
        .set_secret(key.as_bytes())
        .map_err(ks)
}

/// Suffix of the keystore entry that holds a new key while the database is being re-encrypted.
pub const PENDING_SUFFIX: &str = ".pending";

fn pending_entry(service: &str, user: &str) -> Result<Entry, Error> {
    Entry::new(service, &format!("{user}{PENDING_SUFFIX}")).map_err(ks)
}

/// Changes the database key and the keystore entry together (since 0.12.1):
/// 1. the new key is saved as the pending entry `<user>.pending`,
/// 2. `Vault::rekey` re-encrypts the file (SQLCipher does this in one transaction),
/// 3. the main entry `<user>` is overwritten with the new key,
/// 4. the pending entry is removed.
///
/// If the process dies after step 1 the main entry still opens the file; after step 2 or 3 the
/// pending entry does. At startup the app calls [`finish_rekey`] before `load_or_create_key`, which
/// turns either case back into one main entry.
///
/// Errors: before step 2 (`KeyStore`) or in step 2 (`WrongKey`, `Sql` – SQLCipher rolls the
/// re-encryption back) the key is unchanged and `new_key` can be thrown away. An error **after**
/// step 2 is `Error::RekeyIncomplete`: the file already has `new_key`, only the keystore could not
/// be updated. The change is then not failed – the app must not try the old key, another key or
/// another `rekey` with a different key; it restarts (so [`finish_rekey`] promotes the pending
/// entry) or calls `finish_rekey` itself. The open `vault` keeps working under the new key.
pub fn rekey(vault: &Vault, service: &str, user: &str, new_key: &Key) -> Result<(), Error> {
    let pending = pending_entry(service, user)?;
    pending.set_secret(new_key.as_bytes()).map_err(ks)?;
    vault.rekey(new_key)?;
    // from here on the file has the new key: a failure below does not undo the change
    store_key(service, user, new_key)
        .and_then(|()| pending.delete_credential().map_err(ks))
        .map_err(|e| Error::RekeyIncomplete(e.to_string()))
}

/// Completes a [`rekey`] that was interrupted. With a pending entry `<user>.pending`:
/// - if the pending key opens the database at `db_path`, it becomes the main entry (the file was
///   already re-encrypted) and the pending entry is removed – returns `true`;
/// - if it does not, and the **main** entry opens the file (the file was not re-encrypted), the
///   pending entry is removed and the main entry stays – returns `false`;
/// - otherwise nothing is removed and an error is returned: the file cannot be read (locked by
///   another process, I/O error, damaged – `Error::Sql`), the keystore failed (`Error::KeyStore`,
///   also when the main entry is missing), or neither key opens the file (`Error::WrongKey`).
///
/// A pending entry is dropped only after the main key has proven to open the file, so a failure at
/// startup never discards the only key that works; the app can simply try again later.
///
/// Without a pending entry nothing happens (`false`). A database file that does not exist (or is
/// not a file) cannot be checked, so the pending entry stays and `false` is returned – call it at
/// startup, before `load_or_create_key`, for **every** database the app keeps, with that database's
/// exact path (a wrong path would hide a pending key from the check).
pub fn finish_rekey(service: &str, user: &str, db_path: &Path) -> Result<bool, Error> {
    let pending = pending_entry(service, user)?;
    let bytes = match pending.get_secret() {
        Ok(bytes) => Zeroizing::new(bytes),
        Err(KsError::NoEntry) => return Ok(false),
        Err(e) => return Err(ks(e)),
    };
    if !db_path.is_file() {
        return Ok(false);
    }
    if bytes.len() == KEY_LEN {
        let mut arr = Zeroizing::new([0u8; KEY_LEN]);
        arr.copy_from_slice(&bytes);
        let key = Key::from_bytes(arr);
        match Vault::open(db_path, &key) {
            Ok(_) => {
                store_key(service, user, &key)?;
                pending.delete_credential().map_err(ks)?;
                return Ok(true);
            }
            Err(Error::WrongKey) => {}
            Err(e) => return Err(e),
        }
    }
    // The pending key does not open the file (or has the wrong length): drop it only once the main
    // key is known to open the file – until then it may be the only key that does.
    let main = match Entry::new(service, user).map_err(ks)?.get_secret() {
        Ok(bytes) => key_from_keystore(bytes)?,
        Err(KsError::NoEntry) => {
            return Err(Error::KeyStore(
                "no key for the database in the keystore; the pending entry is kept".into(),
            ))
        }
        Err(e) => return Err(ks(e)),
    };
    Vault::open(db_path, &main)?;
    pending.delete_credential().map_err(ks)?;
    Ok(false)
}

fn ks(e: KsError) -> Error {
    Error::KeyStore(e.to_string())
}
