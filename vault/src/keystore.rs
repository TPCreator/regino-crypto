//! Database key in the OS keystore (Windows: Windows Credential Manager / DPAPI).
//! The key never leaves the device and is never written to a file or a log.
//!
//! Changing the key: `Vault::rekey` and the keystore entry are two separate writes, so a crash
//! between them would leave a keystore entry that no longer opens the file. [`rekey`] orders the
//! writes through a pending entry (`<user>.pending`) and [`finish_rekey`], called at startup,
//! completes or discards an interrupted change – at every point one of the two entries opens the
//! database. Apps that keep the database key wrapped elsewhere as well (Dôverník: in its key file)
//! can also recover from there; apps with the keystore as the only copy (Gazda) must use these two.

use crate::{Error, Key, Vault, KEY_LEN};
use keyring_core::{Entry, Error as KsError};
use std::path::Path;

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
        Ok(bytes) => {
            let bytes = zeroize::Zeroizing::new(bytes);
            if bytes.len() != KEY_LEN {
                return Err(Error::KeyStore("key in the keystore has the wrong length".into()));
            }
            let mut arr = zeroize::Zeroizing::new([0u8; KEY_LEN]);
            arr.copy_from_slice(&bytes);
            Ok((Key::from_bytes(arr), false))
        }
        Err(KsError::NoEntry) => {
            let key = Key::generate()?;
            entry.set_secret(key.as_bytes()).map_err(ks)?;
            Ok((key, true))
        }
        Err(e) => Err(ks(e)),
    }
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
/// turns either case back into one main entry. An error before step 2 leaves the key unchanged.
pub fn rekey(vault: &Vault, service: &str, user: &str, new_key: &Key) -> Result<(), Error> {
    let pending = pending_entry(service, user)?;
    pending.set_secret(new_key.as_bytes()).map_err(ks)?;
    vault.rekey(new_key)?;
    store_key(service, user, new_key)?;
    pending.delete_credential().map_err(ks)
}

/// Completes a [`rekey`] that was interrupted. If a pending entry exists and opens the database at
/// `db_path`, it becomes the main entry (the file was already re-encrypted); otherwise the pending
/// entry is dropped and the main entry stays (the file was not re-encrypted). Without a pending
/// entry nothing happens. Returns `true` when the pending key was promoted to the main entry.
///
/// Call it at startup before `load_or_create_key`; a database file that does not exist yet has no
/// key to recover, so a stray pending entry is only removed then.
pub fn finish_rekey(service: &str, user: &str, db_path: &Path) -> Result<bool, Error> {
    let pending = pending_entry(service, user)?;
    let bytes = match pending.get_secret() {
        Ok(bytes) => zeroize::Zeroizing::new(bytes),
        Err(KsError::NoEntry) => return Ok(false),
        Err(e) => return Err(ks(e)),
    };
    let promoted = if bytes.len() == KEY_LEN && db_path.is_file() {
        let mut arr = zeroize::Zeroizing::new([0u8; KEY_LEN]);
        arr.copy_from_slice(&bytes);
        promote_if_it_opens(service, user, db_path, &Key::from_bytes(arr))?
    } else {
        false
    };
    pending.delete_credential().map_err(ks)?;
    Ok(promoted)
}

/// The pending key becomes the main entry only if it opens the file; a wrong key is reported as
/// `false`, any other error (locked file, keystore) is returned so that nothing is dropped blindly.
fn promote_if_it_opens(service: &str, user: &str, db_path: &Path, key: &Key) -> Result<bool, Error> {
    match Vault::open(db_path, key) {
        Ok(_) => {
            store_key(service, user, key)?;
            Ok(true)
        }
        Err(Error::WrongKey) => Ok(false),
        Err(e) => Err(e),
    }
}

fn ks(e: KsError) -> Error {
    Error::KeyStore(e.to_string())
}
