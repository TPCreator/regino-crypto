//! Database key in the OS keystore (Windows: Windows Credential Manager / DPAPI).
//! The key never leaves the device and is never written to a file or a log.

use crate::{Error, Key, KEY_LEN};
use keyring_core::{Entry, Error as KsError};

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

/// Stores a new key (after `Vault::rekey`).
pub fn store_key(service: &str, user: &str, key: &Key) -> Result<(), Error> {
    Entry::new(service, user)
        .map_err(ks)?
        .set_secret(key.as_bytes())
        .map_err(ks)
}

fn ks(e: KsError) -> Error {
    Error::KeyStore(e.to_string())
}
