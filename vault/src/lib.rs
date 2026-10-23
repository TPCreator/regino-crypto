//! Encrypted local database for apps built on the regino-crypto core.
//!
//! - SQLite with SQLCipher (AES-256), 256-bit key; without the key the file is unreadable.
//! - Values pass through as JSON (numbers, text, null) so they can be sent over the Tauri bridge.
//! - Knows nothing about the app's tables – the app handles schema and migrations (e.g. with its own TypeScript layer).

use rusqlite::{types::ValueRef, Connection, OpenFlags};
use serde_json::{Map, Number, Value};
use std::path::Path;
use zeroize::Zeroizing;

pub mod backup_chunks;
pub mod backups;
pub mod keystore;

/// Core version – the app shows it in "About" (together with the commit from Cargo.lock).
pub const VERSION: &str = env!("CARGO_PKG_VERSION");

pub const KEY_LEN: usize = 32;

/// Database key; its memory is zeroed when dropped.
pub struct Key(Zeroizing<[u8; KEY_LEN]>);

impl Key {
    pub fn generate() -> Result<Key, Error> {
        let mut bytes = Zeroizing::new([0u8; KEY_LEN]);
        getrandom::fill(bytes.as_mut()).map_err(|e| Error::Random(e.to_string()))?;
        Ok(Key(bytes))
    }

    pub fn from_bytes(bytes: Zeroizing<[u8; KEY_LEN]>) -> Key {
        Key(bytes)
    }

    pub fn as_bytes(&self) -> &[u8] {
        self.0.as_ref()
    }

    pub fn from_hex(hex: &str) -> Result<Key, Error> {
        if hex.len() != KEY_LEN * 2 || !hex.bytes().all(|b| b.is_ascii_hexdigit()) {
            return Err(Error::BadKey);
        }
        let mut bytes = Zeroizing::new([0u8; KEY_LEN]);
        for (i, chunk) in hex.as_bytes().chunks(2).enumerate() {
            let s = std::str::from_utf8(chunk).map_err(|_| Error::BadKey)?;
            bytes[i] = u8::from_str_radix(s, 16).map_err(|_| Error::BadKey)?;
        }
        Ok(Key(bytes))
    }

    /// Hex for `PRAGMA key`: written straight into one pre-sized `Zeroizing` string – no temporary
    /// per-byte strings and no reallocation that would leave unwiped copies of the key behind.
    pub fn to_hex(&self) -> Zeroizing<String> {
        const HEX: &[u8; 16] = b"0123456789abcdef";
        let mut out = Zeroizing::new(String::with_capacity(KEY_LEN * 2));
        for b in self.0.iter() {
            out.push(HEX[(b >> 4) as usize] as char);
            out.push(HEX[(b & 0x0f) as usize] as char);
        }
        out
    }
}

#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("Wrong database key, or the file is not this encrypted database.")]
    WrongKey,
    #[error("The key must be 64 hexadecimal characters.")]
    BadKey,
    #[error("Random number generator failed: {0}")]
    Random(String),
    #[error("OS keystore: {0}")]
    KeyStore(String),
    #[error("Unsupported value type: {0}")]
    BadValue(String),
    #[error("The database is being read by another connection; compact it later.")]
    Busy,
    /// `keystore::rekey`: the file already has the new key, but the keystore could not be updated
    /// (step 3 or 4). The change is **not** failed – do not try the old or another key; restart the
    /// app (`keystore::finish_rekey` completes it) or call `finish_rekey` directly. Since 0.12.1.
    #[error("The database already has the new key, but the keystore was not updated ({0}); restart the app to complete the change.")]
    RekeyIncomplete(String),
    #[error("{0}")]
    Sql(#[from] rusqlite::Error),
}

pub struct Vault {
    conn: Connection,
}

impl Vault {
    /// Opens (or creates) the encrypted file. A wrong key returns `Error::WrongKey` and overwrites nothing.
    /// `WrongKey` means only that: the file could be read but is not an encrypted database under this
    /// key. A file that cannot be read at all (locked by another process, I/O error, damaged) is
    /// `Error::Sql` – it says nothing about the key.
    pub fn open(path: &Path, key: &Key) -> Result<Vault, Error> {
        let conn = Connection::open_with_flags(
            path,
            OpenFlags::SQLITE_OPEN_READ_WRITE
                | OpenFlags::SQLITE_OPEN_CREATE
                | OpenFlags::SQLITE_OPEN_NO_MUTEX,
        )?;
        let pragma = key_pragma("key", key);
        conn.execute_batch(&pragma)?;
        // Key check: with a wrong key (or a file that is not an encrypted database) SQLCipher reports
        // SQLITE_NOTADB "file is not a database" – only that is `WrongKey`. Any other failure here (the
        // file is locked by another process, an I/O error, a damaged file) is `Error::Sql`, so a caller
        // that decides about keys (`keystore::finish_rekey`) never takes it for a wrong key (since
        // 0.12.1; before, every failure of this check was reported as `WrongKey`).
        if let Err(e) = conn.query_row("SELECT count(*) FROM sqlite_master", [], |r| {
            r.get::<_, i64>(0)
        }) {
            return Err(match e {
                rusqlite::Error::SqliteFailure(
                    rusqlite::ffi::Error {
                        code: rusqlite::ErrorCode::NotADatabase,
                        ..
                    },
                    _,
                ) => Error::WrongKey,
                other => Error::Sql(other),
            });
        }
        // cipher_memory_security stays OFF (the SQLCipher default): on Windows, locking every SQLite
        // allocation exhausts the working-set quota (VirtualLock error 1453) and the process then dies
        // with a stack overflow. Key buffers are wiped by SQLCipher and by `zeroize` regardless.
        // secure_delete (since 0.11.1): deleted content is overwritten with zeros inside the pages
        // at delete time, so a deleted row does not linger in the free space of the file (`compact`
        // then removes old page versions and free pages). It is a per-connection setting, hence set
        // on every open; `secure_delete_is_on_after_open` reads it back.
        conn.execute_batch(
            "PRAGMA foreign_keys = ON; PRAGMA journal_mode = WAL; PRAGMA secure_delete = ON;",
        )?;
        Ok(Vault { conn })
    }

    /// Removes what deleted rows leave behind in the files. `secure_delete` zeroes deleted content
    /// inside a page the moment it is deleted, but older versions of the page stay in the `-wal`
    /// file until the WAL is reused, and the page itself may stay in the file as a free page. This
    /// checkpoints and truncates the WAL, rebuilds the file (`VACUUM` – only live rows are copied)
    /// and truncates the WAL again (in WAL mode `VACUUM` writes the rebuilt file through the WAL).
    ///
    /// Scope: this cleans the live database file and WAL only. Truncating a file frees its blocks
    /// without overwriting them, so old WAL frames and old free pages can remain in the free space
    /// of the file system, on an SSD or in shadow copies – encrypted under the database key. That is
    /// out of scope; full-disk encryption is recommended (`AUDIT.md`, question 7 + 12).
    ///
    /// The app calls it after deleting sensitive data (e.g. a client) – not after every change.
    /// Cost: the whole database is rewritten (time proportional to its size). The temporary copy
    /// that `VACUUM` builds is held in memory (the bundled SQLCipher is built with
    /// `SQLITE_TEMP_STORE=2`), so it needs RAM of about the size of the database; on disk the WAL
    /// grows to about the size of the database until the final checkpoint truncates it.
    ///
    /// - `VACUUM` may renumber the `rowid` of tables without an explicit `INTEGER PRIMARY KEY`;
    ///   do not keep references to such rows by bare `rowid`.
    /// - Do not call it inside an open transaction (e.g. after `exec("BEGIN")`): `VACUUM` then
    ///   fails with `Error::Sql` ("cannot VACUUM from within a transaction"), not `Error::Busy`.
    /// - Each checkpoint needs no other connection reading the file; it waits up to the busy
    ///   timeout (about 5 s, the rusqlite default) and then returns `Error::Busy` (nothing is lost –
    ///   try again later). If the second checkpoint returns `Error::Busy`, `VACUUM` has already
    ///   finished and the rebuilt database is in the WAL (encrypted); the WAL stays large until the
    ///   next successful checkpoint (e.g. the next `compact()`).
    /// - Because it can block for seconds, do not call it on the UI thread.
    pub fn compact(&self) -> Result<(), Error> {
        self.checkpoint_truncate()?;
        self.conn.execute_batch("VACUUM;")?;
        self.checkpoint_truncate()
    }

    /// `PRAGMA wal_checkpoint(TRUNCATE)`: all WAL frames into the file, WAL truncated to zero bytes.
    /// The first result column is 1 when the checkpoint could not complete (another connection reads).
    fn checkpoint_truncate(&self) -> Result<(), Error> {
        let busy: i64 = self
            .conn
            .query_row("PRAGMA wal_checkpoint(TRUNCATE)", [], |r| r.get(0))?;
        if busy != 0 {
            return Err(Error::Busy);
        }
        Ok(())
    }

    pub fn exec(&self, sql: &str) -> Result<(), Error> {
        self.conn.execute_batch(sql)?;
        Ok(())
    }

    /// A single statement with parameters; returns the number of changed rows.
    pub fn run(&self, sql: &str, params: &[Value]) -> Result<usize, Error> {
        let values = to_sql(params)?;
        let mut stmt = self.conn.prepare(sql)?;
        Ok(stmt.execute(rusqlite::params_from_iter(values.iter()))?)
    }

    /// A query; rows as JSON objects (column -> value).
    pub fn all(&self, sql: &str, params: &[Value]) -> Result<Vec<Map<String, Value>>, Error> {
        let values = to_sql(params)?;
        let mut stmt = self.conn.prepare(sql)?;
        let names: Vec<String> = stmt.column_names().iter().map(|s| s.to_string()).collect();
        let mut rows = stmt.query(rusqlite::params_from_iter(values.iter()))?;
        let mut out = Vec::new();
        while let Some(row) = rows.next()? {
            let mut obj = Map::with_capacity(names.len());
            for (i, name) in names.iter().enumerate() {
                obj.insert(name.clone(), from_sql(row.get_ref(i)?)?);
            }
            out.push(obj);
        }
        Ok(out)
    }

    /// Changes the key (e.g. after enabling a PIN or during recovery); the whole file is re-encrypted.
    pub fn rekey(&self, key: &Key) -> Result<(), Error> {
        let pragma = key_pragma("rekey", key);
        self.conn.execute_batch(&pragma)?;
        Ok(())
    }
}

/// `PRAGMA key|rekey = "x'<hex>'";` built in one pre-sized `Zeroizing` string (no reallocation copies).
fn key_pragma(name: &str, key: &Key) -> Zeroizing<String> {
    let mut p = Zeroizing::new(String::with_capacity(32 + KEY_LEN * 2));
    p.push_str("PRAGMA ");
    p.push_str(name);
    p.push_str(" = \"x'");
    p.push_str(key.to_hex().as_str());
    p.push_str("'\";");
    p
}

fn to_sql(params: &[Value]) -> Result<Vec<rusqlite::types::Value>, Error> {
    use rusqlite::types::Value as V;
    params
        .iter()
        .map(|p| match p {
            Value::Null => Ok(V::Null),
            Value::Bool(b) => Ok(V::Integer(i64::from(*b))),
            Value::Number(n) => n
                .as_i64()
                .map(V::Integer)
                .or_else(|| n.as_f64().map(V::Real))
                .ok_or_else(|| Error::BadValue(n.to_string())),
            Value::String(s) => Ok(V::Text(s.clone())),
            other => Err(Error::BadValue(other.to_string())),
        })
        .collect()
}

fn from_sql(v: ValueRef<'_>) -> Result<Value, Error> {
    Ok(match v {
        ValueRef::Null => Value::Null,
        ValueRef::Integer(i) => Value::Number(i.into()),
        // NaN and ±Inf have no JSON form; refused like on the way in, never turned into null
        ValueRef::Real(f) => Number::from_f64(f).map(Value::Number).ok_or_else(|| Error::BadValue(f.to_string()))?,
        ValueRef::Text(t) => Value::String(String::from_utf8_lossy(t).into_owned()),
        ValueRef::Blob(_) => return Err(Error::BadValue("blob".into())),
    })
}

/// Profile id (a separate book: Personal, Cottage…) used in the file name – only lowercase letters,
/// digits and hyphen, 1 to 32 characters, so it cannot be turned into a path.
pub fn valid_profile_id(id: &str) -> bool {
    !id.is_empty()
        && id.len() <= 32
        && id
            .chars()
            .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '-')
}
