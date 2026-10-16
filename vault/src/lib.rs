//! Encrypted local database for apps built on the regino-crypto core.
//!
//! - SQLite with SQLCipher (AES-256), 256-bit key; without the key the file is unreadable.
//! - Values pass through as JSON (numbers, text, null) so they can be sent over the Tauri bridge.
//! - Knows nothing about the app's tables – the app handles schema and migrations (e.g. with its own TypeScript layer).

use rusqlite::{types::ValueRef, Connection, OpenFlags};
use serde_json::{Map, Number, Value};
use std::path::Path;
use zeroize::Zeroizing;

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

    pub fn to_hex(&self) -> Zeroizing<String> {
        Zeroizing::new(self.0.iter().map(|b| format!("{b:02x}")).collect())
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
    #[error("{0}")]
    Sql(#[from] rusqlite::Error),
}

pub struct Vault {
    conn: Connection,
}

impl Vault {
    /// Opens (or creates) the encrypted file. A wrong key returns `Error::WrongKey` and overwrites nothing.
    pub fn open(path: &Path, key: &Key) -> Result<Vault, Error> {
        let conn = Connection::open_with_flags(
            path,
            OpenFlags::SQLITE_OPEN_READ_WRITE
                | OpenFlags::SQLITE_OPEN_CREATE
                | OpenFlags::SQLITE_OPEN_NO_MUTEX,
        )?;
        let pragma = Zeroizing::new(format!("PRAGMA key = \"x'{}'\";", key.to_hex().as_str()));
        conn.execute_batch(&pragma)?;
        // Key check: with a wrong key SQLCipher reports "file is not a database".
        if conn
            .query_row("SELECT count(*) FROM sqlite_master", [], |r| {
                r.get::<_, i64>(0)
            })
            .is_err()
        {
            return Err(Error::WrongKey);
        }
        // cipher_memory_security stays OFF (the SQLCipher default): on Windows, locking every SQLite
        // allocation exhausts the working-set quota (VirtualLock error 1453) and the process then dies
        // with a stack overflow. Key buffers are wiped by SQLCipher and by `zeroize` regardless.
        conn.execute_batch("PRAGMA foreign_keys = ON; PRAGMA journal_mode = WAL;")?;
        Ok(Vault { conn })
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
        let pragma = Zeroizing::new(format!("PRAGMA rekey = \"x'{}'\";", key.to_hex().as_str()));
        self.conn.execute_batch(&pragma)?;
        Ok(())
    }
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
        ValueRef::Real(f) => Number::from_f64(f)
            .map(Value::Number)
            .unwrap_or(Value::Null),
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
