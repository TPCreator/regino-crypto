//! Backup version 4 (0.19.0, audit F-02, `testvectors/regino/backup-v4-0.19.0.json`, made by TypeScript). One
//! Argon2id(code, header salt, header parameters) gives the backup key, the chunk keys and the server id: Rust must
//! derive the same values, open the whole version-4 backups and chunks made by TypeScript, and keep version 3 apart.

use aes_gcm::aead::{Aead, KeyInit, Payload};
use aes_gcm::Aes256Gcm;
use regino_keys::backup_chunks::BackupChunkKeys;
use regino_keys::backup_code::{self, BackupCode};
use regino_keys::kdf::KdfParams;
use serde_json::Value;
use sha2::{Digest, Sha256};

fn doc() -> Value {
    serde_json::from_str(include_str!("../../testvectors/regino/backup-v4-0.19.0.json")).unwrap()
}

fn s<'a>(v: &'a Value, k: &str) -> &'a str {
    v[k].as_str().unwrap_or_else(|| panic!("{k}"))
}

fn unhex(h: &str) -> Vec<u8> {
    (0..h.len()).step_by(2).map(|i| u8::from_str_radix(&h[i..i + 2], 16).unwrap()).collect()
}

fn hex(b: &[u8]) -> String {
    b.iter().map(|x| format!("{x:02x}")).collect()
}

const B64: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

fn unb64(t: &str) -> Vec<u8> {
    let (mut out, mut buf, mut bits) = (Vec::new(), 0u32, 0);
    for c in t.bytes().filter(|&c| c != b'=') {
        buf = (buf << 6) | B64.iter().position(|&a| a == c).unwrap() as u32;
        bits += 6;
        if bits >= 8 {
            bits -= 8;
            out.push((buf >> bits) as u8);
        }
    }
    out
}

fn b64(b: &[u8]) -> String {
    let mut out = String::new();
    for c in b.chunks(3) {
        let n = (u32::from(c[0]) << 16) | (u32::from(*c.get(1).unwrap_or(&0)) << 8) | u32::from(*c.get(2).unwrap_or(&0));
        for i in 0..4 {
            out.push(if i <= c.len() { B64[(n >> (18 - 6 * i) & 63) as usize] as char } else { '=' });
        }
    }
    out
}


fn params(k: &Value) -> KdfParams {
    let n = |f: &str| k[f].as_u64().unwrap() as u32;
    KdfParams { memory_kib: n("m"), iterations: n("t"), parallelism: n("p") }
}

fn code(text: &str) -> BackupCode {
    BackupCode::parse(text).unwrap_or_else(|e| panic!("{text}: {e:?}"))
}

/// Opens a version-4 backup JSON exactly as `ts/src/backup.ts` does.
fn open_backup(code: &BackupCode, file: &Value, app: &str) -> Vec<u8> {
    assert_eq!(s(file, "format"), format!("{app}-backup"));
    assert_eq!(file["version"], 4);
    assert_eq!(s(file, "secret"), "code16");
    let kdf = &file["kdf"];
    assert_eq!(s(kdf, "name"), "argon2id");
    let p = params(kdf);
    assert!(backup_code::valid_params(p));
    let salt: [u8; 16] = unb64(s(file, "salt")).try_into().unwrap();
    let key = backup_code::backup_key_v4(code, &salt, p, app).unwrap();
    let mut names: Vec<&str> = file["chunks"].as_array().map(|a| a.iter().map(|c| c.as_str().unwrap()).collect()).unwrap_or_default();
    names.sort();
    let digest = b64(&Sha256::digest(names.join("\n").as_bytes()));
    let aad = format!(
        "{app}-backup|4|{}|code16|argon2id m={} t={} p={}|{digest}",
        s(file, "createdAt"),
        p.memory_kib,
        p.iterations,
        p.parallelism
    );
    let nonce: [u8; 12] = unb64(s(file, "nonce")).try_into().unwrap();
    let cipher = Aes256Gcm::new(key.as_bytes().into());
    let ct = unb64(s(file, "ciphertext"));
    // the version-3 key (same Argon2id, other HKDF info) does not open a version-4 backup
    let v3 = backup_code::backup_key(code, &salt, p, app).unwrap();
    assert_ne!(v3.as_bytes(), key.as_bytes());
    let aad3 = aad.replacen("|4|", "|3|", 1);
    assert!(Aes256Gcm::new(v3.as_bytes().into()).decrypt(&nonce.into(), Payload { msg: &ct, aad: aad3.as_bytes() }).is_err());
    cipher.decrypt(&nonce.into(), Payload { msg: &ct, aad: aad.as_bytes() }).expect("the backup opens")
}

#[test]
fn keys_and_ids_are_the_same_as_in_typescript() {
    let d = doc();
    assert_eq!(s(&d, "version"), "0.19.0");
    let app = s(&d, "app");
    let keys = d["keys"].as_array().unwrap();
    assert_eq!(keys.len(), 3);
    for k in keys {
        let c = BackupCode::from_bytes(unhex(s(k, "secret")).try_into().unwrap()).unwrap();
        assert_eq!(c.format().as_str(), s(k, "code"));
        let salt: [u8; 16] = unhex(s(k, "salt")).try_into().unwrap();
        let p = params(&k["kdf"]);
        assert_eq!(hex(backup_code::stretch(&c, &salt, p).unwrap().as_bytes()), s(k, "argon2id"));
        assert_eq!(hex(backup_code::backup_key_v4(&c, &salt, p, app).unwrap().as_bytes()), s(k, "backup_key"));
        assert_eq!(hex(&backup_code::backup_id(&c, &salt, p, app).unwrap()), s(k, "id"));
        assert_eq!(hex(&backup_code::backup_code_id(&c, app).unwrap()), s(k, "id_v1"));
        assert_ne!(s(k, "id"), s(k, "id_v1"));
        let ck = BackupChunkKeys::from_backup_code_v4(&c, &salt, p, app).unwrap();
        assert_eq!(ck.name(b"x"), s(k, "chunk_name_of_x"));
        // not the version-3 chunk keys (fixed salt of the application)
        assert_ne!(BackupChunkKeys::from_backup_code(&c, app).unwrap().name(b"x"), ck.name(b"x"));
    }
}

#[test]
fn backups_and_chunks_made_by_typescript_open() {
    let d = doc();
    let app = s(&d, "app");
    for b in d["backups"].as_array().unwrap() {
        let plain = open_backup(&code(s(b, "code")), &b["file"], app);
        assert_eq!(serde_json::from_slice::<Value>(&plain).unwrap(), b["payload"], "{}", s(b, "name"));
        assert!(s(b, "aad_prefix").starts_with(&format!("{app}-backup|4|")));
    }
    let c = &d["chunks"];
    let k = code(s(c, "code"));
    let salt: [u8; 16] = unhex(s(&c["params"], "salt")).try_into().unwrap();
    let p = params(&c["params"]["kdf"]);
    let keys = BackupChunkKeys::from_backup_code_v4(&k, &salt, p, app).unwrap();
    assert_eq!(keys.name(s(c, "content").as_bytes()), s(c, "name"));
    assert_eq!(keys.open(s(c, "name"), &unhex(s(c, "blob"))).unwrap().as_slice(), s(c, "content").as_bytes());
    // two backups share the chunk: the same salt and parameters in both headers, so the same chunk keys
    let backups = c["backups"].as_array().unwrap();
    assert_eq!(backups.len(), 2);
    for b in backups {
        let f = &b["file"];
        assert_eq!(unb64(s(f, "salt")), salt.to_vec());
        assert_eq!(params(&f["kdf"]), p);
        assert_eq!(f["chunks"][0].as_str().unwrap(), s(c, "name"));
        let plain = open_backup(&k, f, app);
        assert_eq!(serde_json::from_slice::<Value>(&plain).unwrap(), b["payload"]);
    }
}

#[test]
fn refused_inputs() {
    let k = code("04HM-ASW9-NF6Y-Y09F");
    let salt = [7u8; 16];
    let low = KdfParams { memory_kib: 1024, iterations: 1, parallelism: 1 };
    let ok = backup_code::DEFAULT_PARAMS;
    assert!(backup_code::backup_key_v4(&k, &salt, low, "demo").is_err());
    assert!(backup_code::backup_id(&k, &salt, low, "demo").is_err());
    assert!(BackupChunkKeys::from_backup_code_v4(&k, &salt, low, "demo").is_err());
    assert!(backup_code::backup_key_v4(&k, &salt, ok, "Bad").is_err());
    assert!(backup_code::backup_id(&k, &salt, ok, "Bad").is_err());
    assert!(BackupChunkKeys::from_backup_code_v4(&k, &salt, ok, "Bad").is_err());
    // the salt separates users: another salt, other keys and id
    let a = backup_code::backup_id(&k, &salt, KdfParams::MIN, "demo").unwrap();
    let b = backup_code::backup_id(&k, &[8u8; 16], KdfParams::MIN, "demo").unwrap();
    assert_ne!(a, b);
}
