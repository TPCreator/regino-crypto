//! Backup code of 16 characters (0.15.0, `testvectors/regino/backup-code-0.15.0.json`, made by the
//! TypeScript side with `@noble/hashes` Argon2id). Rust (RustCrypto `argon2`) must read the same codes,
//! refuse the same inputs with the same error, derive the same Argon2id outputs, backup keys, ids and
//! chunk keys, and open the whole backups made by TypeScript.

use aes_gcm::aead::{Aead, KeyInit, Payload};
use aes_gcm::Aes256Gcm;
use argon2::{Algorithm, Argon2, AssociatedData, ParamsBuilder, Version};
use regino_keys::backup_chunks::BackupChunkKeys;
use regino_keys::backup_code::{self, BackupCode, CodeError};
use regino_keys::kdf::KdfParams;
use serde_json::Value;
use sha2::{Digest, Sha256};

fn doc() -> Value {
    serde_json::from_str(include_str!("../../testvectors/regino/backup-code-0.15.0.json")).unwrap()
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

/// Opens a version-3 backup JSON exactly as `ts/src/backup.ts` does.
fn open_backup(code: &BackupCode, file: &Value, app: &str) -> Vec<u8> {
    assert_eq!(s(file, "format"), format!("{app}-backup"));
    assert_eq!(file["version"], 3);
    assert_eq!(s(file, "secret"), "code16");
    let kdf = &file["kdf"];
    assert_eq!(s(kdf, "name"), "argon2id");
    let p = params(kdf);
    assert!(backup_code::valid_params(p));
    let salt: [u8; 16] = unb64(s(file, "salt")).try_into().unwrap();
    let key = backup_code::backup_key(code, &salt, p, app).unwrap();
    let mut names: Vec<&str> = file["chunks"].as_array().map(|a| a.iter().map(|c| c.as_str().unwrap()).collect()).unwrap_or_default();
    names.sort();
    let digest = b64(&Sha256::digest(names.join("\n").as_bytes()));
    let aad = format!(
        "{app}-backup|3|{}|code16|argon2id m={} t={} p={}|{digest}",
        s(file, "createdAt"),
        p.memory_kib,
        p.iterations,
        p.parallelism
    );
    let nonce: [u8; 12] = unb64(s(file, "nonce")).try_into().unwrap();
    Aes256Gcm::new(key.as_bytes().into())
        .decrypt(&nonce.into(), Payload { msg: &unb64(s(file, "ciphertext")), aad: aad.as_bytes() })
        .expect("the backup opens")
}

#[test]
fn codes_and_refused_inputs_are_the_same_as_in_typescript() {
    let d = doc();
    assert_eq!(s(&d, "version"), "0.15.0");
    assert_eq!(s(&d, "alphabet").as_bytes(), backup_code::ALPHABET);
    assert_eq!(params(&d["kdf"]["default"]), backup_code::DEFAULT_PARAMS);
    assert_eq!(params(&d["kdf"]["min"]), KdfParams::MIN);
    assert_eq!(params(&d["kdf"]["max"]), backup_code::MAX_PARAMS);
    assert_eq!(d["kdf"]["max"]["work"].as_u64().unwrap(), backup_code::MAX_WORK_KIB);
    for c in d["codes"].as_array().unwrap() {
        let secret: [u8; 10] = unhex(s(c, "secret")).try_into().unwrap();
        let k = BackupCode::from_bytes(secret).unwrap();
        assert_eq!(k.format().as_str(), s(c, "code"));
        assert_eq!(k.qr_text().as_str(), s(c, "qr"));
        for input in c["accepted"].as_array().unwrap() {
            assert_eq!(code(input.as_str().unwrap()).as_bytes(), &secret, "{input}");
        }
    }
    for t in d["invalid"].as_array().unwrap() {
        let e = &t["error"];
        let expected = match s(e, "code") {
            "length" => CodeError::Length(e["length"].as_u64().unwrap() as usize),
            "unknown-char" => CodeError::UnknownChar {
                index: e["index"].as_u64().unwrap() as usize,
                ch: s(e, "char").chars().next().unwrap(),
            },
            _ => CodeError::Checksum,
        };
        assert_eq!(BackupCode::parse(s(t, "input")).unwrap_err(), expected, "{}", t["input"]);
    }
}

#[test]
fn argon2id_backup_keys_salt_and_ids_are_the_same_as_in_typescript() {
    let d = doc();
    let app = s(&d, "app");
    assert_eq!(hex(&backup_code::app_salt(app).unwrap()), s(&d, "app_salt"));
    for k in d["keys"].as_array().unwrap() {
        let c = BackupCode::from_bytes(unhex(s(k, "secret")).try_into().unwrap()).unwrap();
        let salt: [u8; 16] = unhex(s(k, "salt")).try_into().unwrap();
        let p = params(&k["kdf"]);
        assert_eq!(hex(backup_code::stretch(&c, &salt, p).unwrap().as_bytes()), s(k, "argon2id"));
        assert_eq!(hex(backup_code::backup_key(&c, &salt, p, app).unwrap().as_bytes()), s(k, "backup_key"));
    }
    for c in d["codes"].as_array().unwrap().iter().take(3) {
        let k = code(s(c, "code"));
        assert_eq!(hex(&backup_code::backup_code_id(&k, app).unwrap()), s(c, "id"));
    }
}

#[test]
fn backups_and_chunks_made_by_typescript_open() {
    let d = doc();
    let app = s(&d, "app");
    for b in d["backups"].as_array().unwrap() {
        let plain = open_backup(&code(s(b, "code")), &b["file"], app);
        assert_eq!(serde_json::from_slice::<Value>(&plain).unwrap(), b["payload"]);
        // the AAD written in the vector is the one built here
        assert!(s(b, "aad").starts_with(&format!("{app}-backup|3|")));
    }
    let c = &d["chunks"][0];
    let k = code(s(c, "code"));
    let keys = BackupChunkKeys::from_backup_code(&k, app).unwrap();
    assert_eq!(keys.name(s(c, "content").as_bytes()), s(c, "name"));
    assert_eq!(keys.open(s(c, "name"), &unhex(s(c, "blob"))).unwrap().as_slice(), s(c, "content").as_bytes());
    let plain = open_backup(&k, &c["backup"]["file"], app);
    assert_eq!(serde_json::from_slice::<Value>(&plain).unwrap(), c["backup"]["payload"]);
    // words keys and code keys never coincide, and the app name separates them
    assert_ne!(BackupChunkKeys::new(&[0u8; 16], app).unwrap().name(b"x"), keys.name(b"x"));
    assert!(BackupChunkKeys::from_backup_code(&k, "Bad").is_err());
}

#[test]
fn argon2id_passes_the_rfc_9106_vector() {
    let d = doc();
    let r = &d["rfc9106_argon2id"];
    let p = ParamsBuilder::new()
        .m_cost(r["m"].as_u64().unwrap() as u32)
        .t_cost(r["t"].as_u64().unwrap() as u32)
        .p_cost(r["p"].as_u64().unwrap() as u32)
        .data(AssociatedData::new(&unhex(s(r, "ad"))).unwrap())
        .output_len(32)
        .build()
        .unwrap();
    let secret = unhex(s(r, "secret"));
    let a = Argon2::new_with_secret(&secret, Algorithm::Argon2id, Version::V0x13, p).unwrap();
    let mut out = [0u8; 32];
    a.hash_password_into(&unhex(s(r, "password")), &unhex(s(r, "salt")), &mut out).unwrap();
    assert_eq!(hex(&out), "0d640df58d78766c08c037a34a8b53c9d01ef0452d75b65eb52520e96b01e659");
    assert_eq!(hex(&out), s(r, "tag"));
}
