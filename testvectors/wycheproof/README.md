# Wycheproof – test vectors

Source: <https://github.com/C2SP/wycheproof>, folder `testvectors_v1`, commit `7a325932231bd7a724c791c8b0d65ea4d6d2f435`.
License: Apache-2.0 (`LICENSE` in this folder).

Only the groups the core uses are kept:

| File | Groups | Where it is used |
|---|---|---|
| `xchacha20_poly1305_test.json` | key 256 b, nonce 192 b, tag 128 b | `keys/src/wrap.rs` (key wrapping, sealing) |
| `aes_gcm_test.json` | key 256 b, IV 96 b, tag 128 b | `ts/src/backup.ts` (backups, WebCrypto) |
| `hkdf_sha256_test.json` | all | `ts/src/backup.ts`, `keys/src/recovery.rs` |
| `ed25519_test.json` | all (DER/PEM/JWK key forms removed) | `ts/src/signed.ts` (signed tokens, `@noble/ed25519`) |

Tests: `keys/tests/wycheproof.rs`, `ts/src/wycheproof.test.ts`. They verify that the implementations used
(RustCrypto `chacha20poly1305`, `hkdf`; WebCrypto in Node; `@noble/ed25519`) accept valid and reject invalid inputs.
