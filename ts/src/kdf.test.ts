import { argon2idAsync } from '@noble/hashes/argon2.js';
import { afterEach, describe, expect, it, vi } from 'vitest';
import rust from '../../testvectors/regino/keys-0.11.1.json';
import v from '../../testvectors/regino/password-key-0.16.0.json';
import { MAX_BACKUP_CODE_KDF, MIN_BACKUP_CODE_KDF } from './backupCode';
import {
  DEFAULT_PASSWORD_KDF,
  MAX_PASSWORD_KDF,
  MIN_PASSWORD_KDF,
  PASSWORD_KEY_BYTES,
  PASSWORD_SALT_BYTES,
  newPasswordSalt,
  passwordKey,
  validPasswordKdf,
} from './kdf';

// Key from a password (0.16.0), byte for byte `regino_keys::kdf::derive`.
const hex = (b: Uint8Array) => Array.from(b, (x) => x.toString(16).padStart(2, '0')).join('');
const unhex = (h: string) => Uint8Array.from(h.match(/../g) ?? [], (x) => parseInt(x, 16));
const MIN = { m: 19456, t: 2, p: 1 };

afterEach(() => {
  vi.restoreAllMocks();
});

describe('the same keys as Rust', () => {
  it('reproduces the Argon2id keys made by Rust 0.11.1 (keys-0.11.1.json)', async () => {
    expect(rust.kdf).toHaveLength(2);
    for (const k of rust.kdf) {
      const kdf = { m: k.memory_kib, t: k.iterations, p: k.parallelism };
      expect(hex(await passwordKey(unhex(k.password), unhex(k.salt), kdf)), JSON.stringify(kdf)).toBe(k.key);
      // the passwords are UTF-8 text, so the string form gives the same key
      const text = new TextDecoder('utf-8', { fatal: true }).decode(unhex(k.password));
      expect(hex(await passwordKey(text, unhex(k.salt), kdf))).toBe(k.key);
    }
  });

  it('gives the keys of password-key-0.16.0.json (checked by Rust in keys/tests/password_key_0_16_0.rs)', async () => {
    expect(v.version).toBe('0.16.0');
    expect(v.derive).toHaveLength(7);
    for (const c of v.derive) {
      expect(hex(new TextEncoder().encode(c.password_text)), c.name).toBe(c.password);
      const kdf = { m: c.memory_kib, t: c.iterations, p: c.parallelism };
      expect(hex(await passwordKey(c.password_text, unhex(c.salt), kdf)), c.name).toBe(c.key);
    }
  }, 60_000);

  it('does not normalise: NFC and NFD of the same text give different keys', async () => {
    const [nfc, nfd] = [v.derive[1]!, v.derive[2]!];
    expect(nfc.password_text.normalize('NFD')).toBe(nfd.password_text);
    expect(nfc.password_text).toBe(nfc.password_text.normalize('NFC'));
    expect(nfc.key).not.toBe(nfd.key);
  });

  it('accepts an empty password, as Rust does', async () => {
    const c = v.derive[3]!;
    expect(c.password_text).toBe('');
    expect(hex(await passwordKey('', unhex(c.salt), MIN))).toBe(c.key);
    expect(hex(await passwordKey(new Uint8Array(0), unhex(c.salt), MIN))).toBe(c.key);
  });

  it('refuses the parameters of the vectors before any work (Rust Error::KdfParams)', async () => {
    expect(v.refused).toHaveLength(7);
    for (const c of v.refused) {
      const kdf = { m: c.memory_kib, t: c.iterations, p: c.parallelism };
      expect(validPasswordKdf(kdf), c.name).toBe(false);
      await expect(passwordKey('password', new Uint8Array(16), kdf), c.name).rejects.toThrow('Argon2id parameters out of bounds.');
    }
  });
});

describe('Testurion (keyring.ts) computes the same key', () => {
  it('the default is 64 MiB, 3 passes, 1 lane and matches argon2idAsync of the UTF-8 password', async () => {
    expect(DEFAULT_PASSWORD_KDF).toEqual({ m: 65536, t: 3, p: 1 });
    const c = v.derive[5]!;
    expect({ m: c.memory_kib, t: c.iterations, p: c.parallelism }).toEqual(DEFAULT_PASSWORD_KDF);
    const salt = unhex(c.salt);
    // exactly the call in Testurion app/src/lib/author/keyring.ts (passwordWrapKey)
    const testurion = await argon2idAsync(new TextEncoder().encode(c.password_text), salt, { m: 65536, t: 3, p: 1, dkLen: 32, version: 0x13 });
    const core = await passwordKey(c.password_text, salt);
    expect(hex(core)).toBe(hex(testurion));
    expect(hex(core)).toBe(c.key);
  });

  it('the same key for the cheapest parameters (Testurion MIN_PASSWORD_KDF, its tests)', async () => {
    const salt = newPasswordSalt();
    const pw = 'heslo správcu 🔑';
    const testurion = await argon2idAsync(new TextEncoder().encode(pw), salt, { ...MIN, dkLen: 32, version: 0x13 });
    expect(hex(await passwordKey(pw, salt, MIN_PASSWORD_KDF))).toBe(hex(testurion));
  });
});

describe('parameters, salt and password', () => {
  it('bounds are those of Rust KdfParams::MIN / MAX / MAX_WORK_KIB (and of a backup code)', () => {
    expect(MIN_PASSWORD_KDF).toEqual(MIN);
    expect(MAX_PASSWORD_KDF).toEqual({ m: 131072, t: 8, p: 4, work: 262144 });
    expect(MIN_PASSWORD_KDF).toBe(MIN_BACKUP_CODE_KDF);
    expect(MAX_PASSWORD_KDF).toBe(MAX_BACKUP_CODE_KDF);
    expect(Object.isFrozen(DEFAULT_PASSWORD_KDF)).toBe(true);
    expect(validPasswordKdf(DEFAULT_PASSWORD_KDF)).toBe(true);
    expect(validPasswordKdf(MIN)).toBe(true);
    expect(validPasswordKdf({ m: 131072, t: 2, p: 4 })).toBe(true);
    expect(validPasswordKdf({ m: 32768, t: 8, p: 1 })).toBe(true);
    for (const bad of [null, undefined, 1, 'x', {}, { m: 65536, t: 3 }, { m: '65536', t: 3, p: 1 }, { m: 65536.5, t: 3, p: 1 }])
      expect(validPasswordKdf(bad), JSON.stringify(bad)).toBe(false);
  });

  it('refuses bad parameter objects, salts and passwords before any work', async () => {
    const salt = new Uint8Array(16);
    for (const kdf of [null, 5, { m: 65536, t: 3 }])
      await expect(passwordKey('password', salt, kdf as never)).rejects.toThrow('Argon2id parameters out of bounds.');
    for (const s of [new Uint8Array(15), new Uint8Array(17), new Uint8Array(0), Array(16).fill(0), 'x'.repeat(16)])
      await expect(passwordKey('password', s as never, MIN)).rejects.toThrow('The salt must have 16 bytes.');
    for (const pw of [null, undefined, 1, ['a'], new Uint16Array(4)])
      await expect(passwordKey(pw as never, salt, MIN)).rejects.toThrow('The password must be a string or bytes.');
  });

  it('refuses a string with a lone surrogate (it has no UTF-8 form), accepts pairs', async () => {
    const salt = new Uint8Array(16);
    for (const pw of ['a\uD83D', '\uD83Db', 'a\uDD11', '\uDD11\uD83D', '\uD800𐀀\uDC00'])
      await expect(passwordKey(pw, salt, MIN), JSON.stringify(pw)).rejects.toThrow('lone surrogate');
    // without the check both would encode to U+FFFD and give one key
    expect(hex(new TextEncoder().encode('\uD83D'))).toBe(hex(new TextEncoder().encode('�')));
    expect(await passwordKey('🔑', salt, MIN)).toHaveLength(PASSWORD_KEY_BYTES);
  });

  it('checks a copy of the parameters: a getter cannot change them after the check', async () => {
    let reads = 0;
    const tricky = {
      get m() {
        return reads++ === 0 ? 19456 : 4 * 1024 * 1024;
      },
      t: 2,
      p: 1,
    };
    const salt = new Uint8Array(16).fill(7);
    expect(hex(await passwordKey('quiet evening', salt, tricky))).toBe(rust.kdf[0]!.key);
    expect(reads).toBe(1);
  });

  it('wipes its UTF-8 copy of the password, leaves the caller’s bytes and gives a fresh 32-byte key', async () => {
    const encode = vi.spyOn(TextEncoder.prototype, 'encode');
    const salt = new Uint8Array(16);
    const key = await passwordKey('tajné heslo', salt, MIN);
    expect(key).toHaveLength(32);
    const copy = encode.mock.results[0]!.value as Uint8Array;
    expect(copy.length).toBeGreaterThan(0);
    expect(copy.every((b) => b === 0)).toBe(true);
    encode.mockClear();
    const mine = new TextEncoder().encode('tajné heslo');
    encode.mockClear();
    expect(hex(await passwordKey(mine, salt, MIN))).toBe(hex(key));
    expect(new TextDecoder().decode(mine)).toBe('tajné heslo');
    expect(encode).not.toHaveBeenCalled();
  });

  it('newPasswordSalt gives 16 random bytes', () => {
    const a = newPasswordSalt();
    const b = newPasswordSalt();
    expect(PASSWORD_SALT_BYTES).toBe(16);
    expect(a).toBeInstanceOf(Uint8Array);
    expect(a).toHaveLength(16);
    expect(hex(a)).not.toBe(hex(b));
  });
});
