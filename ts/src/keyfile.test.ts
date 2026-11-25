import { describe, expect, it } from 'vitest';
import v from '../../testvectors/regino/keyfile-0.22.0.json';
import { b64, unb64 } from './ecdh';
import { MIN_PASSWORD_KDF, passwordKey } from './kdf';
import {
  createKeyFile,
  KEYFILE_WRAP_BYTES,
  parseKeyFile,
  unlockWithKey,
  unlockWithPassword,
  unlockWithRecovery,
  unwrapMaster,
  withKey,
  withNewRecovery,
  withoutKey,
  withPassword,
  wrapMaster,
} from './keyfile';
import { recoveryKey } from './recovery';

const h = (s: string) => Uint8Array.from(s.match(/../g) ?? [], (x) => parseInt(x, 16));
const hex = (b: Uint8Array | null) => (b ? [...b].map((x) => x.toString(16).padStart(2, '0')).join('') : null);
const KDF = MIN_PASSWORD_KDF;

describe('keyfile – vectors (Rust checks the same file)', () => {
  it('wraps', async () => {
    for (const w of v.wraps) {
      expect(hex(await wrapMaster(h(w.kek), h(w.master), w.app, w.method, h(w.nonce)))).toBe(w.wrap);
      expect(hex(await unwrapMaster(h(w.kek), h(w.wrap), w.app, w.method))).toBe(w.master);
    }
    // the same key and nonce for another app gives other bytes
    expect(v.wraps[0]!.wrap).not.toBe(v.wraps[2]!.wrap);
  });

  it('password and recovery keys', async () => {
    const p = v.password;
    expect(hex(await passwordKey(p.password, h(p.salt), p.kdf))).toBe(p.kek);
    expect(hex(await unwrapMaster(h(p.kek), h(p.wrap), p.app, 'password'))).toBe(p.master);
    for (const r of v.recovery) {
      expect(hex(await recoveryKey(h(r.secret), r.app))).toBe(r.kek);
      expect(hex(await unwrapMaster(h(r.kek), h(r.wrap), r.app, 'recovery'))).toBe(r.master);
    }
  }, 30000);
});

describe('keyfile – wrap', () => {
  const kek = new Uint8Array(32).fill(1);
  const master = new Uint8Array(32).fill(2);

  it('random nonce, 64 bytes, bound to app and method', async () => {
    const a = await wrapMaster(kek, master, 'app', 'shares');
    const b = await wrapMaster(kek, master, 'app', 'shares');
    expect(a).toHaveLength(KEYFILE_WRAP_BYTES);
    expect(hex(a)).not.toBe(hex(b));
    expect(await unwrapMaster(kek, a, 'app', 'shares')).toEqual(master);
    expect(await unwrapMaster(kek, a, 'app', 'password')).toBeNull();
    expect(await unwrapMaster(kek, a, 'iny', 'shares')).toBeNull();
    expect(await unwrapMaster(new Uint8Array(32), a, 'app', 'shares')).toBeNull();
    const bad = a.slice();
    bad[0] = 0;
    expect(await unwrapMaster(kek, bad, 'app', 'shares')).toBeNull();
    expect(await unwrapMaster(kek, a.subarray(0, 63), 'app', 'shares')).toBeNull();
    expect(await unwrapMaster(kek, 'x' as never, 'app', 'shares')).toBeNull();
  });

  it('invalid arguments throw', async () => {
    await expect(wrapMaster(kek, master, 'A', 'shares')).rejects.toThrow(/application/);
    await expect(wrapMaster(kek, master, 'app', 'Shares')).rejects.toThrow(/method/);
    await expect(wrapMaster(kek, master, 'app', 'a:b:c')).rejects.toThrow(/method/);
    await expect(wrapMaster(kek, master, 1 as never, 'x')).rejects.toThrow(/application/);
    await expect(wrapMaster(kek, master, 'app', 1 as never)).rejects.toThrow(/method/);
    await expect(wrapMaster(kek, new Uint8Array(31), 'app', 'x')).rejects.toThrow(/master key/);
    await expect(wrapMaster(new Uint8Array(31), master, 'app', 'x')).rejects.toThrow(/wrapping key/);
    await expect(wrapMaster('k' as never, master, 'app', 'x')).rejects.toThrow(/wrapping key/);
    await expect(wrapMaster(kek, master, 'app', 'x', new Uint8Array(8))).rejects.toThrow(/nonce/);
    await expect(wrapMaster(kek, master, 'app', 'x', 'n' as never)).rejects.toThrow(/nonce/);
  });
});

describe('keyfile – file', () => {
  it('create, unlock with password and phrase, change both, other keys, remove', async () => {
    const { file, master, secret } = await createKeyFile('testapp', 'heslo správcu', { kdf: KDF });
    expect(file).toMatchObject({ format: 'regino-keyfile', v: 1, app: 'testapp', words: 12, kdf: { m: KDF.m, t: KDF.t, p: KDF.p } });
    expect(Object.keys(file.wraps).sort()).toEqual(['password', 'recovery']);
    expect(secret).toHaveLength(16);
    expect(parseKeyFile(JSON.stringify(file))).toEqual(file);
    expect(await unlockWithPassword(file, 'heslo správcu')).toEqual(master);
    expect(await unlockWithPassword(file, 'zlé heslo')).toBeNull();
    expect(await unlockWithRecovery(file, secret)).toEqual(master);
    expect(await unlockWithRecovery(file, new Uint8Array(16))).toBeNull();
    expect(await unlockWithRecovery(file, new Uint8Array(32))).toBeNull();

    const pw = await withPassword(file, master, 'nové heslo');
    expect(pw.kdf.salt).not.toBe(file.kdf.salt);
    expect(await unlockWithPassword(pw, 'heslo správcu')).toBeNull();
    expect(await unlockWithPassword(pw, 'nové heslo')).toEqual(master);
    expect(await unlockWithRecovery(pw, secret)).toEqual(master);

    const r = await withNewRecovery(pw, master, 24);
    expect(r.file.words).toBe(24);
    expect(await unlockWithRecovery(r.file, secret)).toBeNull();
    expect(await unlockWithRecovery(r.file, r.secret)).toEqual(master);
    expect((await withNewRecovery(pw, master)).file.words).toBe(12);

    const share = crypto.getRandomValues(new Uint8Array(32));
    const s = await withKey(r.file, master, 'shares', share);
    expect(await unlockWithKey(s, 'shares', share)).toEqual(master);
    expect(await unlockWithKey(s, 'device:windows-hello', share)).toBeNull();
    await expect(unlockWithKey(s, 'Zle', share)).rejects.toThrow(/method/);
    const off = withoutKey(s, 'shares');
    expect(off.wraps.shares).toBeUndefined();
    expect(s.wraps.shares).toBeDefined();
    expect(() => withoutKey(s, 'password')).toThrow(/cannot be removed/);
    expect(() => withoutKey(s, 'recovery')).toThrow(/cannot be removed/);
    await expect(createKeyFile('A', 'x', { kdf: KDF })).rejects.toThrow(/application/);
  }, 60000);

  it('default parameters and 24 words', async () => {
    const { file } = await createKeyFile('testapp', 'x', { words: 24 });
    expect(file.words).toBe(24);
    expect(file.kdf).toMatchObject({ m: 65536, t: 3, p: 1 });
  }, 60000);

  it('parse refuses anything else before any work', () => {
    const good = {
      format: 'regino-keyfile',
      v: 1,
      app: 'testapp',
      kdf: { ...KDF, salt: b64(new Uint8Array(16)) },
      words: 12,
      wraps: { password: b64(new Uint8Array(64)) },
    };
    expect(parseKeyFile(good)).toEqual(good);
    for (const bad of [
      null,
      'nie json',
      '[1]',
      { ...good, format: 'x' },
      { ...good, v: 2 },
      { ...good, app: 'A' },
      { ...good, app: 7 },
      { ...good, kdf: undefined },
      { ...good, kdf: { ...good.kdf, m: 1 << 30 } },
      { ...good, kdf: { ...good.kdf, salt: b64(new Uint8Array(15)) } },
      { ...good, kdf: { ...good.kdf, salt: 'nie base64!' } },
      { ...good, kdf: { ...good.kdf, salt: 'A' } },
      { ...good, kdf: { ...good.kdf, salt: 5 } },
      { ...good, words: 18 },
      { ...good, wraps: null },
      { ...good, wraps: [] },
      { ...good, wraps: { Zle: b64(new Uint8Array(64)) } },
      { ...good, wraps: { password: b64(new Uint8Array(63)) } },
    ])
      expect(parseKeyFile(bad)).toBeNull();
    expect(unb64(parseKeyFile(JSON.stringify(good))!.wraps.password!)).toHaveLength(64);
  });
});
