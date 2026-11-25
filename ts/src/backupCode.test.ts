import jsQR from 'jsqr';
import { argon2id } from '@noble/hashes/argon2.js';
import { describe, expect, it, vi } from 'vitest';
import v from '../../testvectors/regino/backup-code-0.15.0.json';
import { BACKUP_VERSION, BACKUP_VERSIONS, decryptBackup, encryptBackup, type EncryptedBackup } from './backup';
import {
  BACKUP_CODE_ALPHABET,
  BACKUP_CODE_QR_PREFIX,
  DEFAULT_BACKUP_CODE_KDF,
  MAX_BACKUP_CODE_KDF,
  MIN_BACKUP_CODE_KDF,
  backupCodeAppSalt,
  backupCodeId,
  backupCodeQrText,
  backupCodeStretch,
  formatBackupCode,
  hkdf32,
  isBackupCodeSecret,
  looksLikeBackupCode,
  newBackupCode,
  newBackupCodeParams,
  newBackupCodeSecret,
  parseBackupCode,
  validBackupCodeKdf,
} from './backupCode';
import { assembleChunkedFile, backupChunkKeys, openBackupChunk, sealBackupChunk } from './backupChunks';
import * as index from './index';
import { openBackup } from './openBackup';
import { newRecoverySecret, recoveryKey, secretToWords } from './recovery';
import { recoveryQrMatrix, recoveryQrSvg, recoverySheetHtml } from './sheet';

const hex = (b: Uint8Array) => Array.from(b, (x) => x.toString(16).padStart(2, '0')).join('');
const unhex = (h: string) => Uint8Array.from(h.match(/../g) ?? [], (x) => parseInt(x, 16));
const secretOf = (code: string) => {
  const r = parseBackupCode(code);
  if (!r.ok) throw new Error(`not a code: ${code}`);
  return r.secret;
};
const FAST = { kdf: MIN_BACKUP_CODE_KDF };
// Every key from a code is an Argon2id of 19–32 MiB (0.2–0.4 s in Node, more under coverage on a busy runner).
vi.setConfig({ testTimeout: 60_000 });
const data = { portfolio: [{ pupil: 'Bodka' }] };

describe('backup code – format', () => {
  it('has 16 characters of Crockford Base32 in four groups and 75 random bits', () => {
    expect(BACKUP_CODE_ALPHABET).toBe('0123456789ABCDEFGHJKMNPQRSTVWXYZ');
    expect(BACKUP_CODE_ALPHABET).not.toMatch(/[ILOU]/);
    const seen = new Set<string>();
    for (let i = 0; i < 200; i++) {
      const code = newBackupCode();
      expect(code).toMatch(/^[0-9A-HJKMNP-TV-Z]{4}(-[0-9A-HJKMNP-TV-Z]{4}){3}$/);
      seen.add(code);
      const r = parseBackupCode(code);
      expect(r.ok && r.code).toBe(code);
      expect(r.ok && isBackupCodeSecret(r.secret)).toBe(true);
    }
    expect(seen.size).toBe(200);
    // the 5 bits after the 75 bits are always zero
    for (let i = 0; i < 50; i++) expect((newBackupCodeSecret()[9] as number) & 0x1f).toBe(0);
  });

  it('every single wrong character and every swap of two different characters is detected', () => {
    for (let n = 0; n < 60; n++) {
      const plain = newBackupCode().replace(/-/g, '');
      for (let i = 0; i < 16; i++) {
        for (const ch of BACKUP_CODE_ALPHABET) {
          if (ch === plain[i]) continue;
          const bad = plain.slice(0, i) + ch + plain.slice(i + 1);
          expect(parseBackupCode(bad)).toEqual({ ok: false, error: { code: 'checksum' } });
        }
        for (let j = i + 1; j < 16; j++) {
          if (plain[i] === plain[j]) continue;
          const a = [...plain];
          [a[i], a[j]] = [a[j] as string, a[i] as string];
          expect(parseBackupCode(a.join(''))).toEqual({ ok: false, error: { code: 'checksum' } });
        }
      }
    }
  });

  it('random strings of 16 characters pass the check about once in 32', () => {
    let ok = 0;
    const n = 6400;
    for (let i = 0; i < n; i++) {
      const s = Array.from(crypto.getRandomValues(new Uint8Array(16)), (b) => BACKUP_CODE_ALPHABET[b & 31]).join('');
      if (parseBackupCode(s).ok) ok++;
    }
    expect(ok).toBeGreaterThan(n / 32 / 2);
    expect(ok).toBeLessThan((n / 32) * 2);
  });

  it('reading tolerates case, spaces, hyphens, dashes, look-alikes and the QR prefix', () => {
    const secret = newBackupCodeSecret();
    const code = formatBackupCode(secret);
    const plain = code.replace(/-/g, '');
    for (const input of [
      code,
      plain,
      plain.toLowerCase(),
      `  ${code}\n`,
      code.replace(/-/g, ' '),
      code.replace(/-/g, '–'),
      code.replace(/-/g, ' — '),
      plain.replace(/(.)/g, '$1 '),
      plain.replace(/0/g, 'O').replace(/1/g, 'I'),
      plain.replace(/0/g, 'o').replace(/1/g, 'l'),
      plain.replace(/1/g, 'i'),
      backupCodeQrText(secret),
      backupCodeQrText(secret).toLowerCase(),
      ` ${BACKUP_CODE_QR_PREFIX}${code}`,
    ]) {
      const r = parseBackupCode(input);
      expect(r.ok && hex(r.secret), input).toBe(hex(secret));
      expect(r.ok && r.code).toBe(code);
    }
  });

  it('errors say exactly what is wrong', () => {
    const code = formatBackupCode(unhex('0123456789abcdef0120'));
    expect(parseBackupCode('')).toEqual({ ok: false, error: { code: 'length', length: 0 } });
    expect(parseBackupCode(code.slice(0, -1))).toEqual({ ok: false, error: { code: 'length', length: 15 } });
    expect(parseBackupCode(`${code}-0000`)).toEqual({ ok: false, error: { code: 'length', length: 20 } });
    // the first unknown character wins over a wrong length
    expect(parseBackupCode('AB-U')).toEqual({ ok: false, error: { code: 'unknown-char', index: 2, char: 'U' } });
    expect(parseBackupCode(`${code.slice(0, 5)}u${code.slice(6)}`)).toEqual({ ok: false, error: { code: 'unknown-char', index: 4, char: 'u' } });
    expect(parseBackupCode(`😀${code.slice(1)}`)).toEqual({ ok: false, error: { code: 'unknown-char', index: 0, char: '😀' } });
    expect(parseBackupCode(`${code}ß`)).toEqual({ ok: false, error: { code: 'unknown-char', index: 16, char: 'ß' } });
    expect(parseBackupCode('RGR1:ABC')).toEqual({ ok: false, error: { code: 'unknown-char', index: 4, char: ':' } });
    expect(parseBackupCode(code.replace(/-/g, '_'))).toEqual({ ok: false, error: { code: 'unknown-char', index: 4, char: '_' } });
  });

  it('only a canonical 10-byte secret is a backup code secret', () => {
    expect(isBackupCodeSecret(new Uint8Array(10))).toBe(true);
    expect(isBackupCodeSecret(Uint8Array.of(0, 0, 0, 0, 0, 0, 0, 0, 0, 1))).toBe(false);
    expect(isBackupCodeSecret(new Uint8Array(16))).toBe(false);
    expect(isBackupCodeSecret('0000-0000-0000-0000')).toBe(false);
    expect(() => formatBackupCode(Uint8Array.of(0, 0, 0, 0, 0, 0, 0, 0, 0, 1))).toThrow('10 bytes');
    expect(() => backupCodeQrText(new Uint8Array(16))).toThrow('10 bytes');
  });

  it('recognises input meant as a code (only for messages)', () => {
    const code = newBackupCode();
    expect(looksLikeBackupCode(code)).toBe(true);
    expect(looksLikeBackupCode(code.replace(/-/g, ' '))).toBe(true);
    expect(looksLikeBackupCode(code.slice(0, 15))).toBe(true);
    expect(looksLikeBackupCode('rgc1:x')).toBe(true);
    expect(looksLikeBackupCode('one two')).toBe(false);
    expect(looksLikeBackupCode('abeceda batoh mreža batoh jedľa atlas')).toBe(false);
    expect(looksLikeBackupCode('abc def ghi jkl mno')).toBe(false);
  });

  it('the package exports only the public API of the backup code', () => {
    expect(typeof index.parseBackupCode).toBe('function');
    expect(typeof index.backupCodeId).toBe('function');
    for (const internal of ['backupCodeStretch', 'backupCodeBase', 'backupCodeAppSalt', 'hkdf32']) expect(index).not.toHaveProperty(internal);
  });
});

describe('backup code – Argon2id parameters', () => {
  it('default 32 MiB / 2 passes / 1 lane, minimum = OWASP (= Rust KdfParams::MIN), upper bounds', () => {
    expect(DEFAULT_BACKUP_CODE_KDF).toEqual({ m: 32768, t: 2, p: 1 });
    expect(MIN_BACKUP_CODE_KDF).toEqual({ m: 19456, t: 2, p: 1 });
    expect(MAX_BACKUP_CODE_KDF).toEqual({ m: 131072, t: 8, p: 4, work: 262144 });
    expect(validBackupCodeKdf(DEFAULT_BACKUP_CODE_KDF)).toBe(true);
    expect(validBackupCodeKdf(MIN_BACKUP_CODE_KDF)).toBe(true);
    expect(validBackupCodeKdf({ m: 131072, t: 2, p: 4 })).toBe(true);
    expect(validBackupCodeKdf({ m: 32768, t: 8, p: 1 })).toBe(true);
    for (const bad of [
      null,
      'x',
      {},
      { m: 19455, t: 2, p: 1 },
      { m: 32768, t: 1, p: 1 },
      { m: 32768, t: 2, p: 0 },
      { m: 131073, t: 2, p: 1 },
      { m: 32768, t: 9, p: 1 },
      { m: 32768, t: 2, p: 5 },
      { m: 65536, t: 5, p: 1 }, // work above 256 MiB
      { m: 32768.5, t: 2, p: 1 },
      { m: '32768', t: 2, p: 1 },
      { m: 1e12, t: 1e6, p: 1 },
    ])
      expect(validBackupCodeKdf(bad), JSON.stringify(bad)).toBe(false);
  });

  it('noble Argon2id passes the RFC 9106 test vector', () => {
    const r = v.rfc9106_argon2id;
    const tag = argon2id(unhex(r.password), unhex(r.salt), { m: r.m, t: r.t, p: r.p, dkLen: 32, key: unhex(r.secret), personalization: unhex(r.ad) });
    expect(hex(tag)).toBe('0d640df58d78766c08c037a34a8b53c9d01ef0452d75b65eb52520e96b01e659');
    expect(r.tag).toBe(hex(tag));
  });

  it('stretching refuses a wrong secret, salt or parameters', async () => {
    const s = newBackupCodeSecret();
    await expect(backupCodeStretch(new Uint8Array(16), new Uint8Array(16), MIN_BACKUP_CODE_KDF)).rejects.toThrow('10 bytes');
    await expect(backupCodeStretch(s, new Uint8Array(8), MIN_BACKUP_CODE_KDF)).rejects.toThrow('salt');
    await expect(backupCodeStretch(s, 'x' as unknown as Uint8Array, MIN_BACKUP_CODE_KDF)).rejects.toThrow('salt');
    await expect(backupCodeStretch(s, new Uint8Array(16), { m: 1024, t: 1, p: 1 })).rejects.toThrow('bounds');
    await expect(backupCodeAppSalt('Bad')).rejects.toThrow('application');
  });
});

describe('backup code – shared vectors with Rust (testvectors/regino/backup-code-0.15.0.json)', () => {
  it('codes, accepted spellings and refused inputs', () => {
    expect(v.version).toBe('0.15.0');
    expect(v.alphabet).toBe(BACKUP_CODE_ALPHABET);
    expect(v.kdf).toEqual({ default: DEFAULT_BACKUP_CODE_KDF, min: MIN_BACKUP_CODE_KDF, max: MAX_BACKUP_CODE_KDF });
    expect(v.codes.length).toBe(5);
    for (const c of v.codes) {
      expect(formatBackupCode(unhex(c.secret))).toBe(c.code);
      expect(backupCodeQrText(unhex(c.secret))).toBe(c.qr);
      for (const input of c.accepted) expect(hex(secretOf(input))).toBe(c.secret);
    }
    for (const t of v.invalid) expect(parseBackupCode(t.input)).toEqual({ ok: false, error: t.error });
  });

  it('Argon2id, backup keys, app salt and ids', async () => {
    expect(hex(await backupCodeAppSalt(v.app))).toBe(v.app_salt);
    for (const k of v.keys) {
      const stretch = await backupCodeStretch(unhex(k.secret), unhex(k.salt), k.kdf);
      expect(hex(stretch)).toBe(k.argon2id);
      expect(hex(await hkdf32(stretch, `${v.app} backup v3 code16`))).toBe(k.backup_key);
    }
    for (const c of v.codes.slice(0, 3)) expect(hex(await backupCodeId(unhex(c.secret), v.app))).toBe(c.id);
  });

  it('the fixed backups and the chunk open unchanged', async () => {
    for (const b of v.backups) {
      const r = await decryptBackup(secretOf(b.code), b.file, v.app);
      expect(r).toEqual({ ok: true, payload: b.payload, createdAt: b.file.createdAt });
    }
    const c = v.chunks[0]!;
    const secret = secretOf(c.code);
    const keys = await backupChunkKeys(secret, v.app);
    expect(new TextDecoder().decode(await openBackupChunk(keys, c.name, unhex(c.blob)))).toBe(c.content);
    const r = await decryptBackup(secret, c.backup.file, v.app);
    expect(r).toEqual({ ok: true, payload: c.backup.payload, createdAt: c.backup.file.createdAt, chunks: [c.name] });
  });
});

describe('backup code – backups (version 4 written since 0.19.0; version 3 read)', () => {
  it('encrypts with Argon2id parameters in the header and opens only with the same code', async () => {
    const secret = newBackupCodeSecret();
    const file = await encryptBackup(secret, data, '2026-11-14T08:00:00.000Z', 'ziacik', undefined, FAST);
    expect(BACKUP_VERSION).toBe(4);
    expect(BACKUP_VERSIONS).toEqual([1, 2, 3, 4]);
    expect(file).toMatchObject({ format: 'ziacik-backup', version: 4, secret: 'code16', kdf: { name: 'argon2id', ...MIN_BACKUP_CODE_KDF } });
    expect(file.chunks).toBeUndefined();
    expect(await decryptBackup(secret, file, 'ziacik')).toEqual({ ok: true, payload: data, createdAt: '2026-11-14T08:00:00.000Z' });
    expect(await decryptBackup(newBackupCodeSecret(), file, 'ziacik')).toEqual({ ok: false, error: 'wrong-key-or-damaged' });
    expect(await decryptBackup(secret, { ...file, format: 'other-backup' }, 'other')).toEqual({ ok: false, error: 'wrong-key-or-damaged' });
  });

  it('uses the default parameters and a new salt every time', async () => {
    const secret = newBackupCodeSecret();
    const a = await encryptBackup(secret, data, undefined, 'demo');
    const b = await encryptBackup(secret, data, undefined, 'demo');
    expect(a.kdf).toEqual({ name: 'argon2id', ...DEFAULT_BACKUP_CODE_KDF });
    expect(a.salt).not.toBe(b.salt);
    expect((await decryptBackup(secret, b, 'demo')).ok).toBe(true);
  });

  it('raised parameters are written to the header and read back', async () => {
    const secret = newBackupCodeSecret();
    const file = await encryptBackup(secret, data, undefined, 'demo', [], { kdf: { m: 20480, t: 3, p: 2 } });
    expect(file.kdf).toEqual({ name: 'argon2id', m: 20480, t: 3, p: 2 });
    expect((await decryptBackup(secret, file, 'demo')).ok).toBe(true);
    await expect(encryptBackup(secret, data, undefined, 'demo', [], { kdf: { m: 1024, t: 1, p: 1 } })).rejects.toThrow('bounds');
    await expect(encryptBackup(newRecoverySecret(), data, undefined, 'demo', [], { kdf: MIN_BACKUP_CODE_KDF })).rejects.toThrow('only for a backup code');
    await expect(encryptBackup(Uint8Array.of(0, 0, 0, 0, 0, 0, 0, 0, 0, 1), data, undefined, 'demo')).rejects.toThrow('12 or 24');
  });

  it('a changed header is detected; a planted or unknown header is refused before any work', async () => {
    const secret = newBackupCodeSecret();
    const file = await encryptBackup(secret, data, '2026-11-14T08:00:00.000Z', 'demo', undefined, FAST);
    const bad = (patch: Record<string, unknown>) => decryptBackup(secret, { ...file, ...patch }, 'demo');
    expect(await bad({ createdAt: '2026-11-15T08:00:00.000Z' })).toEqual({ ok: false, error: 'wrong-key-or-damaged' });
    expect(await bad({ kdf: { name: 'argon2id', m: 19456, t: 3, p: 1 } })).toEqual({ ok: false, error: 'wrong-key-or-damaged' });
    expect(await bad({ salt: btoa('x'.repeat(16)) })).toEqual({ ok: false, error: 'wrong-key-or-damaged' });
    expect(await bad({ salt: btoa('short') })).toEqual({ ok: false, error: 'wrong-key-or-damaged' });
    expect(await bad({ chunks: [] })).toEqual({ ok: false, error: 'wrong-key-or-damaged' });
    expect(await bad({ chunks: [1] })).toEqual({ ok: false, error: 'wrong-key-or-damaged' });
    expect(await bad({ chunks: ['a'.repeat(64)] })).toEqual({ ok: false, error: 'wrong-key-or-damaged' });
    // a header asking for 1 TiB of memory (or an unknown KDF / kind of secret) is not even tried
    for (const patch of [
      { kdf: { name: 'argon2id', m: 2 ** 30, t: 1000, p: 1 } },
      { kdf: { name: 'argon2id', m: 19456, t: 1, p: 1 } },
      { kdf: { name: 'scrypt', m: 32768, t: 2, p: 1 } },
      { kdf: 'argon2id' },
      { kdf: null },
      { kdf: undefined },
      { secret: 'words12' },
      { secret: undefined },
    ])
      expect(await bad(patch), JSON.stringify(patch)).toEqual({ ok: false, error: 'not-backup' });
    expect(await bad({ version: 5 })).toEqual({ ok: false, error: 'newer-version' });
    // a version-4 file relabelled as version 3 (or the other way round) does not open: other key and AAD
    expect(await bad({ version: 3 })).toEqual({ ok: false, error: 'wrong-key-or-damaged' });
  });

  it('a secret of the other kind never opens a backup', async () => {
    const code = newBackupCodeSecret();
    const words = newRecoverySecret();
    const byCode = await encryptBackup(code, data, undefined, 'demo', undefined, FAST);
    const byWords = await encryptBackup(words, data, undefined, 'demo');
    expect(await decryptBackup(words, byCode, 'demo')).toEqual({ ok: false, error: 'wrong-key-or-damaged' });
    expect(await decryptBackup(code, byWords, 'demo')).toEqual({ ok: false, error: 'wrong-key-or-damaged' });
    // also not a words backup relabelled as version 3, nor a code backup relabelled as version 1
    expect(await decryptBackup(code, { ...byWords, version: 3, secret: 'code16', kdf: byCode.kdf }, 'demo')).toEqual({ ok: false, error: 'wrong-key-or-damaged' });
    expect(await decryptBackup(code, { ...byCode, version: 1 }, 'demo')).toEqual({ ok: false, error: 'wrong-key-or-damaged' });
    // the words API refuses the code secret
    await expect(recoveryKey(code, 'demo')).rejects.toThrow('16 or 32 bytes');
    await expect(secretToWords(code)).rejects.toThrow('16 or 32 bytes');
  });

  it('the id is deterministic per code and application and independent of the backup key', async () => {
    const secret = newBackupCodeSecret();
    const id = await backupCodeId(secret, 'ziacik');
    expect(id.length).toBe(32);
    expect(hex(await backupCodeId(secret, 'ziacik'))).toBe(hex(id));
    expect(hex(await backupCodeId(secret, 'gazda'))).not.toBe(hex(id));
    expect(hex(await backupCodeId(newBackupCodeSecret(), 'ziacik'))).not.toBe(hex(id));
    await expect(backupCodeId(secret, 'Bad name')).rejects.toThrow('application');
    await expect(backupCodeId(new Uint8Array(16), 'demo')).rejects.toThrow('10 bytes');
  });
});

describe('backup code – chunks, opening tool and sheet', () => {
  it('backup chunks work with a code; the keys differ from those of words', async () => {
    const secret = newBackupCodeSecret();
    const keys = await backupChunkKeys(secret, 'demo');
    const c = await sealBackupChunk(keys, new TextEncoder().encode('fotka práce'));
    expect(new TextDecoder().decode(await openBackupChunk(await backupChunkKeys(secret, 'demo'), c.name, c.blob))).toBe('fotka práce');
    await expect(openBackupChunk(await backupChunkKeys(newBackupCodeSecret(), 'demo'), c.name, c.blob)).rejects.toThrow('code');
    await expect(backupChunkKeys(Uint8Array.of(0, 0, 0, 0, 0, 0, 0, 0, 0, 1), 'demo')).rejects.toThrow('16-character');
    await expect(backupChunkKeys(secret, 'X')).rejects.toThrow('application');
  });

  it('openBackup opens a code backup, with its files', async () => {
    const secret = newBackupCodeSecret();
    const code = formatBackupCode(secret);
    // version 4: the chunk keys come from the salt and parameters the backup is written with
    const params = newBackupCodeParams(MIN_BACKUP_CODE_KDF);
    const keys = await backupChunkKeys(secret, 'ziacik', params);
    const c = await sealBackupChunk(keys, new TextEncoder().encode('príloha'));
    const payload = { files: [{ name: 'a.txt', mime: 'text/plain', size: 8, chunks: [c.name] }] };
    const file = JSON.stringify(await encryptBackup(secret, payload, '2026-11-14T09:00:00.000Z', 'ziacik', [c.name], { params }));
    const r = await openBackup(file, code.toLowerCase().replace(/-/g, ' '));
    if (!r.ok || !r.chunkKeys) throw new Error('not opened');
    expect(r).toMatchObject({ app: 'ziacik', createdAt: '2026-11-14T09:00:00.000Z', payload });
    const parts = await assembleChunkedFile(r.chunkKeys, r.files[0]!, async (n) => (n === c.name ? c.blob : null));
    expect(new TextDecoder().decode(parts[0])).toBe('príloha');
    expect(await openBackup(file, backupCodeQrText(secret))).toMatchObject({ ok: true });
    const plain = JSON.stringify(await encryptBackup(secret, data, '2026-11-14T09:00:00.000Z', 'ziacik', undefined, FAST));
    expect(await openBackup(plain, code)).toEqual({ ok: true, app: 'ziacik', createdAt: '2026-11-14T09:00:00.000Z', payload: data, files: [], chunkKeys: null });
  });

  it('openBackup gives understandable messages for codes', async () => {
    const secret = unhex('0123456789abcdef0120');
    const code = formatBackupCode(secret);
    const file = JSON.stringify(await encryptBackup(secret, data, undefined, 'demo', undefined, FAST));
    expect(await openBackup(file, code.slice(0, 12))).toEqual({ ok: false, message: 'The backup code has 16 characters, 10 entered.' });
    expect(await openBackup(file, code.replace('A', 'U'))).toEqual({ ok: false, message: expect.stringContaining('Character no. 5 ("U")') });
    expect(await openBackup(file, code.replace('04', '40'))).toEqual({ ok: false, message: expect.stringContaining('two are swapped') });
    expect(await openBackup(file, newBackupCode())).toEqual({ ok: false, message: 'The code does not belong to this backup, or the file is damaged.' });
    const words = (await secretToWords(newRecoverySecret())).join(' ');
    expect(await openBackup(file, words)).toEqual({ ok: false, message: 'This backup is protected by a 16-character backup code, not by words.' });
    // a words backup with a code typed in
    const wordsFile = JSON.stringify(await encryptBackup(newRecoverySecret(), data, undefined, 'demo'));
    expect(await openBackup(wordsFile, code)).toEqual({ ok: false, message: expect.stringContaining('protected by 12 or 24 words') });
    expect(await openBackup(wordsFile, 'one two')).toEqual({ ok: false, message: '12 or 24 words are required, 2 entered.' });
  });

  it('the sheet shows the code and a QR code that reads back to the same secret', async () => {
    const secret = newBackupCodeSecret();
    const code = formatBackupCode(secret);
    const html = await recoverySheetHtml(secret, { appName: 'Žiačik', owner: 'Učiteľ <3. A>', createdAt: new Date('2026-11-14'), lang: 'sk' });
    expect(html).toContain('Žiačik – kód zálohy');
    expect(html).toContain('Učiteľ &lt;3. A&gt;');
    expect(html).toContain('16 znakov');
    expect(html).toContain(code.split('-').map((g) => `<span>${g}</span>`).join('<i>–</i>'));
    expect(html).toContain('aria-label="QR kód kódu zálohy"');
    expect(html).not.toMatch(/<ol>/);
    const en = await recoverySheetHtml(secret, { appName: 'App' });
    expect(en).toContain('App – backup code');
    expect(en).toContain('16 characters');
    expect(en).toContain('O = 0, I and L = 1');
    expect(await recoveryQrSvg(secret)).toContain('aria-label="QR code of the backup code"');
    // QR → image → jsQR, as the opening tool does with a photo
    const m = await recoveryQrMatrix(secret);
    const scale = 4;
    const quiet = 4;
    const size = (m.length + 2 * quiet) * scale;
    const px = new Uint8ClampedArray(size * size * 4).fill(255);
    m.forEach((row, r) =>
      row.forEach((dark, c) => {
        if (!dark) return;
        for (let y = 0; y < scale; y++)
          for (let x = 0; x < scale; x++) {
            const i = (((r + quiet) * scale + y) * size + (c + quiet) * scale + x) * 4;
            px[i] = px[i + 1] = px[i + 2] = 0;
          }
      }),
    );
    const text = jsQR(px, size, size)?.data as string;
    expect(text).toBe(backupCodeQrText(secret));
    expect(hex(secretOf(text))).toBe(hex(secret));
  });
});

// keep the type in use (documentation of the header shape)
const _shape: Partial<EncryptedBackup> = { version: 3, secret: 'code16', kdf: { name: 'argon2id', m: 32768, t: 2, p: 1 } };
void _shape;
