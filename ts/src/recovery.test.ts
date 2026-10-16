import { describe, expect, it } from 'vitest';
import {
  DEFAULT_STRENGTH,
  newRecoverySecret,
  normalizeWord,
  parseRecoveryQr,
  recoveryKey,
  recoveryQrText,
  secretToWords,
  strengthOf,
  wordsToSecret,
  type RecoveryStrength,
} from './recovery';
import { WORDLIST_SK } from './wordlist-sk';

// 24-word code from version 0.1.0 (fixed vector). The recovery words are Slovak by design.
const OLD_WORDS =
  'aréna jednota hrad halušky krajčír pätka verbovať hudobník jedáleň satelit paroh tapeta fúra hladký defekt vŕba pinzeta dlaň veľtrh lotos bobrík úsmev kaučuk otec';
const hex = (b: Uint8Array) => Array.from(b, (x) => x.toString(16).padStart(2, '0')).join('');

describe('word list', () => {
  it('2048 words, 4–8 letters, unique first 4 letters without diacritics', () => {
    expect(WORDLIST_SK).toHaveLength(2048);
    const prefixes = new Set(WORDLIST_SK.map((w) => normalizeWord(w).slice(0, 4)));
    expect(prefixes.size).toBe(2048);
    for (const w of WORDLIST_SK) expect(normalizeWord(w), w).toMatch(/^[a-z]{4,8}$/);
  });

  it('the list never changes (fingerprint)', async () => {
    const digest = await crypto.subtle.digest(
      'SHA-256',
      new TextEncoder().encode(WORDLIST_SK.join('\n')),
    );
    expect(hex(new Uint8Array(digest))).toMatchSnapshot();
  });
});

describe('recovery code', () => {
  it('12 words (128 bits) by default, 24 words (256 bits) optionally', () => {
    expect(DEFAULT_STRENGTH).toBe(12);
    expect(newRecoverySecret()).toHaveLength(16);
    expect(newRecoverySecret(24)).toHaveLength(32);
    expect(() => newRecoverySecret(18 as RecoveryStrength)).toThrow('12 or 24');
  });

  it.each([12, 24] as const)('%i words → the same bytes back', async (n) => {
    for (let i = 0; i < 20; i++) {
      const secret = newRecoverySecret(n);
      const words = await secretToWords(secret);
      expect(words).toHaveLength(n);
      expect(strengthOf(secret)).toBe(n);
      const back = await wordsToSecret(words.join(' '));
      expect(back.ok && hex(back.secret)).toBe(hex(secret));
    }
  });

  it('known vector: all zeros', async () => {
    const words = await secretToWords(new Uint8Array(32));
    expect(words.slice(0, 23)).toEqual(Array(23).fill(WORDLIST_SK[0]));
    // 12 words: 128 zeros + 4 checksum bits of SHA-256(16 × 0x00) = 0x37… → 0011
    const w12 = await secretToWords(new Uint8Array(16));
    expect(w12.slice(0, 11)).toEqual(Array(11).fill(WORDLIST_SK[0]));
    expect(w12[11]).toBe(WORDLIST_SK[3]);
  });

  it('the 24-word code from version 0.1.0 stays valid (fixed vector)', async () => {
    const secret = new Uint8Array(32).map((_, i) => i * 7 + 3);
    expect((await secretToWords(secret)).join(' ')).toBe(OLD_WORDS);
  });

  it('accepts the first 4 letters, no diacritics, upper case, commas and new lines', async () => {
    const secret = newRecoverySecret();
    const words = await secretToWords(secret);
    const typed = words
      .map((w, i) => (i % 2 ? normalizeWord(w).slice(0, 4).toUpperCase() : normalizeWord(w)))
      .map((w, i) => w + (i % 3 === 0 ? ', ' : '\n'))
      .join('');
    const r = await wordsToSecret(typed);
    expect(r.ok && hex(r.secret)).toBe(hex(secret));
  });

  it.each([12, 24] as const)('errors with %i words: count, unknown word, typo, checksum', async (n) => {
    const words = await secretToWords(newRecoverySecret(n));
    expect(await wordsToSecret(words.slice(0, n - 1).join(' '))).toEqual({
      ok: false,
      error: { code: 'count', count: n - 1 },
    });
    const unknown = [...words];
    unknown[5] = 'xyzq';
    expect(await wordsToSecret(unknown.join(' '))).toEqual({
      ok: false,
      error: { code: 'unknown-word', index: 5, word: 'xyzq' },
    });
    const short = [...words];
    short[2] = 'abc';
    expect(await wordsToSecret(short.join(' '))).toMatchObject({
      ok: false,
      error: { code: 'unknown-word', index: 2 },
    });
    const typo = [...words];
    typo[0] = normalizeWord(words[0] as string) + 'x';
    expect(await wordsToSecret(typo.join(' '))).toMatchObject({
      ok: false,
      error: { code: 'unknown-word', index: 0 },
    });
    // swapping two different words almost always breaks the checksum
    const swapped = [...words];
    const j = swapped.findIndex((w, k) => k > 0 && w !== swapped[0]);
    [swapped[0], swapped[j]] = [swapped[j] as string, swapped[0] as string];
    const r = await wordsToSecret(swapped.join(' '));
    if (!r.ok) expect(r.error.code).toBe('checksum');
  });

  it('the checksum catches a change of the last word', async () => {
    const words = await secretToWords(new Uint8Array(32).fill(7));
    const idx = WORDLIST_SK.indexOf(words[23] as string);
    let caught = 0;
    for (let d = 1; d <= 16; d++) {
      const w = [...words];
      w[23] = WORDLIST_SK[(idx + d) % 2048] as string;
      const r = await wordsToSecret(w.join(' '));
      if (!r.ok && r.error.code === 'checksum') caught++;
    }
    expect(caught).toBeGreaterThanOrEqual(15); // 8 checksum bits: 1 in 256 passes by chance
  });

  it('the checksum (4 bits) catches most changes of the last of 12 words', async () => {
    const words = await secretToWords(new Uint8Array(16).fill(7));
    const idx = WORDLIST_SK.indexOf(words[11] as string);
    let caught = 0;
    for (let d = 1; d <= 64; d++) {
      const w = [...words];
      w[11] = WORDLIST_SK[(idx + d) % 2048] as string;
      const r = await wordsToSecret(w.join(' '));
      if (!r.ok && r.error.code === 'checksum') caught++;
    }
    expect(caught).toBeGreaterThanOrEqual(56); // 1 in 16 passes by chance
  });

  it('rejects a wrong secret length', async () => {
    await expect(secretToWords(new Uint8Array(20))).rejects.toThrow('16 or 32 bytes');
  });
});

describe('recovery sheet QR code', () => {
  it.each([12, 24] as const)('%i words: QR text → the same secret, no URL', async (n) => {
    const secret = newRecoverySecret(n);
    const text = await recoveryQrText(secret);
    expect(text).toMatch(/^RGR1:[A-Z2-7]+$/); // QR alphanumeric mode, no http
    expect(text).toHaveLength(n === 12 ? 34 : 60);
    const r = await wordsToSecret(text);
    expect(r.ok && hex(r.secret)).toBe(hex(secret));
    const lower = await wordsToSecret(`  ${text.toLowerCase()}\n`);
    expect(lower.ok && hex(lower.secret)).toBe(hex(secret));
  });

  it('damaged or incomplete QR text is rejected', async () => {
    const text = await recoveryQrText(newRecoverySecret());
    const flipped = text.slice(0, 10) + (text[10] === 'A' ? 'B' : 'A') + text.slice(11);
    expect(await wordsToSecret(flipped)).toEqual({ ok: false, error: { code: 'qr' } });
    expect(await wordsToSecret(text.slice(0, -4))).toEqual({ ok: false, error: { code: 'qr' } });
    expect(await wordsToSecret('RGR1:abc!')).toEqual({ ok: false, error: { code: 'qr' } });
    expect(parseRecoveryQr('aréna jednota')).toBeNull();
    await expect(recoveryQrText(new Uint8Array(8))).rejects.toThrow();
  });
});

describe('key from the recovery code', () => {
  it('fixed vectors – identical to Rust (regino-keys::recovery)', async () => {
    const s16 = Uint8Array.from({ length: 16 }, (_, i) => i);
    const s32 = Uint8Array.from({ length: 32 }, (_, i) => i);
    expect(hex(await recoveryKey(s16, 'demo'))).toBe('4d5711cad6ba1e73e9417e9b796bce4e2f3e81b4208a436da51eaef046d55b59');
    expect(hex(await recoveryKey(s32, 'demo'))).toBe('5bb59f517c2278f3c4e392fc31514a57fa04e678ec5edc0d41975d08ae4ac700');
  });

  it('rejects an invalid application name', async () => {
    await expect(recoveryKey(new Uint8Array(16), 'Do-vernik')).rejects.toThrow('application name');
  });
});
