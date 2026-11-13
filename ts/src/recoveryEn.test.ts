import { describe, expect, it } from 'vitest';
import v from '../../testvectors/regino/recovery-en-0.14.0.json';
import { encryptBackup } from './backup';
import { openBackup } from './openBackup';
import {
  DEFAULT_LANGUAGE,
  RECOVERY_LANGUAGES,
  newRecoverySecret,
  normalizeWord,
  recoveryKey,
  recoveryQrText,
  recoveryWordList,
  secretToWords,
  wordsToSecret,
  wordsToSecretAuto,
  type RecoveryLanguage,
} from './recovery';
import { recoverySheetHtml } from './sheet';
import { WORDLIST_EN } from './wordlist-en';
import { WORDLIST_SK } from './wordlist-sk';

// English word list (0.14.0): the standard BIP-39 list. Nothing about the Slovak code changes –
// the tests in recovery.test.ts, sheet.test.ts and openBackup.test.ts run unchanged.
const hex = (b: Uint8Array) => Array.from(b, (x) => x.toString(16).padStart(2, '0')).join('');
const unhex = (h: string) => Uint8Array.from(h.match(/../g) ?? [], (x) => parseInt(x, 16));

describe('English word list', () => {
  it('is the BIP-39 English list byte for byte (SHA-256 of english.txt)', async () => {
    const file = new TextEncoder().encode(WORDLIST_EN.join('\n') + '\n');
    const digest = new Uint8Array(await crypto.subtle.digest('SHA-256', file));
    expect(hex(digest)).toBe(v.wordlists.en.sha256_of_file);
    expect(hex(digest)).toBe('2f5eed53a4727b4bf8880d8f3f199efc90e58503646d9ff8eff3a2ed3b24dbda');
  });

  it('2048 words, 3–8 ASCII letters, unique first 4 letters', () => {
    expect(WORDLIST_EN).toHaveLength(2048);
    expect(new Set(WORDLIST_EN.map((w) => w.slice(0, 4))).size).toBe(2048);
    for (const w of WORDLIST_EN) expect(normalizeWord(w), w).toBe(w);
    for (const w of WORDLIST_EN) expect(w).toMatch(/^[a-z]{3,8}$/);
  });

  it('word lists by language; Slovak stays the default', () => {
    expect(DEFAULT_LANGUAGE).toBe('sk');
    expect(RECOVERY_LANGUAGES).toEqual(['sk', 'en']);
    expect(recoveryWordList()).toBe(WORDLIST_SK);
    expect(recoveryWordList('sk')).toBe(WORDLIST_SK);
    expect(recoveryWordList('en')).toBe(WORDLIST_EN);
    for (const bad of ['de', 'EN', '', 'toString', '__proto__'])
      expect(() => recoveryWordList(bad as RecoveryLanguage), bad).toThrow('Unknown recovery word list');
  });
});

describe('English recovery code', () => {
  it('BIP-39 test vectors: the same words for the same entropy', async () => {
    for (const [entropy, mnemonic] of v.bip39_english.vectors as [string, string][]) {
      expect((await secretToWords(unhex(entropy), 'en')).join(' ')).toBe(mnemonic);
      const r = await wordsToSecret(mnemonic, 'en');
      expect(r.ok && hex(r.secret)).toBe(entropy);
    }
  });

  it('shared vectors: English and Slovak words, QR text and key of one secret (Rust checks the key)', async () => {
    for (const c of v.codes) {
      const secret = unhex(c.secret);
      expect((await secretToWords(secret, 'en')).join(' ')).toBe(c.en);
      expect((await secretToWords(secret)).join(' ')).toBe(c.sk);
      expect((await secretToWords(secret, 'sk')).join(' ')).toBe(c.sk);
      expect(await recoveryQrText(secret)).toBe(c.qr);
      expect(hex(await recoveryKey(secret, v.app))).toBe(c.recovery_key);
      for (const [input, lang] of [[c.en, 'en'], [c.sk, 'sk'], [c.qr, 'en'], [c.qr, 'sk']] as const) {
        const r = await wordsToSecret(input, lang);
        expect(r.ok && hex(r.secret)).toBe(c.secret);
      }
      for (const [input, lang] of [[c.en, 'en'], [c.sk, 'sk'], [c.qr, null]] as const)
        expect(await wordsToSecretAuto(input)).toEqual({ ok: true, secret, lang });
    }
  });

  it.each([12, 24] as const)('%i words → the same bytes back; prefixes, upper case, separators', async (n) => {
    for (let i = 0; i < 20; i++) {
      const secret = newRecoverySecret(n);
      const words = await secretToWords(secret, 'en');
      expect(words).toHaveLength(n);
      const typed = words
        .map((w, k) => (k % 2 ? w.slice(0, 4).toUpperCase() : w))
        .map((w, k) => w + (k % 3 === 0 ? ', ' : '\n'))
        .join('');
      for (const r of [await wordsToSecret(typed, 'en'), await wordsToSecretAuto(typed)])
        expect(r.ok && hex(r.secret)).toBe(hex(secret));
    }
  });

  it('a 3-letter word is typed whole; a shorter or longer form is refused', async () => {
    // all zeros + "zoo" words: "abandon … about" / "zoo … wrong"
    const zoo = 'zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo wrong';
    expect((await wordsToSecret(zoo, 'en')).ok).toBe(true);
    for (const bad of ['zo', 'zoox', 'zook'])
      expect(await wordsToSecret(zoo.replace('zoo', bad), 'en')).toEqual({
        ok: false,
        error: { code: 'unknown-word', index: 0, word: bad },
      });
    // a 4-letter prefix that continues wrongly, or a typo in a longer word
    expect(await wordsToSecret('abandonx '.repeat(11) + 'about', 'en')).toMatchObject({
      ok: false,
      error: { code: 'unknown-word', index: 0 },
    });
  });

  it('English words are not accepted by the Slovak list (default) and vice versa', async () => {
    const secret = unhex(v.codes[2]!.secret);
    const en = (await secretToWords(secret, 'en')).join(' ');
    const sk = (await secretToWords(secret)).join(' ');
    expect((await wordsToSecret(en)).ok).toBe(false);
    expect((await wordsToSecret(sk, 'en')).ok).toBe(false);
  });

  it('errors with English words: count, unknown word, checksum', async () => {
    const words = await secretToWords(newRecoverySecret(), 'en');
    expect(await wordsToSecret(words.slice(1).join(' '), 'en')).toEqual({ ok: false, error: { code: 'count', count: 11 } });
    const unknown = [...words];
    unknown[4] = 'xyzq';
    expect(await wordsToSecret(unknown.join(' '), 'en')).toEqual({
      ok: false,
      error: { code: 'unknown-word', index: 4, word: 'xyzq' },
    });
    const idx = WORDLIST_EN.indexOf(words[11] as string);
    let caught = 0;
    for (let d = 1; d <= 64; d++) {
      const w = [...words];
      w[11] = WORDLIST_EN[(idx + d) % 2048] as string;
      const r = await wordsToSecret(w.join(' '), 'en');
      if (!r.ok && r.error.code === 'checksum') caught++;
    }
    expect(caught).toBeGreaterThanOrEqual(56); // 1 in 16 passes by chance
  });

  it('an unknown language is refused', async () => {
    await expect(secretToWords(new Uint8Array(16), 'de' as RecoveryLanguage)).rejects.toThrow('Unknown recovery word list');
    await expect(wordsToSecret('abc', 'de' as RecoveryLanguage)).rejects.toThrow('Unknown recovery word list');
  });
});

describe('word list recognised from the words (wordsToSecretAuto)', () => {
  it('a code valid in both lists is never decoded silently', async () => {
    const a = v.ambiguous;
    const r = await wordsToSecretAuto(a.input);
    expect(r).toEqual({
      ok: false,
      error: {
        code: 'ambiguous',
        candidates: [
          { lang: 'sk', secret: unhex(a.sk) },
          { lang: 'en', secret: unhex(a.en) },
        ],
      },
    });
    // with one list only it is not ambiguous
    expect(await wordsToSecretAuto(a.input, ['en'])).toEqual({ ok: true, secret: unhex(a.en), lang: 'en' });
    expect(await wordsToSecretAuto(a.input, ['sk', 'sk'])).toEqual({ ok: true, secret: unhex(a.sk), lang: 'sk' });
    // and the explicit language decodes it as before
    const sk = await wordsToSecret(a.input);
    expect(sk.ok && hex(sk.secret)).toBe(a.sk);
  });

  it('errors: the list that got furthest', async () => {
    const en = await secretToWords(newRecoverySecret(), 'en');
    expect(await wordsToSecretAuto(en.slice(0, 11).join(' '))).toEqual({ ok: false, error: { code: 'count', count: 11 } });
    // English words, one unknown at index 7: Slovak stops at index 0 (or earlier), English at 7
    const unknown = [...en];
    unknown[7] = 'xyzq';
    const sk0 = WORDLIST_SK[0] as string; // "abeceda" – not English
    unknown[0] = WORDLIST_EN.find((w) => !WORDLIST_SK.some((s) => normalizeWord(s).slice(0, 4) === w.slice(0, 4))) as string;
    const ru = await wordsToSecretAuto(unknown.join(' '));
    if (ru.ok) throw new Error('accepted');
    expect(ru.error).toEqual({ code: 'unknown-word', index: 7, word: 'xyzq' });
    // all words known in one list, but a wrong checksum → checksum
    const zeros = (sk0 + ' ').repeat(12).trim(); // 12 × list[0]: the checksum of 16 zero bytes needs list[3]
    expect(await wordsToSecretAuto(zeros)).toEqual({ ok: false, error: { code: 'checksum' } });
    const zerosEn = 'abandon '.repeat(12).trim();
    expect(await wordsToSecretAuto(zerosEn)).toEqual({ ok: false, error: { code: 'checksum' } });
    // the same index in both lists: the first list in order wins
    expect(await wordsToSecretAuto('xyzq '.repeat(12).trim())).toEqual({
      ok: false,
      error: { code: 'unknown-word', index: 0, word: 'xyzq' },
    });
    // a damaged QR text
    const qr = await recoveryQrText(newRecoverySecret());
    expect(await wordsToSecretAuto(qr.slice(0, -1))).toEqual({ ok: false, error: { code: 'qr' } });
  });

  it('refuses an empty or unknown list of languages', async () => {
    await expect(wordsToSecretAuto('abc', [])).rejects.toThrow('At least one');
    await expect(wordsToSecretAuto('abc', ['sk', 'xx' as RecoveryLanguage])).rejects.toThrow('Unknown recovery word list');
  });
});

describe('recovery sheet and backup opening with English words', () => {
  it("the sheet prints English words with wordList 'en' (Slovak by default)", async () => {
    const secret = unhex(v.codes[2]!.secret);
    const opts = { appName: 'Demo', createdAt: new Date('2026-10-16T10:00:00Z') };
    const en = await recoverySheetHtml(secret, { ...opts, wordList: 'en' });
    expect(en).toContain('<li><b>1.</b> ozone</li>');
    expect(en).toContain('<li><b>12.</b> picnic</li>');
    const sk = await recoverySheetHtml(secret, opts);
    expect(sk).toContain('<li><b>1.</b> pitný</li>');
    // only the words differ – the QR code and the rest of the sheet are identical
    const strip = (h: string) => h.replace(/<ol>.*<\/ol>/s, '');
    expect(strip(en)).toBe(strip(sk));
    expect(await recoverySheetHtml(secret, { ...opts, wordList: 'sk' })).toBe(sk);
  });

  it.each([12, 24] as const)('open-backup opens a backup with English words (%i words)', async (n) => {
    const secret = newRecoverySecret(n);
    const file = JSON.stringify(await encryptBackup(secret, { a: 1 }, '2026-11-13T10:00:00.000Z', 'testik'));
    const r = await openBackup(file, (await secretToWords(secret, 'en')).join(' '));
    expect(r).toMatchObject({ ok: true, app: 'testik', payload: { a: 1 } });
  });

  it('words valid in both lists: the candidate that opens the backup wins', async () => {
    const a = v.ambiguous;
    for (const lang of ['sk', 'en'] as const) {
      const file = JSON.stringify(await encryptBackup(unhex(a[lang]), { lang }, '2026-11-13T10:00:00.000Z', 'demo'));
      expect(await openBackup(file, a.input)).toMatchObject({ ok: true, payload: { lang } });
    }
    const other = JSON.stringify(await encryptBackup(newRecoverySecret(), {}, '2026-11-13T10:00:00.000Z', 'demo'));
    expect(await openBackup(other, a.input)).toEqual({
      ok: false,
      message: 'The code does not belong to this backup, or the file is damaged.',
    });
  });
});
