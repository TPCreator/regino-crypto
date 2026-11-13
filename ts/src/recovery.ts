import { equalBytes } from './bytes';
import { WORDLIST_EN } from './wordlist-en';
import { WORDLIST_SK } from './wordlist-sk';

/**
 * Recovery code (same structure as BIP-39, a list of 2048 words – Slovak by default, English since 0.14.0):
 * - standard: 128 bits of randomness + 4 checksum bits = 132 bits = **12 words** (default),
 * - maximum security: 256 bits + 8 bits = 264 bits = **24 words**.
 * Checksum = the first bits of SHA-256 of the secret. On recovery, the length follows from the word count.
 * Backup keys (and later sync keys) are derived from the code. It is shown once – print it and store it safely.
 */
export type RecoveryStrength = 12 | 24;
export const DEFAULT_STRENGTH: RecoveryStrength = 12;
export const WORD_COUNTS: readonly RecoveryStrength[] = [12, 24];
const BYTES: Record<RecoveryStrength, number> = { 12: 16, 24: 32 };
/** @deprecated original constants of the 24-word code – kept for backward compatibility */
export const SECRET_BYTES = 32;
/** @deprecated */
export const WORD_COUNT = 24;

export function normalizeWord(word: string): string {
  return word
    .normalize('NFD')
    .replace(/\p{Diacritic}/gu, '')
    .toLowerCase()
    .trim();
}

/**
 * Language of the word list (since 0.14.0). Only the words differ: the secret, the checksum, the QR text
 * and every key derived from the secret are the same in all languages. Default `'sk'` (the only list up
 * to 0.13.x), so calls without a language behave exactly as before.
 * - `'sk'`: the Slovak list (`wordlist-sk.ts`),
 * - `'en'`: the standard BIP-39 English list (`wordlist-en.ts`, MIT).
 */
export type RecoveryLanguage = 'sk' | 'en';
export const DEFAULT_LANGUAGE: RecoveryLanguage = 'sk';
/** All word lists, in the order `wordsToSecretAuto` tries them. */
export const RECOVERY_LANGUAGES: readonly RecoveryLanguage[] = ['sk', 'en'];

const LISTS: Readonly<Record<RecoveryLanguage, readonly string[]>> = { sk: WORDLIST_SK, en: WORDLIST_EN };
/** First 4 letters without diacritics (or the whole word if shorter) → index; unique in each list. */
const BY_PREFIX: Readonly<Record<RecoveryLanguage, ReadonlyMap<string, number>>> = {
  sk: new Map(WORDLIST_SK.map((w, i) => [normalizeWord(w).slice(0, 4), i])),
  en: new Map(WORDLIST_EN.map((w, i) => [normalizeWord(w).slice(0, 4), i])),
};

/** The 2048 words of a language (throws for an unknown language). */
export function recoveryWordList(lang: RecoveryLanguage = DEFAULT_LANGUAGE): readonly string[] {
  if (!Object.hasOwn(LISTS, lang)) throw new Error(`Unknown recovery word list: ${String(lang)}.`);
  return LISTS[lang];
}

export function newRecoverySecret(strength: RecoveryStrength = DEFAULT_STRENGTH): Uint8Array {
  const n = BYTES[strength];
  if (!n) throw new Error('The recovery code must have 12 or 24 words.');
  return crypto.getRandomValues(new Uint8Array(n));
}

/** Word count for a secret of the given length (16 B → 12, 32 B → 24). */
export function strengthOf(secret: Uint8Array): RecoveryStrength {
  if (secret.length === 16) return 12;
  if (secret.length === 32) return 24;
  throw new Error('The recovery secret must have 16 or 32 bytes.');
}

/** Checksum bits: the first `secret.length / 4` bits of SHA-256 (4 bits for 12 words, 8 for 24). */
async function checksumBits(secret: Uint8Array): Promise<string> {
  const digest = new Uint8Array(await crypto.subtle.digest('SHA-256', secret as BufferSource));
  return (digest[0] as number).toString(2).padStart(8, '0').slice(0, secret.length / 4);
}

const toBits = (bytes: Uint8Array) => [...bytes].map((b) => b.toString(2).padStart(8, '0')).join('');

/** 16 or 32 bytes → 12 or 24 words of the given list (with diacritics, as in the word list). */
export async function secretToWords(
  secret: Uint8Array,
  lang: RecoveryLanguage = DEFAULT_LANGUAGE,
): Promise<string[]> {
  const list = recoveryWordList(lang);
  const count = strengthOf(secret);
  const bits = toBits(secret) + (await checksumBits(secret));
  const words: string[] = [];
  for (let i = 0; i < count; i++)
    words.push(list[parseInt(bits.slice(i * 11, i * 11 + 11), 2)] as string);
  return words;
}

export type RecoveryError =
  | { code: 'count'; count: number }
  | { code: 'unknown-word'; index: number; word: string }
  | { code: 'checksum' }
  /** the QR code text is damaged or incomplete */
  | { code: 'qr' };

/**
 * User input → 16 or 32 bytes (by word count: 12 or 24). Accepts words with or without
 * diacritics, in upper or lower case, separated by spaces, commas or new lines; the first
 * 4 letters of each word are enough (a shorter word is typed whole). Also accepts the text from the
 * recovery sheet QR code (the same in every language).
 *
 * `lang` selects the word list (default Slovak, as up to 0.13.x). An app that does not know which list
 * the user's code comes from uses `wordsToSecretAuto`.
 */
export async function wordsToSecret(
  input: string,
  lang: RecoveryLanguage = DEFAULT_LANGUAGE,
): Promise<{ ok: true; secret: Uint8Array } | { ok: false; error: RecoveryError }> {
  const list = recoveryWordList(lang);
  const qr = parseRecoveryQr(input);
  if (qr) {
    if (!qr.ok) return { ok: false, error: { code: 'qr' } };
    const check = await sha2(qr.secret);
    if (!equalBytes(check, qr.check)) return { ok: false, error: { code: 'qr' } };
    return { ok: true, secret: qr.secret };
  }
  const words = input.split(/[\s,;.]+/).filter(Boolean);
  const count = words.length as RecoveryStrength;
  if (!WORD_COUNTS.includes(count)) return { ok: false, error: { code: 'count', count: words.length } };
  let bits = '';
  for (const [index, word] of words.entries()) {
    const n = normalizeWord(word);
    const i = BY_PREFIX[lang].get(n.slice(0, 4));
    // Exactly the first 4 letters, or the whole word – more letters must spell the whole word, not just
    // start like it (typo protection). The Slovak words have at least 4 letters, so for them this is the
    // rule of 0.13.x unchanged; an English word of 3 letters is typed whole.
    if (i === undefined || (n.length !== 4 && normalizeWord(list[i] as string) !== n)) {
      return { ok: false, error: { code: 'unknown-word', index, word } };
    }
    bits += i.toString(2).padStart(11, '0');
  }
  const secret = new Uint8Array(BYTES[count]);
  for (let b = 0; b < secret.length; b++) secret[b] = parseInt(bits.slice(b * 8, b * 8 + 8), 2);
  const enc = new TextEncoder();
  if (!equalBytes(enc.encode(await checksumBits(secret)), enc.encode(bits.slice(secret.length * 8))))
    return { ok: false, error: { code: 'checksum' } };
  return { ok: true, secret };
}

/** Error of `wordsToSecretAuto`: a `RecoveryError`, or words that are a valid code in more than one list. */
export type RecoveryAutoError =
  | RecoveryError
  /**
   * Valid (words and checksum) in more than one list – practically never happens with codes made by
   * `secretToWords`, but possible. The caller tries each candidate (e.g. the one that unwraps the key or
   * opens the backup – AEAD decides) or asks the user which language the code is in.
   */
  | { code: 'ambiguous'; candidates: { lang: RecoveryLanguage; secret: Uint8Array }[] };

/**
 * Like `wordsToSecret`, but the word list is recognised from the words (since 0.14.0): the code is
 * decoded with every list in `languages` and accepted only when exactly one of them gives valid words
 * **and** a valid checksum; a code valid in more than one list is never decoded silently
 * (`ambiguous`). `lang` is the list that matched (`null` for the QR text, which has no language).
 * When no list fits, the error of the list that got furthest is returned: `checksum` (all words known),
 * else `unknown-word` with the highest index, else `count`.
 */
export async function wordsToSecretAuto(
  input: string,
  languages: readonly RecoveryLanguage[] = RECOVERY_LANGUAGES,
): Promise<
  { ok: true; secret: Uint8Array; lang: RecoveryLanguage | null } | { ok: false; error: RecoveryAutoError }
> {
  const langs = [...new Set(languages)];
  if (!langs.length) throw new Error('At least one recovery word list is required.');
  langs.forEach((l) => recoveryWordList(l));
  if (parseRecoveryQr(input)) {
    const r = await wordsToSecret(input);
    return r.ok ? { ok: true, secret: r.secret, lang: null } : r;
  }
  const results = await Promise.all(langs.map(async (lang) => ({ lang, r: await wordsToSecret(input, lang) })));
  const candidates: { lang: RecoveryLanguage; secret: Uint8Array }[] = [];
  for (const { lang, r } of results) if (r.ok) candidates.push({ lang, secret: r.secret });
  if (candidates.length === 1) {
    const [c] = candidates as [{ lang: RecoveryLanguage; secret: Uint8Array }];
    return { ok: true, secret: c.secret, lang: c.lang };
  }
  if (candidates.length > 1) return { ok: false, error: { code: 'ambiguous', candidates } };
  const rank = (e: RecoveryError) => (e.code === 'checksum' ? Infinity : e.code === 'unknown-word' ? e.index : -1);
  let best: RecoveryError | undefined;
  for (const { r } of results) {
    const e = (r as { ok: false; error: RecoveryError }).error;
    if (!best || rank(e) > rank(best)) best = e;
  }
  return { ok: false, error: best as RecoveryError };
}

/*
 * QR code on the recovery sheet: data only, no URL – "RGR1:" + base32 (A–Z, 2–7) of
 * [secret | 2 bytes of SHA-256]. Base32 fits the QR alphanumeric mode (smaller code).
 * The secret length (12 / 24 words) follows from the text length.
 */
export const QR_PREFIX = 'RGR1:';
const B32 = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567';

function base32(bytes: Uint8Array): string {
  const bits = toBits(bytes);
  let out = '';
  for (let i = 0; i < bits.length; i += 5) out += B32[parseInt(bits.slice(i, i + 5).padEnd(5, '0'), 2)];
  return out;
}

/** Base32 text length → byte count: 18 B (12 words + 2 check bytes) = 29 characters, 34 B (24 words) = 55. */
const QR_LENGTHS: Readonly<Record<number, number>> = { 29: 18, 55: 34 };

/**
 * Canonical base32 only (since 0.12.1): exactly 29 or 55 characters and the padding bits after the
 * last byte all zero – one secret has one QR text, trailing characters or non-zero padding are refused.
 */
function unbase32(text: string): Uint8Array | null {
  const len = QR_LENGTHS[text.length];
  if (!len) return null;
  let bits = '';
  for (const ch of text) {
    const v = B32.indexOf(ch);
    if (v < 0) return null;
    bits += v.toString(2).padStart(5, '0');
  }
  if (/[^0]/.test(bits.slice(len * 8))) return null;
  const out = new Uint8Array(len);
  for (let b = 0; b < len; b++) out[b] = parseInt(bits.slice(b * 8, b * 8 + 8), 2);
  return out;
}

async function sha2(bytes: Uint8Array): Promise<Uint8Array> {
  return new Uint8Array(await crypto.subtle.digest('SHA-256', bytes as BufferSource)).slice(0, 2);
}

/** Text for the recovery sheet QR code (created locally only, never sent anywhere). */
export async function recoveryQrText(secret: Uint8Array): Promise<string> {
  strengthOf(secret);
  return QR_PREFIX + base32(new Uint8Array([...secret, ...(await sha2(secret))]));
}


/**
 * Recognises text from the recovery sheet QR code. Returns null if the text is not a recovery
 * sheet QR code (it is then treated as words). The checksum is verified by `wordsToSecret` –
 * only syntax and length are checked here.
 */
export function parseRecoveryQr(
  input: string,
): { ok: true; secret: Uint8Array; check: Uint8Array } | { ok: false } | null {
  const t = input.trim().toUpperCase();
  if (!t.startsWith(QR_PREFIX)) return null;
  const raw = unbase32(t.slice(QR_PREFIX.length));
  if (!raw) return { ok: false };
  return { ok: true, secret: raw.slice(0, -2), check: raw.slice(-2) };
}

/**
 * Recovery code secret → 32-byte key for wrapping the master key.
 * Same computation as `regino_keys::recovery::recovery_key` in Rust (HKDF-SHA256,
 * context "<app> recovery-key v1 k128|k256") – a fixed vector in the tests guards the match.
 */
export async function recoveryKey(secret: Uint8Array, app: string): Promise<Uint8Array> {
  const bits = strengthOf(secret) === 12 ? 128 : 256;
  if (!/^[a-z][a-z0-9]{1,31}$/.test(app)) throw new Error('Invalid application name.');
  const base = await crypto.subtle.importKey('raw', secret as BufferSource, 'HKDF', false, ['deriveBits']);
  const out = await crypto.subtle.deriveBits(
    { name: 'HKDF', hash: 'SHA-256', salt: new Uint8Array(0), info: new TextEncoder().encode(`${app} recovery-key v1 k${bits}`) },
    base,
    256,
  );
  return new Uint8Array(out);
}
