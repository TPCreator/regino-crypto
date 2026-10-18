import { equalBytes } from './bytes';
import { WORDLIST_SK } from './wordlist-sk';

/**
 * Recovery code (same structure as BIP-39, Slovak list of 2048 words):
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

const BY_PREFIX = new Map(WORDLIST_SK.map((w, i) => [normalizeWord(w).slice(0, 4), i]));

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

/** 16 or 32 bytes → 12 or 24 words (with diacritics, as in the word list). */
export async function secretToWords(secret: Uint8Array): Promise<string[]> {
  const count = strengthOf(secret);
  const bits = toBits(secret) + (await checksumBits(secret));
  const words: string[] = [];
  for (let i = 0; i < count; i++)
    words.push(WORDLIST_SK[parseInt(bits.slice(i * 11, i * 11 + 11), 2)] as string);
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
 * 4 letters of each word are enough. Also accepts the text from the recovery sheet QR code.
 */
export async function wordsToSecret(
  input: string,
): Promise<{ ok: true; secret: Uint8Array } | { ok: false; error: RecoveryError }> {
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
    const i = n.length >= 4 ? BY_PREFIX.get(n.slice(0, 4)) : undefined;
    // If more than 4 letters are entered, the whole word must match, not just the prefix (typo protection).
    const full = i === undefined ? undefined : normalizeWord(WORDLIST_SK[i] as string);
    if (i === undefined || (n.length > 4 && full !== n)) {
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

function unbase32(text: string): Uint8Array | null {
  let bits = '';
  for (const ch of text) {
    const v = B32.indexOf(ch);
    if (v < 0) return null;
    bits += v.toString(2).padStart(5, '0');
  }
  const out = new Uint8Array(Math.floor(bits.length / 8));
  for (let b = 0; b < out.length; b++) out[b] = parseInt(bits.slice(b * 8, b * 8 + 8), 2);
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
  if (!raw || (raw.length !== 18 && raw.length !== 34)) return { ok: false };
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
