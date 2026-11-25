/**
 * Data key on a device, a short PIN only as a gate (since 0.20.0; audit validation 2026-11-25, V-02 and L-04;
 * maintainer's decision 2026-11-25 "the PIN is nowhere the source of a key"). Design from app-core
 * `docs/deviceVault.md`, now as one fixed, versioned format in the core – apps do not assemble it themselves.
 *
 * - **Data key:** 32 random bytes, never derived from the PIN.
 * - **Device key:** a non-extractable AES-256-GCM `CryptoKey` that wraps the data key:
 *   - from a secret the operating system or a passkey gives (`deviceKeyFromSecret`, `deviceKeyFromPasskey`):
 *     HKDF-SHA256 with info `<app> device-key v1 <method>` – byte for byte Rust `regino_keys::device::device_key`
 *     (vectors `testvectors/regino/device-vault-0.20.0.json`); a **passkey PRF** output (WebAuthn `prf`
 *     extension) works the same in a browser, so there too the PIN is only a gate;
 *   - in a browser without a passkey: `newBrowserDeviceKey()` (`generateKey`, `extractable: false`, kept by the
 *     app as a `CryptoKey` in IndexedDB) – a script cannot read it, but a copy of the browser profile contains it,
 *     so the PIN must be a second factor there (`factor`).
 * - **Envelope** (`DeviceVaultEnvelope`, JSON): `format: "regino-device-vault"`, `version: 1`, `app`, `mode`,
 *   `nonce`, `ciphertext` = AES-256-GCM(device key, inner JSON, AAD `regino-device-vault|1|<app>|<mode>`):
 *   - `none`: `{ k }` – the data key; for data without a PIN;
 *   - `gate`: `{ k, pin }` – the data key and a PIN hash (`hashPin`: PBKDF2-SHA256, random salt). The hash is
 *     inside the encryption, so without the device key the PIN cannot even be tried; the app counts failures
 *     (`pinAttemptAllowed` / `afterPinAttempt`). For a device key from the OS or a passkey;
 *   - `factor`: `{ salt, kdf, nonce, ct }` – the data key sealed with Argon2id(PIN, salt, kdf) → HKDF
 *     `<app> device-vault v1 factor` → AES-256-GCM: the device key **and** the PIN are needed (8–12 digits). For
 *     `newBrowserDeviceKey`.
 *   The device layer is always opened first: a wrong or missing device key is `device-mismatch`, before any PIN work.
 * - What it does not protect: an unlocked app and code running in its window (it can use the key without reading
 *   it); with the OS keystore, someone with access to the **same OS account** who can ask the OS for the secret.
 *
 * TypeScript only (apps with Rust wrap with `device::device_key` + `wrap::wrap_key`); flow in `docs/DEVICE-VAULT.md`.
 */
import { b64, gcmNonce, unb64 } from './ecdh';
import { DEFAULT_BACKUP_CODE_KDF, hkdf32, validBackupCodeKdf, type BackupCodeKdf } from './backupCode';
import { hashPin, validPin, verifyPin } from './pin';
import { argon2idAsync } from '@noble/hashes/argon2.js';

export const DEVICE_VAULT_FORMAT = 'regino-device-vault';
export const DEVICE_VAULT_VERSION = 1;
export type DeviceVaultMode = 'none' | 'gate' | 'factor';
export const DEVICE_VAULT_MODES: readonly DeviceVaultMode[] = ['none', 'gate', 'factor'];
/** Shortest device secret (bytes), as Rust `device::MIN_SECRET`. */
export const MIN_DEVICE_SECRET = 32;
/** Method label of a passkey PRF device key (`<app> device-key v1 passkey-prf`). */
export const PASSKEY_PRF_METHOD = 'passkey-prf';
/** Argon2id of the `factor` PIN by default: 32 MiB, 2 passes, 1 lane (bounds as a backup code). */
export const DEFAULT_FACTOR_KDF: Readonly<BackupCodeKdf> = DEFAULT_BACKUP_CODE_KDF;

export interface DeviceVaultEnvelope {
  format: typeof DEVICE_VAULT_FORMAT;
  version: number;
  app: string;
  mode: DeviceVaultMode;
  /** base64, 12 B */
  nonce: string;
  /** base64 */
  ciphertext: string;
}

const enc = new TextEncoder();
const dec = new TextDecoder();
const APP = /^[a-z][a-z0-9]{1,31}$/;
const METHOD = /^[a-z][a-z0-9-]{2,31}$/;
const FACTOR_PIN = /^\d{8,12}$/;
function checkApp(app: string): void {
  if (typeof app !== 'string' || !APP.test(app)) throw new Error('Invalid application name.');
}

/** (internal) The 32 bytes of the device key – `regino_keys::device::device_key(secret, app, method)`. */
export async function deviceKeyBytes(secret: Uint8Array, app: string, method: string): Promise<Uint8Array> {
  checkApp(app);
  if (typeof method !== 'string' || !METHOD.test(method)) throw new Error('Invalid method label.');
  if (!(secret instanceof Uint8Array) || secret.length < MIN_DEVICE_SECRET) throw new Error(`The device secret must have at least ${MIN_DEVICE_SECRET} bytes.`);
  return hkdf32(secret, `${app} device-key v1 ${method}`);
}

async function importAesKey(raw: Uint8Array): Promise<CryptoKey> {
  try {
    return await crypto.subtle.importKey('raw', raw as BufferSource, 'AES-GCM', false, ['encrypt', 'decrypt']);
  } finally {
    raw.fill(0);
  }
}

/**
 * Device key from a secret held by the device: a Windows Hello signature, a secret from the OS keystore (DPAPI,
 * Android Keystore, Keychain) or a passkey PRF output; at least 32 bytes. `method` names the source (lowercase,
 * e.g. `windows-hello`, `os-keystore`, `passkey-prf`). Non-extractable. The caller wipes `secret` when done.
 */
export async function deviceKeyFromSecret(secret: Uint8Array, app: string, method: string): Promise<CryptoKey> {
  return importAesKey(await deviceKeyBytes(secret, app, method));
}

/** Device key generated in the browser (non-extractable; the app keeps the `CryptoKey` in IndexedDB). */
export async function newBrowserDeviceKey(): Promise<CryptoKey> {
  return crypto.subtle.generateKey({ name: 'AES-GCM', length: 256 }, false, ['encrypt', 'decrypt']);
}

// ---------- passkey (WebAuthn PRF extension) ----------

/**
 * The PRF input (32 bytes) the app asks a passkey to evaluate: SHA-256(`regino passkey-prf v1|<app>|<label>`). Fixed
 * per app and label, so the same passkey gives the same output on every sign-in (and another app another one).
 */
export async function passkeyPrfInput(app: string, label = 'device-vault'): Promise<Uint8Array> {
  checkApp(app);
  if (typeof label !== 'string' || !METHOD.test(label)) throw new Error('Invalid label.');
  return new Uint8Array(await crypto.subtle.digest('SHA-256', enc.encode(`regino passkey-prf v1|${app}|${label}`)));
}

/** The `extensions` part of `navigator.credentials.create` / `.get` options asking for the PRF of `input`. */
export function passkeyPrfExtension(input: Uint8Array): { prf: { eval: { first: Uint8Array } } } {
  if (!(input instanceof Uint8Array) || input.length !== 32) throw new Error('The PRF input must have 32 bytes.');
  return { prf: { eval: { first: input.slice() } } };
}

interface PrfCredential {
  getClientExtensionResults(): { prf?: { enabled?: boolean; results?: { first?: unknown } } };
}

/** Whether a passkey just created supports PRF (`prf.enabled`) – if not, the app falls back to `factor`. */
export function passkeyPrfEnabled(credential: PrfCredential): boolean {
  return credential.getClientExtensionResults().prf?.enabled === true;
}

/** The PRF output of a passkey sign-in (32 bytes, a copy), or null when the authenticator gave none. */
export function passkeyPrfOutput(credential: PrfCredential): Uint8Array | null {
  const first = credential.getClientExtensionResults().prf?.results?.first;
  const bytes =
    first instanceof ArrayBuffer ? new Uint8Array(first) : ArrayBuffer.isView(first) ? new Uint8Array(first.buffer, first.byteOffset, first.byteLength) : null;
  return bytes && bytes.length === 32 ? bytes.slice() : null;
}

/** Device key from a passkey PRF output (`deviceKeyFromSecret(output, app, 'passkey-prf')`); wipes `output`. */
export async function deviceKeyFromPasskey(output: Uint8Array, app: string): Promise<CryptoKey> {
  try {
    return await deviceKeyFromSecret(output, app, PASSKEY_PRF_METHOD);
  } finally {
    if (output instanceof Uint8Array) output.fill(0);
  }
}

// ---------- the envelope ----------

/** Options of `wrapDeviceVault` / `createDeviceVault`. */
export interface DeviceVaultOptions {
  mode: DeviceVaultMode;
  /** `gate`: 4–8 digits; `factor`: 8–12 digits; `none`: not allowed */
  pin?: string;
  /** `factor`: Argon2id parameters (default `DEFAULT_FACTOR_KDF`) */
  kdf?: BackupCodeKdf;
}

const aad = (app: string, mode: DeviceVaultMode) => enc.encode(`${DEVICE_VAULT_FORMAT}|${DEVICE_VAULT_VERSION}|${app}|${mode}`);
const factorAad = (app: string) => enc.encode(`${app} device-vault v1 factor`);

async function factorKey(pin: string, salt: Uint8Array, kdf: BackupCodeKdf, app: string): Promise<CryptoKey> {
  const pinBytes = enc.encode(pin);
  const stretched = await argon2idAsync(pinBytes, salt, { m: kdf.m, t: kdf.t, p: kdf.p, dkLen: 32, version: 0x13 });
  pinBytes.fill(0);
  const raw = await hkdf32(stretched, `${app} device-vault v1 factor`);
  stretched.fill(0);
  return importAesKey(raw);
}

/**
 * Wraps an existing data key (32 bytes) for this device: a new envelope, e.g. after changing the PIN or the mode,
 * or when moving from an older envelope – the data key and the data stay the same. The data key is not wiped.
 */
export async function wrapDeviceVault(
  deviceKey: CryptoKey,
  app: string,
  dataKey: Uint8Array,
  options: DeviceVaultOptions,
): Promise<DeviceVaultEnvelope> {
  checkApp(app);
  if (!(dataKey instanceof Uint8Array) || dataKey.length !== 32) throw new Error('The data key must have 32 bytes.');
  const mode = options?.mode;
  if (!DEVICE_VAULT_MODES.includes(mode)) throw new Error('Unknown mode.');
  const pin = options.pin;
  let inner: Record<string, unknown>;
  if (mode === 'none') {
    if (pin !== undefined) throw new Error('Mode none takes no PIN.');
    inner = { k: b64(dataKey) };
  } else if (mode === 'gate') {
    if (typeof pin !== 'string' || !validPin(pin)) throw new Error('The PIN must have 4 to 8 digits.');
    if (options.kdf) throw new Error('Mode gate takes no Argon2id parameters.');
    inner = { k: b64(dataKey), pin: await hashPin(pin) };
  } else {
    if (typeof pin !== 'string' || !FACTOR_PIN.test(pin)) throw new Error('The PIN must have 8 to 12 digits in mode factor.');
    const kdf = { ...(options.kdf ?? DEFAULT_FACTOR_KDF) };
    if (!validBackupCodeKdf(kdf)) throw new Error('Argon2id parameters out of bounds.');
    const salt = crypto.getRandomValues(new Uint8Array(16));
    const nonce = crypto.getRandomValues(new Uint8Array(12));
    const ct = await crypto.subtle.encrypt({ name: 'AES-GCM', iv: nonce, additionalData: factorAad(app) as BufferSource }, await factorKey(pin, salt, kdf, app), dataKey as BufferSource);
    inner = { salt: b64(salt), kdf: { name: 'argon2id', m: kdf.m, t: kdf.t, p: kdf.p }, nonce: b64(nonce), ct: b64(new Uint8Array(ct)) };
  }
  const plain = enc.encode(JSON.stringify(inner));
  const nonce = crypto.getRandomValues(new Uint8Array(12));
  try {
    const ct = await crypto.subtle.encrypt({ name: 'AES-GCM', iv: nonce, additionalData: aad(app, mode) as BufferSource }, deviceKey, plain as BufferSource);
    return { format: DEVICE_VAULT_FORMAT, version: DEVICE_VAULT_VERSION, app, mode, nonce: b64(nonce), ciphertext: b64(new Uint8Array(ct)) };
  } finally {
    plain.fill(0);
  }
}

/** A new random data key (32 bytes, the caller keeps it only in memory and wipes it on lock) and its envelope. */
export async function createDeviceVault(
  deviceKey: CryptoKey,
  app: string,
  options: DeviceVaultOptions,
): Promise<{ dataKey: Uint8Array; envelope: DeviceVaultEnvelope }> {
  const dataKey = crypto.getRandomValues(new Uint8Array(32));
  try {
    return { dataKey, envelope: await wrapDeviceVault(deviceKey, app, dataKey, options) };
  } catch (e) {
    dataKey.fill(0);
    throw e;
  }
}

// ---------- PIN attempts (the gate) ----------

/** Failed PIN attempts, kept by the app next to the envelope (not secret). */
export interface PinAttempts {
  failures: number;
  /** ms since the epoch; 0 = not locked */
  lockedUntil: number;
}
export const NO_PIN_ATTEMPTS: Readonly<PinAttempts> = Object.freeze({ failures: 0, lockedUntil: 0 });
/** Failures allowed before waiting: 5; then 30 s, doubling per failure, at most 1 hour. */
export const PIN_FREE_ATTEMPTS = 5;
export const PIN_FIRST_WAIT_MS = 30_000;
export const PIN_MAX_WAIT_MS = 3_600_000;

const validAttempts = (a: unknown): a is PinAttempts => {
  const x = a as PinAttempts | null;
  return !!x && Number.isInteger(x.failures) && x.failures >= 0 && Number.isFinite(x.lockedUntil) && x.lockedUntil >= 0;
};

/** May a PIN be tried now? (A damaged state counts as locked for the longest wait.) */
export function pinAttemptAllowed(state: PinAttempts, now: number): { ok: true } | { ok: false; waitMs: number } {
  if (!validAttempts(state)) return { ok: false, waitMs: PIN_MAX_WAIT_MS };
  return state.lockedUntil > now ? { ok: false, waitMs: state.lockedUntil - now } : { ok: true };
}

/** The state after an attempt: a right PIN clears it, a wrong one counts and, from the 5th, locks. */
export function afterPinAttempt(state: PinAttempts, ok: boolean, now: number): PinAttempts {
  if (ok) return { ...NO_PIN_ATTEMPTS };
  const failures = (validAttempts(state) ? state.failures : PIN_FREE_ATTEMPTS) + 1;
  if (failures < PIN_FREE_ATTEMPTS) return { failures, lockedUntil: 0 };
  const wait = Math.min(PIN_MAX_WAIT_MS, PIN_FIRST_WAIT_MS * 2 ** Math.min(failures - PIN_FREE_ATTEMPTS, 20));
  return { failures, lockedUntil: now + wait };
}

// ---------- opening ----------

export type DeviceVaultError =
  /** not an envelope of this app (format, app, mode, fields) */
  | { code: 'not-vault' }
  /** a newer version of the envelope */
  | { code: 'newer-version' }
  /** the device key does not open it (another device, a deleted keystore or browser data) – no PIN helps */
  | { code: 'device-mismatch' }
  /** `gate` / `factor` without a PIN, or a PIN in mode `none` */
  | { code: 'pin-required' }
  /** too many wrong PINs: wait `waitMs` */
  | { code: 'locked'; waitMs: number }
  /** a wrong PIN (counted in `attempts`) */
  | { code: 'wrong-pin' };

export interface OpenDeviceVaultOptions {
  /** failed attempts so far (default none); the result gives the new state for the app to store */
  attempts?: PinAttempts;
  /** ms since the epoch (default `Date.now()`) */
  now?: number;
}

/**
 * Opens the envelope: the device layer first, then (gate) the PIN hash or (factor) the Argon2id layer. With a PIN,
 * the attempt limit is checked before any work and the new `attempts` are returned on both success and failure.
 */
export async function openDeviceVault(
  deviceKey: CryptoKey,
  envelope: unknown,
  app: string,
  pin?: string,
  options: OpenDeviceVaultOptions = {},
): Promise<{ ok: true; dataKey: Uint8Array; attempts: PinAttempts } | { ok: false; error: DeviceVaultError; attempts: PinAttempts }> {
  const now = options.now ?? Date.now();
  const attempts = options.attempts ?? { ...NO_PIN_ATTEMPTS };
  const fail = (error: DeviceVaultError, a: PinAttempts = attempts) => ({ ok: false as const, error, attempts: a });
  checkApp(app);
  const e = envelope as Partial<DeviceVaultEnvelope> | null;
  if (!e || typeof e !== 'object' || e.format !== DEVICE_VAULT_FORMAT || e.app !== app) return fail({ code: 'not-vault' });
  if (Number.isInteger(e.version) && (e.version as number) > DEVICE_VAULT_VERSION) return fail({ code: 'newer-version' });
  if (e.version !== DEVICE_VAULT_VERSION || !DEVICE_VAULT_MODES.includes(e.mode as DeviceVaultMode) || typeof e.nonce !== 'string' || typeof e.ciphertext !== 'string')
    return fail({ code: 'not-vault' });
  const mode = e.mode as DeviceVaultMode;
  if ((mode === 'none') !== (pin === undefined)) return fail({ code: 'pin-required' });
  if (mode !== 'none') {
    const allowed = pinAttemptAllowed(attempts, now);
    if (!allowed.ok) return fail({ code: 'locked', waitMs: allowed.waitMs });
  }
  let inner: Record<string, unknown>;
  try {
    const plain = new Uint8Array(
      await crypto.subtle.decrypt({ name: 'AES-GCM', iv: gcmNonce(e.nonce) as BufferSource, additionalData: aad(app, mode) as BufferSource }, deviceKey, unb64(e.ciphertext) as BufferSource),
    );
    inner = JSON.parse(dec.decode(plain)) as Record<string, unknown>;
    plain.fill(0);
  } catch {
    return fail({ code: 'device-mismatch' });
  }
  const key = (v: unknown) => {
    const k = typeof v === 'string' ? unb64(v) : null;
    if (!k || k.length !== 32) throw new Error('bad data key');
    return k;
  };
  try {
    if (mode === 'none') return { ok: true, dataKey: key(inner.k), attempts };
    if (mode === 'gate') {
      const dataKey = key(inner.k);
      if (typeof inner.pin === 'string' && (await verifyPin(pin as string, inner.pin))) return { ok: true, dataKey, attempts: afterPinAttempt(attempts, true, now) };
      dataKey.fill(0);
      return fail({ code: 'wrong-pin' }, afterPinAttempt(attempts, false, now));
    }
    const kdf = inner.kdf as ({ name?: unknown } & BackupCodeKdf) | undefined;
    if (kdf?.name !== 'argon2id' || !validBackupCodeKdf(kdf) || typeof inner.salt !== 'string' || typeof inner.nonce !== 'string' || typeof inner.ct !== 'string')
      return fail({ code: 'not-vault' });
    const salt = unb64(inner.salt);
    if (salt.length !== 16) return fail({ code: 'not-vault' });
    if (!FACTOR_PIN.test(pin as string)) return fail({ code: 'wrong-pin' }, afterPinAttempt(attempts, false, now));
    try {
      const dk = await crypto.subtle.decrypt(
        { name: 'AES-GCM', iv: gcmNonce(inner.nonce) as BufferSource, additionalData: factorAad(app) as BufferSource },
        await factorKey(pin as string, salt, { m: kdf.m, t: kdf.t, p: kdf.p }, app),
        unb64(inner.ct) as BufferSource,
      );
      // authenticated: the bytes are the 32 written by wrapDeviceVault
      return { ok: true, dataKey: new Uint8Array(dk), attempts: afterPinAttempt(attempts, true, now) };
    } catch {
      return fail({ code: 'wrong-pin' }, afterPinAttempt(attempts, false, now));
    }
  } catch {
    // the device layer opened, but the inside is not an envelope of this format
    return fail({ code: 'not-vault' });
  }
}

/** A 4–8-digit PIN for `gate` (the PIN of `pin.ts`, `validPin`). */
export const validGatePin = (pin: string): boolean => validPin(pin);
/** An 8–12-digit PIN for `factor`. */
export const validFactorPin = (pin: string): boolean => typeof pin === 'string' && FACTOR_PIN.test(pin);
