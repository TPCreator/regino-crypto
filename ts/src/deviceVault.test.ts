import { describe, expect, it, vi } from 'vitest';
import v from '../../testvectors/regino/device-vault-0.20.0.json';
import { MIN_BACKUP_CODE_KDF } from './backupCode';
import {
  DEFAULT_FACTOR_KDF,
  DEVICE_VAULT_FORMAT,
  NO_PIN_ATTEMPTS,
  PIN_FIRST_WAIT_MS,
  PIN_FREE_ATTEMPTS,
  PIN_MAX_WAIT_MS,
  afterPinAttempt,
  createDeviceVault,
  deviceKeyBytes,
  deviceKeyFromPasskey,
  deviceKeyFromSecret,
  newBrowserDeviceKey,
  openDeviceVault,
  passkeyPrfEnabled,
  passkeyPrfExtension,
  passkeyPrfInput,
  passkeyPrfOutput,
  pinAttemptAllowed,
  validFactorPin,
  validGatePin,
  wrapDeviceVault,
  type DeviceVaultEnvelope,
  type PinAttempts,
} from './deviceVault';
import { b64, unb64 } from './ecdh';
import * as index from './index';

// Device key + short PIN as a gate (0.20.0): the data key never comes from the PIN.
vi.setConfig({ testTimeout: 60_000 });

const hex = (b: Uint8Array) => Array.from(b, (x) => x.toString(16).padStart(2, '0')).join('');
const unhex = (h: string) => Uint8Array.from(h.match(/../g) ?? [], (x) => parseInt(x, 16));
const FAST = { kdf: MIN_BACKUP_CODE_KDF };
const T0 = 1_800_000_000_000;
const vectorKey = () => deviceKeyFromSecret(unhex(v.keys[0]!.secret), 'demo', 'windows-hello');

describe('device key (the same as Rust device::device_key)', () => {
  it.each(v.keys.map((k) => [k.name, k] as const))('%s', async (_, k) => {
    expect(hex(await deviceKeyBytes(unhex(k.secret), k.app, k.method))).toBe(k.key);
  });

  it('the first vector is the fixed vector of keys/src/device.rs (VEC_HELLO)', () => {
    expect(v.keys[0]!.key).toBe('798a6ee2d26b83644e682f57ed46bdbd4007246b5ae0ac90542fa54a68a92e32');
  });

  it('is a non-extractable AES-GCM key; refuses short secrets and bad names', async () => {
    const k = await deviceKeyFromSecret(new Uint8Array(32), 'demo', 'os-keystore');
    expect(k.extractable).toBe(false);
    expect(k.algorithm).toMatchObject({ name: 'AES-GCM', length: 256 });
    await expect(deviceKeyFromSecret(new Uint8Array(31), 'demo', 'os-keystore')).rejects.toThrow('at least 32');
    await expect(deviceKeyFromSecret('x' as unknown as Uint8Array, 'demo', 'os-keystore')).rejects.toThrow('at least 32');
    await expect(deviceKeyFromSecret(new Uint8Array(32), 'Demo', 'os-keystore')).rejects.toThrow('application');
    await expect(deviceKeyFromSecret(new Uint8Array(32), 'demo', 'OS')).rejects.toThrow('method');
    await expect(deviceKeyFromSecret(new Uint8Array(32), 'demo', 7 as unknown as string)).rejects.toThrow('method');
    const b = await newBrowserDeviceKey();
    expect(b.extractable).toBe(false);
  });
});

describe('passkey PRF', () => {
  it('the PRF input is fixed per app and label', async () => {
    for (const p of v.prf_inputs) expect(hex(await passkeyPrfInput(p.app, p.label))).toBe(p.input);
    expect(hex(await passkeyPrfInput('dyspro'))).toBe(v.prf_inputs[0]!.input);
    await expect(passkeyPrfInput('dyspro', 'X')).rejects.toThrow('label');
    await expect(passkeyPrfInput('Bad')).rejects.toThrow('application');
  });

  it('extension options, enabled flag and the output of a sign-in', async () => {
    const input = await passkeyPrfInput('dyspro');
    const ext = passkeyPrfExtension(input);
    expect(hex(ext.prf.eval.first)).toBe(hex(input));
    expect(ext.prf.eval.first).not.toBe(input);
    expect(() => passkeyPrfExtension(new Uint8Array(16))).toThrow('32 bytes');
    const cred = (r: unknown) => ({ getClientExtensionResults: () => r as never });
    expect(passkeyPrfEnabled(cred({ prf: { enabled: true } }))).toBe(true);
    expect(passkeyPrfEnabled(cred({ prf: {} }))).toBe(false);
    expect(passkeyPrfEnabled(cred({}))).toBe(false);
    const out = new Uint8Array(32).fill(9);
    expect(hex(passkeyPrfOutput(cred({ prf: { results: { first: out.buffer } } }))!)).toBe(hex(out));
    const view = new Uint8Array(40).fill(9).subarray(4, 36);
    expect(hex(passkeyPrfOutput(cred({ prf: { results: { first: view } } }))!)).toBe(hex(out));
    expect(passkeyPrfOutput(cred({ prf: { results: { first: new Uint8Array(16).buffer } } }))).toBeNull();
    expect(passkeyPrfOutput(cred({ prf: { results: { first: 'x' } } }))).toBeNull();
    expect(passkeyPrfOutput(cred({}))).toBeNull();
  });

  it('a device key from the PRF output wipes it and equals deviceKeyFromSecret(…, "passkey-prf")', async () => {
    const k = v.keys[1]!;
    const output = unhex(k.secret);
    const key = await deviceKeyFromPasskey(output, 'dyspro');
    expect(output.every((b) => b === 0)).toBe(true);
    // the same key: an envelope from one opens with the other
    const { dataKey, envelope } = await createDeviceVault(key, 'dyspro', { mode: 'gate', pin: '1234' });
    const r = await openDeviceVault(await deviceKeyFromSecret(unhex(k.secret), 'dyspro', 'passkey-prf'), envelope, 'dyspro', '1234');
    expect(r.ok && hex(r.dataKey)).toBe(hex(dataKey));
    await expect(deviceKeyFromPasskey(new Uint8Array(8), 'dyspro')).rejects.toThrow('at least 32');
    await expect(deviceKeyFromPasskey(null as unknown as Uint8Array, 'dyspro')).rejects.toThrow('at least 32');
  });
});

describe('envelopes made by 0.20.0 still open (device-vault-0.20.0.json)', () => {
  it.each(v.envelopes.map((e) => [e.mode, e] as const))('%s', async (_, e) => {
    const r = await openDeviceVault(await vectorKey(), e.envelope, 'demo', (e as { pin?: string }).pin, { now: T0 });
    expect(r.ok && hex(r.dataKey)).toBe(v.data_key);
  });
});

describe('modes', () => {
  it('none: the device key alone; no PIN taken', async () => {
    const dk = await newBrowserDeviceKey();
    const { dataKey, envelope } = await createDeviceVault(dk, 'demo', { mode: 'none' });
    expect(envelope).toMatchObject({ format: DEVICE_VAULT_FORMAT, version: 1, app: 'demo', mode: 'none' });
    expect(Object.keys(envelope).sort()).toEqual(['app', 'ciphertext', 'format', 'mode', 'nonce', 'version']);
    const r = await openDeviceVault(dk, envelope, 'demo');
    expect(r.ok && hex(r.dataKey)).toBe(hex(dataKey));
    expect(await openDeviceVault(dk, envelope, 'demo', '1234')).toMatchObject({ ok: false, error: { code: 'pin-required' } });
    await expect(createDeviceVault(dk, 'demo', { mode: 'none', pin: '1234' })).rejects.toThrow('no PIN');
  });

  it('gate: a wrong PIN is counted, the right one clears the count; no PIN at all is pin-required', async () => {
    const dk = await newBrowserDeviceKey();
    const { dataKey, envelope } = await createDeviceVault(dk, 'demo', { mode: 'gate', pin: '4821' });
    const bad = await openDeviceVault(dk, envelope, 'demo', '0000', { now: T0 });
    expect(bad).toEqual({ ok: false, error: { code: 'wrong-pin' }, attempts: { failures: 1, lockedUntil: 0 } });
    const good = await openDeviceVault(dk, envelope, 'demo', '4821', { attempts: bad.attempts, now: T0 });
    expect(good.ok && hex(good.dataKey)).toBe(hex(dataKey));
    expect(good.attempts).toEqual(NO_PIN_ATTEMPTS);
    expect(await openDeviceVault(dk, envelope, 'demo')).toMatchObject({ ok: false, error: { code: 'pin-required' } });
    expect(await openDeviceVault(dk, envelope, 'demo', 'abcd', { now: T0 })).toMatchObject({ ok: false, error: { code: 'wrong-pin' } });
    for (const pin of ['123', '123456789', 'abcd', undefined])
      await expect(createDeviceVault(dk, 'demo', { mode: 'gate', pin })).rejects.toThrow('4 to 8 digits');
    await expect(createDeviceVault(dk, 'demo', { mode: 'gate', pin: '1234', ...FAST })).rejects.toThrow('no Argon2id');
  });

  it('factor: the device key AND an 8–12-digit PIN (Argon2id)', async () => {
    const dk = await newBrowserDeviceKey();
    const { dataKey, envelope } = await createDeviceVault(dk, 'demo', { mode: 'factor', pin: '48213907', ...FAST });
    const r = await openDeviceVault(dk, envelope, 'demo', '48213907');
    expect(r.ok && hex(r.dataKey)).toBe(hex(dataKey));
    expect(await openDeviceVault(dk, envelope, 'demo', '48213908', { now: T0 })).toEqual({ ok: false, error: { code: 'wrong-pin' }, attempts: { failures: 1, lockedUntil: 0 } });
    expect(await openDeviceVault(dk, envelope, 'demo', '1234', { now: T0 })).toMatchObject({ ok: false, error: { code: 'wrong-pin' } });
    for (const pin of ['1234567', '1234567890123', 'abcdefgh'])
      await expect(createDeviceVault(dk, 'demo', { mode: 'factor', pin, ...FAST })).rejects.toThrow('8 to 12 digits');
    await expect(createDeviceVault(dk, 'demo', { mode: 'factor', pin: '12345678', kdf: { m: 1024, t: 1, p: 1 } })).rejects.toThrow('bounds');
    expect(DEFAULT_FACTOR_KDF).toEqual({ m: 32768, t: 2, p: 1 });
    // the default parameters
    const d = await createDeviceVault(dk, 'demo', { mode: 'factor', pin: '123456789012' });
    const o = await openDeviceVault(dk, d.envelope, 'demo', '123456789012');
    expect(o.ok && hex(o.dataKey)).toBe(hex(d.dataKey));
  });

  it('another device key opens nothing – before any PIN work, and without counting', async () => {
    const dk = await newBrowserDeviceKey();
    for (const opts of [{ mode: 'none' as const }, { mode: 'gate' as const, pin: '1234' }, { mode: 'factor' as const, pin: '12345678', ...FAST }]) {
      const { envelope } = await createDeviceVault(dk, 'demo', opts);
      const r = await openDeviceVault(await newBrowserDeviceKey(), envelope, 'demo', opts.pin, { now: T0 });
      expect(r).toEqual({ ok: false, error: { code: 'device-mismatch' }, attempts: NO_PIN_ATTEMPTS });
    }
  });

  it('rewrapping keeps the data key (PIN change, mode change, moving from an older envelope)', async () => {
    const dk = await newBrowserDeviceKey();
    const { dataKey, envelope } = await createDeviceVault(dk, 'demo', { mode: 'factor', pin: '11112222', ...FAST });
    const opened = await openDeviceVault(dk, envelope, 'demo', '11112222');
    if (!opened.ok) throw new Error('not opened');
    const os = await deviceKeyFromSecret(new Uint8Array(32).fill(1), 'demo', 'os-keystore');
    const next = await wrapDeviceVault(os, 'demo', opened.dataKey, { mode: 'gate', pin: '5555' });
    const r = await openDeviceVault(os, next, 'demo', '5555');
    expect(r.ok && hex(r.dataKey)).toBe(hex(dataKey));
    expect(hex(opened.dataKey)).toBe(hex(dataKey));
    await expect(wrapDeviceVault(os, 'demo', new Uint8Array(16), { mode: 'none' })).rejects.toThrow('32 bytes');
    await expect(wrapDeviceVault(os, 'demo', dataKey, { mode: 'other' as never })).rejects.toThrow('Unknown mode');
    await expect(wrapDeviceVault(os, 'demo', dataKey, undefined as never)).rejects.toThrow('Unknown mode');
    await expect(wrapDeviceVault(os, 'Bad', dataKey, { mode: 'none' })).rejects.toThrow('application');
  });

  it('a failed create wipes the new data key', async () => {
    const fills: Uint8Array[] = [];
    const real = Uint8Array.prototype.fill;
    const spy = vi.spyOn(Uint8Array.prototype, 'fill').mockImplementation(function (this: Uint8Array, value: number, s?: number, e?: number) {
      if (value === 0 && this.length === 32) fills.push(this);
      return real.call(this, value, s, e);
    });
    try {
      await expect(createDeviceVault(await newBrowserDeviceKey(), 'demo', { mode: 'gate', pin: 'x' })).rejects.toThrow();
    } finally {
      spy.mockRestore();
    }
    expect(fills.length).toBe(1);
  });
});

describe('refused envelopes', () => {
  it('foreign, newer, damaged or changed envelopes', async () => {
    const dk = await newBrowserDeviceKey();
    const { envelope } = await createDeviceVault(dk, 'demo', { mode: 'gate', pin: '1234' });
    const open = (e: unknown, pin: string | undefined = '1234') => openDeviceVault(dk, e, 'demo', pin, { now: T0 });
    for (const bad of [null, 'x', {}, { ...envelope, format: 'other' }, { ...envelope, app: 'other' }, { ...envelope, version: 0 }, { ...envelope, version: '1' }, { ...envelope, mode: 'x' }, { ...envelope, nonce: 1 }, { ...envelope, ciphertext: undefined }])
      expect((await open(bad)).ok === false && (await open(bad) as { error: { code: string } }).error.code, JSON.stringify(bad)).toBe('not-vault');
    expect(await open({ ...envelope, version: 2 })).toMatchObject({ ok: false, error: { code: 'newer-version' } });
    // the mode is bound in the AAD: relabelled gate → factor/none does not open with the device key
    expect(await open({ ...envelope, mode: 'factor' }, '12345678')).toMatchObject({ ok: false, error: { code: 'device-mismatch' } });
    expect(await openDeviceVault(dk, { ...envelope, mode: 'none' }, 'demo')).toMatchObject({ ok: false, error: { code: 'device-mismatch' } });
    const ct = unb64(envelope.ciphertext);
    ct[0] = (ct[0] as number) ^ 1;
    expect(await open({ ...envelope, ciphertext: b64(ct) })).toMatchObject({ ok: false, error: { code: 'device-mismatch' } });
    await expect(openDeviceVault(dk, envelope, 'Bad', '1234')).rejects.toThrow('application');
  });

  it('a well-sealed inside that is not this format is not-vault', async () => {
    const dk = await newBrowserDeviceKey();
    const sealAs = async (mode: string, inner: unknown): Promise<DeviceVaultEnvelope> => {
      const nonce = crypto.getRandomValues(new Uint8Array(12));
      const ct = await crypto.subtle.encrypt(
        { name: 'AES-GCM', iv: nonce, additionalData: new TextEncoder().encode(`regino-device-vault|1|demo|${mode}`) as BufferSource },
        dk,
        new TextEncoder().encode(typeof inner === 'string' ? inner : JSON.stringify(inner)) as BufferSource,
      );
      return { format: 'regino-device-vault', version: 1, app: 'demo', mode: mode as 'none', nonce: b64(nonce), ciphertext: b64(new Uint8Array(ct)) };
    };
    const code = async (e: DeviceVaultEnvelope, pin?: string) => {
      const r = await openDeviceVault(dk, e, 'demo', pin, { now: T0 });
      return r.ok ? 'ok' : r.error.code;
    };
    expect(await code(await sealAs('none', 'not json'))).toBe('device-mismatch');
    expect(await code(await sealAs('none', { k: b64(new Uint8Array(16)) }))).toBe('not-vault');
    expect(await code(await sealAs('none', { k: 5 }))).toBe('not-vault');
    expect(await code(await sealAs('gate', { k: b64(new Uint8Array(32)), pin: 7 }), '1234')).toBe('wrong-pin');
    expect(await code(await sealAs('gate', { pin: 'x' }), '1234')).toBe('not-vault');
    const kdf = { name: 'argon2id', ...MIN_BACKUP_CODE_KDF };
    const salt = b64(new Uint8Array(16));
    const n = b64(new Uint8Array(12));
    expect(await code(await sealAs('factor', { salt, kdf: { ...kdf, m: 2 ** 30 }, nonce: n, ct: 'AA==' }), '12345678')).toBe('not-vault');
    expect(await code(await sealAs('factor', { salt, kdf: { ...kdf, name: 'scrypt' }, nonce: n, ct: 'AA==' }), '12345678')).toBe('not-vault');
    expect(await code(await sealAs('factor', { salt: b64(new Uint8Array(8)), kdf, nonce: n, ct: 'AA==' }), '12345678')).toBe('not-vault');
    expect(await code(await sealAs('factor', { salt, kdf, nonce: n }), '12345678')).toBe('not-vault');
    expect(await code(await sealAs('factor', { salt, kdf, nonce: n, ct: 'AAAA' }), '12345678')).toBe('wrong-pin');
  });
});

describe('PIN attempts', () => {
  it('5 free failures, then 30 s doubling up to 1 hour; a right PIN clears', () => {
    let s: PinAttempts = { ...NO_PIN_ATTEMPTS };
    const waits: number[] = [];
    for (let i = 0; i < 14; i++) {
      s = afterPinAttempt(s, false, T0);
      waits.push(s.lockedUntil ? s.lockedUntil - T0 : 0);
    }
    expect(waits.slice(0, PIN_FREE_ATTEMPTS - 1)).toEqual([0, 0, 0, 0]);
    expect(waits[4]).toBe(PIN_FIRST_WAIT_MS);
    expect(waits[5]).toBe(2 * PIN_FIRST_WAIT_MS);
    expect(waits[13]).toBe(PIN_MAX_WAIT_MS);
    expect(pinAttemptAllowed(s, T0 + 1000)).toEqual({ ok: false, waitMs: PIN_MAX_WAIT_MS - 1000 });
    expect(pinAttemptAllowed(s, T0 + PIN_MAX_WAIT_MS)).toEqual({ ok: true });
    expect(afterPinAttempt(s, true, T0)).toEqual(NO_PIN_ATTEMPTS);
    // a huge count does not overflow
    expect(afterPinAttempt({ failures: 10_000, lockedUntil: 0 }, false, T0).lockedUntil).toBe(T0 + PIN_MAX_WAIT_MS);
  });

  it('a damaged state counts as locked', () => {
    for (const bad of [null, {}, { failures: -1, lockedUntil: 0 }, { failures: 1.5, lockedUntil: 0 }, { failures: 1, lockedUntil: NaN }])
      expect(pinAttemptAllowed(bad as never, T0)).toEqual({ ok: false, waitMs: PIN_MAX_WAIT_MS });
    expect(afterPinAttempt(null as never, false, T0)).toEqual({ failures: PIN_FREE_ATTEMPTS + 1, lockedUntil: T0 + 2 * PIN_FIRST_WAIT_MS });
  });

  it('a locked vault is not tried at all; the default time is now', async () => {
    const dk = await newBrowserDeviceKey();
    const { envelope } = await createDeviceVault(dk, 'demo', { mode: 'gate', pin: '1234' });
    const locked = { failures: 5, lockedUntil: Date.now() + 60_000 };
    const r = await openDeviceVault(dk, envelope, 'demo', '1234', { attempts: locked });
    expect(r.ok).toBe(false);
    if (!r.ok) {
      expect(r.error.code).toBe('locked');
      expect(r.attempts).toBe(locked);
    }
  });

  it('PIN forms', () => {
    expect(validGatePin('1234')).toBe(true);
    expect(validGatePin('123456789')).toBe(false);
    expect(validFactorPin('12345678')).toBe(true);
    expect(validFactorPin('1234567')).toBe(false);
    expect(validFactorPin(5 as unknown as string)).toBe(false);
  });

  it('public API', () => {
    expect(typeof index.createDeviceVault).toBe('function');
    expect(typeof index.deviceKeyFromPasskey).toBe('function');
  });
});
