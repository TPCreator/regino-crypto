import { describe, expect, it } from 'vitest';
import { hashPin, MAX_PIN_ITERATIONS, validPin, verifyPin } from './pin';

describe('PIN', () => {
  it('verifies the correct PIN and rejects another one', async () => {
    const h = await hashPin('2580', 1000);
    expect(h).toMatch(/^pbkdf2\$1000\$[0-9a-f]{32}\$[0-9a-f]{64}$/);
    expect(await verifyPin('2580', h)).toBe(true);
    expect(await verifyPin('2581', h)).toBe(false);
    expect(await verifyPin('12', h)).toBe(false);
    // The same PIN gets a different hash every time (salt).
    expect(await hashPin('2580', 1000)).not.toBe(h);
  });

  it('default iterations and PIN format', async () => {
    expect((await hashPin('12345678')).split('$')[1]).toBe('200000');
    expect(validPin('1234')).toBe(true);
    expect(validPin('123')).toBe(false);
    expect(validPin('12a4')).toBe(false);
    await expect(hashPin('12')).rejects.toThrow('4 to 8');
  });

  it('a damaged hash does not pass', async () => {
    expect(await verifyPin('2580', 'something')).toBe(false);
    expect(await verifyPin('2580', 'pbkdf2$10')).toBe(false);
    expect(await verifyPin('2580', 'pbkdf2$0$aa$bb')).toBe(false);
    expect(await verifyPin('2580', 'pbkdf2$x$aa$bb')).toBe(false);
    expect(await verifyPin('2580', 'pbkdf2$10$$bb')).toBe(false);
    expect(await verifyPin('2580', 'pbkdf2$10$aa$')).toBe(false);
    expect(await verifyPin('2580', 'pbkdf2$10$zz$bb')).toBe(false);
    expect(await verifyPin('2580', 'pbkdf2$10$a$bb')).toBe(false);
  });

  // 0.12.1: exact shape of a stored hash – iterations 1..MAX_PIN_ITERATIONS, salt 16 bytes, hash 32 bytes.
  it('iteration count is bounded and salt and hash must have their exact lengths', async () => {
    expect(MAX_PIN_ITERATIONS).toBe(10_000_000);
    const h = await hashPin('2580', 1000);
    const [, , salt, hash] = h.split('$') as [string, string, string, string];
    const withIter = (iter: string) => `pbkdf2$${iter}$${salt}$${hash}`;
    expect(await verifyPin('2580', withIter('1000'))).toBe(true);
    // a planted or damaged record with billions of iterations is refused before any work is done
    expect(await verifyPin('2580', withIter(String(MAX_PIN_ITERATIONS + 1)))).toBe(false);
    expect(await verifyPin('2580', withIter('1e3'))).toBe(false); // Number('1e3') is 1000, but not a stored form
    expect(await verifyPin('2580', withIter('+1000'))).toBe(false);
    expect(await verifyPin('2580', withIter('1000.0'))).toBe(false);
    expect(await verifyPin('2580', withIter(''))).toBe(false);
    // salt: exactly 32 hex characters; hash: exactly 64
    expect(await verifyPin('2580', `pbkdf2$1000$${salt.slice(2)}$${hash}`)).toBe(false);
    expect(await verifyPin('2580', `pbkdf2$1000$${salt}00$${hash}`)).toBe(false);
    expect(await verifyPin('2580', `pbkdf2$1000$${salt.toUpperCase()}$${hash}`)).toBe(false);
    expect(await verifyPin('2580', `pbkdf2$1000$${salt}$${hash.slice(2)}`)).toBe(false);
    expect(await verifyPin('2580', `pbkdf2$1000$${salt}$${hash}00`)).toBe(false);
    expect(await verifyPin('2580', `pbkdf2$1000$${salt}$${hash}$`)).toBe(false); // five parts
    expect(await verifyPin('2580', `${h}$x`)).toBe(false);
    // the bound also applies when hashing
    await expect(hashPin('2580', MAX_PIN_ITERATIONS + 1)).rejects.toThrow('Iterations');
    await expect(hashPin('2580', 0)).rejects.toThrow('Iterations');
    await expect(hashPin('2580', 1.5)).rejects.toThrow('Iterations');
    expect((await hashPin('2580', 1)).split('$')[1]).toBe('1');
  });
});
