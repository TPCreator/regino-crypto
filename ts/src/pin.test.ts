import { describe, expect, it } from 'vitest';
import { hashPin, validPin, verifyPin } from './pin';

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
});
