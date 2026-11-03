import { describe, expect, it } from 'vitest';
import v from '../../testvectors/regino/group-key-0.13.1.json';
import { groupKeyCode, groupKeyId } from './groupKey';

const hexd = (s: string) => Uint8Array.from(s.match(/../g) ?? [], (h) => parseInt(h, 16));

describe('group key code and id (shared vectors with Rust)', () => {
  it('match Rust, are bound to key and context, independent of each other', async () => {
    for (const t of v.code) expect(await groupKeyCode(hexd(t.key), t.context)).toBe(t.code);
    for (const t of v.id) expect(await groupKeyId(hexd(t.key), t.label)).toBe(t.id);
    expect(v.code[0]!.code).toMatch(/^[0-9a-f]{4}( [0-9a-f]{4}){4}$/);
    expect(v.id[0]!.id).toMatch(/^[0-9a-f]{24}$/);
    expect(new Set(v.code.map((t) => t.code)).size).toBe(v.code.length);
    const k = new Uint8Array(32).fill(0x11);
    expect((await groupKeyCode(k, 'x')).replace(/ /g, '')).not.toBe((await groupKeyId(k, 'x')).slice(0, 20));
  });

  it('refuses a key that is not 32 bytes and an empty context', async () => {
    await expect(groupKeyCode(new Uint8Array(31), 'x')).rejects.toThrow('32 bytes');
    await expect(groupKeyId('x' as unknown as Uint8Array, 'x')).rejects.toThrow('32 bytes');
    await expect(groupKeyCode(new Uint8Array(32), '')).rejects.toThrow('must not be empty');
  });
});
