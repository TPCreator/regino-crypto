import { describe, expect, it } from 'vitest';
import { CONTEXT_PREFIX, MAX_CONTEXT_LEN, structuredContext } from './context';
import { openRecord, recordKey, sealRecord, newGroupKey } from './sync';
import vectors from '../../testvectors/regino/context-0.17.0.json';

describe('structuredContext (0.17.0, L-01)', () => {
  it('gives the shared vectors (the same as Rust context::structured)', () => {
    for (const v of vectors.valid) expect(structuredContext(v.parts)).toBe(v.context);
    for (const v of vectors.invalid) expect(() => structuredContext(v.parts)).toThrow();
    expect(vectors.valid.length).toBeGreaterThan(5);
  });

  it('parts with separators do not collide', () => {
    expect(structuredContext(['a|b', 'c'])).not.toBe(structuredContext(['a', 'b|c']));
    expect(structuredContext(['a/b'])).toBe(`${CONTEXT_PREFIX}|3:a/b`);
    expect(structuredContext(['x'.repeat(1011)]).length).toBe(MAX_CONTEXT_LEN);
  });

  it('refuses no parts, empty or non-text parts, lone surrogates and too long contexts', () => {
    expect(() => structuredContext([])).toThrow('at least one part');
    expect(() => structuredContext('abc' as unknown as string[])).toThrow('at least one part');
    expect(() => structuredContext(['a', ''])).toThrow('non-empty string');
    expect(() => structuredContext([1 as unknown as string])).toThrow('non-empty string');
    // '\ud800' and '�' would both be EF BF BD in UTF-8
    expect(() => structuredContext(['\ud800'])).toThrow('valid text');
    expect(structuredContext(['�'])).toBe(`${CONTEXT_PREFIX}|3:�`);
    expect(() => structuredContext(['x'.repeat(1012)])).toThrow('at most 1024 bytes');
  });

  it('a record sealed under one structured context does not open under the other', async () => {
    const key = await recordKey(newGroupKey());
    const sealed = await sealRecord(key, structuredContext(['gazda', 'event', 'a|b', 'c']), { x: 1 });
    await expect(openRecord(key, structuredContext(['gazda', 'event', 'a|b', 'c']), sealed)).resolves.toEqual({ x: 1 });
    await expect(openRecord(key, structuredContext(['gazda', 'event', 'a', 'b|c']), sealed)).rejects.toThrow();
  });
});
