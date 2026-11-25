// Audit validation 2026-11-25 (docs/validacia-auditu-2026-11-25.md), 0.17.0 – no change of formats:
// L-06 size bound of a member list (the same as Rust sign::MAX_MANIFEST_LEN, keys/tests/audit_0_17_0.rs),
// L-07 safe names, MIME and nesting depth in findChunkedFiles (tools/open-backup.html).
import { describe, expect, it } from 'vitest';
import { findChunkedFiles, MAX_PAYLOAD_DEPTH, safeFileName } from './backupChunks';
import {
  MAX_CONTEXT,
  MAX_KEY,
  MAX_MANIFEST_LEN,
  MAX_MEMBERS,
  MAX_NAME,
  MAX_VERSION,
  openManifest,
  signingPublicKey,
  signManifest,
  verifyManifest,
  type Member,
} from './signing';

describe('member list size bound (L-06)', () => {
  it('the largest canonical list has exactly MAX_MANIFEST_LEN bytes; anything longer is refused', async () => {
    expect(MAX_MANIFEST_LEN).toBe(1602216);
    const admin = new Uint8Array(32).fill(1);
    const members: Member[] = [];
    for (let i = 0; i < MAX_MEMBERS; i++) {
      const seed = new Uint8Array(32);
      new DataView(seed.buffer).setUint32(0, i + 1);
      const seal = new Uint8Array(MAX_KEY);
      new DataView(seal.buffer).setUint32(0, i);
      const id = String(i).padStart(4, '0').padEnd(MAX_NAME, 'm');
      members.push({ id, role: 'r'.repeat(MAX_NAME), admin: i === 0, sign: await signingPublicKey(i === 0 ? admin : seed), seal, sealVersion: MAX_VERSION });
    }
    const scope = 's'.repeat(MAX_CONTEXT);
    const blob = await signManifest(admin, { scope, version: 1, epoch: MAX_VERSION, prev: new Uint8Array(32), members });
    expect(blob.length).toBe(MAX_MANIFEST_LEN);
    expect((await verifyManifest(blob, scope, [await signingPublicKey(admin)])).manifest.members).toHaveLength(MAX_MEMBERS);
    const longer = new Uint8Array(blob.length + 1);
    longer.set(blob);
    await expect(openManifest(longer)).rejects.toThrow('Not a valid member list.');
  }, 60_000);
});

describe('findChunkedFiles: safe names, MIME and depth (L-07)', () => {
  const chunk = 'a'.repeat(64);
  it('names are safe for a download', () => {
    expect(safeFileName('zprava.pdf')).toBe('zprava.pdf');
    expect(safeFileName('../../Windows/System32/x.dll')).toBe('x.dll');
    expect(safeFileName('C:\\Users\\a\\evil.exe')).toBe('evil.exe');
    expect(safeFileName('a<b>c:"d|e?f*g\u0000h\u202ei.txt')).toBe('a_b_c__d_e_f_g_h_i.txt');
    expect(safeFileName('...hidden.  ')).toBe('hidden');
    expect(safeFileName('...')).toBe('file');
    expect(safeFileName('/')).toBe('file');
    expect(safeFileName('')).toBe('file');
    expect(safeFileName('č'.repeat(200))).toBe('č'.repeat(120));
  });
  it('MIME only as type/subtype, names through safeFileName', () => {
    const files = findChunkedFiles([
      { name: '../x.html', mime: 'text/html', chunks: [chunk] },
      { name: 'b', mime: 'text/html; charset=utf-8', chunks: [chunk] },
      { name: 'c', mime: 'application/vnd.oasis.opendocument.text', chunks: [chunk] },
      { name: 'd', mime: 'x', chunks: [chunk] },
      { name: '', chunks: [chunk] },
    ]);
    expect(files.map((f) => [f.name, f.mime])).toEqual([
      ['x.html', 'text/html'],
      ['b', undefined],
      ['c', 'application/vnd.oasis.opendocument.text'],
      ['d', undefined],
      ['file', undefined],
    ]);
  });
  it('a payload nested deeper than MAX_PAYLOAD_DEPTH is refused, one level less is walked', () => {
    const nest = (n: number): unknown => {
      let v: unknown = { name: 'deep', chunks: [chunk] };
      for (let i = 0; i < n; i++) v = i % 2 ? [v] : { x: v };
      return v;
    };
    expect(findChunkedFiles(nest(MAX_PAYLOAD_DEPTH))).toHaveLength(1);
    expect(() => findChunkedFiles(nest(MAX_PAYLOAD_DEPTH + 1))).toThrow('nested too deeply');
    expect(() => findChunkedFiles(nest(100_000))).toThrow('nested too deeply');
  });
});
