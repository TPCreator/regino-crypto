import jsQR from 'jsqr';
import { describe, expect, it } from 'vitest';
import { newRecoverySecret, recoveryQrText, wordsToSecret } from './recovery';
import { recoveryQrMatrix, recoveryQrSvg, recoverySheetHtml } from './sheet';

const hex = (b: Uint8Array) => Array.from(b, (x) => x.toString(16).padStart(2, '0')).join('');

/** QR matrix → image (RGBA) → jsQR, as if a tool were reading it from a photo. */
function scan(m: boolean[][], scale = 4, quiet = 4): string | undefined {
  const size = (m.length + 2 * quiet) * scale;
  const px = new Uint8ClampedArray(size * size * 4).fill(255);
  m.forEach((row, r) =>
    row.forEach((dark, c) => {
      if (!dark) return;
      for (let y = 0; y < scale; y++)
        for (let x = 0; x < scale; x++) {
          const i = (((r + quiet) * scale + y) * size + (c + quiet) * scale + x) * 4;
          px[i] = px[i + 1] = px[i + 2] = 0;
        }
    }),
  );
  return jsQR(px, size, size)?.data;
}

describe('recovery sheet', () => {
  it.each([12, 24] as const)('the QR code (%i words) reads back to the same secret', async (n) => {
    const secret = newRecoverySecret(n);
    const text = scan(await recoveryQrMatrix(secret));
    expect(text).toBe(await recoveryQrText(secret));
    const r = await wordsToSecret(text as string);
    expect(r.ok && hex(r.secret)).toBe(hex(secret));
  });

  it('the SVG is only an image – no links or scripts', async () => {
    const svg = await recoveryQrSvg(newRecoverySecret());
    expect(svg).toMatch(/^<svg [^>]*viewBox="0 0 \d+ \d+"/);
    expect(svg).not.toMatch(/href|script|http(?!:\/\/www\.w3\.org)/);
    expect(svg).toContain('aria-label="QR code of the recovery code"');
    expect(await recoveryQrSvg(newRecoverySecret(), 4, 'sk')).toContain('aria-label="QR kód obnovovacieho kódu"');
  });

  it('the sheet has numbered words, a QR code, a warning and escaped text', async () => {
    const secret = newRecoverySecret(24);
    const html = await recoverySheetHtml(secret, {
      appName: 'Demo',
      owner: 'Dr. <Jane> & Co.',
      createdAt: new Date('2026-10-16T10:00:00Z'),
    });
    expect(html).toContain('<b>24.</b>');
    expect(html).toContain('columns:3');
    expect(html).toContain('<svg');
    expect(html).toContain('lang="en"');
    expect(html).toContain('Demo – recovery code');
    expect(html).toContain('created 16/10/2026 · 24 words');
    expect(html).toContain('Whoever has this sheet has access to your data.');
    expect(html).toContain('aria-label="QR code of the recovery code"');
    expect(html).toContain('Dr. &lt;Jane&gt; &amp; Co.');
    const short = await recoverySheetHtml(newRecoverySecret(), { appName: 'Other' });
    expect(short).toContain('<b>12.</b>');
    expect(short).not.toContain('<b>13.</b>');
    expect(short).toContain('columns:2');
  });

  it("lang 'sk' prints the Slovak text", async () => {
    const html = await recoverySheetHtml(newRecoverySecret(), {
      appName: 'Demo',
      createdAt: new Date('2026-10-16T10:00:00Z'),
      lang: 'sk',
    });
    expect(html).toContain('lang="sk"');
    expect(html).toContain('Demo – obnovovací kód');
    expect(html).toContain('vytvorené 16. 10. 2026 · 12 slov');
    expect(html).toContain('<b>Kto má tento list, má prístup k vašim údajom.</b> Odložte ho na bezpečné miesto');
    expect(html).toContain('Pri obnove zadajte slová v poradí');
    expect(html).toContain('aria-label="QR kód obnovovacieho kódu"');
    expect(html).not.toContain('Whoever');
  });
});
