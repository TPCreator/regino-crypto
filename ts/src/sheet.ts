import qrcode from 'qrcode-generator';
import { recoveryQrText, secretToWords } from './recovery';

/**
 * Printable recovery sheet: numbered words + a QR code with the same code.
 * Everything is created locally (no network); the sheet is never stored – the app only shows it for printing.
 */

/** Language of the printed sheet text. The recovery words themselves are always Slovak. */
export type SheetLang = 'en' | 'sk';

const TEXT = {
  en: {
    locale: 'en-GB',
    qrLabel: 'QR code of the recovery code',
    title: 'recovery code',
    created: 'created',
    words: 'words',
    warnStrong: 'Whoever has this sheet has access to your data.',
    warn: `Keep it in a safe place (a safe, a sealed envelope).
Do not photograph it or store it in the cloud, in e-mail or on your phone.`,
    howTo: `To recover, enter the words in order (the first 4 letters are enough, diacritics do not matter) or scan the QR code.
The QR code contains only this code – no address, it opens nothing on the internet.`,
  },
  sk: {
    locale: 'sk-SK',
    qrLabel: 'QR kód obnovovacieho kódu',
    title: 'obnovovací kód',
    created: 'vytvorené',
    words: 'slov',
    warnStrong: 'Kto má tento list, má prístup k vašim údajom.',
    warn: `Odložte ho na bezpečné miesto (trezor, obálka).
Nefoťte ho a neukladajte do cloudu, e-mailu ani do mobilu.`,
    howTo: `Pri obnove zadajte slová v poradí (stačia prvé 4 písmená, diakritika nevadí) alebo naskenujte QR kód.
QR kód obsahuje len tento kód – žiadnu adresu, nič sa ním neotvára na internete.`,
  },
} satisfies Record<SheetLang, Record<string, string>>;

/** QR code modules (true = dark). Error correction "M" – still readable from slightly damaged paper. */
export async function recoveryQrMatrix(secret: Uint8Array): Promise<boolean[][]> {
  const qr = qrcode(0, 'M');
  qr.addData(await recoveryQrText(secret), 'Alphanumeric');
  qr.make();
  const n = qr.getModuleCount();
  return Array.from({ length: n }, (_, r) => Array.from({ length: n }, (_, c) => qr.isDark(r, c)));
}

/** QR code as a standalone SVG (no links, no text). `lang` sets the accessible label (default English). */
export async function recoveryQrSvg(secret: Uint8Array, quiet = 4, lang: SheetLang = 'en'): Promise<string> {
  const m = await recoveryQrMatrix(secret);
  const size = m.length + 2 * quiet;
  let d = '';
  m.forEach((row, r) =>
    row.forEach((dark, c) => {
      if (dark) d += `M${c + quiet} ${r + quiet}h1v1h-1z`;
    }),
  );
  return (
    `<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 ${size} ${size}" shape-rendering="crispEdges" role="img" aria-label="${TEXT[lang].qrLabel}">` +
    `<rect width="${size}" height="${size}" fill="#fff"/><path d="${d}" fill="#000"/></svg>`
  );
}

export interface SheetOptions {
  /** Application name shown on the sheet, e.g. "My App" */
  appName: string;
  /** Whom the code belongs to, e.g. "Dr. Jane Smith – private practice" (optional) */
  owner?: string;
  createdAt?: Date;
  /** Language of the printed text: 'en' (default) or 'sk'. The recovery words are always Slovak. */
  lang?: SheetLang;
}

const esc = (s: string) =>
  s.replace(/[&<>"']/g, (ch) => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' })[ch] as string);

/** The whole recovery sheet as HTML (for printing on A4). */
export async function recoverySheetHtml(secret: Uint8Array, opts: SheetOptions): Promise<string> {
  const lang: SheetLang = opts.lang ?? 'en';
  const t = TEXT[lang];
  const words = await secretToWords(secret);
  const date = (opts.createdAt ?? new Date()).toLocaleDateString(t.locale);
  const items = words.map((w, i) => `<li><b>${i + 1}.</b> ${esc(w)}</li>`).join('');
  return `<section class="regino-sheet" lang="${lang}">
<style>
.regino-sheet{font:14px/1.45 system-ui,sans-serif;color:#000;background:#fff;max-width:180mm;margin:0 auto;padding:8mm}
.regino-sheet h1{font-size:20px;margin:0 0 4px}.regino-sheet .who{margin:0 0 12px;color:#333}
.regino-sheet .grid{display:flex;gap:10mm;align-items:flex-start}
.regino-sheet ol{list-style:none;margin:0;padding:0;columns:${words.length > 12 ? 3 : 2};column-gap:8mm;flex:1;font-size:16px}
.regino-sheet li{padding:3px 0;border-bottom:1px solid #ccc;break-inside:avoid}.regino-sheet li b{display:inline-block;width:2.2em;color:#555}
.regino-sheet .qr{width:45mm;flex:none}.regino-sheet .qr svg{width:100%;height:auto;display:block}
.regino-sheet .warn{border:2px solid #000;padding:8px 10px;margin-top:12px}
.regino-sheet .small{font-size:12px;color:#333}
</style>
<h1>${esc(opts.appName)} – ${t.title}</h1>
<p class="who">${opts.owner ? esc(opts.owner) + ' · ' : ''}${t.created} ${esc(date)} · ${words.length} ${t.words}</p>
<div class="grid"><ol>${items}</ol><div class="qr">${await recoveryQrSvg(secret, 4, lang)}</div></div>
<div class="warn"><b>${t.warnStrong}</b> ${t.warn}</div>
<p class="small">${t.howTo}</p>
</section>`;
}
