// Builds a single self-contained file ../../tools/open-backup.html (no internet, no external libraries).
// CI checks that the file in the repository matches the sources – nobody can change it secretly.
import { build } from 'esbuild';
import { readFileSync, writeFileSync } from 'node:fs';

const here = new URL('.', import.meta.url);
const pkg = JSON.parse(readFileSync(new URL('../package.json', here), 'utf8'));
const r = await build({
  entryPoints: [new URL('page.ts', here).pathname],
  bundle: true, write: false, format: 'iife', target: 'es2022', minify: false, legalComments: 'none',
});
const js = r.outputFiles[0].text.replace(/<\/script/gi, '<\\/script');
const html = readFileSync(new URL('page.html', here), 'utf8')
  .replace('__VERSION__', pkg.version)
  .replace('__SCRIPT__', () => js);
writeFileSync(new URL('../../tools/open-backup.html', here), html);
console.log('tools/open-backup.html', html.length, 'B');
