// "Open backup" tool page – everything runs in the browser, nothing is sent anywhere.
import jsQR from 'jsqr';
import { assembleChunkedFile, type BackupChunkKeys, type ChunkedFile } from '../src/backupChunks';
import { openBackup } from '../src/openBackup';
import { parseRecoveryQr } from '../src/recovery';

const $ = <T extends HTMLElement>(id: string) => document.getElementById(id) as T;

$('go').addEventListener('click', async () => {
  const file = $<HTMLInputElement>('file').files?.[0];
  const out = $('out');
  out.className = '';
  if (!file) {
    out.textContent = 'Select a backup file.';
    out.className = 'err';
    return;
  }
  const r = await openBackup(await file.text(), $<HTMLTextAreaElement>('words').value);
  if (!r.ok) {
    out.textContent = r.message;
    out.className = 'err';
    return;
  }
  const json = JSON.stringify(r.payload, null, 2);
  out.className = 'ok';
  out.textContent = `✓ Backup from app "${r.app}" created ${new Date(r.createdAt).toLocaleString()} was opened with this public code.`;
  const a = document.createElement('a');
  a.href = URL.createObjectURL(new Blob([json], { type: 'application/json' }));
  a.download = `${r.app}-backup-opened.json`;
  a.textContent = 'Download opened data (JSON)';
  out.append(document.createElement('br'), a);
  if (r.files.length && r.chunkKeys) showFiles(r.files, r.chunkKeys);
});

// Large files (attachments) are in the chunk folder next to the backup – the user selects that folder.
function showFiles(files: ChunkedFile[], keys: BackupChunkKeys) {
  const box = $('files');
  box.hidden = false;
  const list = $('filelist');
  list.textContent = '';
  for (const f of files) {
    const li = document.createElement('li');
    const b = document.createElement('button');
    b.textContent = `${f.name}${f.size !== undefined ? ` (${Math.max(1, Math.round(f.size / 1024))} kB)` : ''}`;
    b.className = 'link';
    b.addEventListener('click', async () => {
      const dir = [...($<HTMLInputElement>('chunks').files ?? [])];
      const byName = new Map(dir.map((x) => [x.name.replace(/\.rgb$/, ''), x]));
      const msg = $('filemsg');
      if (!byName.size) {
        msg.textContent = 'First select the chunk folder of the backup.';
        return;
      }
      try {
        msg.textContent = `Opening ${f.name}…`;
        const parts = await assembleChunkedFile(keys, f, async (n) => {
          const x = byName.get(n);
          return x ? new Uint8Array(await x.arrayBuffer()) : null;
        });
        const a = document.createElement('a');
        a.href = URL.createObjectURL(new Blob(parts as BlobPart[], { type: f.mime ?? 'application/octet-stream' }));
        a.download = f.name;
        a.click();
        msg.textContent = `✓ ${f.name} opened.`;
      } catch (e) {
        msg.textContent = (e as Error).message;
      }
    });
    li.append(b);
    list.append(li);
  }
}

// QR code from a photo of the recovery sheet → text "RGR1:…" into the code field (nothing is sent).
$('qr').addEventListener('change', async () => {
  const img = $<HTMLInputElement>('qr').files?.[0];
  const msg = $('qrmsg');
  if (!img) return;
  try {
    const bmp = await createImageBitmap(img);
    // downscale large phone photos – the QR code is read faster and more reliably
    const scale = Math.min(1, 1600 / Math.max(bmp.width, bmp.height));
    const canvas = document.createElement('canvas');
    canvas.width = Math.round(bmp.width * scale);
    canvas.height = Math.round(bmp.height * scale);
    const ctx = canvas.getContext('2d') as CanvasRenderingContext2D;
    ctx.drawImage(bmp, 0, 0, canvas.width, canvas.height);
    const data = ctx.getImageData(0, 0, canvas.width, canvas.height);
    const text = jsQR(data.data, data.width, data.height)?.data ?? '';
    if (!parseRecoveryQr(text)) {
      msg.textContent = 'No recovery-sheet QR code was found in the photo. Try a sharper photo or enter the words.';
      return;
    }
    $<HTMLTextAreaElement>('words').value = text;
    msg.textContent = '✓ QR code read – click Open.';
  } catch {
    msg.textContent = 'The image cannot be opened.';
  }
});
