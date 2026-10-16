// "Open backup" tool page – everything runs in the browser, nothing is sent anywhere.
import jsQR from 'jsqr';
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
});

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
