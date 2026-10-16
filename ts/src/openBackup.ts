import { decryptBackup } from './backup';
import { wordsToSecret } from './recovery';

/**
 * Independent backup opening: file contents + recovery code (12 or 24 words, or the QR text) → data.
 * The application is detected from the file header "<app>-backup".
 * Used by the public tool tools/open-backup.html – proof that the applications encrypt with this code.
 */
export type OpenResult =
  | { ok: true; app: string; createdAt: string; payload: unknown }
  | { ok: false; message: string };

const APP_FORMAT = /^([a-z][a-z0-9]{1,31})-backup$/;

export async function openBackup(fileText: string, words: string): Promise<OpenResult> {
  let file: unknown;
  try {
    file = JSON.parse(fileText);
  } catch {
    return { ok: false, message: 'The file is not a backup (it cannot be read as JSON).' };
  }
  const format = (file as { format?: unknown } | null)?.format;
  const m = typeof format === 'string' ? APP_FORMAT.exec(format) : null;
  if (!m) return { ok: false, message: 'The file is not a backup encrypted with regino-crypto.' };
  const app = m[1] as string;
  const secret = await wordsToSecret(words);
  if (!secret.ok) {
    const e = secret.error;
    if (e.code === 'count')
      return { ok: false, message: `12 or 24 words are required, ${e.count} entered.` };
    if (e.code === 'qr') return { ok: false, message: 'The QR code could not be read completely – try a sharper photo or enter the words.' };
    if (e.code === 'unknown-word')
      return { ok: false, message: `Word no. ${e.index + 1} ("${e.word}") is not in the word list.` };
    return { ok: false, message: 'The words are in the list, but the checksum does not match – check their order.' };
  }
  const r = await decryptBackup(secret.secret, file, app);
  if (!r.ok) {
    return {
      ok: false,
      message:
        r.error === 'newer-version'
          ? 'The backup comes from a newer version – download a newer tool.'
          : 'The code does not belong to this backup, or the file is damaged.',
    };
  }
  return { ok: true, app, createdAt: r.createdAt, payload: r.payload };
}
