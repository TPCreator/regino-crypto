import { decryptBackup } from './backup';
import { backupChunkKeys, findChunkedFiles, type BackupChunkKeys, type ChunkedFile } from './backupChunks';
import { wordsToSecretAuto } from './recovery';

/**
 * Independent backup opening: file contents + recovery code (12 or 24 words, or the QR text) → data.
 * The word list (Slovak or English) is recognised from the words (`wordsToSecretAuto`); words valid in
 * both lists are tried with each – only the right secret opens the backup (AES-GCM).
 * The application is detected from the file header "<app>-backup".
 * Used by the public tool tools/open-backup.html – proof that the applications encrypt with this code.
 */
export type OpenResult =
  | {
      ok: true;
      app: string;
      createdAt: string;
      payload: unknown;
      /** large files kept in the chunk folder next to the backup (backupChunks.ts) */
      files: ChunkedFile[];
      /** keys for opening those chunks (only when there are files) */
      chunkKeys: BackupChunkKeys | null;
    }
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
  const code = await wordsToSecretAuto(words);
  let secrets: Uint8Array[];
  if (code.ok) secrets = [code.secret];
  else if (code.error.code === 'ambiguous') secrets = code.error.candidates.map((c) => c.secret);
  else {
    const e = code.error;
    if (e.code === 'count')
      return { ok: false, message: `12 or 24 words are required, ${e.count} entered.` };
    if (e.code === 'qr') return { ok: false, message: 'The QR code could not be read completely – try a sharper photo or enter the words.' };
    if (e.code === 'unknown-word')
      return { ok: false, message: `Word no. ${e.index + 1} ("${e.word}") is not in the word list.` };
    return { ok: false, message: 'The words are in the list, but the checksum does not match – check their order.' };
  }
  // one secret, or (words valid in more than one list) each candidate until one opens the backup
  let [secret] = secrets as [Uint8Array];
  let r = await decryptBackup(secret, file, app);
  for (const s of secrets.slice(1)) {
    if (r.ok) break;
    secret = s;
    r = await decryptBackup(s, file, app);
  }
  if (!r.ok) {
    return {
      ok: false,
      message:
        r.error === 'newer-version'
          ? 'The backup comes from a newer version – download a newer tool.'
          : 'The code does not belong to this backup, or the file is damaged.',
    };
  }
  const files = findChunkedFiles(r.payload);
  return { ok: true, app, createdAt: r.createdAt, payload: r.payload, files, chunkKeys: files.length ? await backupChunkKeys(secret, app) : null };
}
