import { backupCodeParamsOf, decryptBackup } from './backup';
import { backupChunkKeys, findChunkedFiles, type BackupChunkKeys, type ChunkedFile } from './backupChunks';
import { BACKUP_CODE_SECRET } from './backup';
import { looksLikeBackupCode, parseBackupCode, type BackupCodeError } from './backupCode';
import { wordsToSecretAuto } from './recovery';

/**
 * Independent backup opening: file contents + recovery code (12 or 24 words, or the QR text) or a
 * 16-character backup code (since 0.15.0) → data. The header says which kind the backup needs
 * (versions 3 and 4 = backup code); input of the other kind gets a message saying so. Version 4 (since 0.19.0)
 * takes the chunk keys from the salt and parameters in its header.
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
  let secrets: Uint8Array[];
  if ((file as { secret?: unknown }).secret === BACKUP_CODE_SECRET) {
    const c = parseBackupCode(words);
    if (!c.ok) return { ok: false, message: codeMessage(c.error, words) };
    secrets = [c.secret];
  } else {
    const r = await wordsSecrets(words);
    if (typeof r === 'string') return { ok: false, message: r };
    secrets = r;
  }
  return decryptWith(secrets, file, app);
}

/** Message for a backup code that cannot be read; words typed instead of the code are recognised. */
function codeMessage(e: BackupCodeError, input: string): string {
  if (input.trim().split(/\s+/).length >= 6) return 'This backup is protected by a 16-character backup code, not by words.';
  if (e.code === 'length') return `The backup code has 16 characters, ${e.length} entered.`;
  if (e.code === 'unknown-char')
    return `Character no. ${e.index + 1} ("${e.char}") cannot be in a backup code – it uses only digits and the letters A–Z except U.`;
  return 'The code is not correct – check the characters (one is probably mistyped, or two are swapped).';
}

/** Words (or the QR text) → candidate secrets, or the message for the user. */
async function wordsSecrets(words: string): Promise<Uint8Array[] | string> {
  const code = await wordsToSecretAuto(words);
  if (code.ok) return [code.secret];
  if (code.error.code === 'ambiguous') return code.error.candidates.map((c) => c.secret);
  if (looksLikeBackupCode(words)) return 'This backup is protected by 12 or 24 words – a 16-character code belongs to another backup.';
  const e = code.error;
  if (e.code === 'count') return `12 or 24 words are required, ${e.count} entered.`;
  if (e.code === 'qr') return 'The QR code could not be read completely – try a sharper photo or enter the words.';
  if (e.code === 'unknown-word') return `Word no. ${e.index + 1} ("${e.word}") is not in the word list.`;
  return 'The words are in the list, but the checksum does not match – check their order.';
}

async function decryptWith(secrets: Uint8Array[], file: unknown, app: string): Promise<OpenResult> {
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
  return { ok: true, app, createdAt: r.createdAt, payload: r.payload, files, chunkKeys: files.length ? await backupChunkKeys(secret, app, backupCodeParamsOf(file) ?? undefined) : null };
}
