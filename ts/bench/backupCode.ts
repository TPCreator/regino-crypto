// Time of the Argon2id of a backup code in this JavaScript engine: `npm run bench:code`.
import { backupCodeStretch, DEFAULT_BACKUP_CODE_KDF, MAX_BACKUP_CODE_KDF, MIN_BACKUP_CODE_KDF, newBackupCodeSecret } from '../src/backupCode';

const secret = newBackupCodeSecret();
const salt = new Uint8Array(16);
for (const [label, kdf] of [
  ['minimum', MIN_BACKUP_CODE_KDF],
  ['default', DEFAULT_BACKUP_CODE_KDF],
  ['128 MiB, 2 passes', { m: MAX_BACKUP_CODE_KDF.m, t: 2, p: 1 }],
] as const) {
  await backupCodeStretch(secret, salt, MIN_BACKUP_CODE_KDF); // warm-up
  const n = 5;
  const t = performance.now();
  for (let i = 0; i < n; i++) await backupCodeStretch(secret, salt, kdf);
  console.log(`${label.padStart(18)} (m = ${kdf.m} KiB, t = ${kdf.t}, p = ${kdf.p}): ${((performance.now() - t) / n).toFixed(0)} ms`);
}
