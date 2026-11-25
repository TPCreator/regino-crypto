# Plán pre aplikácie po validácii auditu (2026-11-25)

Úlohy, ktoré z [`validacia-auditu-2026-11-25.md`](validacia-auditu-2026-11-25.md) pripadajú aplikáciám. Jadro sa v nich
**nezapína samo**: aktualizácia pinu jadra je v každej aplikácii samostatný vedomý krok (pravidlo pripínania), poradie
a termín určí Tomáš. Čísla v zátvorkách odkazujú na nálezy (F-xx, L-xx audit, V-xx naše). Priorita: **P1** hneď pri
najbližšej práci na aplikácii, **P2** s najbližšou väčšou verziou, **P3** keď príde príslušná funkcia.

## Dôverník (zdravotné údaje, čl. 9) – pin 97518c5 = 0.16.1

| P | Úloha | Prečo / kde |
|---|---|---|
| P1 | Prejsť na jadro **0.17.0** (submodul) – autorizátor v trezore zablokuje `PRAGMA rekey/key/cipher_*/secure_delete` z okna | V-01, L-08; `db_exec`, `scratch_exec` v `app/src-tauri/src/lib.rs:913–926`, `scratch.rs:39–50` |
| P1 | Obnova z úložiska: overiť monotónnosť (najvyššie poradové číslo/čas snímky, ktoré prax pozná – napr. z papierového listu obnovy alebo z posledného známeho stavu), **podpísať zoznam záloh** a kľúčenku kľúčom praxe a pri obnove ich overiť; používateľovi ukázať dátum a varovať, ak je snímka staršia než posledná známa | F-01, V-06; `lib/storage/snapshot.ts:282–305` |
| P2 | Kľúč na zápis do spisu otvárať cez **`openWriteKey`** (vždy `requireAnchorOnLatest` + `requireCurrentEpoch` + `recipientId`), aj pri spise bez vedenia; ak to model spisu bez kotvy nedovoľuje, zdokumentovať prečo | F-03; `casesign.ts:234–243, 368`, `centercase.ts:1091, 1359` |
| P2 | Párovanie: počítať zlyhania SAS aj na klientovi, po **3 po sebe** zamknúť a upozorniť („niekto môže zasahovať“) | F-04; `sync.ts:748–860`, server `sync.php:280` |
| P2 | Licencie: `verifyWithKeysAt(…, nowSec)` (alebo `null` tam, kde platnosť riešia `valid_*` zámerne) | L-05; `lib/licence/licence.ts:51, 85` |
| P2 | Formulár: zobraziť odtlačok kľúča schránky (celých 80 bitov) pri prvom použití; overovať aj stránku centra s viacerými kľúčmi (`targets`) | F-05; `public/form.ts:50–59, 143–166, 158` |
| P3 | Podpísaný kľúč schránky (inbox v2, keď bude v jadre) | F-05 |
| P2 | Šifrovanie disku: pri vypnutom BitLockeri trvalé varovanie; v DPIA ako podmienka pre čl. 9 | F-06; `src-tauri/src/encryption.rs` |
| P3 | Nové druhy kontextov skladať cez `structuredContext` / `context::structured` (existujúce nemeniť) | L-01; pozn. kolízia `label` (`centercase.ts:389`) |

## DysPro (zdravotné údaje, čl. 9) – cez app-core, jadro 37beca2 = 0.15.1

| P | Úloha | Prečo / kde |
|---|---|---|
| P1 | **Kľúč údajov odborníka nesmie stáť len na PIN-e.** Uložiť ho do úložiska OS (Android Keystore / Keychain / Credential Manager) alebo odvodiť z passkey PRF, PIN nechať ako bránu; do vyriešenia aspoň 8 číslic a jasne v DPIA | V-02, L-04; `app-core/src/pinVault.ts:42–61`, `client/src/lib/app/pinGuard.ts:36` |
| P1 | Rozhodnúť údaje rodiča a dieťaťa v zariadení a v zálohe (dnes bez šifrovania, profil potrieb je čl. 9); PIN rodiča nie ako nesolený SHA-256 | V-07; `client/src/lib/app/pin.ts:2–4` |
| P2 | Šifrovanie disku (zariadenia odborníkov) ako podmienka v DPIA, nie len odporúčanie O4 | F-06; `docs/pravne/DPIA-vzor.md:319` |
| P2 | Prejsť na 0.17.0 spolu s app-core | V-04 |

## Gazda (domáce financie) – pin 37beca2 = 0.15.1

| P | Úloha | Prečo / kde |
|---|---|---|
| P1 | Prejsť na **0.17.0** (`regino-vault` aj `@regino/crypto`) – dnes chýba aj blok `ATTACH`/`VACUUM INTO` z 0.16.1 a `vault_exec/run/all` púšťajú SQL z okna | V-01, V-04, L-08; `client/src-tauri/src/vault.rs:105–126` |
| P2 | Sync: k LWW pridať high-water mark na zariadenie a prev-hash (alebo poradové číslo) udalostí, aby server nevedel zatajiť udalosti ani dať novému zariadeniu starú snímku; po rotácii neprijímať nové udalosti pod starým `keyId` | F-01, F-03; `sync-session.ts:97–120, 229–236` |
| P2 | Licencie: `verifyWithKeysAt(…, nowSec)`, overovať `exp` tokenov zariadení | L-05; `client/src/lib/licence.ts:135` |
| P2 | Zálohy (OneDrive): pri obnove varovať, ak je záloha staršia než posledná známa | F-01 |
| P2 | Doplniť do dokumentácie šifrovanie disku (BitLocker) | F-06 |
| P3 | Zoznam zariadení (`member_devices`) podpisovať, ak sa bude zdieľať mimo jednej domácnosti | F-03 |
| – | Mimo kryptografie, ale bezpečnostné: `pubkey: "TODO-TOMAS"` v updateri (`tauri.conf.json`) | – |

## Žiačik (portfólio, citlivé údaje detí) – vendor 37beca2 = 0.15.1

| P | Úloha | Prečo / kde |
|---|---|---|
| P1 | `acceptGrant`: kľúč žiaka prijať len **podpísaný** odosielateľom zo zoznamu kolegov (`signedWrapForDevice` / `openWriteKey`), nie cez anonymný inbox | F-03, F-05; `portfolio.ts:362–382` |
| P2 | Párovanie: zámok po 3 neúspechoch SAS (klient aj server) | F-04; `sync.ts:359–455`, `PortfolioSyncController.php` |
| P2 | Po odobratí učiteľa/zastupujúceho rotovať aj kľúč položiek `k`, nielen dôverných poznámok | F-01/F-03; `sync.ts:97–99` |
| P2 | Kľúče školy a rodiny: vynútiť kontrolu odtlačku pred prvým pečatením | F-05; `sync.ts:225`, `share.ts:49–50` |
| P2 | Server nesmie vedieť vynútiť zahodenie kľúča žiaka vynechaním v zozname (najprv potvrdenie / podpísaný zoznam) | dostupnosť; `sync.ts:97–99` |
| P2 | Záloha v4 (F-02), keď bude v jadre – Žiačik ako jediný používa kód + kúsky | F-02 |
| P2 | `checkId` aj pre `licenceId` v `ziacik|portfolio|school-key|…` | L-01; `sync.ts:354, 557` |
| P3 | Vlastné PBKDF2 (`backup/nameKey.ts`) presunúť do jadra alebo nahradiť; zálohy pokroku na serveri šifrovať | V-05 |
| P2 | Prejsť na 0.17.0 (oprava `signManifest` a torzie z 0.16.0 – `signManifest` sa používa) | V-04 |

## app-core (spoločný základ) – vendor 37beca2 = 0.15.1

| P | Úloha | Prečo / kde |
|---|---|---|
| P1 | `pinVault`: neposielať PIN do `encryptBackup` ako 75-bitový kód; ponúknuť viazanie kľúča na zariadenie (úložisko OS / passkey) a PIN ako druhý faktor; minimálne odmietnuť 4 číslice pre aplikácie s citlivými údajmi | V-02, L-04; `src/pinVault.ts:255–272` |
| P2 | Overovanie licencií cez jadro (`signed.ts` / `verifyEd25519`, `verifyWithKeysAt`) namiesto vlastného `@noble/ed25519 ^2.3.0`; PBKDF2 (`deriveKeys`, `passwordKey`) presunúť do jadra | V-05; `src/keys.ts:93`, `src/seal.ts:87–101` |
| P2 | `peerDependency "@regino/crypto"` zúžiť na pripnutú verziu | V-05; `package.json` |
| P2 | Prejsť na 0.17.0 | V-04 |

## Vedino – vendor 37beca2 = 0.15.1 (sync len pripravený)

| P | Úloha | Prečo / kde |
|---|---|---|
| P3 | Pred zapojením sync: kľúč skupiny **nie z kódu licencie** (pozná ho vydavateľ – nebolo by to E2E voči prevádzkovateľovi), ale `newGroupKey` + párovanie podľa `docs/PAIRING.md` | `client/src/lib/sync/sync.ts:8–9, 28` |
| P3 | Pri zapojení: high-water mark, tombstones, rotácia (F-01) a 0.17.0 | F-01, V-04 |

## Testurion – pin abf2028 (nezlúčená vetva jadra)

| P | Úloha | Prečo / kde |
|---|---|---|
| P1 | Nepoužívať nezlúčený kód jadra: buď počkať na zlúčenie PR #40 (Shamir v TS + `kdf.ts`) do `main` a pripnúť zlúčený commit, alebo dovtedy deliť kľúč cez Rust `regino_keys::shamir` | V-03; `app/regino-crypto/PIN.json`, `app/src/lib/author/shares.ts:6` |
| P1 | Opraviť označenie verzie vo vendori („0.16.0“ ≠ jadro 0.16.0) | V-03 |
| P3 | Pri zapojení zdieľaného skupinového kľúča `openWriteKey`, high-water mark a rotáciu | F-01, F-03 |
| P3 | Kľúč autora: okrem ručného porovnania odtlačku pripnutie pri prvom použití | F-05; `tsr/package.ts:239–248` |
