# Validácia externého auditu regino-crypto (2026-11-25)

**Zadanie:** Tomáš 2026-11-25 v hlavnej session: „potrebujem jednu session na validaciu tohto“ – nezávisle overiť externý audit
(nástroj Devin) stavu `main` **97518c5, verzia 0.16.1**, nie ho prevziať. Overené na 97518c5 (= `main` v čase validácie),
opravy vo verzii **0.17.0**. Aplikácie boli len čítané (nič sa v nich nemenilo); úlohy pre ne sú v
[`plan-aplikacie-2026-11-25.md`](plan-aplikacie-2026-11-25.md).

**Celkový verdikt:** audit je v jadre presný – všetkých 14 nálezov sa potvrdilo (L-06 čiastočne), odkazy na riadky sedia
s odchýlkou nanajvýš niekoľko riadkov a žiadny nález nie je vymyslený; **podcenil však L-08** (surové SQL do trezoru): cez
verejné `exec` sa dal potichu zmeniť kľúč databázy a vypnúť `secure_delete`, a v Dôverníku aj Gazde toto SQL posiela
okno aplikácie. Najväčšie skutočné riziko nie je v jadre, ale v tom, ako ho používajú aplikácie (DysPro, app-core, Testurion).

## 1. Kontroly, ktoré sme spustili sami

| Kontrola | Audit tvrdí | My (97518c5) | My (0.17.0) |
|---|---|---|---|
| `cargo clippy --workspace --all-targets --locked -- -D warnings` | OK | OK | OK |
| `cargo test --workspace --locked` | 133 OK | **133 OK** | 138 OK |
| `npx tsc --noEmit` | OK | OK | OK |
| `npx vitest run --coverage` | 179 OK, 100 % | **179 OK, 100 %** (1118 príkazov, 732 vetiev) | 188 OK, 100 % (1152 / 757) |
| `npm audit` (behové od moderate, všetko od critical) | 0 | 0 | 0 |
| `cargo-deny check` (0.20.2) | OK, varovania | OK; varovania: duplicitný `syn`, nezastúpené licencie v zozname | OK, rovnaké varovania |
| `npm run build:tool` = `tools/open-backup.html` | identický | **identický** (`git diff` prázdny) | prestavaný (sanitizácia názvov, verzia 0.17.0) |
| `cargo llvm-cov` (riadky) | – | – | 97,30 % (CI vyžaduje ≥ 95 %) |
| `cargo-fuzz` 0.13.2, nightly, 5 min na cieľ (na 97518c5) | nespustené | `sign` 2,2 mil. behov, `shamir_combine` 14,2 mil., `backup_code_parse` 38,3 mil., `wrap_unwrap` 5,2 mil. – **žiadny pád ani únik pamäte** | – |

Dlhé kampane (hodiny až dni), Windows (Credential Manager/DPAPI, `VirtualLock`) a mobil sme nespúšťali – prostredie je Linux.

## 2. Verdikt ku každému nálezu

Odkazy `súbor:riadok` sú na 97518c5. „Odkaz sedí“ = audit ukazuje na to isté miesto (± pár riadkov).

| Nález | Audit tvrdí | Verdikt | Zdôvodnenie (súbor:riadok) | Stav |
|---|---|---|---|---|
| **F-01** vysoká, návrh | formáty nenesú čerstvosť ani poradie; replay/rollback je na aplikácii | **POTVRDENÉ** | `ts/src/sync.ts:17` (hlavička: „the app's duty“), `README.md:22`, `AUDIT.md` § 3.3. AEAD viaže *čo* a *kam*, nie *kedy*; platí pre RGS1/RGW1, zálohy, inbox aj zabalené kľúče. Závažnosť „vysoká“ platí pre aplikácie so serverom; v praxi: Dôverník obnova z úložiska (§ 3), Gazda (LWW bez prev-hash), app-core. | návrh formátu (§ 6, bod 2), úlohy aplikáciám |
| **F-02** stredná, návrh | kľúče kúskov a `backupCodeId` obchádzajú zvýšené KDF zálohy v3; pevná soľ aplikácie | **POTVRDENÉ** | `ts/src/backupCode.ts:221` (`backupCodeAppSalt` = SHA-256 mena aplikácie), `:231` (`backupCodeBase` vždy `DEFAULT_BACKUP_CODE_KDF` 32 MiB / t=2), `ts/src/backupChunks.ts:39`, `keys/src/backup_chunks.rs:53`. Vyššie `options.kdf` sa týka len hlavičky; kúsok aj id sa dajú skúšať za 32 MiB/2. Pevná soľ ⇒ jeden pokus Argon2id testuje kód naraz voči všetkým id/kúskom jednej aplikácie (útok na viac cieľov: očakávaná práca na prvý zásah klesá N-krát). Týka sa len 16-znakového kódu (Gazda, Žiačik; Žiačik používa aj kúsky), nie 12/24 slov. Už bolo odložené na v4 (`docs/rozhodnutia.md` 2026-11-18). | návrh v4 (§ 6, bod 1) |
| **F-03** stredná, aplikácia | forky s rovnakou verziou jadro neodhalí; `require_anchor_on_latest` predvolene vypnuté | **POTVRDENÉ** | `keys/src/sign.rs:644` (dokumentácia priznáva, že fork nezistí), `:762` (`false` predvolene), `:937` `verify_write_key` (všetko zapnuté, od 0.16.0). Odkazy sedia (± 10 riadkov). Riziko vzniká len pri použití starších volaní. Dôverník používa `openSignedWrap` s `requireCurrentEpoch` + `recipientId`, `requireAnchorOnLatest` len pri spise s vedením; ostatné aplikácie na 0.15.1 `openWriteKey` ani nemajú. | úlohy aplikáciám |
| **F-04** stredná, návrh | párovanie cez server chráni len 6-ciferný SAS; bez lockoutu opakovateľné | **POTVRDENÉ** | `ts/src/sync.ts:218` (`pairingCode` – výslovne nie proti serveru), `:274–284` (SAS 6 číslic = 10⁻⁶ na pokus), `docs/PAIRING.md:50–52` (nové nonce, poradie, 3 pokusy – len ako „should“). Jadro lockout nevynucuje, je to stav aplikácie. Dôverník: server 5 pokusov/hod., klient nepočíta; Žiačik: bez zámku; Gazda: QR mimo servera (v poriadku). | úlohy aplikáciám; návrh dlhšieho SAS (§ 6, bod 4) |
| **F-05** stredná | inbox bez autentifikácie odosielateľa a dôvery v kľúč od servera | **POTVRDENÉ** | `ts/src/inbox.ts:12` („sender is anonymous“), `docs/INBOX.md:22–31`. Je to vlastnosť návrhu a je zdokumentovaná. Dôverník: odtlačok v odkaze `#k` sa kontroluje potichu (nezobrazuje sa), SRI na rovnakom pôvode, podpísaný kľúč schránky chýba. Žiačik: kľúč žiaka prijíma cez nepodpísaný inbox (`acceptGrant`). | návrh inbox v2 (§ 6, bod 3), úlohy aplikáciám |
| **F-06** stredná, prostredie | SQLCipher nechráni plaintext v swape; `cipher_memory_security` vypnuté; `compact` nie je forenzné mazanie | **POTVRDENÉ** | `vault/src/lib.rs:124–126`, `:143–169` (dokumentácia `compact` to už priznáva: voľné bloky, SSD, tieňové kópie mimo záruky), `README.md:21`. Šifrovanie disku žiadna aplikácia nevyžaduje (Dôverník ho zisťuje a odporúča, Testurion ho má v DPA, ostatné nič). | úlohy aplikáciám; Windows test `cipher_memory_security` neoverený |
| **L-01** nízka–stredná | štruktúra kontextu je na volajúcom; `checkContext` len neprázdny reťazec | **POTVRDENÉ** | `keys/src/wrap.rs:9–12`, `ts/src/ecdh.ts:32`. V aplikáciách sme kolíziu nenašli (ID sú čísla, UUID alebo base64url overené serverom); Dôverník: teoretická kolízia položky s id `label` s `caseLabelContext`, zachytí ju vnútorná kontrola (`centercase.ts:389`). | **opravené 0.17.0** (`structuredContext`, Rust `context::structured`) |
| **L-02** nízka | jeden AES-GCM kľúč záznamov na skupinu, 96-bit náhodné nonce, limit 2³² nevynútený | **POTVRDENÉ** | `ts/src/sync.ts:50` (`recordKey`), `:95` (nonce), `:86` (limit len v komentári; audit uvádza 49/84 – o 1–2 riadky vedľa). Reálne objemy aplikácií sú o mnoho rádov nižšie. | len zdokumentované; návrh v § 6, bod 2 |
| **L-03** nízka | mená kúskov = HMAC obsahu, server vidí rovnosť príloh | **POTVRDENÉ** | `ts/src/backupChunks.ts:9`. Zámer kvôli deduplikácii, uvedené v `AUDIT.md` (riadok 0.11.0). | bez zmeny (zámer) |
| **L-04** nízka | 16-znakový kód (75 bitov) `encryptBackup` prijme pre akékoľvek údaje | **POTVRDENÉ – a v praxi horšie** | `ts/src/backupCode.ts:7–15`, `ts/src/backup.ts:122`. Jadro nevie, aké údaje šifruje. **app-core `pinVault` posiela do toho istého API PIN so 4–8 číslicami** (V-02) – DysPro tak chráni údaje čl. 9 v zariadení silou PIN-u. | návrh parametra citlivosti (§ 6, bod 5), úloha DysPro/app-core |
| **L-05** nízka | `verifyWithKeys` kontroluje `nbf`/`exp` len s `at` | **POTVRDENÉ** | `ts/src/signed.ts:164`, `:175`. Dôverník (`licence.ts:51, 85`) aj Gazda (`licence.ts:135`) volajú bez `at` (časovú platnosť licencie si riešia vlastnými poľami; `exp` zariadení sa neoverí). | **opravené 0.17.0** (`verifyWithKeysAt` s povinným časom) |
| **L-06** nízka | manifest sa parsuje pred overením podpisu | **ČIASTOČNE** | `keys/src/sign.rs:561–570`: kľúč podpisovateľa je vnútri správy, takže čítanie polí pred podpisom sa obísť nedá; drahé dekódovanie bodov členov ide **už od 0.15.1 až po podpise** (`:566–569`). Chýbal však limit veľkosti blobu (kópie a opätovné zakódovanie celej správy). | **opravené 0.17.0** (`MAX_MANIFEST_LEN` = 1 602 216 B, Rust aj TS) |
| **L-07** nízka | rekurzia `findChunkedFiles` bez limitu; názov súboru v stiahnutí | **POTVRDENÉ** | `ts/src/backupChunks.ts:112`, `ts/tools/page.ts:46, 64` (audit uvádza 38). Zneužiť to vie len ten, kto má kód zálohy (obsah je autentifikovaný), dopad je na nástroj `open-backup.html`. | **opravené 0.17.0** (hĺbka ≤ 64, `safeFileName`, MIME len `typ/podtyp`) |
| **L-08** nízka | surové SQL `exec/run/all`; zvážiť blokovanie `PRAGMA key/rekey`, `secure_delete` | **POTVRDENÉ – závažnosť stredná** | `vault/src/lib.rs:193–220`. Overili sme skúškou: `PRAGMA hexrekey = '00'` cez `exec` súbor **prešifroval na známy kľúč** (kľúč z úložiska ho už neotvorí, ktokoľvek s `00` áno); `PRAGMA secure_delete = OFF` a `cipher_plaintext_header_size` prešli. Dôverník (`db_exec`, `scratch_exec`) aj Gazda (`vault_exec`) posielajú SQL z okna (XSS = priama cesta; zmierňuje len CSP). | **opravené 0.17.0** (autorizátor SQLite, V-01) |

**Neoverené oblasti z auditu:**

| Oblasť | Teraz |
|---|---|
| SQLCipher/OpenSSL, WebCrypto, blahaj, @noble/*, OS keystores | mimo rozsahu aj u nás; používanie API sme spot-kontrolovali (AAD, dĺžky nonce, hranice Argon2id) |
| Windows Credential Manager / DPAPI | neoverené (Linux) |
| Dlhé fuzzovanie | 5-minútové behy všetkých 4 cieľov bez nálezu (§ 1); hodinové kampane stále chýbajú |
| Aplikačné replay/rollback, tombstones, rate-limit `backupCodeId`, piny, lockout, inbox fingerprinty | **overené** pre 7 aplikácií – § 3 |
| Šifrovanie disku a prístup k zariadeniu | overená len dokumentácia/kód aplikácií (§ 3, riadok 11) |

## 3. Aplikácia × povinnosť

Zdroj: čítanie repozitárov 2026-11-25 (Dôverník bcfdae9, Gazda 0ddb538, DysPro 5cca7c5, Žiačik 8e052f7, Vedino 5d39808,
Testurion 072c23a, app-core d628bae). Pin jadra: **Dôverník 97518c5 (0.16.1)**; Gazda, app-core, DysPro, Žiačik, Vedino
**37beca2 (0.15.1)**; Testurion **abf2028 – nezlúčená vetva jadra** (V-03).

`✔` plní · `◐` čiastočne · `✘` neplní · `–` netýka sa

| # | Povinnosť | Dôverník | DysPro | Gazda | Žiačik | app-core | Vedino | Testurion |
|---|---|---|---|---|---|---|---|---|
| 1 | replay/rollback, high-water mark | ◐ sync ✔ (`sync.ts:287–304`), **obnova z úložiska ✘** (`storage/snapshot.ts:282–305` berie najnovší manifest a kľúčenku od servera) | – (lokálny trezor bez verzií) | ◐ LWW/HLC, bez prev-hash a high-water mark (`sync-session.ts:97–120`) | ✔ položky (`items.ts:145–150`), ◐ zálohy na novom zariadení | ✘ (`seal.ts` bez verzie) | – | ◐ denník ✔, sync zatiaľ nie |
| 2 | tombstones | ◐ (stará kľúčenka od servera môže „oživiť“ zmazaného klienta) | – | ✔ `deleted_at` | ✔ | ◐ | – | – |
| 3 | epochy / rotácia | ✔ (`sync.ts:616–670`, `centercase.ts:1292`) | – | ◐ rotácia ✔, staré `keyId` sa prijímajú ďalej | ◐ kľúč položiek sa po odobratí učiteľa nerotuje | – | – | – |
| 4 | `openWriteKey`/`verify_write_key`, piny | ◐ ekvivalent cez `openSignedWrap` + `requireCurrentEpoch` + `recipientId`; `requireAnchorOnLatest` len so správou centra; piny v SQLCipher ✔ | – | ✘ podpisy nepoužíva (zoznam zariadení nepodpísaný) | ◐ kolegovia ✔, **kľúč žiaka cez nepodpísaný inbox** | – | – | – (zatiaľ) |
| 5 | párovanie (QR alebo SAS + lockout) | ◐ SAS ✔, nové nonce ✔, lockout len server 5/hod. | – | ✔ QR mimo servera | ◐ SAS ✔, **bez zámku** | – | – | – |
| 6 | inbox: odtlačok mimo servera, SRI, podpísaný kľúč | ◐ odtlačok sa nezobrazuje, SRI rovnaký pôvod, bez podpisu | – | – | ◐ kľúče školy/rodiny bez kontroly odtlačku | – | – | ◐ ručné porovnanie odtlačku |
| 7 | rate-limit `backupCodeId` | – | – | – (nepoužíva) | – (server id nedostáva) | – | – | – |
| 8 | čas pri overení tokenu | ◐ bez `at`, vlastné `valid_*` | – (app-core) | ◐ bez `at`, `exp` sa neoverí | ✔ cez app-core | ✔ vlastný kód (mimo jadra) | – | – |
| 9 | štruktúra kontextov | ✔ (pozn. `label`) | ✔ | ◐ `id` nevalidované, posledné pole | ✔ (1 výnimka `licenceId`) | ✔ | – | ✔ |
| 10 | surové SQL z okna | **✘** `db_exec`, `scratch_exec` (`src-tauri/src/lib.rs:913–926`) – opravené jadrom 0.17.0 po aktualizácii pinu | – | **✘** `vault_exec` (`vault.rs:105–126`), pin 0.15.1 nemá ani blok `ATTACH` z 0.16.1 | – | – | – | – |
| 11 | šifrovanie disku | ◐ zisťuje a odporúča, nevyžaduje | ◐ len DPIA O4 | ✘ | ◐ len server | ✘ | – | ✔ (DPA) |
| 12 | sila tajomstva pri citlivých údajoch (čl. 9: nie 16 znakov) | ✔ 12 slov | **✘ PIN 6–8 číslic** (rodič 4) cez `pinVault` | ✔ kód 16 (financie) | ✔ kód 16 | **✘ `pinVault` prijme 4 číslice** | – | ✔ 12 slov + heslo |
| 13 | 2³² zapečatení na kľúč | ✔ | ✔ | ◐ bez počítadla | ◐ | ◐ | – | ✔ |
| 14 | kryptografia len v jadre, aktuálny pin | ✔ (0.16.1; AES-GCM len v demo `MemoryVault`) | ◐ 0.15.1 | ◐ 0.15.1 | ◐ 0.15.1, vlastné PBKDF2 (`nameKey.ts`) | **✘** vlastné overenie Ed25519 a PBKDF2 mimo jadra | ◐ 0.15.1; plán: kľúč sync z kódu licencie (nie E2E voči vydavateľovi) | **✘ vlastný Shamir v TS z nezlúčenej vetvy** |

## 4. Čo audit prehliadol (vlastná kontrola)

| # | Nález | Závažnosť | Dôkaz | Stav |
|---|---|---|---|---|
| **V-01** | Cez `Vault::exec/run/all` sa dal **zmeniť kľúč databázy** (`PRAGMA rekey`/`hexrekey`, napr. na `00`), nastaviť `PRAGMA key`, `cipher_*` (napr. nešifrovaná hlavička) a **vypnúť `secure_delete`**. SQL v Dôverníku a Gazde prichádza z okna aplikácie. Následok: buď strata prístupu (kľúč v úložisku už súbor neotvorí), alebo databáza pod kľúčom známym útočníkovi (každá kópia súboru – OneDrive, záloha disku – je potom čitateľná). | stredná (vyžaduje beh kódu v okne, napr. XSS) | skúška na 97518c5: `hexrekey = '00'` prešlo, starý kľúč → `WrongKey`; Dôverník `src-tauri/src/lib.rs:913–926`, Gazda `client/src-tauri/src/vault.rs:105–126` | **opravené 0.17.0** |
| **V-02** | **app-core `pinVault`** zabalí kľúč údajov cez `encryptBackup` s „tajomstvom kódu“ zostaveným z **PIN-u (4–8 číslic)** (`app-core/src/pinVault.ts` `pinSecret`). Jadro to prijme (štruktúra splní `isBackupCodeSecret`), ale entropia je 13–27 bitov namiesto 75. **DysPro** tak chráni údaje čl. 9 v zariadení odborníka 6–8-miestnym PIN-om: pri ukradnutom súbore je offline útok otázkou hodín až dní na jednom počítači. | **vysoká pre DysPro** | `app-core/src/pinVault.ts:42–61`, `dyspro/client/src/lib/app/pinGuard.ts:36`, `dyspro/docs/sifrovanie-zariadenia.md` („10⁶ možností“) | úloha DysPro/app-core; návrh jadra § 6, bod 5 |
| **V-03** | **Testurion** je pripnutý na `abf2028` – hlavu **nezlúčenej** vetvy jadra `claude/ts-shamir` (PR #40) s vlastnou implementáciou **Shamir GF(256) v TypeScripte** (`shamir.ts`) a `kdf.ts`, ktoré v `main` nie sú, a označuje ju „0.16.0“ (skutočná 0.16.0 je `c14df21`). Chýbajú mu opravy 0.16.0 (`openWriteKey`, torzia v `signed.ts`, `signManifest`). Porušuje pravidlo „šifrovanie len v regino-crypto (main)“. | stredná | `testurion/app/regino-crypto/PIN.json`, `app/src/lib/author/shares.ts:6`, `git ls-remote` (`refs/heads/claude/ts-shamir` = `abf2028`) | rozhodnutie Tomáša (§ 7) |
| **V-04** | Päť aplikácií je na **0.15.1** – bez opravy torzie v `signed.ts` (overovanie licencií), `signManifest` (dvaja členovia s jednou pečaťou), `openWriteKey` a Gazda bez bloku `ATTACH`/`VACUUM INTO` z 0.16.1. | nízka–stredná | `PIN.json` app-core, DysPro, Žiačik, Vedino; Gazda `packages/db/package.json:14` | úlohy aplikáciám |
| **V-05** | **app-core** overuje licencie vlastným Ed25519 (`@noble/ed25519 ^2.3.0`, `keys.ts:93`) a odvodzuje kľúče PBKDF2 (`seal.ts:87–101`) mimo jadra; `peerDependency "@regino/crypto": ">=0.8.0"` je voľná. Žiačik má vlastné PBKDF2 (`backup/nameKey.ts`). | nízka | app-core `src/keys.ts`, `src/seal.ts`, `package.json` | úlohy aplikáciám |
| **V-06** | Dôverník obnova z úložiska: server môže podať **starší pravý manifest aj starú kľúčenku** (zmazaný klient by sa obnovil). Je to F-01 v konkrétnom mieste. | stredná | `dovernik/app/src/lib/storage/snapshot.ts:282–305` | úloha Dôverník |
| **V-07** | DysPro: PIN rodiča ako nesolený SHA-256; údaje rodiča a dieťaťa (profil potrieb – podľa CLAUDE.md DysPro údaj čl. 9) v zariadení aj v zálohe bez šifrovania. | stredná (súlad) | `dyspro/client/src/lib/app/pin.ts:2–4`, `docs/rozhodnutia.md:453–458` | rozhodnutie Tomáša (§ 7) |

Ďalej sme skontrolovali bez nálezu: AAD zálohy v1–v3 a kúskov (`backup.ts:142, 212`, `chunks.rs:33`), hranice Argon2id
(`kdf.rs:23–36`), escapovanie listu na obnovu (`sheet.ts:104–147`), CSP nástroja (`page.html:6`, `connect-src 'none'`),
poradie podpis → kľúče členov (`sign.rs:566–569`, `signing.ts` `openManifest`), rotáciu kľúča v Gazde (nový kľúč je
zabalený zvlášť pre každé zostávajúce zariadenie, `sync-session.ts:424–465`).

## 5. Opravené v 0.17.0 (bez zmeny formátov)

Všetky vektory 0.16.1 a starších prechádzajú bez zmeny; zálohy, kódy, tokeny, zabalené kľúče, podpisy a zapečatené
udalosti sa nemenia. Nové API sú doplnky.

| Nález | Zmena | Testy |
|---|---|---|
| L-08 + V-01 | `Vault::open` nainštaluje autorizátor SQLite: `exec`/`run`/`all` odmietnu `PRAGMA key`, `rekey`, `hexkey`, `hexrekey`, `textkey`, `textrekey`, staré `cipher`, `kdf_iter`, `fast_kdf_iter`, `rekey_*`, všetky `cipher_*` a `sqlcipher_*` (okrem čítania `cipher_version`, `cipher_provider`, `cipher_provider_version`, `cipher_fips_status`) a akúkoľvek zmenu `secure_delete` (veľké/malé písmená aj `main.` – SQLite odovzdáva meno bez schémy). `Vault::rekey` povolí len vlastný `PRAGMA rekey`. Pragmy aplikácií (`foreign_keys`, `defer_foreign_keys`, `user_version`, `foreign_key_check`, `table_info`, `wal_checkpoint`, `pragma_page_count()`) ostávajú. Nová funkcia `hooks` crate `rusqlite` (bez nových balíkov). | `vault/tests/vault.rs` `key_and_cipher_pragmas_are_refused_through_app_sql` |
| L-01 | `structuredContext(parts)` (TS, `ts/src/context.ts`) a `regino_keys::context::structured` (Rust): `rg-ctx1` ‖ pre každú časť `|<dĺžka v bajtoch UTF-8>:<časť>`; časti neprázdne, v TS bez osamotených surogátov, spolu ≤ 1024 B. Rovnaké bajty v oboch jazykoch. | `testvectors/regino/context-0.17.0.json`, `ts/src/context.test.ts`, `keys/tests/audit_0_17_0.rs`, `keys/src/context.rs` |
| L-05 | `verifyWithKeysAt(token, keys, expect, at: number \| null)` – čas povinný (celé sekundy ≥ 0), `null` = výslovne „čas kontrolujem sám“; iné hodnoty vyhodia chybu. `verifyWithKeys` prijme aj `at: null` (bez zmeny správania). | `ts/src/signed.test.ts` |
| L-06 | `MAX_MANIFEST_LEN` = 1 602 216 B (najdlhší kanonický zoznam: všetky polia na hranici, 1000 členov); dlhší blob sa odmietne pred čítaním (Rust `sign::open_manifest`, TS `openManifest`). Žiadny prijatý zoznam nemôže byť dlhší. | `keys/tests/audit_0_17_0.rs`, `ts/src/audit0170.test.ts` (najväčší zoznam má presne túto dĺžku) |
| L-07 | `findChunkedFiles`: hĺbka ≤ `MAX_PAYLOAD_DEPTH` (64), názov cez nové `safeFileName` (len posledný segment cesty, bez riadiacich a rezervovaných znakov a obojsmerných značiek, ≤ 120 znakov), `mime` len `typ/podtyp`. `tools/open-backup.html` prestavaný. | `ts/src/audit0170.test.ts` |

## 6. Návrhy zmien formátu (neimplementované, na rozhodnutie)

1. **Záloha v4 (F-02)** – *odporúčam, priorita 2.* Kľúče kúskov a id pre server z **náhodnej soli zálohy** a parametrov
   hlavičky; ak deduplikácia kúskov medzi zálohami musí ostať, tak z jednej náhodnej „soli knižnice kúskov“ uloženej
   v hlavičke každej zálohy (rovnaká pre zálohy jedného zariadenia, iná medzi používateľmi). Id pre server ako HMAC
   s tajným pepperom servera (server id nevie overovať offline). Čítanie v1–v3 ostáva.
2. **Obálka s `epoch`/`seq`/`prev-hash` v AAD (F-01, L-02)** – *odporúčam ako voliteľný formát `sync record v2`, priorita 3.*
   `sealRecordV2(key, context, {epoch, seq, prev}, payload)` → AAD = `sync record v2|<context>|epoch|seq|prev`, plus pomocník
   high-water mark (`acceptNewer(state, header)`), aby aplikácie neskladali poradie samé. Jadro by tak vynucovalo poradie
   v rámci jedného reťazca; zatajenie najnovšej verzie aj tak odhalí len porovnanie s iným zdrojom.
3. **Inbox v2 (F-05)** – *odporúčam, priorita 3 (Dôverník formuláre).* Kľúč schránky doručovaný v objekte podpísanom
   kľúčom praxe (`signData` z `signing.ts`), formulár overí podpis voči kľúču praxe pripnutému z prvej návštevy alebo z QR na
   letáku; odtlačok zobraziť celý (80 bitov) pri prvom použití.
4. **Dlhší SAS (F-04)** – *odporúčam len doplnok, nie výmenu:* `pairingSas` s voliteľnou dĺžkou 8 číslic (10⁻⁸) alebo
   4 slová; hlavne však **stavový automat párovania v jadre** (`PairingAttempt`: poradie krokov, jednorazové nonce, počítadlo
   zlyhaní so zámkom) – to je API, nie formát, a dá sa pridať v 0.18.0 bez zmeny bajtov.
5. **Citlivosť pri zálohe (L-04, V-02)** – `encryptBackup(…, { sensitivity: 'special' })` odmietne 16-znakový kód;
   a nová funkcia pre krátke PIN-y viazaná na zariadenie (kľúč v úložisku OS / passkey PRF + PIN ako druhý faktor), aby
   aplikácie nemuseli zneužívať formát zálohy. Bez zmeny existujúcich formátov.

## 7. Čo treba rozhodnúť (s odporúčaním)

1. **DysPro – ochrana údajov čl. 9 v zariadení (V-02).** Dnes stojí na 6–8-miestnom PIN-e. *Odporúčam:* kľúč údajov
   v úložisku OS (Credential Manager / Keychain / Android Keystore, rovnako ako trezor Dôverníka) alebo passkey PRF, PIN len
   ako brána; do vyriešenia minimálne 8 číslic a jasné upozornenie v DPIA. Zároveň rozhodnúť nešifrované údaje rodiča (V-07).
2. **Testurion a nezlúčený Shamir v TS (V-03).** *Odporúčam:* PR #40 v jadre dokončiť (vektory zhodné s Rust `shamir`, testy,
   fuzz) a zlúčiť ako 0.18.0; Testurion potom pripnúť na zlúčený commit. Kým sa to nestane, nepovažovať podiely Testurionu
   za auditované.
3. **Prechod aplikácií na 0.17.0.** *Odporúčam prednostne Dôverník a Gazdu* (V-01 – SQL z okna); ostatné spolu s ďalšou
   väčšou zmenou. Každá aplikácia vedome, samostatným krokom (pravidlo pripínania).
4. **Záloha v4 (F-02)** – kedy; *odporúčam* spolu s ďalším väčším vydaním Žiačika (jediný s kódom + kúskami).
5. **Šifrovanie disku pre čl. 9** – *odporúčam* pre Dôverník a DysPro z neho urobiť podmienku v DPIA a v aplikácii aspoň
   varovanie pri vypnutom BitLockeri (Dôverník už stav zisťuje).

Úlohy pre jednotlivé aplikácie: [`plan-aplikacie-2026-11-25.md`](plan-aplikacie-2026-11-25.md).
