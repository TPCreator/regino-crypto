# Posudok regino-crypto modelom Mistral Large 4 (2026-11-18) – druhý, menej významný poradný zdroj

Doplnok k [posudku Gemini 4 Argon](argon-posudok-2026-11-18.md) podľa rozhodnutia Tomáša z 2026-11-18 (Žiačik, `docs/rozhodnutia.md`, „Doplnky k licencii pre učiteľa a posudkom“, bod 3). Model dostal **ten istý prompt a tie isté podklady** ako Argon.

| | |
|---|---|
| Model | `mistral-large-latest` (alias `mistral-large-4`, „Mistral Large 4.0“, overené cez `/v1/models`), `/v1/chat/completions`, max_tokens 32 768, streamovanie |
| Dátum | 2026-11-18 |
| Posudzovaný stav | 0.15.1, commit `37beca2` |
| Podklady | rovnaké ako pri Argone (89 súborov, bez testovacích vektorov a skutočných kľúčov) |
| Tokeny | vstup 205 766 (z toho 205 568 z vyrovnávacej pamäte), výstup 31 095 (z toho 22 286 premýšľanie, nie je zverejnené) |
| Cena | táto odpoveď ≈ **0,16 $** (cenník tretích strán: 1,36 $ vstup, 0,14 $ vstup z vyrovnávacej pamäte, 4,18 $ výstup za 1 M tokenov). Prvý pokus skončil chybou proxy („upstream request failed“), Mistral ho však zrejme spracoval (vstup druhého pokusu bol takmer celý v pamäti) a mohol ho zaúčtovať: najviac ≈ 0,42 $. Spolu teda **≈ 0,16 – 0,58 $ (≈ 0,14 – 0,50 €)**. Odhad vopred: ≈ 0,40 €, pod 1 €. |

Odpoveď modelu je nižšie **doslovne** (len textová časť, bez premýšľania). Pod ňou je overenie každého tvrdenia o zraniteľnosti v kóde, so stĺpcom „Zdroj“.

## Prompt (zhodný s Argonom)

```text
Si skúsený kryptograf a bezpečnostný architekt. Robíš nezávislý, kritický posudok knižnice regino-crypto (verzia 0.15.1, commit 37beca2). Píš po slovensky. Žiadne pochvaly, žiadne zhrnutia toho, čo je dobre – len problémy, riziká, chýbajúce veci a konkrétne odporúčania. Keď si niečím nie si istý, napíš to výslovne; nevymýšľaj si správanie kódu, ktorý nevidíš. Pri každom tvrdení uveď súbor a funkciu (prípadne riadok), aby sa dalo overiť.

KONTEXT
- Účel: šifrovacie jadro pre aplikácie s citlivými osobnými údajmi (Rust: regino-keys, regino-vault; TypeScript: @regino/crypto). Rieši: kľúč z hesla (Argon2id), zabalenie kľúčov a zapečatenie dát (XChaCha20-Poly1305 / AES-256-GCM s kontextom v AAD), šifrované zálohy (verzie 1–3; v3 so 16-znakovým záložným kódom a Argon2id v hlavičke), kúsky záloh adresované obsahom, kód obnovy 12/24 slov, Shamir 2 z 3, kľúč zariadenia (Windows Hello / passkey PRF → HKDF), synchronizácia medzi zariadeniami (ECDH P-256), schránka (inbox) pre ľudí bez účtu, podpisy Ed25519 a podpísané zoznamy členov, lokálna databáza SQLCipher s kľúčom v úložisku OS.
- Hrozby (podrobne AUDIT.md § 2 a docs/): ukradnutý súbor zálohy alebo databázy (offline útok), server alebo úložisko, ktoré je zvedavé alebo podvrhuje (podvrhnuté kľúče, zoznamy členov, staré stavy), odobratý správca, poškodené alebo upravené dáta. Čerstvosť, poradie a ochrana proti prehratiu sú podľa návrhu úlohou aplikácie (AUDIT.md § 3.3) – posúď, či je táto deľba jasná a bezpečná.
- Použitie v produktoch (len opis): Žiačik (kópia TS balíka v client/regino-crypto) šifruje zálohy portfólia učiteľa zálohou verzie 3 so 16-znakovým kódom; Vedino a ďalšie produkty regino používajú knižnicu na šifrovanie záloh a portfólia; Dôverník (zdravotné údaje) zostáva pri kóde zo slov; Gazda používa synchronizáciu a PIN. **Formáty sa nesmú meniť** – existujúce zálohy, kódy, zabalené kľúče a podpisy musia ostať čitateľné. Odporúčania, ktoré menia formát, preto navrhuj ako novú verziu formátu s migráciou, nie ako zmenu existujúcej.
- Predchádzajúce posudky a ich nálezy sú v AUDIT.md § 4 – neopakuj opravené veci, ale ak oprava nestačí, povedz to.
- Testovacie vektory (JSON) a zoznamy slov sú vynechané, sú len vymenované na konci.

ČO CHCEME (dodrž štruktúru a nadpisy):
(a) Správnosť použitia primitív: algoritmy, nonce a IV (dĺžky, náhodné vs. odvodené, limity počtu správ pod jedným kľúčom), KDF a parametre (Argon2id, HKDF – salt/info, oddelenie domén), autentifikácia (čo všetko je v AAD, čo nie), porovnanie v konštantnom čase, zdroje náhodnosti, mazanie kľúčov z pamäte, rozdiely medzi Rust a TS.
(b) Formát a verzovanie: hlavičky a verzie (RGW1, RGS1, RGC1, RGB1, zálohy v1–v3, sync wrap v1/v2…), spätná kompatibilita, útoky znížením verzie (downgrade), rotácia kľúčov, migrácia.
(c) API: dá sa ľahko použiť správne a ťažko zle? Nebezpečné predvolené hodnoty, voliteľné kontroly, ktoré by mali byť povinné, chybové hlásenia (orákulá), typy.
(d) Testy: testovacie vektory, negatívne prípady, fuzzing, property testy, krížová zhoda Rust↔TS, čo chýba.
(e) Závislosti a dodávateľský reťazec: verzie, pripnutie, CI, release, SBOM, nástroj open-backup.html.
(f) Konkrétne zraniteľnosti alebo slabé miesta – tabuľka: ID, závažnosť (kritická / vysoká / stredná / nízka), súbor a funkcia, popis, scenár útoku, návrh opravy. Závažnosť hodnoť realisticky podľa hrozieb vyššie; neuvádzaj teoretické veci ako vysoké.
(g) 10 odporúčaní zoradených od najdôležitejšieho, každé jednou-dvomi vetami, s odkazom na nález z (f), ak súvisí.

ZDROJOVÝ KÓD, TESTY A DOKUMENTÁCIA NASLEDUJÚ.
```

## Odpoveď modelu (doslovne)

# Nezávislý kritický posudok – regino-crypto 0.15.1 (commit 37beca2)

**Čo som mal k dispozícii a čo nie:** kompletné zdrojové súbory `keys/`, `vault/`, `ts/src/`, testy, CI, dokumentáciu. **Nemal som:** obsah testovacích vektorov JSON (`testvectors/**` sú len vymenované), `Cargo.lock`, `ts/package-lock.json`, zoznamy slov, `audits/2026-*.md` v plnom znení, zostavený `tools/open-backup.html` a zdrojové kódy tretích strán (blahaj, rusqlite, noble). Tam, kde tvrdím niečo o nich, píšem výslovne, že ide o odhad. Keďže nedostal som čísla riadkov, odkazujem na `súbor::funkcia`.

---

## (a) Správnosť použitia primitív

**Nonce a IV, limity počtu správ pod jedným kľúčom**
- XChaCha20-Poly1305 v `keys/src/wrap.rs` (`encrypt`) a `keys/src/chunks.rs` (`seal_chunk`) používa náhodný 192-bitový nonce – pri náhodnom 192-bitovom nonce je kolízny strop nepraktický. Bez nálezu.
- AES-256-GCM so 96-bitovým náhodným IV používajú: zálohy (`ts/src/backup.ts` – každá záloha má vlastný náhodný salt, teda vlastný kľúč, OK), inbox správy (každá správa má čerstvý эфемerný ECDH kľúč, OK), zabalené skupinové kľúče (`ts/src/sync.ts::wrapForDevice` – эфемerný kľúč, OK), zálohové chunky (`ts/src/backupChunks.ts::sealBackupChunk` – **jeden `enc` kľúč na všetky chunky jedného používateľa**, náhodné 96-bitové noncy; kolízia pri ~2^48 chunkov, realisticky nedosiahnuteľné, nízky riziko).
- **Skutočný problém:** `ts/src/sync.ts::recordKey` odvodí **jediný AES-GCM kľúč z group key** (`info: "sync records v1"`, salt 32 nulových bajtov) a všetky zariadenia skupiny pečatia záznamy (`sealRecord`) pod tým istým kľúčom s nezávislými náhodnými 96-bitovými IV. Žiadny limit počtu správ ani rotácia v kóde nie je (AUDIT.md otázka 13 to priznáva). Kolízia dvoch noncov pod jedným GCM kľúčom = odhalenie autentizačného podkľúča H + možnosť falšovania. Pri 2^48 správach pravdepodobnosť ~2^-1; pri realistickom household use je nízka, ale knižnica slúži aj praxiam s mnohými zariadeniami a rokmi prevádzky, a kód to nijako nebrzdí. Viď RC-02.
- `gcmNonce` (`ts/src/ecdh.ts`) striktne vyžaduje 12 bajtov – OK.

**KDF a parametre**
- Argon2id: Rust `keys/src/kdf.rs::KdfParams::is_valid` (19–128 MiB, t 2–8, p 1–4, m·t ≤ 256 MiB) kontrolované **pred** prácou; TS ekvivalent `ts/src/backupCode.ts::validBackupCodeKdf`. Hranica z hlavičky zálohy v3 je teda ošetrená. Bez nálezu voči DoS cez parametre – ale viď RC-06 (128 MiB v WebView).
- TS používa `@noble/hashes` Argon2id v čistom JS – **nie je konštantno-časový** (data-dependent prístupy do pamäte). V prehliadači sú cache-timing kanály väčšinou mitigované site isolation, ale nie formálne garantované; pre heslo v prehliadači je to bežná prax. Nízke riziko, vedomé.
- HKDF bez saltu (prípadne prázdny salt): `recovery.rs::recovery_key`, `device.rs::device_key`, `ts/src/recovery.ts::recoveryKey`, `ts/src/backupChunks.ts::backupChunkKeys`, `keys/src/backup_chunks.rs::derive` (`Hkdf::new(Some(&[]), …)`). IKM je uniformne náhodný 128/256-bitový secret alebo výstup Argon2id – prípad RFC 5869 §3.1, kde salt nie je povinný; `info` oddeľuje domény. **Rust↔TS ekvivalencia** `None` salt (Rust) vs prázdny salt (WebCrypto) je korektná, lebo HMAC oba prípady doplní nulami na blok – a vektory (`recoveryKey`, `backup-code-0.15.0.json`) to potvrdzujú. Bez nálezu, ale tieto vektory som nevidel – záver stojí na tvrdení dokumentácie + testoch, ktoré som videl.
- `backupCodeId` a chunk kľúče používajú **fixný salt aplikácie + fixné parametre** (`keys/src/backup_code.rs::base`, `app_salt`; `ts/src/backupCode.ts::backupCodeBase`) – to znamená, že ukradnutá serverová DB id umožňuje offline multi-target útoky za fixnú cenu Argon2id, nezávisle od toho, aké parametre si appka zvolila pre zálohy (AUDIT.md q20 to priznáva). Viď RC-10.
- `keys/src/device.rs::device_key` – HKDF z Windows Hello podpisu **fixného challenge** (deterministický PKCS#1 v1.5 podpis = statický bearer token vrámci session); prijateľné, lebo malware v odomknutej session je mimo modelu, ale dokumentácia by mala byť jasnejšia, že podpis fixného challenge je ekvivalent hesla, nie čerstvého tajomstva.

**Autentifikácia (čo je v AAD)**
- Rust: AAD = `magic ‖ context` (`wrap.rs::aad`, `chunks.rs::aad` – chunk navyše `index u64 BE ‖ last`, čo je správne STREAM-viazanie). TS: `sync record v1|ctx`, `sync wrap v2|ctx` (v info aj AAD), `inbox message v1|ctx`, `RGB1|app|name`, hlavička zálohy (format, version, createdAt, prípadne secret-kind, KDF parametre, digest chunk zoznamu) – všetko citlivé hlavičkové je v AAD. Bez nálezu.
- **Gap:** contexty v Rust sú surové bajty (`wrap.rs::encrypt/decrypt`, `chunks.rs::seal_chunk/open_chunk`) – prázdny context je odmietnutý, ale **žiadna kontrola separátora/znakov**; AUDIT.md §3.2 kladie pravidlá na appku. Chýba core-helper `context(fields)` odmietajúci separátor v poliach. Viď RC-13.
- Inbox AAD neviaže identitu odosielateľa – to je dizajnové (anonýmny odosielateľ), OK.

**Porovnanie v konštantnom čase**
- Rust: `subtle::ConstantTimeEq` pre fingerprint Shamir (`shamir.rs::combine`), `Key::eq` (`lib.rs`). TS: `equalBytes` (`ts/src/bytes.ts`) pre checksum, PIN hash, manifest hash, HMAC chunk name cez `crypto.subtle.verify`. AEAD tagy vo vnútri RustCrypto/WebCrypto. Bez nálezu.
- **Výnimka:** Shamir nad GF(256) cez blahaj používa log/exp tabuľky – **nie je konštantno-časový**; operácia je lokálna a jednorazová (AUDIT.md q6). Viď RC-11.

**Zdroje náhodnosti** – `getrandom` (Rust), `crypto.getRandomValues` (TS). Bez nálezu.

**Masanie kľúčov z pamäte**
- Rust: `Key` = `Box<Zeroizing<[u8;32]>>` (`keys/src/lib.rs`), zeroize featury na AEAD/Argon2id crates (test `keys/tests/audit_0_15_1.rs::n5_key_in_one_place_and_zeroize_features`). TS: nemožné spoľahlivo – dokumentácia to priznáva.
- **Zvyšok:** `PRAGMA key` reťazec prechádza C-kópiou v rusqlite (nie je premazaný) – `vault/src/lib.rs::key_pragma` – priznané v AUDIT.md; prijateľné pri FDE, inak reziduum v pamäti procesu. blahaj neprepisuje svoje polynómy (`shamir.rs::combine` komentár) – prijaté.

**Rozdiely Rust↔TS** – okrem vyššie uvedených: `recordKey` existuje len v TS (sync je TS-only) – žiadny Rust protistran nie je potrebný. Poradie kontrol v `open_manifest`/`openManifest` je po 0.15.1 zhodné (podpis pred bodovými kontrolami členov). Ne našiel som rozdiel, ktorý by menil verdicty; opieram sa o spoločné vektory, ktorých obsah som však nevidel.

---

## (b) Formát a verzovanie

- Magic `RGW1/RGS1/RGC1/RGB1/RGK1/RGN-SIG1` fixujú verziu v hlavičke; `SealedRecord.v`, `WrappedGroupKey.v` (1/2), `InboxMessage.v`, verzia zálohy (1–3) sú striktne kontrolované (`sync.ts::unwrapForDevice`, `backup.ts::decryptBackup` – `newer-version` vs `not-backup` rozlíšené správne). Downgrade testy sú prítomné (v3→v1 relabel zlyhá cez AAD, v2→v1 zlyhá, wrap v2→v1 zlyhá). Bez nálezu.
- `sync wrap v1` sa stále číta (`sync.ts::unwrapForDevice`) – to nie je downgrade-zraniteľnosť, lebo v1 blob môže vytvoriť len skutočný vlastník kľúča; prijateľné pre kompatibilitu.
- **Čo vo formátoch chýba:** žiadny formát (RGS1, RGW1, sync record, inbox, chunk, záloha) neobsahuje **žiadnu čerstvosť** – žiadne seq/epoch/prev-hash v AAD. Starý autentický blob sa otvorí vždy. Toto je najväčšia dizajnová medzera jadra – viď RC-01. Rozdelenie „čerstvosť je úloha appky" (AUDIT.md §3.3, hlavička `sync.ts`) je **dokumentačne jasné, ale bezpečnostne krehké**: jadro neurobí bezpečnú vec ťažkou, každá appka si musí vymyslieť prev-hash reťaz, high-water mark, epoch a tombstones sama, a `SealedRecord`/`WrappedGroupKey` na to nemajú ani políčka.
- Forky zoznamov členov jadro nezistí (rovnaká verzia, dva podpisy) – `keys/src/sign.rs::verify_manifest` prijme prvý; detekcia je len cez `manifest_fingerprint` mimo kanála. Viď RC-08.
- Rotácia: `keystore::rekey` + `finish_rekey` (`vault/src/keystore.rs`) je precízne ošetrená (pending entry, `WrongKey` len pre NOTADB, `RekeyIncomplete`). Pre zálohy žiadna epocha – dizajnové rozhodnutie (q16), prijateľné s `discard_backups_before`.
- `Manifest::next` (`keys/src/sign.rs`): `version: prev.manifest.version + 1` – pri `version == MAX_VERSION` (2^53−1) ide v debug o panic, v release o wrap (následne zachytené v `message()`). Viď RC-12.
- `vault/src/backups.rs::sync_dir` – na Windows sa adresár nefsyncuje (`#[cfg(not(unix))] let _ = dir;`) – pri výpadku prúdu môže zmiznúť adresárový záznam po rename. Nízke, poznámka.
- Migračná prax (fixné vektory starých verzií, `keys/tests/compat_0_11_1.rs`) je dobrá; nevidel som vektor pre každý formát od 0.1.0, ale pokrytie (0.1.0 záloha, 0.6.0 ecdh/inbox, 0.8.0 sync) vyzerá rozumne.

---

## (c) API

- `decryptBackup` vracia diskrétne chyby (`not-backup`/`newer-version`/`wrong-key-or-damaged`) – žiadny orákul na kľúč. `parseBackupCode`, `wordsToSecret` hlásia pozície – OK, nie sú tajné.
- `encryptBackup(secret, payload, createdAt, app, chunks?, options?)` – `app` povinné (dobré); `chunks` aplikácia musí najprv zapísať chunky, inak záloha odkazuje na chýbajúce – dostupnosť, dokument.
- **Opt-in bezpečnostné prepínače sú predvolene vypnuté:** `decryptBackup(…, { maxKdf })` (RC-06), `requireAnchorOnLatest` / `confirmations` (`ts/src/signing.ts::verifyManifestChainFromAnchor`, `keys/src/sign.rs::ChainOptions`), `requireCurrentEpoch` (`openSignedWrap`, `WrapOptions`). 0.15.1 opravy S1/S2 teda **pre existujúce appky nič nemenia, kým ich appka nezapne** – viď RC-07.
- `openSignedWrap` má 8 pozičných parametrov – ľahko sa popletú (`list` vs `anchors`); odporúčam options-object. Nízke.
- TS nemá nominálne typy kľúčov (na rozdiel od Rustu, kde `regino_keys::Key` ≠ `regino_vault::Key`): akýkoľvek 32-bajtový `Uint8Array` prejde ako signing seed (`signing.ts::signData`) alebo group key (`sync.ts`) – zámena je možná chybou appky. Viď RC-14.
- Žiadna API-levelná prekážka nezabráni appke zašifrovať špeciálne kategórie dát (GDPR art. 9) 16-znakovým kódom – `encryptBackup` prijme `code16` secret pre akýkoľvek payload. Dokumentácia (README) to odporúča, kód to nevynucuje. Viď RC-09.
- `sealRecord` robí `JSON.stringify(payload)` – ne-JSON hodnoty sa ticho zahodia; appka to musí vedieť.
- `keystore::init_platform_store` je `cfg(windows)` – na iných OS musí appka nastaviť store sama; ak nie, `load_or_create_key` zlyhá – dokumentačná medzera, nízke.

---

## (d) Testy

Prítomné a silné: fixné cross-language vektory (signing, backup-code, recovery-en, chunks, compat 0.11.1), Wycheproof v TS (AES-GCM, HKDF, ECDH, Ed25519) a v Rust (XChaCha, HKDF, Ed25519), negatívne prípady takmer všade, testy súbežného prístupu k vaultu, test `git diff` pre tool.

**Čo chýba:**
- **Žiadny fuzzing** parserov, ktoré čítajú serverom riadené vstupy: `sign.rs::open_manifest`/`Reader`, `signing.ts::openManifest`/`Reader`, `backup.ts::decryptBackup` (hlavička), `backupCode.ts::parseBackupCode`, `recovery.ts::parseRecoveryQr`/`wordsToSecret`, `wrap.rs::decrypt`, `shamir.rs::combine`. Odporúčam cargo-fuzz + JS fuzz (napr. jsfuzz) – najmä kvôli RC-03.
- **Rust coverage sa nemeria** (priznané v AUDIT.md §5) – pri 100 % v TS to vytvára nerovnováhu dôvery.
- Wycheproof AES-256-GCM chýba na **Rust** strane, hoci `aes-gcm` používame v `backup_chunks.rs` (v TS je). Doplniť.
- Chýbajú testy na veľkosť vstupu (RC-03): obrovský manifest blob / obrovský `ciphertext` v zálohe.
- Žiadne property testy (náhodné kontexty round-trip, idempotencia kanonického prekódovania mimo fixných vektorov).
- Testy `keystore` bežia len na mock store – reálne Windows Credential Manager nie je testovateľné v CI, to je pochopiteľné, ale znamená to, že ostrý kód `windows-native-keyring-store` je netestovaný.
- **Nepotvrditeľné mnou:** obsah vektorových JSON som nevidel, takže tvrdenie „všetky staré vektory prechádzajú" beriem na vieru z testov, ktoré som videl.

---

## (e) Závislosti a dodávateľský reťazec

- Rust: verzie bez wildcardov (`deny.toml` `wildcards = "deny"`), `Cargo.lock` commitnutý, CI `--locked`, cargo-deny s RustSec/yanked/licenciami/crates.io-only; TS: všetky runtime závislosti presne pripnuté + test (`audit0151.test.ts::N6`). CI actions pripnuté na SHA, read-only token, release build read-only + upload write, SBOM (CycloneDX) + SHA256SUMS. Dependabot týždenne. `tools/open-backup.html` sa rebuildne a CI failne na `git diff`. Toto všetko je na úrovni – **bez nálezu v mekanizme**.
- **Medzery:** `npm audit --audit-level=moderate` (`.github/workflows/ci.yml`) – nízke nálezy nepadnú; cargo-deny `unmaintained` je predvolene warn; pri release sa `cargo install cargo-cyclonedx --version 0.5.9 --locked` (`release.yml`) sťahuje z crates.io bez overenia kontrolného súčtu (na rozdiel od cargo-deny v CI, kde SHA256 je). Viď RC-18.
- `rusqlite 0.42` s bundled SQLCipher + **vendored OpenSSL** – veľká C plocha; aktualizované v 0.13.4 kvôli CVE. Parser SQLite beží na zašifrovanom súbore, takže útočník bez kľúča nemôže vyrobiť platné stránky – expozícia je obmedzená na držiteľov kľúča. Prijateľné, držať aktualizované.
- `blahaj 0.7` – málo známy crate; jeho zdroj (GF tabuľky, share layout) je malý a q6 ho popisuje, ale formálny audit tretej strany chýba.
- `keyring-core` + `windows-native-keyring-store` – Windows-only; na iné OS žiadny fallback v knižnici (viď (c)).

---

## (f) Konkrétne zraniteľnosti a slabé miesta

| ID | závažnosť | súbor::funkcia | popis | scenár útoku | návrh opravy |
|---|---|---|---|---|---|
| RC-01 | stredná | `ts/src/sync.ts::sealRecord/openRecord`, `keys/src/wrap.rs::seal/open`, `ts/src/inbox.ts`, `ts/src/backupChunks.ts`, `ts/src/backup.ts` (všetky formáty) | Žiadny formát neobsahuje čerstvosť (verzia/poradie/prev-hash/epocha v AAD). Starý autentický blob sa vždy otvorí. Rozdelenie „appka to rieši" (AUDIT.md §3.3) je dokumentačne jasné, ale jadro to nerobí ľahkým. | Sync server alebo úložisko vráti starší autentický `SealedRecord`/wrapped key/zálohu → appka vidí starý stav, vzkriesi zmazaný záznam, „zrotuje" späť do starého kľúča. | Nová verzia formátu (napr. `RGS2`, sync record v2) s voliteľným envelope: `seq ‖ epoch ‖ prev-hash` v AAD + pomocník na tombstones; migrácia cez staré vektory. |
| RC-02 | stredná | `ts/src/sync.ts::recordKey` + `sealRecord` | Jediný AES-256-GCM kľúč pre všetky zariadenia skupiny, náhodné 96-bitové IV, žiadny limit počtu správ ani per-device kľúč. | Kolízia dvoch noncov (cca 2^48 správ) pod jedným GCM kľúčom → odhalenie H, falšovanie záznamov, dešifrovanie. Pre domácnosť nízka pravdepodobnosť, pre prax s mnohými zariadeniami a rokmi nie zanedbateľná; kód to nebrzdí. | Per-device record key (HKDF info + device id) alebo XChaCha20-Poly1305 (192-bit nonce) ako nová verzia `SealedRecord`; prípadne tvrdý limit počtu záznamov na skupinu vynútený v kóde. |
| RC-03 | stredná | `keys/src/sign.rs::open_manifest`/`decode_manifest_unchecked`/`Reader`; `ts/src/signing.ts::openManifest`/`Reader`; `ts/src/backup.ts::decryptBackup` (`unb64(f.ciphertext)`) | Serverom dodaný blob sa parsuje (alokácie podľa veľkosti blobu, až 1000 členov) **pred** overením podpisu; žiadny limit veľkosti blobu. To isté pri `ciphertext` zálohy. | Zlomyseľný server pošle appke multi-GB manifest blob alebo zálohu → OOM/DoS predtým, než sa podpis vôbec skontroluje. Legitímny manifest má max ~2 MB (MAX_MEMBERS × limity polí). | Horný limit veľkosti na vstupe (`open_manifest` napr. 4 MB; zálohu podľa appky); podpis overiť najprv z skorých polí (signer je skoro v hlavičke), až potom plný parse. |
| RC-04 | stredná | `vault/src/lib.rs::Vault::open` | `cipher_memory_security` je OFF (VirtualLock error 1453 na Windows). Dešifrované stránky SQLite môžu ísť do pagefile/voľnej pamäte v plaintexte. | Disk image vrátane swapu (bez FDE) obsahuje dešifrované riadky DB. FDE to zakryje (BitLocker šifruje aj pagefile), ale jadro to nevynucuje. | Skúsiť zapnúť s navýšeným working set procesu (SetProcessWorkingSetSize pred VirtualLock), inak FDE urobiť **povinnou podmienkou** v API dokumentácii, nie len odporúčaním. |
| RC-05 | stredná | `ts/src/inbox.ts::sealToInbox`/`inboxFingerprint`, `docs/INBOX.md`, AUDIT.md q14 | Jadro nedokáže odhaliť, že server podsunul odosielateľovi vlastný P-256 kľúč (prax vidí svoje správne, odosielateľ dostane iné). Ochrana odosielateľa je len mimo kanála cez fingerprint. | MITM na publikovanom inbox kľúči pri vyplňovaní formulára so zdravotnými údajmi (Dôverník): server prečíta správu a prepečiatí ju praxi. | Podpísaný inbox public key (Ed25519 cert cez existujúci `signed.ts`) ako `inbox v2`; pinovanie predošlého kľúča; SRI/oddelený origin už sú, ale nestačia. |
| RC-06 | stredná | `ts/src/backup.ts::decryptBackup` + `backupCode.ts::MAX_BACKUP_CODE_KDF` | Pri čítaní v3 zálohy je predvolený horný limit 128 MiB / m·t 256 MiB (4× default). `MOBILE_BACKUP_CODE_KDF` existuje, ale je opt-in. | Plantnutý súbor zálohy (napr. e-mailom) spustí v telefóne/WebView Argon2id s 128 MiB pamäte → pád/OOM stránky. Dostupnosť, nie únik dát. | Predvolený čítací limit nastaviť na mobilnú hodnotu (64 MiB, m·t ≤ 128 MiB); vyšší limit len explicitným opt-in na desktope. |
| RC-07 | nízka–stredná | `keys/src/sign.rs::ChainOptions::require_anchor_on_latest`, `WrapOptions::require_current_epoch`; `ts/src/signing.ts` ekvivalenty | Opravy S1 (odstránený admin pokračuje staršou verziou reťaze) a S2 (starší epoch podaný ako aktuálny) sú **vypnuté predvolene** – default = správanie 0.15.0. | Appka, ktorá nezapne `requireAnchorOnLatest`/`requireCurrentEpoch`, je stále zraniteľná na scenáre S1/S2 (server + odstránený admin). | V appkách (Dôverník) zapnúť oba prepínače; migračný plán, ktorý ich zapne pri ďalšom core upgrade. |
| RC-08 | nízka | `keys/src/sign.rs::verify_manifest` (forky), `manifest_fingerprint` | Jadro nerozlíši dve rôzne listiny s tou istou verziou; detekcia forku je len cez ručné porovnanie `manifestFingerprint` mimo kanála. | Dvaja admini (alebo odstránený admin + server, čo zadrží novšiu verziu) podpíšu v2 a v2′; členovia sa ticho rozdelia. | Appka musí porovnávať kód listiny s koordinátorom pri každej zmene; zvážiť countersigning členov alebo anchor-podpis každej verzie. |
| RC-09 | nízka | `ts/src/backup.ts::encryptBackup` (prijíma `code16` pre akýkoľvek payload) | 75-bitový kód (s Argon2id) je API dostupný pre akékoľvek dáta; žiadna prekážka nezakáže art. 9 dáta v code-zálohe. Margin je obrovský (q20), takže nejde o prelomenie, ale o nesprávne použitie. | Appka omylom zašifruje zdravotné záznamy 16-znakovým kódom namiesto slov. | Voliteľný povinný parameter klasifikácie (napr. `sensitivity: 'special'` odmietne `code16`) – zmena API, nie formátu; aspoň výrazné varovanie v dokumentácii API. |
| RC-10 | nízka | `keys/src/backup_code.rs::base`/`backup_code_id`/`app_salt`; `ts/src/backupCode.ts::backupCodeBase/backupCodeId` | Fixný salt aplikácie + fixné parametre pre id a chunk kľúče → ukradnutá serverová DB id je offline multi-target orákulum za fixnú cenu; online útoku bráni len serverové rate-limitovanie (mimo jadra). | N ukradnutých id → prvý zásah za 2^74/N pokusov; pri N=10^5 stále obrovské, ale server musí obmedzovať dopyty. | Dokumentácia už varuje; zvážiť server-side pepper alebo keyed id; aspoň exportnú funkciu na rate-limit check (HMAC over id + tajomstvo servera). |
| RC-11 | nízka | `keys/src/shamir.rs::combine`/`split` (cez blahaj) | GF(256) log/exp tabuľky nie sú konštantno-časové; blahaj neprepisuje svoje buffre (prebrané v `Zeroizing`). | Lokálny timingový kanál pri kombinovaní sharetov – vyžaduje lokálne pozorovanie; mimo modelu hrozieb, uvádzam pre úplnosť. | Akceptovať (lokálna operácia) alebo CT implementácia; aspoň preblahaj source raz formálne prejsť. |
| RC-12 | nízka | `keys/src/sign.rs::Manifest::next` | `version + 1` pri `MAX_VERSION` → panic v debug, wrap v release (následne zachytené). | Appka na debug builde môže panicnúť na edge-case; v release s overflow-checks tiež. | `checked_add` → `Error::Format`. |
| RC-13 | nízka | `keys/src/wrap.rs::encrypt/decrypt`, `keys/src/chunks.rs::seal_chunk/open_chunk` (context ako `&[u8]`) | Context je surový reťazec bajtov; jadro nekontroluje separátor ani dĺžku polí – pravidlá §3.2 sú len na appke. | Chyba appky (id obsahujúce `/`) môže vytvoriť rovnaký context pre dva rôzne objekty → cross-object zámena. | Core-helper `context(&["app","client",id])` odmietajúci separátor/prázdne polia (nové API, žiadna zmena formátu). |
| RC-14 | nízka | `ts/src/signing.ts::signData`, `ts/src/sync.ts::newGroupKey/recordKey` | V TS sú všetky kľúče/seedy obyčajné `Uint8Array` – žiadne nominálne typy (Rust ich má). | zámena 32-bajtového poľa (napr. seed vs group key) chybou appky prejde kompiláciou. | Branded typy (`type Seed = Uint8Array & {…}`) pre verejné API. |
| RC-15 | nízka | `ts/src/backupChunks.ts::backupChunkName`; `keys/src/backup_chunks.rs::name` | Meno chunku = HMAC obsahu pod kľúčom používateľa → vrámci jedného používateľa odhaľuje rovnosť obsahu medzi zálohami (dedup metadáta). | Server vidí mená chunkov jedného používateľa – vie, ktoré prílohy sa opakujú; obsah nie. Vedomé (q v 0.11.0), dokument. | Akceptovať pre dedup; upozorniť, že ide o metadátový kanál vrámci používateľa. |
| RC-16 | nízka | `ts/src/recovery.ts` + `wordlist-en.ts` (q19) | Anglické slová = platný BIP-39 mnemonic; používateľ si môže kód pomýliť s wallet seedom (naopak wallet seed v appke „nič neotvorí"). | Zámiena pri obnove; strata prostriedkov, ak niekto pošle na adresu odvodenú z regino kódu. | Jasné UI varovanie pri anglickom kóde; dokumentácia už q19 pokrýva. |
| RC-17 | nízka | testy (pozri (d)) | Žiadny fuzzing parserov serverových vstupov; Rust coverage nemeraná; Wycheproof AES-GCM chýba na Rust strane; žiadne testy veľkosti vstupov. | Neznáme parsovacie bugy v `open_manifest`/`decryptBackup`/`parseBackupCode`. | cargo-fuzz/JS fuzz; Rust coverage v CI; Wycheproof AES-GCM pre `backup_chunks.rs`; DoS-size testy. |
| RC-18 | nízka | `.github/workflows/ci.yml`, `release.yml`, `deny.toml` | `npm audit --audit-level=moderate` (low nepadne); cargo-deny unmaintained = warn; `cargo install cargo-cyclonedx` pri release bez checksumu; release tagy nie sú viditeľne podpísané. | Nízke advisories alebo unmaintained kľúčových crate prejdú CI. | audit-level=low; unmaintained deny pre produkčné crates; checksum pre SBOM tool; podpísané tagy. |

---

## (g) 10 odporúčaní (od najdôležitejšieho)

1. **Pridať voliteľný freshness envelope ako novú verziu formátu** (`RGS2`, sync record v2: `seq ‖ epoch ‖ prev-hash` v AAD) plus pomocník na tombstones – kým nebude v jadre, replay/rollback závisí od disciplíny každej appky (RC-01).
2. **Zmeniť sync záznamy na per-device kľúče alebo XChaCha20-Poly1305** (nová verzia `SealedRecord`) a/alebo vynútiť tvrdý limit počtu záznamov na skupinu – jedna GCM kľúča pre všetky zariadenia je najväčšia kryptografická slabina v jadre (RC-02).
3. **Limitovať veľkosť serverom dodaných blobov pred parsovaním a overiť podpis skôr** – cap ~4 MB pre manifesty, limit pre `ciphertext` zálohy; zabráni to OOM cez falošný server (RC-03).
4. **Predvolený čítací limit Argon2id pre v3 zálohy nastaviť na mobilnú hodnotu** (64 MiB, m·t ≤ 128 MiB); vyšší len explicitným opt-in na desktope (RC-06).
5. **Zaviesť podpísaný inbox public key** (Ed25519 cert cez `signed.ts`) ako inbox v2 s pinovaním predošlého kľúča – dnes odosielateľa chráni len mimo-kanálový fingerprint (RC-05).
6. **Vyriešiť `cipher_memory_security`**: buď zapnúť s navýšeným working set, alebo FDE urobiť povinnou, nie odporúčanou podmienkou pre DB kľúč (RC-04).
7. **V appkách zapnúť `requireAnchorOnLatest` a `requireCurrentEpoch`** a pri každej zmene listiny porovnávať `manifestFingerprint` s koordinátorom – inak S1/S2 a forky ostávajú otvorené (RC-07, RC-08).
8. **Doplniť fuzzing parserov, meranie Rust coverage a Wycheproof AES-GCM na Rust strane**, plus DoS-size testy (RC-17, RC-03).
9. **Pridať core-helper na contexty odmietajúci separátor v poliach a voliteľný policy flag, ktorý odmietne `code16` pre špeciálne kategórie dát** – čisto API, žiadna zmena formátu (RC-13, RC-09).
10. **Sprísniť CI/release**: `npm audit` aj na low, `unmaintained = deny` pre produkčné crates, kontrolný súčet pre SBOM tool, podpísané release tagy (RC-18, RC-10 dokumentácia serverového rate-limitu pre `backupCodeId`).

**Celkový záver:** jadro používa osvedčené primitívy správne na úrovni jednotlivých volaní (AEAD, KDF hranice, konštantné porovnania, pinované závislosti, silné vektory). Slabé miesta sú na úrovni **protokolu a API**: žiadna čerstvosť vo formátoch, zdieľaný GCM kľúč pre sync, parsovanie serverových vstupov pred overením, opt-in bezpečnostné prepínače a mobile-DoS cez hlavičku zálohy.

---

## Vlastné stanovisko (overené v kóde, commit `37beca2`)

**Zhrnutie:** ani Mistral nenašiel nič, čo by bez kódu alebo kľúča otvorilo zálohu, portfólio či iné dáta. Po overení nie je žiadny nález kritický ani vysoký, takže Centrále netreba nič hlásiť mimo tohto dokumentu. Väčšina jeho nálezov sú známe a zdokumentované rozhodnutia (AUDIT.md § 3.3, otázky 6, 11, 13, 14, 20, § 4.5). Dva technické nálezy sú mylné (RC-12, kópia kľúča v rusqlite). Mistral je tu len poradný zdroj, za hlavný sa považuje posudok Argonu.

Označenia: **potvrdené** / **nepotvrdené** / **mylné**, ako pri Argone. Stĺpec „Zdroj“ uvádza, kto tvrdenie priniesol (M = Mistral, A = Argon).

| ID | Zdroj | Model | Verdikt | Overenie | Moja závažnosť |
|---|---|---|---|---|---|
| RC-01 | M | stredná | **potvrdené, zámer** | Žiadny formát nenesie poradie ani čerstvosť. Je to vedomá deľba úloh (AUDIT.md § 3.3, hlavička `ts/src/sync.ts`, README). Pomocník v jadre (nová verzia formátu) by aplikáciám pomohol, nie je to však chyba. | nízka (návrhové) |
| RC-02 | M (A: (a)3) | stredná | **potvrdené (fakt), závažnosť prehnaná** | `ts/src/sync.ts` `recordKey`: jeden kľúč AES-GCM pre celú skupinu, náhodný 96-bitový nonce. Výpočet (≈ 2⁴⁸ záznamov na kolíziu s pravdepodobnosťou ~½) sedí, odporúčaná hranica je 2³² záznamov. Ani tá nie je pri synchronizácii jednej skupiny (Gazda) reálna. Tvrdenie, že ide o „najväčšiu kryptografickú slabinu“, je prehnané. Stačí zapísať limit do dokumentácie. | nízka |
| RC-03 | M | stredná | **čiastočne potvrdené** | `keys/src/sign.rs` `open_manifest` a `ts/src/signing.ts` `openManifest` nemajú strop veľkosti celého blobu a štruktúru čítajú pred overením podpisu. Od 0.15.1 sa však pred podpisom neoverujú body kľúčov členov. Počet členov je obmedzený (`MAX_MEMBERS` = 1000) a polia sú obmedzené dĺžkou blobu. Pamäť je teda rádovo veľkosť blobu, ktorý už aplikácia stiahla a drží. „OOM pred overením podpisu“ je pravdivé len v tom zmysle, že obrovský vstup stojí obrovskú pamäť. Strop (napr. 4 MB) je lacné spevnenie. To isté platí pre `ciphertext` zálohy, ktorú si používateľ sám vyberie. | nízka (dostupnosť) |
| RC-04 | M | stredná | **potvrdené, zdokumentované** | `cipher_memory_security` je vypnuté (`vault/src/lib.rs` r. 124, AUDIT.md otázky 7, 11, 12) a odporúčané je šifrovanie celého disku. Nové nie je nič. Návrh „vynútiť šifrovanie disku v API“ jadro technicky nevie overiť. | nízka |
| RC-05 | M | stredná | **potvrdené, zdokumentované** | Podvrhnutý kľúč schránky (inbox) serverom: AUDIT.md otázka 14 a `audits/2026-10-pre-audit-review.md` bod 2 (riešené v aplikácii Dôverník). Podpísaný kľúč schránky ako inbox v2 je rozumný návrh do budúcna. Regino-crypto sám schránku nepoužíva na zálohy ani portfóliá. | nízka (pre tento posudok) |
| RC-06 | M | stredná | **potvrdené, zdokumentované** | `decryptBackup` bez `maxKdf` povolí až 128 MiB (`MAX_BACKUP_CODE_KDF`), mobilná hranica je voliteľná (AUDIT.md § 4.5 N7). Podvrhnutý súbor nič neotvorí, nanajvýš zhodí stránku v slabom WebView. **Odporúčanie pre Žiačik:** na telefóne volať `decryptBackup(…, { maxKdf: MOBILE_BACKUP_CODE_KDF })`. To je vec aplikácie, nie jadra. | nízka (dostupnosť) |
| RC-07 | M (A: F-01) | nízka–stredná | **potvrdené, zámer** | To isté ako Argon F-01 (`requireAnchorOnLatest`, `requireCurrentEpoch` sú vypnuté v predvolenom nastavení). Overenie a stanovisko sú v Argonovom dokumente. | stredná (predvolená hodnota API) |
| RC-08 | M | nízka | **potvrdené, zdokumentované** | Jadro nerozpozná vetvenie (fork) zoznamu bez pinov, AUDIT.md otázka 18 a `docs/SIGNING.md`. | nízka |
| RC-09 | M | nízka | **potvrdené (fakt)** | `encryptBackup` prijme 16-znakový kód pre akékoľvek dáta. Pravidlo „Dôverník zostáva pri slovách“ je len v dokumentácii. Voliteľná kontrola v API by bola spevnenie, nie oprava. | informatívne |
| RC-10 | M (A: F-02) | nízka | **potvrdené, zdokumentované** | To isté ako Argon F-02 (pevná soľ a parametre pre id a kúsky, AUDIT.md otázka 20). | nízka |
| RC-11 | M | nízka | **potvrdené, zdokumentované** | Tabuľky GF(256) v `blahaj` nemajú konštantný čas (AUDIT.md otázka 6). Ide o lokálnu jednorazovú operáciu. | informatívne |
| RC-12 | M | nízka | **mylné** | `Manifest::next` (`keys/src/sign.rs` r. 478) robí `version + 1` nad `u64`. Prijatý zoznam má `version ≤ MAX_VERSION` = 2⁵³ − 1 (r. 491), takže súčet nepretečie a nespanikári. Väčšiu verziu odmietne kontrola pri podpise. Použiť `checked_add` je len kozmetika. | — |
| RC-13 | M | nízka | **potvrdené (fakt)** | `wrap.rs`, `chunks.rs`: kontext je surové bajty, jadro kontroluje len, či nie je prázdny. Pravidlá sú na aplikácii (AUDIT.md § 3.2). Rovnaký návrh dal aj Argon v (c)6. Pomocník na skladanie kontextu je dobrý návrh API. | nízka |
| RC-14 | M | nízka | **potvrdené (fakt)** | V TS sú kľúče obyčajné `Uint8Array`. Značkované typy by pomohli proti zámene kľúčov. | informatívne |
| RC-15 | M | nízka | **potvrdené, zámer** | Názov kúska (HMAC obsahu) prezradí, že sa obsah u jedného používateľa opakuje. Bez toho by nefungovalo zdieľanie kúskov medzi zálohami (0.11.0). | informatívne |
| RC-16 | M | nízka | **potvrdené (fakt), mimo jadra** | Anglický kód je platná BIP-39 mnemotechnika (zámer v 0.14.0, otázka 19). Varovanie patrí do používateľského rozhrania aplikácie. | informatívne |
| RC-17 | M (A: (d)1) | nízka | **potvrdené** | Chýba fuzzing aj meranie pokrytia v Ruste (zhodne s Argonom). **Nové a pravdivé:** `keys/tests/wycheproof.rs` načítava len XChaCha20-Poly1305, HKDF a Ed25519, **chýba Wycheproof AES-GCM**, hoci `keys/src/backup_chunks.rs` AES-256-GCM používa (TS ho testuje vo `wycheproof.test.ts`). Lacné doplnenie. | nízka |
| RC-18 | M (A: (e)2) | nízka | **čiastočne potvrdené** | Potvrdené: `ci.yml` r. 75 `npm audit --audit-level=moderate` (nízke nálezy nezastavia CI); `cargo install cargo-cyclonedx` bez vlastného hašu (cargo však overí kontrolný súčet z indexu crates.io, ako pri Argone). **Nepotvrdené:** že cargo-deny pri neudržiavaných balíkoch len varuje (v `deny.toml` nie je nastavené, správanie závisí od predvolenej hodnoty cargo-deny pre `version = 2`), a podpisy tagov (nedá sa overiť z kódu). | nízka |

### Ostatné tvrdenia Mistralu v (a)–(e)

- (a) „Reťazec `PRAGMA key` prechádza C-kópiou v rusqlite“ (opiera sa o AUDIT.md otázku 7+12): **mylné pre rusqlite 0.42.** `execute_batch` → `prepare` posiela SQLite priamo smerník a dĺžku a nerobí `CString` (`rusqlite-0.42.0/src/inner_connection.rs` r. 189). Text príkazu si však môže pri `sqlite3_prepare_v2` skopírovať samotné SQLite (do pripraveného príkazu, bez mazania), to som nemeral. **Odporúčanie:** opraviť vetu v AUDIT.md (kópiu robí nanajvýš SQLite, nie rusqlite).
- (a) Argon2id v `@noble/hashes` nemá konštantný čas: **z väčšej časti mylné.** Druhá časť Argon2id závisí od dát z princípu algoritmu, nie preto, že je napísaný v JS. Cache-timing útok v prehliadači je mimo modelu hrozieb.
- (a) `device_key`: podpis Windows Hello pevnej výzvy je stále rovnaký, takže funguje ako heslo: **nepotvrdené.** Závisí od toho, ako ho aplikácia získava. Pripomienka k dokumentácii je rozumná.
- (b) `vault/src/backups.rs` `sync_dir` na Windows adresár nesynchronizuje: **potvrdené** (`#[cfg(not(unix))] let _ = dir;`). Po výpadku prúdu sa môže stratiť premenovanie zálohy. Ide o nízke riziko pre dostupnosť.
- (c) `openSignedWrap` má 8 parametrov podľa poradia: **potvrdené** (`ts/src/signing.ts` r. 334). Hrozí zámena, odporúčam objekt s voľbami v novej funkcii.
- (c) `keystore::init_platform_store` existuje len pre Windows: **potvrdené** (`vault/src/keystore.rs` r. 18). Ide o medzeru v dokumentácii pre iné systémy.
- (c) `sealRecord` cez `JSON.stringify` ticho zahodí hodnoty, ktoré nie sú JSON: **potvrdené**, informatívne.
- (d) Testy úložiska kľúčov bežia len proti náhradnému úložisku: **potvrdené**, pochopiteľné.

### Zhoda a rozdiely s Argonom

- **Oba modely sa zhodli:** voliteľné kontroly S1/S2 (F-01 / RC-07), pevná soľ pre id a kúsky (F-02 / RC-10), náhodný nonce pod jedným kľúčom GCM (Argon (a)3 / RC-02), chýbajúci fuzzing a meranie pokrytia v Ruste (Argon (d)1 / RC-17), `cargo-cyclonedx` bez hašu, kontexty bez štruktúry.
- **Len Mistral, a overené ako pravdivé:** chýba Wycheproof AES-GCM v Ruste (RC-17), nie je strop veľkosti manifestu (RC-03), na Windows sa nesynchronizuje adresár záloh, voliteľná mobilná hranica Argon2id pre Žiačik (RC-06), `npm audit` až od úrovne moderate.
- **Len Argon, a overené ako pravdivé:** `signed.ts` bez kontroly torznej zložky (F-03), preskakovanie ručných kópií záloh pri `gc_chunks` (F-04), nepokrytá vetva `RekeyIncomplete`.
- **Mylné:** Mistral RC-12 a kópia v rusqlite; Argon časti F-04, F-06 a F-09 (pozri Argonov dokument).

### 10 odporúčaní Mistralu (g) – moje stanovisko

| # | Odporúčanie | Stanovisko |
|---|---|---|
| 1 | Obálka s poradím a čerstvosťou ako nová verzia formátu | **Neskôr, voliteľne.** Je to zámerne úloha aplikácie. Pomocník v jadre by pomohol Gazde, pre zálohy a portfóliá nie je potrebný. |
| 2 | Kľúče záznamov pre každé zariadenie alebo XChaCha20 pre sync | **Odložiť.** Riziko je pri reálnom objeme zanedbateľné, stačí zapísať limit 2³² do dokumentácie `sealRecord`. |
| 3 | Strop veľkosti blobov pred čítaním | **Súhlas**, je to lacné (manifest napr. 4 MB). Formát sa nemení. |
| 4 | Mobilná hranica Argon2id ako predvolená | **Pre Žiačik áno, v aplikácii** (`maxKdf: MOBILE_BACKUP_CODE_KDF`). Meniť predvolenú hodnotu v jadre radšej nie, desktopové aplikácie čítajú aj väčšie parametre. |
| 5 | Podpísaný kľúč schránky (inbox v2) | **Neskôr**, týka sa Dôverníka, nie záloh. |
| 6 | Vyriešiť `cipher_memory_security` | **Nesúhlas so zapnutím** (padá na Windows, zdokumentované). Ponechať šifrovanie disku ako požiadavku v dokumentácii aplikácií. |
| 7 | V aplikáciách zapnúť `requireAnchorOnLatest` a `requireCurrentEpoch` | **Súhlas**, zhodne s Argonom bod 1. |
| 8 | Fuzzing, pokrytie v Ruste, Wycheproof AES-GCM v Ruste, testy veľkosti | **Súhlas, najvyššia praktická priorita**, Wycheproof AES-GCM je najlacnejší krok. |
| 9 | Pomocník na kontext a príznak citlivosti dát proti `code16` | **Súhlas s pomocníkom na kontext.** Príznak citlivosti len ako voliteľné spevnenie. |
| 10 | Sprísniť CI (`npm audit` aj na nízke nálezy, neudržiavané balíky ako chyba, haš nástroja SBOM, podpísané tagy) | **Čiastočne:** haš a podpísané tagy áno. `npm audit` na úrovni low môže zbytočne blokovať (vývojové závislosti), radšej len pre závislosti behu. |
