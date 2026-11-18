# Posudok regino-crypto modelom Gemini 4 Argon (2026-11-18)

| | |
|---|---|
| Model | `models/gemini-4-argon` (Google Generative Language API, `generateContent`, temperature 1, maxOutputTokens 32 768) |
| Dátum | 2026-11-18 |
| Posudzovaný stav | 0.15.1, commit `37beca2` |
| Podklady | 89 súborov: README, AUDIT.md, SECURITY.md, docs/, celý zdrojový kód Rust a TS, všetky testy, Cargo.toml, package.json, deny.toml, CI. Vynechané (len vymenované): testovacie vektory JSON, zoznamy slov, zámky závislostí, zostavený `tools/open-backup.html`, staršie posudky v `audits/`. Žiadne skutočné kľúče. |
| Tokeny | vstup 229 026, výstup 11 576 (bez samostatne účtovaných tokenov premýšľania) |
| Cena | ≈ **0,57 $** (úvodná cena 2 $ / 10 $ za 1 M tokenov vstup/výstup do 30. 11. 2026 podľa cenníkov tretích strán; pri štandardnej cene 4 $ / 20 $ by to bolo ≈ 1,15 $). Odhad pred spustením: ≈ 0,8 $, strop 1,4 $. |

Odpoveď modelu je nižšie **doslovne**. Pod ňou je vlastné stanovisko: každé tvrdenie o zraniteľnosti overené v kóde.

## Prompt

Za promptom nasledovali podklady (zdrojový kód, testy, dokumentácia) oddelené riadkami `===== SÚBOR: <cesta> =====`.

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

Tu je nezávislý bezpečnostný a kryptografický posudok knižnice `regino-crypto` (v0.15.1, commit `37beca2`).

---

### (a) Správnosť použitia primitív

1. **Absencia kontroly kanonickosti a prítomnosti malého rádu pre verejné kľúče v `signed.ts` (Rozdiel Rust vs. TS)**
   - **Súbor a funkcia:** `ts/src/signed.ts` (`verifySignature`, `verifyToken`, riadky 85–105).
   - **Problém:** Na rozdiel od `ts/src/signing.ts` (`verifyEd25519` a `isSigningPublicKey`), kde sa explicitne kontroluje, či sú verejný kľúč $A$ aj bod podpisu $R$ kanonické, nemajú malý rád a sú bez torzie (`!p.isSmallOrder() && p.isTorsionFree()`), funkcia `verifySignature` v `signed.ts` volá len `@noble/ed25519` `verifyAsync(..., { zip215: false })`. Samotný `noble` s `zip215: false` používa kofaktorové overenie ($[8]S \cdot B = [8]R + [8]k \cdot A$) a nezamieta body s torznou zložkou, ktoré v Ruste `ed25519-dalek` (`verify_strict`) zamieta. Pre koreňové kľúče a certifikáty v `signed.ts` tak chýba obrana proti kľúčom/podpisom s torznou zložkou, čo protirečí tvrdeniu v komentári o „strict RFC 8032 rules“ v zmysle zhody s `dalek`.

2. **Chýbajúce viazanie príjemcu pri `MemberKey` vyhláseniach a potenciálna kolízia `seal` kľúčov v manifeste**
   - **Súbor a funkcia:** `keys/src/sign.rs` (`Manifest::message`, riadky 346–375; `verify_member_key`, riadky 243–264) a `ts/src/signing.ts` (`encodeManifest`, riadky 356–376; `verifyMemberKey`, riadky 400–416).
   - **Problém:** Pri zostavovaní manifestu sa kontroluje unikátnosť `id` a podpisového kľúča `sign`, ale **nekontroluje sa unikátnosť šifrovacieho kľúča `seal`** (ak nie je prázdny). Ak by škodlivý člen zaregistroval svoj `MemberKey` s `seal` kľúčom iného člena (pretože `sign_member_key` podpisuje len `scope`, `member_id`, `version` a `seal`, ale nevyžaduje dôkaz o vlastníctve privátneho kľúča k `seal`, keďže ide o P-256 ECDH kľúč), a koordinátor by to nevedomky zapísal do manifestu, dvaja členovia by mali rovnaký `seal`. Pri volaní `verify_wrap_for_recipient` (`keys/src/sign.rs`, riadok 205) by potom mohlo dôjsť k nejednoznačnosti, pre koho bol kľúč zabalený, hoci `member_id` je špecifikované.

3. **Zdieľaný kľúč pre `backup_chunks` s 96-bitovým náhodným IV bez limitu počtu kúskov**
   - **Súbor a funkcia:** `keys/src/backup_chunks.rs` (`BackupChunkKeys::seal`, riadky 69–81) a `ts/src/backupChunks.ts` (`sealBackupChunk`, riadky 59–68).
   - **Problém:** Šifrovací kľúč `enc` pre kúsky záloh je odvodený deterministicky z obnovovacieho kódu bez soli (`salt = []`, resp. fixný `app_salt` pre 16-znakový kód). Tento istý AES-256-GCM kľúč sa používa počas celej životnosti obnovovacieho kódu pre všetky kúsky. Pri náhodnom 96-bitovom IV je limit bezpečnosti (NIST SP 800-38D, pravdepodobnosť kolízie $2^{-32}$) $2^{32}$ šifrovaní. Hoci je názov kúska deterministický (HMAC obsahu), funkcia `sealBackupChunk` / `BackupChunkKeys::seal` generuje nový náhodný IV pri každom volaní. Ak aplikácia pred zápisom nevolá `has_chunk` alebo ak opakovane šifruje tie isté dáta (napr. v TS pred odoslaním alebo pri poškodení podľa N4), spotrebováva sa priestor IV pod jedným kľúčom. Pre zálohy jednej praxe je $2^{32}$ volaní nedosiahnuteľných, no architektonicky ide o fixný kľúč s náhodným 96-bitovým IV. Podobne v `ts/src/sync.ts` (`recordKey`, `sealRecord`) sa používa jeden kľúč pre celú skupinu a všetky zariadenia; bez vynútenej rotácie pri veľkom počte záznamov a zariadení neexistuje v jadre žiadne počítadlo ani varovanie.

4. **Mazanie citlivých dát z pamäte v Ruste (Shamir a SQLCipher C-reťazec)**
   - **Súbor a funkcia:** `keys/src/shamir.rs` (`split`, `combine`, riadky 29–84) a `vault/src/lib.rs` (`Vault::open`, `rekey`, riadky 95, 198).
   - **Problém:** 
     - V `shamir.rs` funkcia `split` vracia `Vec<Vec<u8>>` namiesto `Vec<Zeroizing<Vec<u8>>>` a `combine` prijíma `&[Vec<u8>]`. Samotné podiely (shares) na kopa (heap) nie sú po použití nulované. Okrem toho závislosť `blahaj` interne nepracuje so `Zeroize` pre koeficienty polynómu (priznané v AUDIT.md, otázka 6).
     - V `vault/src/lib.rs` funkcia `key_pragma` síce vytvorí `Zeroizing<String>`, ale následné volanie `conn.execute_batch(&pragma)` v `rusqlite` vytvorí internú kópiu pomocou `CString::new`, ktorá sa po uvoľnení v Ruste **nenuluje** (zostáva na haldy alokátora).
     - V `keys/src/backup_chunks.rs` (`BackupChunkKeys::open`, riadok 93) sa pri kontrole HMAC vytvára `expected: Vec<u8>` a výsledok `self.mac(&plain)` (32-bajtové pole na zásobníku), ktoré nie sú obalené v `Zeroizing` (hoci ide o verejný názov kúska, kľúč `self.name` je tajný).

5. **Porovnávanie v nekonštantnom čase pre `manifest` hash a podpisové kľúče v Ruste**
   - **Súbor a funkcia:** `keys/src/sign.rs` (`verify_wrap_for`, riadok 175: `st.manifest != list.hash`, `continues`, riadok 434: `m.prev != p.hash`, `check_pins`, riadok 573: `&a.hash != h`).
   - **Problém:** Zatiaľ čo v TypeScripte (`ts/src/signing.ts`) sa všade dôsledne používa `equalBytes` (konštantný čas), v Ruste sa pre porovnávanie 32-bajtových SHA-256 hašov manifestov a verejných kľúčov (`PublicKey` odvodzuje `PartialEq`) používa štandardný operátor `==` / `!=`. Hoci sú tieto haše a verejné kľúče verejné (nie sú to tajomstvá, takže nejde o priamy únik kľúča), ide o nekonzistentnosť medzi Rust a TS implementáciou.

6. **KDF pre 16-znakový kód: zníženie entropie na 75 bitov a fixné parametre pre `backupCodeId` / `backupChunkKeys`**
   - **Súbor a funkcia:** `keys/src/backup_code.rs` (`DEFAULT_PARAMS`, `base`, `backup_code_id`, riadky 26, 232–243) a `ts/src/backupCode.ts` (`backupCodeBase`, `backupCodeId`, riadky 202–216).
   - **Problém:** Rozhodnutie obetovať 5 bitov z 80 na kontrolný znak (otázka 20 v AUDIT.md) je z hľadiska použiteľnosti správne (zabráni zbytočnému behu Argon2id pri preklepe). Avšak funkcie `backupCodeId` a `backupChunkKeys` používajú **pevne zakódované** parametre `DEFAULT_PARAMS` (m=32 MiB, t=2, p=1) a deterministickú soľ odvodenú len z názvu aplikácie (`SHA-256("regino backup-code salt v1|<app>")[0..16]`). To znamená:
     1. Ak aplikácia zvýši parametre Argon2id v hlavičke zálohy v3 (napr. na 128 MiB, t=4), no záloha obsahuje prílohy (`chunks`), útočník, ktorý získa zálohu v3 aj priečinok s kúskami (`.rgb`), **nemusí** lámať drahší Argon2id zo zálohy v3 – môže lámať kód proti prvým 16 bajtom šifrovaného kúska (`RGB1` + nonce + ciphertext + GCM tag) s fixnými slabšími parametrami `DEFAULT_PARAMS` (32 MiB, t=2), čím úplne obíde navýšenie parametrov v hlavičke zálohy v3.
     2. Keďže je soľ rovnaká pre všetkých používateľov danej aplikácie, pri úniku databázy `backupCodeId` zo servera alebo pri úniku kúskov záloh viacerých používateľov so známym obsahom (napr. štandardná šablóna dokumentu v Žiačikovi) môže útočník vykonávať **multi-target útok**: jeden výpočet Argon2id (s fixnou soľou aplikácie) otestuje proti všetkým $N$ uniknutým `backupCodeId` naraz (cena sa delí $N$).

---

### (b) Formát a verzovanie

1. **Tichá akceptácia poškodených / neplatných UTF-8 reťazcov z databázy v `regino-vault`**
   - **Súbor a funkcia:** `vault/src/lib.rs` (`from_sql`, riadok 218: `ValueRef::Text(t) => Value::String(String::from_utf8_lossy(t).into_owned())`).
   - **Problém:** Pri čítaní textových stĺpcov zo SQLite sa používa `String::from_utf8_lossy`. Ak sa do databázy dostanú neplatné UTF-8 sekvencie, sú potichu nahradené znakom `U+FFFD` () namiesto vrátenia chyby `Error::BadValue`. Ak aplikácia v textovom stĺpci ukladá base64/hex reprezentácie kľúčov, kontextov alebo podpisov, tiché prepísanie bajtov môže viesť k nepredvídateľnému správaniu namiesto čistého zlyhania.

2. **Chýbajúca autentifikácia (alebo obmedzenie) zoznamu záloh pri Garbage Collection kúskov (`referenced_chunks`)**
   - **Súbor a funkcia:** `vault/src/backup_chunks.rs` (`referenced_chunks`, riadky 79–108).
   - **Problém:** Funkcia `referenced_chunks` číta nešifrované pole `"chunks"` zo všetkých súborov v priečinku záloh, vrátane „ručne skopírovaných“ súborov, ktoré končia na `.<ext>` (pridané v 0.13.4). Pri týchto súboroch mimo prísneho vzoru názvu sa akákoľvek chyba čítania alebo parsovania JSON-u **ticho ignoruje** (`if let Some(v) = ...`). Ak je takýto ručne skopírovaný súbor zálohy dočasne uzamknutý iným procesom (napr. antivírusom alebo cloudovou synchronizáciou na Windows) alebo má poškodený koniec, `referenced_chunks` ho potichu preskočí a `gc_chunks` následne **nenávratne zmaže** jeho kúsky, ak na ne neodkazuje iná záloha. Naopak, útočník s prístupom na zápis do priečinka môže podstrčiť súbor s miliónmi neexistujúcich názvov kúskov do poľa `"chunks"`, čo spôsobí alokáciu obrovského `HashSet<String>` v pamäti (DoS).

3. **Spätná kompatibilita `unwrapForDevice` s verziou 1 (Sync Wrap v1) umožňuje downgrade kontextu AAD**
   - **Súbor a funkcia:** `ts/src/sync.ts` (`unwrapForDevice`, riadky 159–188).
   - **Problém:** `unwrapForDevice` stále bezpodmienečne akceptuje `wrapped.v === 1`, kde AAD je len holý `context` bez prefixu `sync wrap v2|`. Hoci HKDF `info` obsahuje `sync wrap v1|<context>` (takže krížová zámena medzi v1 a v2 nefunguje kvôli odlišnému kľúču), neexistuje spôsob, ako v aplikácii (napr. v nových inštaláciách alebo pri `openSignedWrap` v `signing.ts`, ktoré vzniklo až vo verzii 0.13.0, teda dlho po zavedení v2 vo verzii 0.8.0) zakázať akceptovanie zastaranej verzie `v: 1`. V `openSignedWrap` nie je žiadny dôvod akceptovať `w.v === 1`.

4. **Formát `SignedWrappedKey` v `signing.ts` nekontroluje vnútornú štruktúru `WrappedGroupKey` pred overením podpisu nad rámec base64 znakov**
   - **Súbor a funkcia:** `ts/src/signing.ts` (`wrappedKeyBytes`, riadky 199–203).
   - **Problém:** Funkcia `wrappedKeyBytes` kontroluje len `Number.isInteger(w.v)` a či `w.e`, `w.n`, `w.c` vyhovujú regulárnemu výrazu `/^[A-Za-z0-9+/=]+$/`. Nekontroluje kanonický base64 ani dĺžky polí, ani to, či `w.v` je `1` alebo `2`. To je z hľadiska bezpečnosti podpisu v poriadku (keďže `unwrapForDevice` to neskôr odmietne), ale formátovo to dovoľuje podpísať neplatný `WrappedGroupKey`.

---

### (c) API a riziko nesprávneho použitia

1. **Nebezpečné predvolené hodnoty v `openSignedWrap` / `verify_wrap_for` a `verifyManifestChainFromAnchor`**
   - **Súbor a funkcia:** `keys/src/sign.rs` (`verify_wrap_for`, riadok 167; `ChainOptions::default`, riadok 510) a `ts/src/signing.ts` (`openSignedWrap`, riadok 257; `verifyManifestChainFromAnchor`, riadok 542).
   - **Problém:** 
     - Opravy zraniteľností S1 a S2 z auditu 0.15.0 boli pridané ako **opt-in** (`require_anchor_on_latest: false`, `require_current_epoch: false`), a navyše kontrola príjemcu z 0.13.1 (`recipientId` v `OpenWrapOptions`, resp. oddelená funkcia `verify_wrap_for_recipient` v Ruste) je taktiež **voliteľná**.
     - Ak vývojár aplikácie zavolá základnú funkciu `verify_wrap_for` v Ruste alebo `openSignedWrap` v TS bez voliteľného objektu `opts`, aplikácia je **automaticky zraniteľná** na:
       1. Podvrhnutie kľúča zo staršej epochy (S2 – útok znížením epochy na kľúč, ktorý pozná odobratý člen),
       2. Prijatie kľúča, ktorý bol zabalený pre kľúč, ktorý nie je priradený danému `recipientId` v manifeste (ak zariadenie používa kľúč, ktorý v manifeste patrí inému členovi alebo tam vôbec nie je),
       3. Pri obnove reťaze manifestov bez pinov (`verifyManifestChainFromAnchor`) na podvrhnutie vetvy odvolaným správcom (S1).
     - Toto porušuje princíp „bezpečné v predvolenom nastavení“ (secure by default). Spätná kompatibilita formátov si **nevyžadovala**, aby tieto kontroly v API boli predvolene vypnuté – menia len správanie verifikátora, nie formát dát na disku.

2. **Voľný parameter času `at?: number` vo `verifyWithKeys`**
   - **Súbor a funkcia:** `ts/src/signed.ts` (`verifyWithKeys`, riadky 161–177).
   - **Problém:** Zatiaľ čo `verifyCertificate` a `certifiedKeys` majú parameter `at: number` povinný, vo `verifyWithKeys` je `at?: number` voliteľný. Ak volajúci zabudne odovzdať `at` pri overovaní tokenu zariadenia (ktorý má `exp`), expirovaný token prejde bez chyby.

3. **Funkcia `inspectManifestChain` vracia dáta takmer identického tvaru ako `verifyManifestChainFromAnchor`**
   - **Súbor a funkcia:** `keys/src/sign.rs` (`inspect_manifest_chain`, riadok 629) a `ts/src/signing.ts` (`inspectManifestChain`, riadok 584).
   - **Problém:** Hoci dokumentácia varuje, že výsledok `inspectManifestChain` nie je dôveryhodný, návratový typ `InspectedManifest` obsahuje priamo pole `members: Member[]` a `hash: Uint8Array` (igualne ako `AcceptedManifest.manifest`). Vývojár môže ľahko použiť `inspected.at(-1).hash` na automatické pripnutie (pinning) bez skutočného zásahu používateľa, alebo použiť `members` pred schválením.

4. **Nekonzistentný podpis `Key::from_bytes` medzi `regino-keys` a `regino-vault`**
   - **Súbor a funkcia:** `keys/src/lib.rs` (`Key::from_bytes(mut bytes: [u8; 32])`, riadok 37) vs. `vault/src/lib.rs` (`Key::from_bytes(bytes: Zeroizing<[u8; 32]>)`, riadok 28).
   - **Problém:** V `regino-keys` prijíma `Key::from_bytes` surové pole `[u8; 32]` hodnotou. V Ruste odovzdanie `[u8; 32]` hodnotou spôsobí bitovú kópiu (move) na zásobníku volajúceho; vynulovanie `bytes.zeroize()` vo vnútri `from_bytes` vymaže len lokálnu kópiu vo funkcii, nie pôvodné pole u volajúceho. `regino-vault` to rieši správne cez `Zeroizing<[u8; 32]>`.

5. **Tolerantné parsovanie v `findChunkedFiles` v `backupChunks.ts`**
   - **Súbor a funkcia:** `ts/src/backupChunks.ts` (`findChunkedFiles`, riadky 88–103).
   - **Problém:** Funkcia rekurzívne prechádza celý dešifrovaný JSON objekt (`walk`) bez obmedzenia hĺbky rekurzie a akýkoľvek objekt s poľom `chunks` považuje za súbor. Pri hlboko vnorenom JSON-e (napr. v podvrhnutej zálohe pri otvorení v `open-backup.html`) môže spôsobiť pretečenie zásobníka (`RangeError: Maximum call stack size exceeded`). Navyše sa spolieha na to, že `file.name` je bezpečný názov súboru – v `ts/tools/page.ts` (riadok 62) sa `f.name` priamo priradí do `a.download = f.name`, pričom v `findChunkedFiles` nie je žiadna sanitácia názvu súboru (môže obsahovať cesty alebo nebezpečné prípony ako `.exe`, `.html`).

6. **Odpovede na otázky pre audítora v `AUDIT.md` § 4.2 (zhrnutie k dizajnu API a protokolov):**
   - **Otázka 2 + 17 (AAD a kontexty):** Súčasná schéma `magic || context` (Rust) a `<label>|<context>` (TS) je bezpečná **len vtedy**, ak aplikácia striktne dodrží pravidlá v § 3.2 (žiadne oddeľovače v ID, pevný počet polí na účel). Keďže jadro formát kontextu nijako nevaliduje (okrem `!is_empty()`), celá bezpečnosť doménovej separácie leží na aplikácii. Pre nové verzie by bolo výrazne bezpečnejšie prijať štruktúrovaný kontext `&[&str]` a kódovať ho s prefixom dĺžky (ako v `RGN-SIG1`).
   - **Otázka 6 (Shamir):** Tabuľky v GF(256) v `blahaj` nie sú v konštantnom čase, no pri jednorazovom lokálnom rozdelení kľúča je to akceptovateľné. Väčším problémom je chýbajúce `Zeroizing` na výstupe `shamir::split` (pozri nález F-06).
   - **Otázka 7 + 12 (SQLCipher):** Nastavenie `secure_delete = ON` a `compact()` je pre živý súbor správne. Keďže `cipher_memory_security` padá na Windows kvôli `VirtualLock` (chyba 1453), odporúčame zapnúť aspoň `PRAGMA cipher_memory_security = OFF` explicitne alebo zdokumentovať, že stránky v pamäti procesu nie sú zamknuté proti stránkovaniu na disk (swap/pagefile).
   - **Otázka 13 (Sync IV):** Pre domácnosť/ambulanciu je náhodný 96-bitový IV pod jedným skupinovým kľúčom v praxi dostatočný, pokiaľ počet záznamov nepresiahne desiatky miliónov. Jadro by však malo v dokumentácii `sealRecord` uviesť tvrdý limit (napr. $2^{32}$ zápisov na jeden skupinový kľúč).
   - **Otázka 14 (Inbox):** 80-bitový odtlačok (`inboxFingerprint`) je odolný voči preimage útokom ($2^{80}$), no ak útočník (server) generuje kľúč a klient kontroluje len napr. prvé dve štvorice znakov (32 bitov), útočník vie vygenerovať vanitný kľúč. UI musí vyžadovať porovnanie celých 20 hex znakov.
   - **Otázka 15 (Pairing SAS):** Protokol v `docs/PAIRING.md` má záväzok (commitment) len zo strany nového zariadenia ($N$). Existujúce zariadenie ($E$) posiela svoj verejný kľúč $pub_E$ v kroku 2 po prijatí $pub_N$ a svoj nonce $n_E$ po prijatí záväzku $C$. Ak útočník (server) vystupuje ako MITM, nemôže ovplyvniť SAS po tom, čo $N$ odošle $C$, pretože $C$ viaže $pub_N, pub_E, n_N$. Keďže však $E$ posiela $pub_E$ až po prijatí $pub_N$, server môže podvrhnúť obidva kľúče a má šancu $10^{-6}$ na jeden pokus. To je pre 6-miestny SAS štandardné, **ak** aplikácia striktne vynúti limit pokusov (max 3 zlyhania) a zneplatní kľúče. Samotné jadro však tento stavový automat nevynucuje.
   - **Otázka 18 (Podpisy):** `pinned_trusted` nahrádzajúce kotvu je akceptovateľné len vtedy, ak je pin uložený v autentifikovanom lokálnom úložisku (napr. v SQLCipher DB). Naopak, ponechanie `require_anchor_on_latest` a `require_current_epoch` ako vypnutých v predvolenom stave je nebezpečné (nález F-01).
   - **Otázka 19 (Dva jazyky):** Odmietnutie obojstranne platného kódu (`ambiguous`) s vrátením oboch kandidátov je správne rozhodnutie; pravdepodobnosť kolízie je zanedbateľná a AEAD pri dešifrovaní jednoznačne určí správny kľúč.

---

### (d) Testy

1. **Chýbajúce meranie pokrytia a fuzzing v Ruste**
   - Zatiaľ čo TypeScript vynucuje 100 % pokrytie riadkov a vetiev (`vitest.config.ts`), v Ruste sa pokrytie nemeria vôbec (priznané v AUDIT.md § 5).
   - V repozitári úplne chýbajú **fuzzing testy** (`cargo-fuzz` / `libfuzzer`) a **property-based testy** (`proptest` / `quickcheck`), hoci knižnica obsahuje vlastné binárne parsery (`Reader` v `keys/src/sign.rs` a `ts/src/signing.ts`, parser QR kódov v `recovery.ts`, parser 16-znakových kódov v `backup_code.rs` a parser podielov v `shamir.rs`).

2. **Chýbajúca implementácia a krížové testy záloh (v1, v2, v3) a ECDH (sync/inbox) v Ruste**
   - `regino-keys` implementuje len odvodenie kľúčov pre zálohy v3 (`backup_code::backup_key`) a šifrovanie kúskov (`backup_chunks`), ale samotné čítanie/zápis záloh v1–v3 je v Ruste prítomné len ako pomocná funkcia v teste `keys/tests/backup_code_0_15_0.rs` (`open_backup`). Pre `sync.ts` a `inbox.ts` neexistuje v Ruste žiadny náprotivok.

3. **Testy `keystore::rekey` netestujú skutočné zlyhanie zápisu do úložiska po `PRAGMA rekey`**
   - **Súbor a funkcia:** `vault/tests/keystore.rs` (`rekey_incomplete_is_completed_by_finish_rekey`, riadky 228–248).
   - **Problém:** Samotný komentár v teste priznáva, že mock keystore nevie simulovať chybu pri zápise, takže test namiesto volania `keystore::rekey` a overenia vrátenia `Error::RekeyIncomplete` len manuálne volá `pending.set_secret` a `v.rekey`. Samotná vetva `.map_err(|e| Error::RekeyIncomplete(...))` vo funkcii `keystore::rekey` (`vault/src/keystore.rs`, riadok 83) tak **nie je nikdy vykonaná v žiadnom teste**.

---

### (e) Závislosti a dodávateľský reťazec

1. **Nepripnuté verzie v `Cargo.toml` pre knižničných odberateľov**
   - **Súbor:** `keys/Cargo.toml`, `vault/Cargo.toml`.
   - **Problém:** Na rozdiel od `ts/package.json`, kde sú všetky runtime závislosti pripnuté presne (test `N6` v `audit0151.test.ts`), v `keys/Cargo.toml` a `vault/Cargo.toml` je presne pripnutý len `ed25519-dalek = "=3.0.0"`. Ostatné závislosti používajú caret rozsahy (napr. `rusqlite = "0.42"`, `argon2 = "0.6"`, `zeroize = "1"`). Hoci tento repozitár má commitnutý `Cargo.lock` a CI používa `--locked`, klientske aplikácie (Dôverník, Gazda), ktoré pridajú `regino-keys` alebo `regino-vault` ako git závislosť, použijú svoj vlastný `Cargo.lock` a môžu dostať iné minor/patch verzie kryptografických crate-ov.

2. **Inštalácia `cargo-cyclonedx` bez overenia kontrolného súčtu v `release.yml`**
   - **Súbor:** `.github/workflows/release.yml` (riadok 35: `cargo install cargo-cyclonedx --version 0.5.9 --locked`).
   - **Problém:** Zatiaľ čo v `ci.yml` sa binárka `cargo-deny` sťahuje s explicitným overením `DENY_SHA256`, v `release.yml` sa `cargo-cyclonedx` sťahuje a kompiluje z `crates.io` bez overenia hašu tarbalu. Navyše kompilácia prebieha v tom istom kroku, ktorý následne generuje `dist/open-backup.html` a `SHA256SUMS.txt`.

3. **Riziko DOM XSS / stiahnutia nebezpečného súboru v `tools/open-backup.html`**
   - **Súbor:** `ts/tools/page.ts` (`showFiles`, riadky 38–69) a `ts/src/backupChunks.ts` (`findChunkedFiles`, riadok 96).
   - **Problém:** Pri otváraní zálohy obsahujúcej kúsky (`chunks`) sa z dešifrovaného JSON-u vytiahne `f.name` a `f.mime`. Pri kliknutí na súbor sa vytvorí `<a download="${f.name}">` s `Blob` typom `f.mime` a programovo sa naň klikne (`a.click()`). Hoci `Blob` URL pri stiahnutí cez `download` atribút nespustí skript v kontexte stránky (a CSP je prísne), chýba akákoľvek sanitácia `f.name` (napr. odstránenie lomiek, riadiacich znakov alebo varovanie pri spustiteľných príponách `.exe`, `.bat`, `.html`), ak by používateľ otváral podvrhnutú zálohu.

---

### (f) Konkrétne zraniteľnosti a slabé miesta

| ID | Závažnosť | Súbor a funkcia | Popis problému | Scenár útoku | Návrh opravy |
|---|---|---|---|---|---|
| **F-01** | **Vysoká** | `keys/src/sign.rs` (`verify_wrap_for`, `ChainOptions::default`), `ts/src/signing.ts` (`openSignedWrap`, `verifyManifestChainFromAnchor`) | Bezpečnostné kontroly `requireCurrentEpoch` (S2), `requireAnchorOnLatest` (S1) a `recipientId` sú v API voliteľné a predvolene **vypnuté** (`false` / `None`). | Server (alebo odobratý správca v spolupráci so serverom) podvrhne klientovi, ktorý volá `openSignedWrap` bez voliteľných parametrov, starší skupinový kľúč z predchádzajúcej epochy (ktorý pozná odobratý člen) ako aktuálny kľúč, pod ktorým klient začne šifrovať nové dáta. Prípadne pri obnove bez pinov podvrhne fork manifestu vytvorený odobratým správcom. | Zmeniť predvolené hodnoty v `WrapOptions` / `OpenWrapOptions` tak, aby `requireCurrentEpoch` bolo predvolene `true` (pre čítanie historických kľúčov vytvoriť explicitnú voľbu `allowHistoricalEpoch: true` alebo samostatnú funkciu) a vyžadovať `recipientId`. Podobne zapnúť `requireAnchorOnLatest: true` ako predvolené pri obnove bez pinov (nemenia sa tým žiadne formáty). |
| **F-02** | **Stredná** | `keys/src/backup_code.rs` (`base`, `backup_code_id`), `keys/src/backup_chunks.rs` (`from_backup_code`), `ts/src/backupCode.ts` (`backupCodeBase`), `ts/src/backupChunks.ts` (`backupChunkKeys`) | Obídenie zvýšených parametrov Argon2id v zálohe v3 cez kúsky záloh (`chunks`) a možnosť multi-target útoku. `backupCodeBase` vždy používa fixné parametre `DEFAULT_PARAMS` (32 MiB, t=2) a globálnu soľ aplikácie `app_salt`. | 1. Ak aplikácia v budúcnosti zvýši parametre Argon2id v hlavičke zálohy v3 (napr. na m=128 MiB, t=4), no záloha používa kúsky (`.rgb`), útočník s prístupom k zálohe a kúskom bude hádať 75-bitový kód proti kľúču kúskov (len m=32 MiB, t=2).<br>2. Pri úniku databázy `backupCodeId` zo servera môže útočník jedným výpočtom Argon2id testovať kód proti všetkým používateľom danej aplikácie naraz. | Pre novú verziu formátu kúskov (napr. `RGB2` / záloha v4): odvodzovať kľúče pre kúsky z náhodnej soli uloženej v manifeste (alebo v samostatnom súbore soli v priečinku záloh) a s parametrami KDF z hlavičky. Pre `backupCodeId` v dokumentácii dôrazne varovať pred multi-target útokom pri úniku DB zo servera. |
| **F-03** | **Stredná** | `ts/src/signed.ts` (`verifySignature`, `verifyToken`) | Chýbajúca kontrola prvočíselného rádu (beztorznosti) pre verejný kľúč $A$ a bod $R$ pri overovaní licenčných tokenov a certifikátov kľúčov (`@noble/ed25519` s `zip215: false` vykonáva len kofaktorovú kontrolu). | Ak by sa použil kľúč alebo podpis s torznou zložkou (bod malého rádu pridaný k bodu), `signed.ts` ho akceptuje, zatiaľ čo `signing.ts` a Rust `ed25519-dalek` (`verify_strict`) ho odmietnu. Porušuje to deklarovanú prísnu zhodu s RFC 8032 / `dalek`. | V `ts/src/signed.ts` nahradiť implementáciu `verifySignature` volaním `verifyEd25519` z `ts/src/signing.ts` (ktorá overuje `isSigningPublicKey(publicKey)` a `!r.isSmallOrder() && r.isTorsionFree()`). |
| **F-04** | **Stredná** | `vault/src/backup_chunks.rs` (`referenced_chunks`, `gc_chunks`, riadky 79–108) | Tiché ignorovanie chýb čítania/parsovania pri ručne skopírovaných zálohách a neautentifikované čítanie poľa `"chunks"` pred mazaním kúskov. | 1. Ak má používateľ v priečinku kópiu zálohy `zaloha (1).ext` (a pôvodná už bola rotovaná preč) a tento súbor je počas behu `gc_chunks` krátkodobo zamknutý iným procesom (napr. cloud sync / antivírus), `fs::read(&p).ok()` zlyhá potichu a `gc_chunks` **zmaže kúsky tejto zálohy**.<br>2. Podstrčený nešifrovaný JSON s obrovským poľom `"chunks"` spôsobí vyčerpanie pamäte (OOM). | Pri súboroch s príponou `.ext`, ktoré sa nepodarí prečítať kvôli I/O chybe (napr. `PermissionDenied` / `WouldBlock` / zdieľací zámok), prerušiť `referenced_chunks` s chybou rovnako ako pri hlavných zálohách (preskočiť len súbory, ktoré evidentne nie sú JSON objekt s `"format": "<app>-backup"`). Obmedziť maximálny počet položiek čítaných z `"chunks"`. |
| **F-05** | **Nízka** | `ts/src/signed.ts` (`verifyWithKeys`, riadok 165) | Parameter času `at?: number` je vo funkcii `verifyWithKeys` voliteľný. Ak sa vynechá, polia `nbf` a `exp` v tokene sa vôbec nekontrolujú. | Vývojár aplikácie overujúci token zariadenia (ktorý spolieha na `exp`) zabudne odovzdať parameter `at`. Expirovaný alebo ešte neplatný token je akceptovaný. | Zvážiť povinný parameter `at: number | null` (kde `null` explicitne vyjadruje „nekontrolovať čas“ pre bezexpiračné licencie), aby sa na kontrolu času nedalo zabudnúť neúmyselne. |
| **F-06** | **Nízka** | `keys/src/shamir.rs` (`split`, `combine`), `keys/src/lib.rs` (`Key::from_bytes`), `vault/src/lib.rs` (`key_pragma`) | Neúplné nulovanie tajomstiev v pamäti (chýbajúce `Zeroizing` pre podiely Shamira, kopírovanie `[u8; 32]` hodnotou na zásobníku v `Key::from_bytes`, nenulovaný `CString` v `rusqlite`). | Útočník, ktorý neskôr získa výpis pamäte procesu (memory dump, crash dump, swap súbor na disku bez FDE), môže v uvoľnenej pamäti nájsť zvyšky podielov Shamira alebo SQLCipher kľúča. | V `shamir::split` vracať `Vec<Zeroizing<Vec<u8>>>` (alebo v novej verzii API), v `regino_keys::Key::from_bytes` odporučiť odovzdávanie `Zeroizing<[u8; 32]>` podobne ako v `regino-vault`, a v `backup_chunks.rs` obaliť výstup `self.mac(&plain)` do `Zeroizing`. |
| **F-07** | **Nízka** | `keys/src/sign.rs` (`Manifest::message`), `ts/src/signing.ts` (`encodeManifest`) | Manifest kontroluje unikátnosť `id` a podpisového kľúča `sign`, ale nekontroluje unikátnosť neprázdneho šifrovacieho kľúča `seal` medzi členmi. Navyše `MemberKey` neobsahuje dôkaz o vlastníctve privátneho kľúča k `seal` (ECDH P-256). | Zlomyselný člen $M$ podpíše `MemberKey` obsahujúci verejný `seal` kľúč iného člena $A$. Ak to administrátor vloží do manifestu, dvaja členovia zdieľajú rovnaký `seal` kľúč. | Pri kódovaní a dekódovaní manifestu (alebo vo `verify_member_key` voči existujúcemu manifestu) overiť, že žiadny iný člen v zozname už nemá rovnaký neprázdny `seal` kľúč (nemenia sa tým existujúce platné manifesty, kde má každý člen vlastný kľúč). |
| **F-08** | **Nízka** | `vault/src/lib.rs` (`from_sql`, riadok 218) | Použitie `String::from_utf8_lossy` pri čítaní `ValueRef::Text` zo SQLite potichu nahrádza poškodené bajty znakom `` namiesto vrátenia chyby. | Poškodenie dát alebo neplatný vstup uložený v TEXT stĺpci nevedie k chybe pri čítaní, ale k tichej zmene reťazca. | Nahradiť `String::from_utf8_lossy(t)` volaním `std::str::from_utf8(t).map_err(|e| Error::BadValue(e.to_string()))?`. |
| **F-09** | **Nízka** | `ts/src/backupChunks.ts` (`findChunkedFiles`), `ts/tools/page.ts` (`showFiles`) | Neobmedzená rekurzia vo `walk` pri hľadaní `chunks` v JSON-e a použitie nesanitovaného `f.name` v atribúte `download` v `open-backup.html`. | Špeciálne upravený súbor zálohy spôsobí pád `openBackup` na `Maximum call stack size exceeded` alebo ponúkne stiahnutie prílohy s podvrhnutým názvom/príponou. | Obmedziť hĺbku rekurzie vo `findChunkedFiles` (napr. na 32 úrovní) a v `page.ts` sanitovať `f.name` (odstrániť znaky cesty `/`, `\`, riadiace znaky). |
| **F-10** | **Nízka** | `ts/src/sync.ts` (`unwrapForDevice`), `ts/src/signing.ts` (`openSignedWrap`) | `openSignedWrap` (pridané v 0.13.0) akceptuje vnútorný `WrappedGroupKey` verzie 1 (`w.v === 1`), kde AAD neobsahuje doménový štítok `sync wrap v2|`. | Možnosť downgrade-u vnútorného obalu kľúča na `v: 1` v novom protokole podpísaných kľúčov, ktorý nikdy nemusel podporovať `v: 1`. | V `openSignedWrap` (a `signedWrapForDevice`) vyžadovať `signed.w.v === WRAP_VERSION` (teda `2`). Samotný `unwrapForDevice` môže naďalej podporovať `v: 1` pre staré dáta v Gazdovi. |

---

### (g) 10 odporúčaní zoradených podľa dôležitosti

1. **Zapnúť bezpečnostné kontroly podpisov a epoch v predvolenom nastavení (súvisí s F-01):** V `openSignedWrap` / `verify_wrap_for_with` nastavte `requireCurrentEpoch = true` ako predvolené správanie (pre čítanie starých epoch vyžadujte explicitný príznak) a pri obnove manifestu bez pinov (`verifyManifestChainFromAnchor`) zvážte predvolené zapnutie `requireAnchorOnLatest = true`.
2. **Zjednotiť overovanie Ed25519 podpisov v TypeScripte (súvisí s F-03):** V `ts/src/signed.ts` nahraďte priame volanie `verifyAsync` z `@noble/ed25519` volaním `verifyEd25519` z `ts/src/signing.ts`, aby aj licenčné tokeny a certifikáty kľúčov vynucovali beztorznosť (prvočíselný rád) verejného kľúča $A$ a bodu $R$.
3. **Ošetriť I/O chyby pri ručných kópiách záloh v `referenced_chunks` (súvisí s F-04):** V `vault/src/backup_chunks.rs` nerozlišujte medzi I/O chybou čítania hlavnej zálohy a ručnej kópie – ak súbor s príponou zálohy nemožno prečítať (napr. kvôli zámku procesu), zastavte `gc_chunks` s chybou namiesto tichého preskočenia súboru a zmazania jeho kúskov.
4. **Zamedziť obídeniu KDF parametrov zálohy v3 cez kúsky záloh v budúcej verzii formátu (súvisí s F-02):** Pre prípad budúceho navýšenia Argon2id parametrov navrhnite v ďalšej verzii formátu odvodzovanie kľúčov pre kúsky (`BackupChunkKeys`) s rovnakými KDF parametrami (a per-user soľou), aké má samotná záloha, aby kúsky netvorili slabší článok.
5. **Validovať unikátnosť šifrovacích kľúčov (`seal`) v zozname členov (súvisí s F-07):** V `verify_member_key` a pri tvorbe manifestu (`sign_manifest` / `encodeManifest`) odmietnite stav, kedy by dvaja rôzni členovia v tom istom manifeste mali priradený rovnaký neprázdny `seal` kľúč.
6. **Zakázať `WrappedGroupKey` verzie 1 vo vnútri `SignedWrappedKey` (súvisí s F-10):** V `ts/src/signing.ts` (`openSignedWrap` a `wrappedKeyBytes`) vyžadujte `w.v === 2` (`WRAP_VERSION`), keďže podpísané obaly kľúčov vznikli až vo verzii 0.13.0 a nepotrebujú spätnú kompatibilitu s verziou 1 z 0.5.0.
7. **Pridať fuzzing (`cargo-fuzz`) a meranie pokrytia pre Rust (súvisí s časťou d):** Zaveďte fuzzing ciele pre všetky binárne a textové parsery v Ruste (`sign::open_manifest`, `sign::sign_prepared`, `shamir::combine`, `backup_code::BackupCode::parse`) a pridajte kontrolu pokrytia kódu v Ruste do CI.
8. **Zlepšiť prácu s pamäťou pri kľúčoch a podieloch v Ruste (súvisí s F-06):** Upravte `shamir::split` a interné HMAC výpočty v `backup_chunks.rs` tak, aby používali `Zeroizing`, a zjednoťte `regino_keys::Key::from_bytes` s `regino_vault::Key::from_bytes` pomocou `Zeroizing<[u8; 32]>`.
9. **Odstrániť `from_utf8_lossy` v `regino-vault` a obmedziť rekurziu v `findChunkedFiles` (súvisí s F-08, F-09):** V `vault/src/lib.rs` vráťte pri neplatnom UTF-8 v databáze chybu `Error::BadValue` a v `ts/src/backupChunks.ts` obmedzte maximálnu hĺbku vnorenia pri hľadaní kúskov v JSON-e spolu so sanitáciou názvov súborov v `open-backup.html`.
10. **Pripnúť verzie v `Cargo.toml` alebo zdokumentovať politiku `Cargo.lock` pre klientske aplikácie (súvisí s časťou e):** V `release.yml` overujte SHA-256 haš sťahovaného `cargo-cyclonedx` (alebo použite predpripravenú binárku ako pri `cargo-deny`) a zabezpečte, aby klientske aplikácie pri aktualizácii git submodulu/závislosti používali presne otestované verzie tranzitívnych Rust závislostí.

---

## Vlastné stanovisko (overené v kóde, commit `37beca2`)

**Zhrnutie:** model nenašiel nič, čo by umožnilo prečítať zálohu, portfólio ani iné dáta bez kódu alebo kľúča, a ani nič, čo by sa dalo zneužiť bez spolupráce aplikácie. Žiadny nález nie je po overení kritický ani vysoký. Jediný „vysoký“ nález (F-01) je zámerne voliteľná kontrola, ktorá je verejne opísaná v README a v AUDIT.md § 4.5 (S1, S2). Preto tu nie je nič, čo by bolo treba nahlásiť Centrále mimo tohto dokumentu. Formáty sa tu nemenia, kód sa nemenil.

Označenia: **potvrdené** = kód sa správa tak, ako model píše; **nepotvrdené** = nedá sa overiť alebo to závisí od aplikácie; **mylné** = kód sa tak nespráva alebo opísaný útok nefunguje.

### Nálezy z tabuľky (f)

| ID | Model | Verdikt | Overenie | Moja závažnosť |
|---|---|---|---|---|
| F-01 | vysoká | **potvrdené (fakt), závažnosť prehnaná** | `ts/src/signing.ts` `openSignedWrap` (r. 346, 358): `recipientId` a `requireCurrentEpoch` platia len vtedy, keď ich volajúci zadá; `ChainOptions::default` v Ruste má `require_anchor_on_latest: false`. Ide však o zámer zdokumentovaný v AUDIT.md § 4.5 (S1, S2) a v README 0.15.1, nie o chybu. Útok popísaný modelom („server podvrhne starší kľúč“) nefunguje bez spolupráce správcu: kľúč staršej epochy musí podpísať **správca práve prijatého zoznamu** a podpis viaže hash tohto zoznamu aj kľúč príjemcu (`verify_wrap_for`, `keys/src/sign.rs` r. 228 a ďalej). Server môže prehrať len skutočný, správcom podpísaný starší kľúč, ktorý člen dostal na čítanie starých položiek. Riziko teda reálne vzniká len vtedy, keď aplikácia zapečatí **nové** položky kľúčom bez `requireCurrentEpoch`. Prepnutie predvolieb nemení formát, mení však správanie pre existujúcich volajúcich (noví členovia by prestali dostávať staré kľúče), preto ho navrhujem ako samostatnú funkciu na „kľúč na zapisovanie“, nie ako tichú zmenu. | **stredná** (predvolená hodnota API) |
| F-02 | stredná | **potvrdené, už zdokumentované** | `ts/src/backupCode.ts` `backupCodeBase` (pevná soľ aplikácie + `DEFAULT_BACKUP_CODE_KDF`), `backupChunks.ts` `backupChunkKeys`. AUDIT.md otázka 20 to opisuje doslova (viac cieľov naraz pri ukradnutých id a kúskoch so známym obsahom; zvýšenie parametrov v hlavičke nezvýši cenu útoku na kúsky). Dnes všetky zálohy používajú predvolené parametre, takže „obídenie vyšších parametrov“ zatiaľ nemá čo obísť. Pri 75 bitoch a Argon2id 32 MiB je rezerva podľa výpočtu v otázke 20 obrovská aj pri 10⁵ cieľoch. Odporúčanie (kľúče kúskov s náhodnou soľou v novej verzii formátu) je rozumné až pre budúci formát. | **nízka** |
| F-03 | stredná | **čiastočne potvrdené** | `ts/src/signed.ts` `verifySignature` (r. 83) volá len `verifyAsync(…, { zip215: false })`. `@noble/ed25519` 3.2.0 (`index.js` r. 672–694) pri tomto nastavení vyžaduje kanonické `A`, `R` a odmieta `A` malého rádu, ale overuje kofaktorovou rovnicou a **nekontroluje** torznú zložku `A` ani `R`, kým `signing.ts` (`isSigningPublicKey`, kontrola `R`) to robí. Toto je pravda. **Mylné** je však tvrdenie, že sa tým porušuje sľúbená zhoda s `dalek`: `signed.ts` nemá náprotivok v Ruste a takú zhodu nikde nesľubuje. Dopad: koreňové kľúče sú zabudované v aplikácii a sú poctivé, takže torzia dovolí iba vyrobiť ďalšiu platnú podobu existujúceho podpisu (malleability), nie podpis nového tokenu. Problém by vznikol len vtedy, keby aplikácia rozpoznávala tokeny podľa bajtov podpisu. | **nízka** |
| F-04 | stredná | **potvrdené (časť 1), mylné (časť 2)** | `vault/src/backup_chunks.rs` `referenced_chunks` (r. 98–110): ručne vytvorenú kópiu zálohy, ktorá sa nedá prečítať (napr. ju práve zamkol antivírus alebo synchronizácia), funkcia potichu preskočí. `gc_chunks` potom môže zmazať kúsky, ktoré potrebuje **len** táto kópia (riadne zálohy pri chybe čítania zastavia mazanie). Ide o riziko straty dát, nie o únik. Ochranu dáva len `min_age` a to, že riadne zálohy na kúsky odkazujú tiež. Časť 2 (podstrčený obrovský zoznam → nedostatok pamäte) je mylná ako hrozba: kto môže zapisovať do priečinka záloh, môže zálohy rovno zmazať. | **nízka** (dostupnosť ručných kópií) |
| F-05 | nízka | **potvrdené, zdokumentované** | `ts/src/signed.ts` `verifyWithKeys(…, at?)` (r. 164): bez `at` sa `nbf`/`exp` nekontrolujú. V 0.12.1 to bolo zámerne zdokumentované („time is the caller's“). Povinný parameter by bol bezpečnejší. | nízka |
| F-06 | nízka | **čiastočne potvrdené, čiastočne mylné** | Potvrdené: `shamir::split` vracia `Vec<Vec<u8>>` bez `Zeroizing`; `Key::from_bytes([u8;32])` nevymaže kópiu volajúceho (komentár v `keys/src/lib.rs` to výslovne hovorí). **Mylné:** rusqlite 0.42 `execute_batch` → `prepare` **nerobí** `CString` kópiu príkazu PRAGMA s kľúčom, posiela SQLite priamo smerník a dĺžku (`inner_connection.rs` r. 189). Kópie vnútri SQLCipher sú iná vec. **Mylné:** výsledok `self.mac(&plain)` v `backup_chunks.rs` je verejný názov kúska, nie tajomstvo, takže ho nie je treba mazať. | nízka |
| F-07 | nízka | **potvrdené (fakt), dopad mylný** | `ts/src/signing.ts` `encodeManifest` a Rust `Manifest` kontrolujú jedinečnosť `id` a `sign`, nie `seal`. Člen, ktorý si do zoznamu dá cudzí `seal`, však nič nedešifruje (nemá súkromný kľúč). Kľúče pre neho dostane druhý člen, ktorý ich aj tak smie mať. Výsledkom je zmätok alebo odopretie služby, nie únik. Kontrolu jedinečnosti pri **tvorbe** zoznamu odporúčam ako lacné spevnenie (formát sa nemení). | nízka |
| F-08 | nízka | **potvrdené (kód), dopad zanedbateľný** | `vault/src/lib.rs` r. 254 `String::from_utf8_lossy`. Text zapísaný cez rusqlite z Rust `String` je vždy platné UTF-8 a SQLCipher stránky autentifikuje (HMAC), takže tichá zmena by vyžadovala poškodenie, ktoré SQLCipher sám neodhalí. Vrátiť chybu by bolo čistejšie. | nízka |
| F-09 | nízka | **mylné ako útok** | `findChunkedFiles` aj `f.name` a `f.mime` pochádzajú z **dešifrovaného a autentifikovaného** obsahu zálohy (AES-GCM), takže „podvrhnutá záloha“ by vyžadovala kód alebo kľúč. `page.ts` vkladá texty cez `textContent`, nie ako HTML, a prehliadač pri `download` sám upraví názov súboru (lomky). Ostáva len kozmetické obmedzenie hĺbky a čistenie názvu. | informatívne |
| F-10 | nízka | **potvrdené (fakt), bez bezpečnostného dopadu** | `openSignedWrap` → `wrappedKeyBytes` prijme ľubovoľné celé `v` a `unwrapForDevice` prijme `v: 1`. Verziu však volí podpisujúci správca a podpis ju pokrýva, takže ju útočník nemôže znížiť. Aj v1 má v HKDF `info` doménový štítok `sync wrap v1|…`. Vyžadovať `v === 2` pri **zápise** (`signedWrapForDevice`) je rozumné. Pri čítaní by to mohlo rozbiť staré podpísané kľúče, ak nejaké existujú. | informatívne |

### Ostatné tvrdenia v (a)–(e)

- (a)3 – AES-GCM s náhodným 96-bitovým nonce pod pevným kľúčom kúskov a pod skupinovým kľúčom: **potvrdené**, hranica 2³² zapečatení je však ďaleko od reálneho použitia (zálohy portfólia, záznamy jednej skupiny). Odporúčam ju len zapísať do dokumentácie `sealRecord` a `sealBackupChunk`.
- (a)5 – v Ruste sa haše zoznamov a verejné kľúče porovnávajú bez konštantného času: **potvrdené, bez dopadu**, ide o verejné hodnoty.
- (b)2 – tie isté body ako F-04.
- (b)4 – `wrappedKeyBytes` nekontroluje dĺžky ani kanonický base64: **potvrdené**, bez dopadu na bezpečnosť (model to sám uvádza).
- (c)3 – `inspectManifestChain` vracia dáta podobné tým dôveryhodným: **potvrdené**, ide o riziko použitia. Typ by mohol niesť výrazné označenie („untrusted“).
- (c)4 – rozdielne `Key::from_bytes` vo `keys` a `vault`: **potvrdené**. Pri `keys` je to zdokumentované a v 0.15.1 zámerne ponechané kvôli kompatibilite.
- (c)6 – odpovede na otázky z AUDIT.md: ide o názory, nie o nálezy. Pri otázke 7+12 model navrhuje „zapnúť `cipher_memory_security = OFF` explicitne“: v kóde je už vypnuté s komentárom (`vault/src/lib.rs` r. 124) a dôvod je v README 0.4.0. Odporúčanie preto nemá zmysel.
- (d)1 – v Ruste chýba fuzzing, testy vlastností a meranie pokrytia: **potvrdené** (vo `dev-dependencies` je len `serde_json`, README priznáva chýbajúce pokrytie v Ruste). Je to najužitočnejšie odporúčanie z celého posudku.
- (d)2 – Rust nečíta zálohy v1–v3 ani sync či inbox: **potvrdené**, ale je to zámerný návrh (zálohy rieši TS, Rust má len odvodenie kľúčov a kúsky, krížovú zhodu stráži `backup_code_0_15_0.rs`). Nejde o chybu.
- (d)3 – vetva `Error::RekeyIncomplete` v `keystore::rekey` nie je pokrytá testom: **potvrdené** (test `rekey_incomplete_is_completed_by_finish_rekey` to v komentári priznáva, stav vyrába ručne).
- (e)1 – Rust závislosti okrem `ed25519-dalek` majú rozsahy `^`, nie presné verzie: **potvrdené**. Aplikácia, ktorá jadro berie ako git závislosť, rozhoduje podľa vlastného `Cargo.lock`. Odporúčam zapísať do README pravidlo, že aplikácia drží rovnaké verzie ako `Cargo.lock` jadra (alebo ich kontroluje v CI).
- (e)2 – `cargo install cargo-cyclonedx` bez vlastného SHA-256: **čiastočne mylné**. Cargo overuje kontrolný súčet balíka voči indexu crates.io a `--locked` drží jeho závislosti. Rozdiel oproti `cargo-deny` je len v tom, že sa dôveruje indexu, nie pevne zapísanému hašu. Nástroj beží v tom istom jobe ako zostavenie `open-backup.html`, ale až po kontrole `git diff --exit-code`. Nízke riziko.
- (e)3 – tie isté body ako F-09.

### 10 odporúčaní (g) – moje stanovisko

| # | Odporúčanie modelu | Stanovisko |
|---|---|---|
| 1 | `requireCurrentEpoch` a `requireAnchorOnLatest` zapnúť v predvolenom nastavení | **Súhlas so smerom, nie s formou.** Nemeniť tíško predvolené hodnoty (rozbilo by to odovzdávanie starých kľúčov novým členom). Lepšie je pridať samostatnú funkciu na kľúč na zapisovanie (napr. `openCurrentSignedWrap`), ktorá kontrolu vždy zapne, a v aplikáciách, ktoré podpísané kľúče používajú, overiť, že ju volajú. |
| 2 | `signed.ts` overovať cez `verifyEd25519` zo `signing.ts` | **Súhlas**, je to lacné. Treba však overiť, či nejaká vydaná licencia nemá torzný podpis (veľmi nepravdepodobné). Dopad je len malleability. |
| 3 | `referenced_chunks`: pri chybe čítania ručnej kópie zastaviť mazanie | **Súhlas, s úpravou:** zastaviť pri I/O chybe (zámok, prístup), ale súbor, ktorý sa dá prečítať a nie je JSON zálohy, naďalej preskočiť. |
| 4 | Kľúče kúskov s náhodnou soľou a parametrami z hlavičky v novom formáte | **Odložiť.** Je to až pre budúcu verziu formátu (záloha v4 / `RGB2`). Dnes sa parametre nezvyšujú a riziko je zdokumentované v otázke 20. |
| 5 | Jedinečný `seal` v zozname členov | **Súhlas**, ako kontrolu pri tvorbe zoznamu. Pri čítaní existujúcich zoznamov až po overení, že žiadny reálny zoznam nemá duplicitu. |
| 6 | Vo vnútri podpísaného kľúča vyžadovať `w.v === 2` | **Čiastočne:** pri zápise áno, pri čítaní nie (bez bezpečnostného prínosu, riziko rozbitia starých dát). |
| 7 | Fuzzing a pokrytie v Ruste | **Súhlas, najvyššia priorita z praktických krokov:** `cargo-fuzz` pre `sign` (čítanie zoznamov a `sign_prepared`), `shamir::combine`, `BackupCode::parse`, `wrap::unwrap_key`; `cargo llvm-cov` v CI. |
| 8 | `Zeroizing` pre podiely Shamira, zjednotiť `Key::from_bytes` | **Čiastočne:** podiely áno (nové API popri starom). Zmazanie výsledku `mac` je zbytočné, je to verejný názov. `Key::from_bytes` meniť len novou funkciou, nie zmenou podpisu. |
| 9 | Odstrániť `from_utf8_lossy`, obmedziť hĺbku rekurzie, čistiť názvy súborov | **Nízka priorita.** UTF-8 áno (vrátiť `BadValue`). Rekurzia a názvy sú len kozmetika, lebo obsah je autentifikovaný. |
| 10 | Pripnúť Rust závislosti alebo zapísať pravidlo pre `Cargo.lock` aplikácií; haš pre `cargo-cyclonedx` | **Súhlas s pravidlom v README** (aplikácie kontrolujú zhodu verzií s `Cargo.lock` jadra). Haš pre `cargo-cyclonedx` je len malé spevnenie. |

Čo model neodhalil a stojí za pozornosť: nič nové nad rámec AUDIT.md. Posudok je užitočný najmä ako nezávislé potvrdenie, že zámerné rozhodnutia (voliteľné kontroly S1/S2, pevná soľ pre id a kúsky) sú pre nezainteresovaného čitateľa ľahko prehliadnuteľné. To podporuje odporúčania 1 a 7.
