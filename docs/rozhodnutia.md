# Rozhodnutia – regino-crypto

Rozhodnutia Tomáša k jadru šifrovania (novšie hore).

- **2026-11-25 – PIN nikde nie je zdroj kľúča: kľúč zariadenia + krátky PIN a passkey PRF v jadre (0.20.0).** Tomáš
  2026-11-25 v hlavnej session Žiačika k hláseniu DysPro: „Toto preco neriesime?“ (Ziacik `docs/rozhodnutia.md`
  2026-11-25) – do jadra prihlásenie cez prístupový kľúč (passkey, WebAuthn PRF) a hotová funkcia „kľúč zariadenia +
  krátky PIN“ podľa app-core `docs/deviceVault.md`; app-core ju potom použije namiesto vlastného skladania.
  `ts/src/deviceVault.ts`, `docs/DEVICE-VAULT.md`, `AUDIT.md` § 4.11.
- **2026-11-25 – Body § 7 validácie: Testurion na `main` jadra (0.18.0), záloha v4 pripraviť v jadre.** Tomáš 2026-11-25
  v hlavnej session Žiačika: „4 nechcem, ostatne chcem“ (Ziacik `docs/rozhodnutia.md` 2026-11-25) – k § 7
  `docs/validacia-auditu-2026-11-25.md`. Pre jadro: (3) dokončiť PR #40 (Shamir GF(256) a `passwordKey` v TypeScripte)
  na aktuálnom `main` – vektory zhodné s Rust `shamir` vrátane rovnakých podielov z rovnakého vstupu, kontroly ako
  v Ruste, 100 % pokrytie – a zlúčiť ako **0.18.0**; Testurion pripnúť na zlúčený commit `main` (nie na vetvu).
  (5) **záloha v4** (F-02): kľúče kúskov a id pre server z náhodnej soli zálohy a parametrov KDF hlavičky, Rust aj TS
  zhodne; v1–v3 sa naďalej otvoria; do Žiačika až s jeho ďalším väčším vydaním. (4) šifrovanie disku ako podmienka
  pre Dôverník a DysPro – **nie** (ostáva odporúčanie). Body (1) a (2) sú úlohy aplikácií (`docs/plan-aplikacie-2026-11-25.md`).
- **2026-11-25 – Validácia externého auditu 0.16.1 a 0.17.0.** Tomáš 2026-11-25 v hlavnej session: „potrebujem jednu session na
  validaciu tohto“ (audit Devin, 97518c5). Opravy bez zmeny formátov vo verzii 0.17.0 (autorizátor trezoru proti `PRAGMA
  key/rekey/cipher_*`/`secure_delete`, `structuredContext`, `verifyWithKeysAt`, `MAX_MANIFEST_LEN`, bezpečné názvy v nástroji);
  zmeny formátu (záloha v4, `sync record v2`, inbox v2, dlhší SAS) len navrhnuté – `docs/validacia-auditu-2026-11-25.md` § 6–7,
  úlohy aplikácií `docs/plan-aplikacie-2026-11-25.md`. Rozhodnutia z § 7 sú otvorené.
- **2026-11-20 – 0.16.1: trezor bez pripojených databáz (`ATTACH`, `VACUUM INTO`).** Tomáš 2026-11-20 („potvrdzujem“ –
  body B kontroly Dôverníka v1, `Dovernik/docs/kontrola-v1-2026-11-20.md` B1): obmedzenie patrí do jadra, nie do aplikácie.
  `SQLITE_LIMIT_ATTACHED = 0` pri otvorení, `compact` ho zdvihne len na vlastný `VACUUM`. Formáty sa nemenia.
- **2026-11-18 – `npm audit` v CI: behové závislosti od `moderate`, vývojové od `critical`.** Tomáš v hlavnej session
  Žiačika: „všetko áno“ (k návrhu Centrály): nález `picomatch` (GHSA-fc5q-39xc-vjpf, ReDoS) prichádza len cez vývojový
  `vitest`, opravená verzia neexistuje. Kontrola: `npm audit --omit=dev --audit-level=moderate` a
  `npm audit --audit-level=critical`; celý výpis sa naďalej vypíše. Po vydaní opravy `picomatch` vrátiť na `moderate`.
- **2026-11-18 – Posudok Gemini 4 Argon + Mistral: prijaté odporúčania (formáty sa nemenia).** Tomáš v hlavnej session
  Žiačika: „všetko áno“ – k `docs/audit/argon-posudok-2026-11-18.md`, kap. „10 odporúčaní (g) – moje stanovisko“.
  (1) fuzzing (`cargo-fuzz`: `sign`, `shamir::combine`, `BackupCode::parse`, `wrap::unwrap_key`) a `cargo llvm-cov` v CI;
  (2) samostatná funkcia na kľúč na zapisovanie s vždy zapnutými kontrolami (`requireCurrentEpoch`, `requireAnchorOnLatest`),
  predvolené hodnoty sa nemenia, aplikácie overiť; (3) `signed.ts` overovať cez `verifyEd25519`; (4) `referenced_chunks`
  zastaví mazanie pri I/O chybe ručnej kópie; (5) jedinečný `seal` pri tvorbe zoznamu, `v === 2` pri zápise, `Zeroizing`
  pre podiely (nové API), `BadValue` namiesto `from_utf8_lossy`, pravidlo v README o zhode verzií s `Cargo.lock` jadra,
  limit 2³² zapečatení v dokumentácii. Odložené: kľúče kúskov s náhodnou soľou (až záloha v4). Posudok zlúčiť do `main`.
