# Rozhodnutia – regino-crypto

Rozhodnutia Tomáša k jadru šifrovania (novšie hore).

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
