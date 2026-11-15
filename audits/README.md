# Audits and reviews of regino-crypto

Reports and findings about this repository, newest first. Each engagement gets a signed tag marking
the reviewed commit and, after the retest, the fixed commit.

| Date | Who | Type | Commit | Document |
|---|---|---|---|---|
| 2026-11-15 | AI-assisted review (Fable) run by the maintainer, with its own test programs | Argon2id bounds, order of checks of member lists, canonical chunk lists, damaged chunks, zeroize, pinning, mobile Argon2id bound, chain of a removed admin, older epoch keys | reviewed `888a7e8` (0.15.0), fixes in 0.15.1 | [AUDIT.md § 4.5](../AUDIT.md#45-ai-assisted-review-of-0150-2026-11-15--what-was-fixed-in-0151) |
| 2026-10-23 | AI-assisted review run by the maintainer on his computer (another assistant, possibly over an older checkout) | input validation and hygiene: Shamir share length, `rekey` atomicity, base32 canonicity, backup version, PIN hash shape, certificate `v`, token expiry, `peekToken`, device revocation | checked against 0.12.0, fixes in 0.12.1 | [AUDIT.md § 4.3](../AUDIT.md#43-external-ai-review-2026-10-23--what-was-fixed-in-0121) |
| 2026-10-22 | AI-assisted review run by the maintainer (three independent model runs) | client deletion and key destruction; replay and rollback of sync and storage – core 0.11.0 together with the app that pins it | reviewed `914288a` (0.11.0), fixes in 0.11.1 | [2026-10-22-ai-review.md](2026-10-22-ai-review.md) |
| 2026-10-18 | own self-review before the audit | answers to AUDIT.md questions 1–17, fixes | `v0.7.0` → `v0.8.0` | [2026-10-pre-audit-review.md § Self-review](2026-10-pre-audit-review.md#self-review-for-080-2026-10-18), [AUDIT.md § 4](../AUDIT.md#4-our-answers--please-verify) |
| 2026-10 | external pre-audit review (informal, no written report) | design and code review of `v0.6.0` | reviewed `v0.6.0`, fixes in `v0.7.0` | [2026-10-pre-audit-review.md](2026-10-pre-audit-review.md) |

Reporting a vulnerability: [SECURITY.md](../SECURITY.md). Brief for a formal review: [AUDIT.md](../AUDIT.md).
