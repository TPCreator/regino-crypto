# Security

**Found a vulnerability?** Please report it privately. Do not open a public issue.

1. **Preferred:** the **Security › Report a vulnerability** tab of this repository (GitHub private
   vulnerability reporting). You get a private thread with us and a CVE can be requested from there.
2. **Fallback** (no GitHub account, or the tab is unavailable): e-mail **security@regino.sk** with the
   subject "regino-crypto security". If you need encryption, ask for a key in a first message.

We confirm receipt within **5 business days** and give a first assessment within **10 business days**.

**Scope:** the code in this repository (`vault/`, `keys/`, `ts/`, `tools/`). Apps that use this core
have their own reporting process. Findings against the apps' servers or web pages are forwarded.

**Disclosure:** we fix confirmed issues in the next release and publish an advisory with credit to the
reporter (if wanted). We ask reporters to hold details for **90 days** or until the fixed version is
released, whichever comes first; a longer delay is agreed case by case. Known findings from reviews and
their status are listed in [`audits/`](audits/).

**Not in scope:** issues that require an attacker inside the unlocked user session or malware on the
device, the user-switch PIN as a data-protection boundary (it is not one, see `AUDIT.md`), and
third-party libraries except where we use them incorrectly.
