# Security Policy

## ⚠️ Status: not independently audited

Qsafe has **not** undergone an independent security audit. It is built on
well-reviewed cryptographic primitives (OpenSSL, [liboqs](https://github.com/open-quantum-safe/liboqs))
and ships with known-answer tests, sanitizer/Valgrind CI, and a fuzzing harness,
but the surrounding code has not been formally reviewed by a third party.

Until that changes, treat Qsafe as suitable for personal use and experimentation
by people who understand the trade-offs — not as a turnkey replacement for an
audited tool where the cost of failure is high. See [THREAT_MODEL.md](THREAT_MODEL.md)
for exactly what Qsafe does and does not protect.

## Supported versions

Security fixes are applied to the latest released major version only.

| Version | Supported |
|:--|:--|
| 5.x | ✅ |
| ≤ 4.x | ❌ (format superseded; see README "Compatibility") |

## Reporting a vulnerability

**Please do not open a public issue for security vulnerabilities.**

- Preferred: open a [GitHub private security advisory](https://docs.github.com/en/code-security/security-advisories/guidance-on-reporting-and-writing-information-about-vulnerabilities/privately-reporting-a-security-vulnerability)
  on this repository ("Security" tab → "Report a vulnerability").
- Alternatively, email the maintainer (see the repository profile) with the
  subject line `QSAFE SECURITY`.

Please include: affected version/commit, a description, and ideally a minimal
reproducer (a crafted input file is ideal — see the fuzzing harness in
`tests/fuzz_decrypt.c`).

### What to expect

This is a personal open-source project, not a funded program, so response is
best-effort:

- Acknowledgement: within ~7 days.
- Fix or mitigation plan: depends on severity and complexity.
- Credit: reporters are credited in the release notes unless they prefer not to be.

Please allow a reasonable window for a fix before any public disclosure.

## Scope

In scope:
- Memory-safety bugs (the C decrypt/dearmor/inspect parsers handle untrusted input).
- Cryptographic mistakes: nonce/IV reuse, missing authentication, weak KDF
  parameters, mis-bound additional data, downgrade issues.
- Logic flaws that let an unauthorized party read or forge data.

Out of scope (by design — see the threat model):
- Metadata that Qsafe intentionally does not hide (file size, recipient count).
- Passphrase strength and protection of key files on a compromised host.
- Weaknesses in the underlying primitives themselves (report those upstream to
  OpenSSL / liboqs / NIST).
