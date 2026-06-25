# Changelog

All notable changes to Qsafe are documented here. The format is based on
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and this project
aims to follow [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added
- **Framed AEAD (QSAFE006):** encrypt now writes a framed format — the payload
  is a sequence of 64 KiB AES-256-GCM frames (counter+final-flag nonces), giving
  constant-memory streaming *and* verify-before-release (no whole-payload
  buffering), with truncation/reordering detection.
- Dual-read: decrypt accepts both QSAFE006 and the legacy QSAFE005, verified by
  an interop test fixture produced by the v5.0.0 binary.
- CI quality gates: `-Werror` build, cppcheck static analysis (`quality.yml`).
- `CONTRIBUTING.md` with build/test/static-analysis/security guidelines.
- `docs/FORMAT.md`: complete byte-level on-disk format specification.

### Fixed
- README: corrected per-file overhead (21-byte header prefix, not 33; 1969
  bytes for a single recipient).

## [5.0.0] - 2026-06-25

Major release. **Breaking:** the on-disk format is now `QSAFE005` and is
incompatible with v4 files — regenerate keypairs and re-encrypt (decrypt old
files with a 4.x build first).

### Added
- **Hybrid key establishment** — every identity carries both an X25519 and an
  ML-KEM-1024 keypair; their shared secrets are combined via HKDF-SHA256. A file
  is confidential unless *both* layers are broken.
- **Multi-recipient encryption** — `-r/--recipient` (repeatable); a random
  content key seals the payload and is wrapped per recipient.
- **Detached signatures** — `sign-keygen`, `sign`, `verify-sig` using ML-DSA-87.
- **New commands** — `verify`, `rekey`, `inspect`.
- **New options** — `--check`, `--armor`, `--scrypt-cost <log2N>`.
- Public-key SHA-256 fingerprints on `keygen` and `inspect`.
- Self-describing, authenticated scrypt-cost header on secret-key files.
- Threat model, security policy, man page, shell completions.
- Hardening: ASan/UBSan + Valgrind CI, libFuzzer harness, known-answer tests.

### Changed
- Encrypted-file format → `QSAFE005`; secret-key files gain a `QSAFEK01` header
  (legacy headerless keys still load).
- Decrypt pipe path now buffers and verifies before releasing plaintext, so a
  tampered file emits nothing to stdout.

### Security
- The entire file header (magic, recipient count, nonce, recipient records) is
  authenticated as AEAD additional data.

## [4.0.0] - 2026-06-21
- Durable public-key workflow (one-time `keygen`); `QSAFE004` format; stdin/
  stdout piping; encrypted metadata block; cross-platform build.

## [3.0.0] - 2026-05-21
- Switched to ML-KEM-1024; scrypt-wrapped secret keys; streaming decryption;
  CI and expanded tests.

[Unreleased]: https://github.com/SP1R4/Qsafe/compare/v5.0.0...HEAD
[5.0.0]: https://github.com/SP1R4/Qsafe/releases/tag/v5.0.0
[4.0.0]: https://github.com/SP1R4/Qsafe/releases/tag/v4.0.0
[3.0.0]: https://github.com/SP1R4/Qsafe/releases/tag/v3.0.0
