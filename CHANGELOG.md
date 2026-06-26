# Changelog

All notable changes to Qsafe are documented here. The format is based on
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and this project
aims to follow [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added
- **age interop** (`age-keygen` / `age-encrypt` / `age-decrypt`): read and write
  [age](https://age-encryption.org) v1 files for X25519 recipients, byte-compatible
  with the `age` tool (validated both directions in CI). Note: age is a *classical*
  X25519 format with no post-quantum protection — this is for ecosystem
  compatibility, not PQ security.
- **`libqsafe` + Python bindings**: a stable C library API (`include/libqsafe.h`,
  `make lib` → `libqsafe.{so,dylib,dll}`) around the engine, and a `ctypes`
  Python module (`python/qsafe.py`) with file and byte-buffer helpers
  (`encrypt_bytes`/`decrypt_bytes`). New CI job runs the Python tests.
- **Keyring / named identities** under `~/.qsafe` (override `$QSAFE_HOME`):
  `keys` subcommand (`list`/`path`/`import`/`remove`), `--identity <name>` to
  use/create a keyring identity, and `-r <name>` to address recipients by name
  (a real file path still wins).
- **Windows support** (MSYS2 / MinGW-w64): a platform shim (`include/platform.h`)
  for binary stdio, no-echo console input, temp files, `mkdir`, `realpath`,
  `chmod`, and `utime`; Makefile auto-detects MinGW and builds `qsafe.exe`; a
  Windows CI job builds and tests on `windows-latest`.
- CodeQL static analysis workflow (results in the repo Security tab).
- Continuous-fuzzing workflow: daily + on parser changes, with a corpus
  persisted across runs and crash inputs uploaded as artifacts.
- **Windows release binaries**: the release workflow now also builds, tests,
  signs, and attaches a self-contained Windows `x86_64` archive (with the MinGW
  runtime DLLs); `workflow_dispatch` allows validating the pipeline without a tag.
- `docs/REVIEW.md`: a reviewer's guide (code map + assumptions to attack) to
  enable an independent security review; concrete reporting channel in SECURITY.md.

## [6.0.0] - 2026-06-25

Default encrypted-file format is now the framed **QSAFE006**. Not a breaking
change for reading (decrypt still accepts QSAFE005), but `encrypt` output is
unreadable by 5.x builds.

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

[Unreleased]: https://github.com/SP1R4/Qsafe/compare/v6.0.0...HEAD
[6.0.0]: https://github.com/SP1R4/Qsafe/compare/v5.0.0...v6.0.0
[5.0.0]: https://github.com/SP1R4/Qsafe/releases/tag/v5.0.0
[4.0.0]: https://github.com/SP1R4/Qsafe/releases/tag/v4.0.0
[3.0.0]: https://github.com/SP1R4/Qsafe/releases/tag/v3.0.0
