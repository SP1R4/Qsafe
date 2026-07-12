# Changelog

All notable changes to Qsafe are documented here. The format is based on
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and this project
aims to follow [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added
- **Deniable hidden volumes** (`qsafe vault init|write|read|footprint`,
  *experimental*): a header-less container of pure CSPRNG randomness holding
  independently-passphrased slots at caller-chosen `(offset, capacity)`
  coordinates. A slot's ciphertext is indistinguishable from the surrounding
  random filler, so a coerced decoy passphrase cannot prove a second, hidden
  payload exists. Symmetric/passphrase-only and deliberately separate from the
  QSAFE007 public-key container — ML-KEM ciphertext is not proven
  indistinguishable from random, so it cannot back a deniable format. Reuses
  the audited framed-AEAD primitives and scrypt KDF; wrong-passphrase and
  empty-region reads are byte-for-byte indistinguishable. Full design,
  format, and threat model in [docs/HIDDEN_VOLUMES.md](docs/HIDDEN_VOLUMES.md).

- **Vault v2 — passphrase-addressed volumes** (`vault create|add|ls|extract|rm`,
  *experimental*, [docs/HIDDEN_VOLUMES_V2.md](docs/HIDDEN_VOLUMES_V2.md)): a
  passphrase alone locates its **anchor** (a slot at a passphrase-derived
  offset) whose encrypted **directory** lists that volume's named slots — so v2
  no longer requires remembering per-slot `(offset, capacity)`. Every mutating
  command is a **whole-container rewrite**: the entire file is re-randomized and
  each preserved slot re-sealed under a fresh per-write nonce salt, so a
  byte-level diff of two container snapshots leaks nothing (closing v1's
  two-snapshot weakness). A write preserves only the volumes whose passphrase it
  is given (target + `--keep`); omitting one destroys it (the VeraCrypt
  outer-clobbers-hidden tension, made explicit). Adds an exported
  `crypto_hkdf_sha256` (general HKDF with explicit salt/info).
- **Vault v2 two-factor keyfile** (`--keyfile <path>`): mixes a
  `SHA-256`-derived keyfile key into both the anchor-location and slot-key
  derivations, so the passphrase alone can neither find nor open a volume — both
  factors are independently required. Opt-in and backward-compatible: with no
  keyfile, every derivation is byte-identical to before. The anchor-offset
  reduction was also changed to a constant-time Lemire multiply-shift (from a
  data-dependent `x mod m`).
- **Vault v2 `passwd`** (`vault passwd <container> --new-passphrase-file`):
  changes a volume's passphrase in place — reads the volume under the current
  passphrase and re-seals its slots and relocates its anchor under the new one,
  in one whole-container rewrite, so the old passphrase opens nothing
  afterward. Slot content and `--keep` volumes are preserved.
- **Vault v2 auto-placement**: `vault add`'s `--offset` and `--capacity` are now
  optional. Capacity defaults to an exact fit for the content; the offset is
  auto-chosen as the lowest free gap avoiding every slot/anchor the command can
  see (the target volume's and each `--keep` volume's). Explicit
  `--offset`/`--capacity` still work for manual placement.
- **Vault v2 in libqsafe + Python**: `qsafe_vault_create` / `_add` / `_extract`
  / `_remove` (single-volume, no-keyfile) exposed through the C API and the
  Python module (`qsafe.vault_create`/`vault_add`/`vault_extract`/`vault_remove`),
  so volumes are embeddable, not CLI-only.
- **Vault v2 overflow directories**: a volume can now hold up to 181 slots (was
  46). When a directory block fills, the block spends one record on a
  flag-marked pointer to a chained overflow block. No format-version bump — a
  volume of ≤ 46 slots serializes byte-identically to before, so existing
  containers, the frozen fixture, and the directory KAT are unaffected.
- **Vault v2 Argon2id KDF** (`--argon2`): opt-in, derives passphrase keys with
  Argon2id (RFC 9106) instead of scrypt — memory-hard, GPU/ASIC-resistant, and
  data-independent (the *id* variant). Mixed into both the anchor location and
  slot keys; `--scrypt-cost` is reused as the Argon2 memory cost (2^c KiB). The
  KDF choice is remembered out-of-band (headerless container); the scrypt path
  is byte-identical, so existing containers/fixtures/KATs are unaffected. Adds
  an exported `crypto_derive_key_argon2id`, KAT-pinned against the `openssl kdf`
  CLI. Requires OpenSSL 3.2+.
- **`secrets` — encrypted credential store** (`secrets set|get|list|rm`): a
  password-manager-style key-value store layered on a single vault volume,
  inheriting its deniability and honouring `--keyfile`/`--argon2`/cost. `set`
  reads the value from stdin (or prompts without echo on a tty) and replaces an
  existing key in one rewrite; `get` writes the value to stdout. Values move
  only in memory — a plaintext credential never touches a temp file. Default
  store `~/.qsafe/secrets.bin`, overridable with `--store`.
- **Man page + shell completions** now cover every `vault` and `secrets`
  subcommand and option.

### Assurance
- Vault known-answer tests (salt derivation, `ciphertext_len`, frame AEAD with
  coordinate AAD, scrypt), a frozen fixture container, deniability integration
  tests, a dedicated fuzz harness (`tests/fuzz_vault.c`, `make fuzz-vault`,
  wired into `fuzz.yml`/`hardening.yml`/OSS-Fuzz), and constant-time coverage
  of the AES-GCM frame key and vault-cost scrypt (`tests/ct_check.c`).
- Vault v2 KATs (anchor offset, v2 slot frame key, directory serialization,
  RFC 5869 HKDF vector), directory parser hostile-input rejections, and
  integration tests including a direct check that a mutating write re-randomizes
  ≥99% of the container (the snapshot-diff property) and that `--keep` preserves
  while omission destroys — all clean under ASan/UBSan.

## [8.0.0] - 2026-07-02

The write format moves to **QSAFE007** (decrypt still reads QSAFE006/005, so
nothing is stranded; v5/v6/v7 fixtures are pinned in CI). The QSAFE007 layout
is now **frozen** and specified with test vectors (docs/FORMAT.md §10).

### Added
- **Embedded sender authentication** (`encrypt --sign-with <sk>`): an
  ML-DSA-87 signature over (header ‖ metadata ‖ contents) travels *inside* the
  encrypted payload and is verified automatically on decrypt/verify — the
  signer's identity stays hidden from anyone who cannot decrypt. `--signer
  <pk>` pins the expected signer; an invalid signature or the wrong signer
  fails closed and removes any output.
- **Size-hiding padding** (`encrypt --pad`): random padding to the file's
  [Padmé](https://petsymposium.org/2019/files/papers/issue4/popets-2019-0056.pdf)
  bucket, so the ciphertext length leaks only O(log log n) bits of the true
  size (≤ ~12% overhead). Stripped transparently on decrypt.
- **Shamir key recovery** (`split-key --threshold t --shares n` /
  `join-key <shares...>`): information-theoretic secret sharing of the secret
  key over GF(256). Shares carry a random set-id (foreign shares can't be
  combined) and a digest (a corrupt share fails closed); `join-key` re-wraps
  under a freshly confirmed passphrase.
- **`age-plugin-qsafe`** — post-quantum recipients for the whole age
  ecosystem: implements the C2SP age plugin protocol, so `age -r
  age1qsafe1...` encrypts to a hybrid X25519 + ML-KEM-1024 identity from any
  age client (validated against age 1.3.1, including mixed native+plugin
  recipient files). `--keygen` / `-y` follow age-keygen conventions.
- **Windows keychain backend**: `--keychain` now works on Windows via DPAPI
  (user-scoped `CryptProtectData`, sealed blob under `%APPDATA%\qsafe\`).
- **PyPI packaging**: `pip install qsafe` — per-platform wheels with libqsafe
  bundled (cibuildwheel; published on tags via PyPI trusted publishing).
- **Known-answer vectors + frozen fixtures**: independently generated KATs for
  the hybrid KEK, frame AEAD, Padmé buckets, and the age-plugin label; frozen
  plain/signed/padded QSAFE007 fixtures pin the reader.
- **Supply-chain hardening**: SLSA build provenance on releases
  (`gh attestation verify`), a reproducible-build CI gate (double build must
  be byte-identical), a ctgrind-style constant-time valgrind harness
  (`make ct`, advisory CI job), and OSS-Fuzz project files (`oss-fuzz/`)
  ready for enrollment.

### Changed
- `encrypt` writes QSAFE007 (288-byte metadata block carrying content length,
  padding length, and feature flags). Readers up to 7.x cannot read new
  files; decrypt reads v7/v6/v5.
- Object files now depend on the public headers in the Makefile, so header
  changes can no longer produce stale-ABI builds.

## [7.0.0] - 2026-06-26

A feature release. **No on-disk format change** — `encrypt` still writes
QSAFE006 and decrypt reads QSAFE006/005, so v6 files and keypairs keep working.
Everything below is additive.

### Added
- **OS keychain-backed passphrase** (`--keychain`): the secret-key passphrase can
  be generated and stored in the OS keychain instead of typed. macOS uses the
  Keychain via the Security framework (Secure-Enclave-protected on supported
  hardware); Linux (libsecret) and Windows (DPAPI) are documented stubs for now.
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

[Unreleased]: https://github.com/SP1R4/Qsafe/compare/v7.0.0...HEAD
[7.0.0]: https://github.com/SP1R4/Qsafe/compare/v6.0.0...v7.0.0
[6.0.0]: https://github.com/SP1R4/Qsafe/compare/v5.0.0...v6.0.0
[5.0.0]: https://github.com/SP1R4/Qsafe/releases/tag/v5.0.0
[4.0.0]: https://github.com/SP1R4/Qsafe/releases/tag/v4.0.0
[3.0.0]: https://github.com/SP1R4/Qsafe/releases/tag/v3.0.0
