# Contributing to Qsafe

Thanks for your interest. Qsafe is a cryptographic tool, so contributions are
held to a high bar for correctness and clarity.

## Reporting security issues

**Do not** open a public issue for vulnerabilities. Follow the process in
[SECURITY.md](SECURITY.md). See [THREAT_MODEL.md](THREAT_MODEL.md) for what is
and isn't in scope.

## Building

```bash
# macOS
brew install openssl@3 liboqs
make

# Linux (build liboqs from source, see README)
make
```

## Running the checks before you push

Every PR must pass these (CI enforces them):

```bash
make test                                   # unit + integration suite
make EXTRA_CFLAGS="-Werror"                 # no compiler warnings allowed
cppcheck --enable=warning,performance,portability --std=c11 \
  --inline-suppr --error-exitcode=1 --suppress=missingIncludeSystem \
  -Iinclude src/crypto_utils.c src/main.c   # static analysis
```

Recommended for anything touching parsing or memory:

```bash
# AddressSanitizer + UndefinedBehaviorSanitizer
ASAN_OPTIONS=detect_leaks=0 make test \
  EXTRA_CFLAGS="-fsanitize=address,undefined -fno-sanitize-recover=all -g -O1" \
  EXTRA_LDFLAGS="-fsanitize=address,undefined"

# Fuzz the untrusted-input parsers (needs clang/libFuzzer)
make fuzz FUZZ_CC=clang
tests/fuzz_decrypt -max_len=8192 -max_total_time=60 corpus/
```

CI runs the same: `ci.yml` (build with `-Werror` + tests), `hardening.yml`
(ASan/UBSan, Valgrind, fuzz smoke), and `quality.yml` (cppcheck).

## Coding guidelines

- **Match the surrounding style.** C11, 4-space indent, braces on the same line.
- **Never hand-roll crypto.** Use OpenSSL and liboqs primitives. New algorithms
  go through their vetted APIs, never bespoke implementations.
- **Treat all file contents as untrusted.** Bounds-check every read; size every
  buffer from a validated length; reject malformed input rather than coping.
- **Authenticate before acting.** Do not release plaintext or trust parsed
  values before the relevant tag/signature verifies.
- **Wipe secrets.** Use `OPENSSL_cleanse` on key material, derived keys, and
  passphrase buffers before they go out of scope.
- **Cover new behavior with tests.** Add to `tests/test_crypto_utils.c` (unit)
  and/or `tests/test.sh` (end-to-end), including negative/tamper cases.

## On-disk format changes

Any change to the encrypted-file or key-file layout is a **breaking change**.
Bump the version magic, update [THREAT_MODEL.md](THREAT_MODEL.md) and the README
format spec, and add round-trip + rejection tests.

## Commits & PRs

- Keep commits coherent and scoped; write a clear message explaining *why*.
- Open PRs against the active development branch; describe the change, the
  testing done, and any security implications.
- Update `CHANGELOG.md` under `[Unreleased]`.
