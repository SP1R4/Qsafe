# Qsafe — Reviewer's Guide

This document helps an independent reviewer assess Qsafe efficiently. It points
at the crypto-critical code, states the assumptions worth attacking, and lists
what has already been checked so you don't repeat it.

Qsafe is **not yet independently audited** — that is exactly what this guide is
meant to enable. Findings: please follow [SECURITY.md](../SECURITY.md).

## 1. What Qsafe is (1 paragraph)

A C command-line tool that encrypts files to a **hybrid** recipient key
(X25519 + ML-KEM-1024), authenticates with AES-256-GCM, supports multiple
recipients and ML-DSA-87 detached signatures, and wraps secret keys at rest with
scrypt. The on-disk formats are specified byte-for-byte in
[FORMAT.md](FORMAT.md); the security goals and non-goals are in
[THREAT_MODEL.md](THREAT_MODEL.md). Read those two first.

## 2. Build, test, fuzz

```bash
# Build (needs OpenSSL 3 + liboqs 0.12)
make

# Functional tests (unit + integration)
make test

# Sanitizers
ASAN_OPTIONS=detect_leaks=0 make test \
  EXTRA_CFLAGS="-fsanitize=address,undefined -fno-sanitize-recover=all -g -O1" \
  EXTRA_LDFLAGS="-fsanitize=address,undefined"

# Fuzz the untrusted-input parsers (needs clang/libFuzzer)
make fuzz FUZZ_CC=clang
tests/fuzz_decrypt -max_len=8192 corpus/
```

## 3. Where the crypto lives (code map)

All cryptography is in `src/crypto_utils.c` (CLI/arg-parsing is in
`src/main.c`). Key functions:

| Area | Function(s) | Notes |
|:--|:--|:--|
| Hybrid identity gen | `crypto_generate_identity` | X25519 (OpenSSL) + ML-KEM (liboqs) |
| Per-recipient key wrap | `hybrid_wrap_cek` / `hybrid_unwrap_cek` | `HKDF(dh ‖ kem_ss)` → KEK → AES-GCM wrap of the CEK |
| KDF | `hkdf_sha256`, `crypto_derive_aes_key` | HKDF-SHA256; empty salt (RFC 5869 zero salt) |
| Framed payload (v6) | `crypto_encrypt_file`, `crypto_decrypt_file` | per-frame AES-GCM; `frame_nonce` = counter ‖ final-flag |
| Legacy payload (v5) | `crypto_decrypt_file` (`is_v6 == 0` path) | single AES-GCM, tag held back; read-only |
| Frame AEAD | `gcm_seal_aad` / `gcm_open_aad` | header bound as AAD on frame 0 |
| Secret-key wrap | `crypto_save_secret_key` / `crypto_load_secret_key` | scrypt (`QSAFEK01` header, params authenticated as AAD) |
| Signatures | `crypto_sign_file` / `crypto_verify_signature` | ML-DSA-87 over SHA-256(file) |
| Output sink / metadata | `dec_sink_*` | parses the 272-byte metadata block; path-traversal defense |
| Armor | `crypto_armor` / `crypto_dearmor` | base64 transport only |

## 4. Highest-value things to attack

These are the assumptions we most want challenged:

1. **The hybrid combiner.** `KEK = HKDF-SHA256(IKM = X25519_dh ‖ ML-KEM_ss,
   info="qsafe-v5-hybrid-kek")`. Is concatenation-then-HKDF a sound combiner
   here? Any way to make one layer's compromise leak the KEK?
2. **Framed-AEAD integrity (v6).** Nonce = `000000 ‖ u64_be(counter) ‖
   final_flag`; the CEK is random per file. Can frames be reordered, dropped,
   duplicated, truncated, or the stream extended without detection? Is the
   "non-final frames are always full, final is strictly shorter" rule a sound
   length-delimiter? (See FORMAT.md §2.3/§2.5.)
3. **Header binding.** The header (magic, recipient count, all recipient
   records) is AAD on frame 0 only. Is binding it to frame 0 sufficient, or can
   a recipient set / count be manipulated?
4. **Parser memory safety.** `crypto_decrypt_file`, `crypto_inspect_file`,
   `crypto_dearmor` consume fully attacker-controlled bytes. The recipient count
   is a single byte (bounded 1..16); record/frame sizes are derived from it.
   Look for under-allocation, integer issues, OOB.
5. **Release of unverified plaintext.** Documented in THREAT_MODEL §6.2: framed
   mode releases each frame after its tag verifies (so a verified *prefix* can be
   emitted before a later corrupt frame is caught). Is this characterized
   correctly, and is the file-output delete-on-failure race acceptable?
6. **Secret-key wrap.** scrypt params live in an authenticated `QSAFEK01` header;
   bounds-checked on load. Any downgrade or parameter-confusion path?
7. **Randomness / nonce uniqueness.** All keys, the CEK, ephemeral X25519 keys,
   and wrap nonces come from `RAND_bytes`. Any path that reuses a (key, nonce)?

## 5. Already checked (so you can skip)

- Known-answer vectors for SHA-256, HKDF-SHA256, scrypt (computed independently
  of Qsafe) — `tests/test_crypto_utils.c`.
- ASan + UBSan + Valgrind over the full suite (CI: `hardening.yml`).
- libFuzzer over the parsers + a continuous-fuzz job (`fuzz.yml`).
- CodeQL + cppcheck + `-Werror` (CI).
- Tamper / truncation / reorder / wrong-key / non-recipient rejection, and v5↔v6
  interop, in `tests/test.sh`.

## 6. Out of scope

- The primitives themselves (X25519, ML-KEM-1024, ML-DSA-87, AES-GCM, HKDF,
  scrypt, SHA-256) — report those upstream to OpenSSL / liboqs / NIST.
- Metadata that Qsafe intentionally does not hide (file size, recipient count).
- Host-compromise / side-channel resistance beyond what the libraries provide.

Thank you — clear, reproducible findings (ideally a crafted input file) are the
most useful thing you can send.
