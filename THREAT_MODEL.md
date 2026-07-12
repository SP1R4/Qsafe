# Qsafe Threat Model

This document states, as plainly as possible, **what Qsafe protects, what it
does not, and the assumptions it relies on.** Read it before trusting Qsafe with
anything that matters. Honesty about limitations is part of the security
posture — a guarantee that isn't written down here is a guarantee Qsafe does not
make.

Applies to the **QSAFE005** file format (Qsafe 5.x).

---

## 1. What Qsafe is

A command-line tool that encrypts a file (or directory) so only the holder(s) of
the corresponding secret key can read it, and that can produce detached
signatures. Key establishment is **hybrid**:

- **X25519** (classical Diffie–Hellman, RFC 7748), and
- **ML-KEM-1024** (post-quantum KEM, NIST FIPS 203)

Their two shared secrets are concatenated and run through **HKDF-SHA256** to
derive a key-encryption key. A random per-file **content key (CEK)** seals the
payload with **AES-256-GCM**. The CEK is wrapped once per recipient. Signatures
use **ML-DSA-87** (NIST FIPS 204). Secret keys are wrapped at rest with a key
derived from a passphrase via **scrypt**.

---

## 2. Assets

1. **Plaintext confidentiality** — the contents of encrypted files.
2. **Plaintext/ciphertext integrity** — detection of any modification.
3. **Secret keys** — the long-term KEM/signing secret keys on disk.
4. **Sender authenticity** — for signed files, that a file came from a given key.

---

## 3. Adversaries considered

| Adversary | Capability | Defended? |
|:--|:--|:--|
| Passive eavesdropper | Reads ciphertext in transit/at rest | ✅ confidentiality |
| Active network attacker | Modifies/replaces ciphertext bytes | ✅ detected (AEAD) |
| **Future quantum attacker** | Recorded ciphertext today, runs Shor/Grover later | ✅ ML-KEM layer |
| Cryptanalytic break of *one* primitive | Breaks X25519 **or** ML-KEM (not both) | ✅ hybrid design |
| Thief of a `.qsafe` file | Has ciphertext only | ✅ needs a secret key |
| Thief of a secret-key file | Has the wrapped key, not the passphrase | ⚠️ only as strong as scrypt + passphrase |
| Malicious recipient (multi-recipient) | Is one of several recipients | ⚠️ can read the file (by design) and learns the recipient count |
| Attacker on your machine while you decrypt | Reads memory/keystrokes/plaintext | ❌ out of scope |

---

## 4. Security goals and how they are met

- **Confidentiality (classical + post-quantum):** the payload key is derived
  from *both* an X25519 DH and an ML-KEM encapsulation. An attacker must break
  **both** to recover plaintext. "Harvest now, decrypt later" is mitigated by
  the ML-KEM layer.
- **Integrity + authentication of the container:** AES-256-GCM authenticates the
  payload, and the **entire header** — magic, recipient count, payload nonce,
  and every recipient record — is fed as Additional Authenticated Data (AAD).
  Reordering, swapping, truncating, or editing any of it causes decryption to
  fail.
- **Per-recipient wrap integrity:** each recipient record wraps the CEK under
  AES-256-GCM; a tampered ephemeral key or KEM ciphertext yields a wrong
  key-wrapping key and the wrap tag fails to verify.
- **Sender authenticity (signatures):** ML-DSA-87 over the SHA-256 digest of the
  file. `verify-sig` returns success only for a valid signature by the named
  public key.
- **Key-at-rest protection:** secret keys are sealed with AES-256-GCM under a
  scrypt-derived key (default N=2¹⁵, tunable via `--scrypt-cost`); the scrypt
  parameters are authenticated, so they cannot be silently downgraded.

### Cryptographic details worth auditing

- **Hybrid combiner:** `HKDF-SHA256(ikm = X25519_dh ‖ ML-KEM_ss, info =
  "qsafe-v5-hybrid-kek")`. Concatenation-then-KDF is a standard hybrid
  construction; the security relies on HKDF acting as a good extractor.
- **Nonces:** the payload CEK is random per file and its 96-bit GCM nonce is
  random; each per-recipient wrap uses an independent random 96-bit nonce. With
  random keys per file, nonce-reuse risk is negligible.
- **Ephemerality:** each recipient record uses a fresh ephemeral X25519 key.
  Note this does **not** provide forward secrecy against compromise of the
  *long-term recipient secret key* (see §6).

---

## 5. What Qsafe deliberately does NOT hide (metadata leakage)

An observer of a `.qsafe` file learns:

- **Approximate plaintext size** — ciphertext length ≈ plaintext + a fixed
  overhead. `--pad` (v8+) reduces this to a Padmé bucket (the length then
  leaks only O(log log n) bits of the true size, at ≤ ~12% overhead); without
  `--pad` the size is essentially exact.
- **The number of recipients** — the header stores the recipient count, and each
  recipient adds a fixed-size record. Recipient *identities* are not stored, but
  the count and the file's growth with more recipients are visible.
- **That the file is a Qsafe file** — the `QSAFE007` magic is in cleartext.
- **For directories:** the structure and per-file sizes (each file is encrypted
  individually).

The original filename, permission bits, and mtime ARE encrypted (inside the
authenticated payload) and are not leaked. So is the embedded sender
signature (`--sign-with`): whether a file is signed, and by whom, is visible
only to someone who can decrypt it.

---

## 6. Non-goals and known limitations

These are real and intentional gaps. If your threat model needs any of them,
Qsafe is the wrong tool.

1. **No forward secrecy for long-term keys.** Decryption requires the long-term
   recipient secret key. If that key (and passphrase) are later compromised,
   **all** past files encrypted to it can be decrypted. The ephemeral X25519 key
   protects the *sender's* side only.
2. **Release of unverified plaintext (RUP).** The current format (QSAFE007) is
   **framed**: the payload is a sequence of 64 KiB frames, each authenticated
   independently, and **each frame's plaintext is released only after that
   frame's tag verifies** — for both files and pipes, in constant memory. No
   unauthenticated byte is ever released. The framing also makes truncation (a
   missing final frame) and reordering detectable.
   - **Caveat (prefix release):** for a multi-frame file, earlier frames are
     released before a later corrupt/truncated frame is detected. Every released
     byte was authenticated, but a mid-stream failure means a verified *prefix*
     may already have reached the consumer. A single-frame (small) file is
     all-or-nothing; a large file is prefix-or-error. This is the standard,
     unavoidable semantics of streaming AEAD. **Check the exit code** before
     treating output as complete.
   - **file output** is additionally `remove()`d on failure, so no partial
     plaintext file persists after Qsafe exits (a concurrent reader could still
     observe it during the run).
   - **Legacy QSAFE005** files (still decryptable) are not framed; for those the
     pipe path buffers the whole payload in memory and releases nothing on
     failure (all-or-nothing, at the cost of RAM).
3. **No protection of a compromised host.** Qsafe assumes the machine is trusted
   at the moment of use. Malware, keyloggers, swap/coredumps, or another local
   user can defeat it. Sensitive buffers are wiped with `OPENSSL_cleanse`, but
   this is best-effort, not a guarantee against a privileged adversary.
4. **Passphrase strength is your responsibility.** scrypt slows guessing, but a
   weak passphrase on a stolen key file is the weakest link.
5. **The standard container (`encrypt`/`decrypt`) offers no deniability or
   anti-traffic-analysis.** It has a visible `QSAFE007` magic, a visible
   recipient count, and no plausible-deniability mode; `--pad` blunts *size*
   leakage and nothing else. A **separate, opt-in** format —
   `qsafe vault` (experimental, [docs/HIDDEN_VOLUMES.md](docs/HIDDEN_VOLUMES.md))
   — does provide deniable hidden volumes, but it is a distinct symmetric-only
   container with its own threat model and its own limitations (notably: broken
   by an adversary holding two snapshots of the same container). It is not a
   property of the normal encrypt path, and nothing here retrofits deniability
   onto a `.qsafe` file.
6. **No replay/freshness context.** Qsafe authenticates that a file is intact and
   addressed to you; it does not bind a file to a time, sequence, or context.
   Re-sending an old valid ciphertext is not detected by Qsafe itself.
7. **No protection against a malicious recipient** in multi-recipient mode — any
   listed recipient can read the file and could redistribute the plaintext.
8. **Signatures sign a SHA-256 digest**, not the raw message. SHA-256 collision
   resistance is assumed (this is standard hash-then-sign).
9. **Unsigned files carry no sender authenticity.** Anyone with your public
   key can produce a ciphertext that decrypts cleanly. `--sign-with` (v8+)
   closes this: the embedded ML-DSA-87 signature binds the contents *and* the
   recipient set to the signer, and decrypt fails closed on a bad signature.
   Note a legitimate *recipient* can always decrypt and re-encrypt the
   contents unsigned — the signature proves origin, not exclusivity.
10. **Key shares are unencrypted key material.** `split-key` shares
    reconstruct the secret key *without* a passphrase (that is their purpose:
    passphrase-loss recovery). Below the threshold they reveal nothing
    (information-theoretic), but each share must be guarded like a key
    fragment. The share files record a SHA-256 digest of the secret blob for
    integrity, which also lets someone holding a *candidate* secret blob
    confirm it matches a share set.

---

## 7. Trust assumptions

Qsafe's guarantees hold only if:

- **The primitives are secure** as specified: X25519, ML-KEM-1024, ML-DSA-87,
  AES-256-GCM, HKDF-SHA256, scrypt, SHA-256. Weaknesses in these are upstream
  (OpenSSL / liboqs / NIST), not Qsafe.
- **The CSPRNG is sound.** Qsafe relies on OpenSSL `RAND_bytes` (and liboqs'
  RNG) for keys, the CEK, and all nonces. A broken/weakly-seeded RNG breaks
  confidentiality.
- **liboqs is built correctly.** The post-quantum implementations come from
  liboqs; use a release build and track its advisories.
- **The host is trusted at time of use** (see §6.3).

---

## 8. Assurance measures in this repository

- **Known-answer tests** for SHA-256, HKDF-SHA256, scrypt, the QSAFE007 frame
  AEAD, and the `vault` salt derivation, with values computed independently of
  Qsafe's code (`tests/test_crypto_utils.c`), plus frozen container fixtures
  for both formats.
- **AddressSanitizer + UndefinedBehaviorSanitizer + Valgrind** over the test
  suite in CI (`.github/workflows/hardening.yml`).
- **Fuzzing harnesses** over the untrusted-input parsers — the QSAFE
  decrypt/inspect/dearmor path (`tests/fuzz_decrypt.c`) and the `vault`
  hidden-volume reader (`tests/fuzz_vault.c`) — via `make fuzz` / `make
  fuzz-vault`, with CI smoke runs and OSS-Fuzz build targets.
- **End-to-end tests** for tamper rejection, wrong-key rejection,
  multi-recipient isolation, signature forgery rejection, and `vault`
  deniability (wrong-passphrase and empty-region failures are byte-for-byte
  identical) (`tests/test.sh`).

These raise confidence; they are **not** a substitute for an independent audit
(see [SECURITY.md](SECURITY.md)).

---

*If you find a gap between what this document claims and what the code does,
that is a security bug — please report it (see SECURITY.md).*
