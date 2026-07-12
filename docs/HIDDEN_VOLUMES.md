# Hidden Volumes (`qsafe vault`) — Design and Format Specification

Status: **experimental**, v1. Command: `qsafe vault init|write|read|footprint`.

> **Next stage:** the v1 primitive here is coordinate-addressed — you supply
> and remember every `(offset, capacity, cost)`. The **anchor + directory**
> architecture that lets a passphrase alone open a whole named *volume*, and
> the write-whole-container change that closes the two-snapshot weakness, are
> specified in [HIDDEN_VOLUMES_V2.md](HIDDEN_VOLUMES_V2.md) (design stage).

This document explains the threat model this feature answers, why it is
deliberately *not* built on the QSAFE007 public-key container (§2 of
[FORMAT.md](FORMAT.md)), the on-disk format, and — in the spirit of
[THREAT_MODEL.md](../THREAT_MODEL.md) — exactly where it stops protecting you.

---

## 1. The problem

Every format described in FORMAT.md answers "can an eavesdropper read this
file." None of them answer a different, harder question: **can the holder of
a file be forced to prove what it contains, or that it contains anything at
all?** A `--passphrase` prompt is a single point of coercion — anyone who can
compel you to type it (a border search, a captor, a subpoena backed by
contempt-of-court) gets everything, and refusing to type it is itself
evidence that something is being withheld.

Deniable encryption answers this by making a single ciphertext container able
to hold **two (or more) independent plaintexts**, each unlocked by a
different passphrase, such that an observer with the container and one
passphrase cannot tell whether a second, hidden plaintext exists. You give up
the passphrase to the decoy; the real payload's existence is not provable.
This is the VeraCrypt "hidden volume" model, adapted to Qsafe's primitives.

## 2. Why this is a new, separate, symmetric-only format

It would be natural to ask for this on top of the existing recipient-record
container (§2.2 of FORMAT.md) — encrypt a decoy to one public key and a
hidden payload to another inside the same file. That construction was
considered and rejected for a specific, technical reason:

**ML-KEM-1024 ciphertexts are not proven indistinguishable from uniform random
bytes.** Unlike an X25519 public key (which, after standard clamping, is
close enough to a uniform 32-byte string for this purpose) or the output of
AES-256-GCM (indistinguishable from random under the standard PRF/PRP
assumptions), a lattice-KEM ciphertext is a set of polynomial coefficients
reduced mod `q = 3329` — a non-power-of-two modulus, which means individual
bytes are *not* uniformly distributed over `[0, 255]`. Whether this is
practically distinguishable with realistic sample sizes is not settled in
the literature; several PQ-obfuscation projects specifically whiten or
re-encode Kyber/ML-KEM ciphertext for exactly this reason before sending it
over a channel that must look like noise. Building hidden-volume deniability
on top of recipient records would inherit that open question — a hidden
slot could, in principle, be fingerprinted as "a real ML-KEM ciphertext"
versus "random filler," which defeats the entire point.

AES-256-GCM ciphertext and scrypt-derived keys carry no such caveat. So
`qsafe vault` is a **second, symmetric-only, passphrase-only container
format**, independent of the hybrid identity system, reusing only the
already-audited framed-AEAD primitives (`crypto_frame_nonce`,
`crypto_gcm_seal_aad`/`open_aad` — the same ones QSAFE007 uses for its
payload frames) and the existing scrypt passphrase KDF
(`crypto_derive_key_from_passphrase`). No new cryptographic primitive is
introduced; only a new arrangement of the existing ones.

## 3. The core design

A container is just a file of CSPRNG random bytes:

```
qsafe vault init <path> --size <bytes>
```

There is **no magic, no header, no version byte** anywhere in the container —
by construction, the entire file must remain indistinguishable from a file of
independent random bytes, whether it holds zero, one, or several slots. Any
fixed identifying byte pattern (a version tag, a checksum-shaped field, fixed
KDF parameters) would let an inspector locate "the interesting bytes" without
the passphrase, which is exactly the property being defended against.

A **slot** is a byte range `[offset, offset + ciphertext_len(capacity))` that
the *user* chooses and remembers — it does not need to be secret. Deniability
does not come from hiding *where* the bytes are; it comes from the fact that
ciphertext and untouched random filler are the same distribution. An
adversary who knows exactly which byte range you might be using still cannot
tell whether it holds real data or is simply the padding you left over from
`vault init`.

```
qsafe vault write <container> --offset O --capacity C \
    --passphrase-file pf  <input-file>

qsafe vault read  <container> --offset O --capacity C \
    --passphrase-file pf  <output-file>
```

Writing a slot:

1. `salt   = SHA-256("qsafe-vault-salt-v1" ‖ u64le(offset) ‖ u64le(capacity))[0:16]`
   (not secret — pure domain separation so reusing one passphrase across two
   regions, or two containers of different layout, derives unrelated keys).
2. `slot_key = scrypt(passphrase, salt, N, r=8, p=1)` — `N` defaults to `2^20`
   (~1 GiB), higher than the default keyfile cost (`2^15`), because here the
   passphrase is the *only* thing standing between an adversary and the
   plaintext (a stolen keyfile still needs a secret key; a vault slot does
   not exist independently of the passphrase at all). `--scrypt-cost`
   overrides it — but see §5, "what is not stored," below.
3. The logical plaintext is `u64le(content_len) ‖ content_bytes ‖
   random_padding`, exactly `capacity` bytes long regardless of how large
   `content_bytes` actually is. `content_len` must be `<= capacity - 8`.
4. This plaintext is split into the same frame layout QSAFE007 payloads use
   (§2.3 FORMAT.md): 64 KiB plaintext frames, each independently sealed with
   `crypto_gcm_seal_aad(slot_key, crypto_frame_nonce(counter, is_final), aad,
   ...)`, where `aad = u64le(offset) ‖ u64le(capacity)` on frame 0 only. The
   resulting ciphertext — always exactly `ciphertext_len(capacity)` bytes,
   *never* `ciphertext_len(content_len)` — is written at `offset`.

Because the sealed length is a function of the declared `capacity`, not of
the actual secret's size, two slots holding a 10-byte note and a 4 GiB disk
image reserved with the same `--capacity` produce byte-for-byte identical
footprints on disk. The true content length lives only inside the encrypted
plaintext.

Reading a slot re-derives `salt` and `slot_key` from `(offset, capacity,
passphrase)`, decrypts frames in order, and stops as soon as it has emitted
`content_len` content bytes — it does not bother opening the remaining
padding frames. If a passphrase is wrong, the very first frame's GCM tag
fails to verify (probability of a false accept ≈ 2⁻¹²⁸), and the tool prints
one generic message:

```
Error: no data at this location for this passphrase
```

There is deliberately no way to distinguish "wrong passphrase," "right
passphrase but this range was never written," and "right passphrase, correct
range, but bytes here are corrupted" — collapsing all three into one message
is load-bearing for deniability, not a UX shortcut.

`qsafe vault footprint --capacity C` prints `ciphertext_len(C)` (`= C + 16 *
(C / 65536 + 1)`) so you can plan non-overlapping slot layouts before
writing anything — e.g. reserve `[0, 10MiB)` for a decoy and `[512MiB, 1GiB)`
for the real payload, and confirm the arithmetic doesn't collide, without
touching the container.

## 4. Using it as a hidden volume

There is no "outer" or "hidden" flag anywhere in the format — that
distinction exists only in your head. A typical layout:

```
qsafe vault init secrets.bin --size 1073741824          # 1 GiB, all random

# decoy: something plausible, in the first 200 MiB
qsafe vault write secrets.bin --offset 0 --capacity 209715200 \
    --passphrase-file decoy.pass vacation_photos.tar

# real payload: reserved region far away, only you know it's meaningful
qsafe vault write secrets.bin --offset 600000000 --capacity 52428800 \
    --passphrase-file real.pass engagement_loot.tar.qsafe

qsafe vault read secrets.bin --offset 0 --capacity 209715200 \
    --passphrase-file decoy.pass -                       # gives up the decoy
```

Under coercion, you hand over `decoy.pass`, `--offset 0`, `--capacity
209715200`. That decrypts to something real and plausible. Nothing about the
container proves a second slot exists — the remaining ~800 MiB is
indistinguishable from the untouched randomness `vault init` wrote on day
one, whether or not it secretly holds your actual secret.

## 5. What is *not* stored, and why that's a usability cost

Unlike the QSAFEK01 keyfile format (§5 FORMAT.md), which self-describes its
scrypt cost in an authenticated header, a vault slot stores **nothing**
about itself — no scrypt parameters, no salt, no length. Storing scrypt's
`N/r/p` in the clear, even as "just a few configuration bytes," would plant a
recognizable, low-entropy byte pattern at a fixed position relative to every
slot — exactly the kind of structural fingerprint this format exists to
avoid. The cost: **you must remember, out of band, every `(offset, capacity,
scrypt-cost)` triple you used**, the same way VeraCrypt requires you to
remember a hidden volume's declared size when mounting it. `--scrypt-cost`
defaults to `2^20` if you don't override it; if you do, you must supply the
identical value on read, or the derived key silently differs and you get the
same generic "no data here" error as a wrong passphrase.

## 6. Threat model and limitations (read this before trusting it)

Matching the codebase's existing convention of stating limits plainly:

| Adversary / scenario | Outcome |
|:--|:--|
| Has the container + no passphrase | Cannot distinguish "empty" from "holds N slots"; cannot read anything. |
| Has the container + the decoy passphrase (coerced disclosure) | Reads the decoy; gets no evidence the hidden slot exists. |
| Has the container + guesses/brute-forces a passphrase | Bounded by scrypt cost + passphrase strength, same as any Qsafe key. |
| Tampers with ciphertext bytes in a slot's range | Detected (GCM tag) — but reveals nothing about whether a slot was really there. |
| **Has two point-in-time snapshots of the same container** (e.g. an old backup and the current file) | **Broken.** Diffing the snapshots reveals exactly which byte ranges changed, i.e. that *something* was written there, even without a passphrase. This is the same limitation VeraCrypt documents for hidden volumes, and it is not solvable at this layer — never let a container you're using this way exist in more than one retained copy. |
| Filesystem/OS-level leakage: journaling filesystems, swap, thumbnail/preview caches, editor autosave of the plaintext you fed in, shell history holding a `--passphrase` (use `--passphrase-file`) | **Out of scope**, same "attacker on your machine" line item already in THREAT_MODEL.md. |
| Overwriting a slot | A second `vault write` at the same `(offset, capacity)` simply replaces whatever ciphertext (or randomness) was there — no versioning, no wear-leveling. |
| Capacity vs. content-length side channel | None: ciphertext length is a pure function of declared `capacity`, never of actual content size. |
| Adversarial/extreme `--offset` or `--capacity` (e.g. near `UINT64_MAX`) | Rejected up front: `VAULT_MAX_OFFSET`/`VAULT_MAX_CAPACITY` (2^48 each, `include/vault.h`) bound both, so `vault_ciphertext_len(capacity)` and `offset + vault_ciphertext_len(capacity)` cannot wrap a 64-bit integer and accidentally pass the container-size sanity check. |

**Not yet implemented / explicitly future work**, so this doc doesn't overclaim:

- No `libqsafe` API surface yet (CLI only) — could be added to `include/libqsafe.h` alongside `qsafe_encrypt`/`qsafe_decrypt` if embedding is needed.
- No shared-library (`age-plugin-qsafe`-style) integration.
- No automated collision protection between slots — the tool does not (cannot, without the other passphrase) warn you if two `--offset/--capacity` ranges you chose overlap. `vault footprint` is a planning aid, not an enforcement mechanism.

## 7. Test vectors

Following FORMAT.md §10's conventions:

- **Deterministic KATs** (`tests/test_crypto_utils.c`, `test_vault_known_answer_vectors`):
  the salt formula (§3 above) is pinned against values computed independently
  in Python (`hashlib` + the `cryptography` package) for two distinct
  `(offset, capacity)` pairs, confirming the coordinates actually
  domain-separate the derivation. `vault_ciphertext_len` is checked against a
  table of known answers, including the boundary cases (`VAULT_MIN_CAPACITY`,
  an exact multiple of `QSAFE_FRAME_SIZE`, one byte past it). Frame sealing is
  exercised through the *actual* exported `crypto_frame_nonce` /
  `crypto_gcm_seal_aad` / `crypto_gcm_open_aad` — the same functions vault.c
  calls — with a vault-style 16-byte coordinate AAD, including a negative
  check that this AAD does not authenticate under QSAFE007's `"HDR"` AAD (the
  two formats' framing must not cross-authenticate). scrypt is additionally
  pinned at `N = 2^14`, the cost the fixture below uses to stay fast in CI.
- **Frozen fixture** (`tests/fixtures/vault/`): a 300000-byte container with
  two non-overlapping slots — `container.bin`, decrypted by `decoy.pass`
  (offset 0, capacity 140000) and `hidden.pass` (offset 200000, capacity
  90000), both at `--scrypt-cost 14`. `tests/test.sh` decrypts both and
  diffs against `decoy.expected`/`hidden.expected`, so a future change to
  `vault.c` that alters its byte-level output is caught immediately, the same
  guarantee the QSAFE007 fixtures give the main format.
- **Dynamic integration tests** (`tests/test.sh`): round-trip write/read,
  `--force` behavior on `vault init`, oversized-input and stdin rejection on
  `vault write`, and — the property that actually matters for this feature —
  an automated check that a wrong passphrase and a correct passphrase pointed
  at an untouched region produce **byte-for-byte identical** stderr output,
  not just "both fail."
- **Fuzzing** (`tests/fuzz_vault.c`, `make fuzz-vault`, wired into
  `oss-fuzz/build.sh`): unlike QSAFE007, a vault container has no header to
  sniff or version to dispatch on — the entire untrusted-input surface is raw
  ciphertext bytes at a fixed `(offset, capacity)`, so that's what's fuzzed,
  seeded from the frozen fixture container so the mutator starts from real
  ciphertext rather than nothing. The `(offset, capacity)` *arithmetic*
  (overflow bounds, §6's `VAULT_MAX_OFFSET`/`VAULT_MAX_CAPACITY`) is
  deliberately a unit-test target instead, not a fuzz target — a byte-fuzzed
  64-bit pair would spend nearly all its time on values the bounds check
  already rejects in O(1). Locally smoke-tested via the same
  `QSAFE_STANDALONE` ASan/UBSan fallback `fuzz_decrypt.c` uses on toolchains
  without a linkable libFuzzer runtime (Apple clang among them): 46
  hand-built edge cases (every frame-boundary truncation, single-byte flips
  at each frame/tag boundary) plus 800 randomized mutations, 0 crashes. Real,
  continuous fuzzing runs through OSS-Fuzz once enrolled (see
  `oss-fuzz/README.md`), same as `fuzz_decrypt`.
