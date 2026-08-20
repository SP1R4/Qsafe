# qsafe-pq

**Private.** This fork adds a **post-quantum messaging-crypto layer** on top of
qsafe's primitives — the crypto core behind the [veil](https://github.com/SP1R4/veil)
messenger. The base qsafe file-encryption tool is documented in
[`README-qsafe.md`](README-qsafe.md); this file covers the PQ additions.

## What's added

- **`src/ratchet.{c,h}` — Double Ratchet.** Signal's Double Ratchet on qsafe's
  primitives: X25519 DH ratchet, HKDF root/chain keys, AES-256-GCM per message
  with the header authenticated as AAD, bounded skipped-message keys, and a
  *transactional* decrypt (state is committed only after the tag verifies, so one
  forged packet can't desync a session). Sessions serialize encrypted-at-rest
  (Argon2id + AES-GCM).

- **Continuous / periodic PQ ratchet.** An ML-KEM-1024 secret is mixed into the
  root KDF at ratchet steps, so post-compromise re-keys resist a future quantum
  adversary — not just the initial handshake. The **periodic** variant rotates the
  ML-KEM secret every K steps and self-describes each message as `0x03` full
  (carries ~3.1 KB of KEM material) or `0x04` lite (42-byte header), so ~7/8 of
  messages are lite. Opt-in; the classical path is byte-identical.

- **`src/pqxdh.{c,h}` — PQXDH handshake.** Clean post-quantum X3DH: four X25519 DH
  legs plus an independent ML-KEM-1024 leg, concatenated once into HKDF to seed
  the ratchet (harvest-now-decrypt-later protection). ML-DSA-87–signed prekey
  bundles, a one-time-prekey pool with durable replay rejection, and a signed
  PQ-intent flag so a relay can't downgrade the ratchet.

- **`src/crypto_utils.c` additions.** Raw X25519 keypair/DH, buffer-based ML-DSA
  sign/verify/keypair, and a reusable `crypto_seal_at_rest` / `crypto_open_at_rest`
  (Argon2id + AES-256-GCM) envelope.

## Build & test

```sh
make test-ratchet    # KAT (HKDF cross-checked vs an independent impl), behavioural,
                     # pqxdh, continuous+periodic PQ ratchet, and an out-of-order soak
make test            # the base qsafe unit suite (123 cases)
```

All ratchet/PQXDH tests are AddressSanitizer/UBSan-clean.

## Status

Working and heavily tested (isolated tests + soak + a crypto-review pass on the PQ
ratchet construction). **Not yet production-grade** — pending broader interop/soak
and independent review. The full protocol design lives in the veil repo
(`docs/SPEC.md`, `docs/PQ_RATCHET.md`, `docs/PQ_RATCHET_PERIODIC.md`).
