# Qsafe On-Disk Format Specification

Version: **QSAFE005** (Qsafe 5.x) · Status: stable

This document specifies the byte layout and cryptographic construction of every
file Qsafe writes, precisely enough to build an interoperable implementation
without reading the source. Where this document and the code disagree, that is a
bug — please report it (see [SECURITY.md](../SECURITY.md)).

For the security properties and limitations of this design, see
[THREAT_MODEL.md](../THREAT_MODEL.md).

---

## 1. Conventions

- **Endianness:** all multi-byte integers are **little-endian** unless stated.
- **Notation:** `u8`/`u16`/`u32`/`u64` are unsigned integers of that width;
  `X(n)` is `n` bytes of field `X`; `A ‖ B` is concatenation.
- **Sizes** below are for the mandated algorithms; an implementation MUST use the
  canonical sizes of the named primitives.

### Algorithms

| Role | Algorithm | Spec | Sizes (bytes) |
|:--|:--|:--|:--|
| Classical KEX | X25519 | RFC 7748 | pub 32, secret 32, shared 32 |
| Post-quantum KEM | ML-KEM-1024 | NIST FIPS 203 | pub 1568, secret 3168, ciphertext 1568, shared 32 |
| Signatures | ML-DSA-87 | NIST FIPS 204 | pub 2592, secret 4896, signature ≤ 4627 |
| AEAD | AES-256-GCM | NIST SP 800-38D | key 32, nonce 12, tag 16 |
| KDF (key combine) | HKDF-SHA256 | RFC 5869 | output 32 |
| KDF (passphrase) | scrypt | RFC 7914 | output 32 |
| Hash (sign, fingerprint) | SHA-256 | FIPS 180-4 | digest 32 |

Constants used throughout: `NONCE = 12`, `TAG = 16`, `KEY = 32`, `CEK = 32`,
`X25519 = 32`, `SALT = 16`.

---

## 2. Encrypted file (`QSAFE005`)

### 2.1 Layout

```
offset  size                       field
------  -------------------------  ---------------------------------
0       8                          magic = "QSAFE005" (ASCII)
8       1                          recipient_count R   (1..16)
9       12                         payload_nonce        (AES-GCM IV)
21      R * 1660                    recipient_record[0..R-1]  (see 2.2)
21+RR   variable                   payload_ciphertext   (see 2.3)
EOF-16  16                         payload_tag          (AES-GCM tag)
```

`RR = R * 1660`. The bytes from offset `0` to the start of `payload_ciphertext`
(i.e. `magic ‖ recipient_count ‖ payload_nonce ‖ all recipient_records`,
length `21 + RR`) are the **header** and are authenticated as AEAD Additional
Authenticated Data (AAD) for the payload — see 2.3.

`recipient_count` MUST be in `1..16`. A value of `0` or `> 16` MUST be rejected.

### 2.2 Recipient record (1660 bytes for ML-KEM-1024)

```
offset  size    field
------  ------  --------------------------------------
0       32      ephemeral_x25519_pub
32      1568    mlkem_ciphertext
1600    12      wrap_nonce          (AES-GCM IV for the CEK wrap)
1612    32      wrapped_cek         (AES-GCM ciphertext of the 32-byte CEK)
1644    16      wrap_tag            (AES-GCM tag for the CEK wrap)
```

Record size = `32 + 1568 + 12 + 32 + 16 = 1660`.

### 2.3 Cryptographic construction (encryption)

Let `recipient_pub[i] = x25519_pub[i] ‖ mlkem_pub[i]` (see §4).

1. Generate a random 32-byte **content-encryption key** `CEK` and a random
   12-byte `payload_nonce`. (One CEK per file.)
2. Build the metadata block `META` (§5).
3. For each recipient `i`, wrap `CEK` into `recipient_record[i]` (§2.4).
4. Form the header `H = magic ‖ R ‖ payload_nonce ‖ record[0] ‖ … ‖ record[R-1]`.
5. AEAD-encrypt the payload:
   ```
   AES-256-GCM:
     key   = CEK
     iv    = payload_nonce
     aad   = H                       (the entire header)
     pt    = META ‖ file_contents
   -> payload_ciphertext, payload_tag
   ```
6. Write `H ‖ payload_ciphertext ‖ payload_tag`.

Because the whole header is AAD, any reordering, substitution, truncation, or
edit of the magic, recipient count, nonce, or any record causes authentication
to fail.

### 2.4 Per-recipient key wrap

For recipient `i` with public key `x25519_pub[i] ‖ mlkem_pub[i]`:

```
(e_pk, e_sk)      = X25519.KeyGen()                      # fresh per record
dh                = X25519(e_sk, x25519_pub[i])          # 32 bytes
(kem_ct, kem_ss)  = ML-KEM-1024.Encaps(mlkem_pub[i])     # kem_ss = 32 bytes
KEK               = HKDF-SHA256(IKM   = dh ‖ kem_ss,
                                salt  = "" (empty),
                                info  = "qsafe-v5-hybrid-kek",
                                L     = 32)
wrap_nonce        = random(12)
wrapped_cek,
wrap_tag          = AES-256-GCM(key=KEK, iv=wrap_nonce, pt=CEK, aad=none)
record[i]         = e_pk ‖ kem_ct ‖ wrap_nonce ‖ wrapped_cek ‖ wrap_tag
```

Notes:
- `salt = ""` means HKDF uses a salt of `HashLen` (32) zero bytes, per RFC 5869.
- The CEK wrap uses **no** AAD; its integrity is covered by `wrap_tag`, and the
  record as a whole is additionally bound into the payload tag via the header AAD.
- `IKM` is exactly 64 bytes (`32 + 32`) for these algorithms.

### 2.5 Decryption procedure

```
1. Read magic(8); reject if != "QSAFE005".
2. Read R = u8; reject if R == 0 or R > 16.
3. Read payload_nonce(12).
4. Read R recipient records (R * 1660 bytes); reject if truncated.
5. For each record, attempt to recover the CEK (§2.6). The first record whose
   wrap_tag verifies yields the CEK. If none verify, this key is not a recipient
   -> reject.
6. AEAD-decrypt the payload with key=CEK, iv=payload_nonce, aad=H (the exact
   header bytes read in steps 1-4). The trailing 16 bytes of the file are
   payload_tag.
7. Verify payload_tag. Only after it verifies, treat the first 272 plaintext
   bytes as META (§5) and the remainder as the file contents.
```

Implementations SHOULD NOT release plaintext to an irreversible sink (a pipe) or
act on parsed metadata before step 7 succeeds. Qsafe buffers pipe output until
the tag verifies, and removes a partial output file on failure.

### 2.6 Per-recipient unwrap (decryption)

Given the recipient's secret `x25519_sec ‖ mlkem_sec` (§4) and a `record`:

```
dh       = X25519(x25519_sec, record.e_pk)
kem_ss   = ML-KEM-1024.Decaps(mlkem_sec, record.mlkem_ct)   # always returns 32 bytes
KEK      = HKDF-SHA256(dh ‖ kem_ss, salt="", info="qsafe-v5-hybrid-kek", L=32)
CEK      = AES-256-GCM-Open(key=KEK, iv=record.wrap_nonce,
                            ct=record.wrapped_cek, tag=record.wrap_tag)
```

If `AES-256-GCM-Open` fails (tag mismatch), this record is not for us. ML-KEM
implicit rejection means a tampered `mlkem_ct` yields a different `kem_ss`, hence
a wrong `KEK`, hence a wrap-tag failure — so tampering is caught here.

---

## 3. Metadata block (`META`, 272 bytes)

Prepended to the plaintext before payload encryption; little-endian.

```
offset  size    field
------  ------  ----------------------------------------
0       1       flags        (bit 0 = metadata present)
1       1       reserved     (0)
2       2       name_len     (u16, <= 255)
4       256     name         (name_len valid bytes; remainder 0)
260     4       mode         (u32, st_mode & 0o777)
264     8       mtime        (u64, seconds since Unix epoch)
```

Total `1 + 1 + 2 + 256 + 4 + 8 = 272`.

On decryption, `name` MUST be reduced to its final path component and a value of
`".."` MUST be discarded (directory-traversal defense). When `flags` bit 0 is
clear (e.g. data came from stdin), no name/mode/mtime are restored.

---

## 4. Public and secret key material

A Qsafe **identity** is a hybrid keypair.

### 4.1 Public key blob (1600 bytes, stored in the clear)

```
offset  size    field
------  ------  -----------------------
0       32      x25519_pub
32      1568    mlkem_pub
```

### 4.2 Secret key blob (3200 bytes, before wrapping)

```
offset  size    field
------  ------  -----------------------
0       32      x25519_sec
32      3168    mlkem_sec
```

The secret blob is never written in the clear; it is wrapped as in §6.

---

## 5. Secret-key file (`QSAFEK01`)

The secret blob (§4.2 for an encryption identity, or the raw ML-DSA-87 secret
key for a signing identity) is sealed with a passphrase-derived key.

```
offset  size       field
------  ---------  ------------------------------------------
0       8          magic = "QSAFEK01" (ASCII)
8       8          scrypt_N   (u64)
16      4          scrypt_r   (u32)
20      4          scrypt_p   (u32)
24      12         nonce      (AES-GCM IV)
36      16         salt       (scrypt salt)
52      variable   ciphertext (AES-GCM of the secret blob)
EOF-16  16         tag        (AES-GCM tag)
```

Construction:

```
wrap_key = scrypt(passphrase, salt, N=scrypt_N, r=scrypt_r, p=scrypt_p, dkLen=32)
header24 = magic ‖ scrypt_N ‖ scrypt_r ‖ scrypt_p          # bytes 0..23
ciphertext, tag = AES-256-GCM(key=wrap_key, iv=nonce,
                              pt=secret_blob, aad=header24)
```

- The 24-byte header (magic + scrypt parameters) is authenticated as AAD, so the
  declared cost cannot be silently altered.
- Default cost: `N = 2^15`, `r = 8`, `p = 1`. Qsafe's `--scrypt-cost <log2N>`
  sets `N = 2^log2N` for `log2N ∈ [14, 22]`.
- A reader MUST sanity-bound the declared parameters before allocating
  (Qsafe rejects: `N` not a power of two, `N < 2` or `N > 2^24`, `r = 0` or
  `r > 64`, `p = 0` or `p > 16`).

### 5.1 Legacy (v4) secret keys

A secret-key file that does **not** begin with `QSAFEK01` is read as the
headerless v4 layout: `nonce(12) ‖ salt(16) ‖ ciphertext ‖ tag(16)`, with fixed
`N=2^15, r=8, p=1` and **no** AAD. New files are always written with the
`QSAFEK01` header.

---

## 6. Detached signatures

Qsafe signs the **SHA-256 digest** of the input (hash-then-sign):

```
digest    = SHA-256(file_contents)               # 32 bytes
signature = ML-DSA-87.Sign(signing_secret, digest)
```

- The signature file contains the raw ML-DSA-87 signature bytes (length ≤ 4627);
  no framing.
- Verification recomputes `digest` and runs `ML-DSA-87.Verify(signing_pub,
  digest, signature)`.
- A signing **public** key is stored in the clear as the raw 2592-byte ML-DSA-87
  public key. A signing **secret** key is wrapped exactly as in §5.
- Signing keys are independent of encryption keys.

---

## 7. ASCII armor

`--armor` wraps the raw binary container (§2, or any Qsafe output) in
PEM-style text:

```
-----BEGIN QSAFE MESSAGE-----
<standard base64 of the binary, wrapped at 64 columns>
-----END QSAFE MESSAGE-----
```

De-armoring ignores anything before the `BEGIN` line, decodes the base64 body up
to the `END` line, and yields the original binary, which is then processed
normally. Armor is a pure transport encoding and adds no cryptographic
properties.

---

## 8. Fingerprints

A public-key fingerprint is the lowercase hex SHA-256 of the public-key blob
bytes:

```
fingerprint = hex(SHA-256(public_blob))
```

For an encryption identity this is over the 1600-byte hybrid public blob (§4.1).

---

## 9. Versioning and compatibility

- The 8-byte magic identifies the format: `QSAFE005` (files), `QSAFEK01`
  (secret-key files). A reader MUST reject an unrecognized magic.
- `QSAFE005` is intentionally incompatible with `QSAFE004` and earlier. Any
  change to a layout or construction in this document is a breaking change and
  MUST bump the corresponding magic.
- Known-answer vectors for the deterministic primitives (SHA-256 fingerprint,
  HKDF-SHA256, scrypt) are in `tests/test_crypto_utils.c`.
