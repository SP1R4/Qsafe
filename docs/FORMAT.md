# Qsafe On-Disk Format Specification

Current write format: **QSAFE007** (framed AEAD, extended metadata) · Also
readable: **QSAFE006**, **QSAFE005** · Status: stable

`qsafe encrypt` always writes QSAFE007. `qsafe decrypt` accepts QSAFE007,
QSAFE006 and QSAFE005, so files produced by Qsafe 5.0–7.0 are not stranded.
The formats share the header's recipient records, key wrap, key files,
signatures, and armor. QSAFE007 differs from QSAFE006 only inside the
*encrypted* payload: a 16-byte-longer metadata block (§3) that enables an
optional embedded sender signature (§3.1) and optional size-hiding padding
(§3.2). QSAFE005 additionally differs in payload layout (§2-legacy).

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

## 2. Encrypted file (`QSAFE007`)

### 2.1 Layout

```
offset  size                       field
------  -------------------------  ---------------------------------
0       8                          magic = "QSAFE007" (ASCII)
8       1                          recipient_count R   (1..16)
9       R * 1660                    recipient_record[0..R-1]  (see 2.2)
9+RR    variable                   frame[0..k-1]        (see 2.3)
```

A `QSAFE006` file is identical except for the magic and the 272-byte (§3-v6)
metadata block inside the payload.

`RR = R * 1660`. The **header** `H = magic ‖ recipient_count ‖ all
recipient_records` (length `9 + RR`) is authenticated as AEAD Additional
Authenticated Data (AAD) on the first payload frame (§2.3). Unlike the legacy
v5 format (§2-legacy), there is no single payload nonce field — each frame
derives its own nonce from a counter.

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

### 2.3 Cryptographic construction (encryption) — framed payload

The payload

```
P = META ‖ file_contents ‖ [SIG_TRAILER] ‖ [PADDING]
```

(§3 for META; the optional trailer §3.1 is present iff META flag bit 1 is set,
the optional padding §3.2 iff bit 2 is set) is split into frames of
`FRAME = 65536` plaintext bytes and each frame is sealed independently. This
gives constant-memory streaming *and* per-frame verify-before-release.

```
1. Generate a random 32-byte content-encryption key CEK. (One per file.)
2. For each recipient i, wrap CEK into recipient_record[i] (§2.4).
3. H = magic ‖ recipient_count ‖ record[0] ‖ … ‖ record[R-1].   # 9 + RR bytes
4. Write H.
5. Split P into chunks of FRAME bytes. Read chunks until a read returns fewer
   than FRAME bytes (0..FRAME-1) — that short/empty chunk is the FINAL frame.
   For frame index c (from 0):
       nonce_c = 0x00 0x00 0x00 ‖ uint64_be(c) ‖ (c is final ? 0x01 : 0x00)   # 12 bytes
       aad_c   = (c == 0) ? H : (empty)
       ct_c, tag_c = AES-256-GCM(key=CEK, iv=nonce_c, aad=aad_c, pt=chunk_c)
       write ct_c ‖ tag_c                     # ct_c has the same length as chunk_c
```

Framing rule (so the reader needs no length prefix): every non-final frame
carries exactly `FRAME` plaintext bytes, so on the wire it is exactly
`FRAME + 16` bytes. The single final frame carries `0..FRAME-1` plaintext bytes,
so it is always **strictly shorter** than `FRAME + 16`. If the plaintext length
is an exact multiple of `FRAME`, the final frame is empty (0 plaintext, 16-byte
tag).

Security of the framing:
- `CEK` is random per file, so the deterministic counter nonce is unique per key.
- The counter binds frame **order**; reordering or duplicating a frame changes
  its expected nonce and the tag fails.
- The final-frame flag in the nonce plus the "non-final frames are full" rule
  makes **truncation** (a missing final frame) and **extension** (data after the
  final frame) detectable: a reader that hits EOF right after a full frame, or
  finds a full frame where it expected the short final one, MUST reject.
- `H` is bound into frame 0, so the recipient set and count are authenticated.

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

### 2.5 Decryption procedure (framed)

```
1. Read magic(8). If "QSAFE007" or "QSAFE006" -> framed (this section).
   If "QSAFE005" -> legacy (§2-legacy). Otherwise reject.
2. Read R = u8; reject if R == 0 or R > 16.
3. Read R recipient records (R * 1660 bytes); reject if truncated.
4. Recover CEK from whichever record is ours (§2.6); reject if none.
5. For frame index c = 0, 1, ...:
     read up to FRAME+16 bytes into buf.
       got == FRAME+16  -> non-final frame (last=0). If EOF follows with no
                           further frame, the file is truncated -> reject.
       16 <= got < FRAME+16 -> FINAL frame (last=1).
       got < 16          -> truncated/garbage -> reject.
     nonce_c = 0x000000 ‖ uint64_be(c) ‖ (last ? 0x01 : 0x00)
     aad_c   = (c == 0) ? H : empty
     pt_c    = AES-256-GCM-Open(CEK, nonce_c, aad_c, ct=buf[0..got-16], tag=buf[got-16..got])
     if Open fails -> reject (corrupt / wrong key / reordered / wrong final flag)
     release pt_c     # already authenticated
     if last: stop.
6. The first 288 (QSAFE007) or 272 (QSAFE006) released plaintext bytes are
   META (§3); the rest is the file contents, followed — in QSAFE007 — by the
   optional signature trailer (§3.1) and padding (§3.2), split per META's
   declarations and checked per §3's consistency rules.
```

Because each frame is authenticated *before* its plaintext is released, a pipe
consumer never receives unverified bytes and no whole-payload buffering is
needed. **Caveat:** for a multi-frame file, earlier frames are released before a
later corrupt/truncated frame is detected — every released byte was
authenticated, but a failure partway through means a verified *prefix* may
already have been emitted. A single-frame (small) file is therefore all-or-
nothing; a large file is prefix-or-error. File outputs are removed on failure.

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

### 2-legacy. QSAFE005 (readable, never written)

Qsafe 5.0 produced a non-framed format. `qsafe decrypt` still reads it. It
differs from §2 only in the header and payload:

```
offset  size        field
------  ----------  ---------------------------------
0       8           magic = "QSAFE005"
8       1           recipient_count R
9       12          payload_nonce
21      R * 1660    recipient_record[0..R-1]      (identical structure to §2.2)
21+RR   variable    payload_ciphertext            (AES-256-GCM of META ‖ file)
EOF-16  16          payload_tag
```

The whole payload is a single AES-256-GCM:
`key = CEK`, `iv = payload_nonce`, `aad = H = magic ‖ count ‖ payload_nonce ‖
records`, `pt = META ‖ file`. The 16-byte tag is the trailing bytes; a decoder
holds back the last 16 bytes while streaming and verifies at EOF (so unverified
plaintext must be buffered before release on a pipe — the limitation §2 removes).
Key wrap (§2.4) and unwrap (§2.6) are identical.

---

## 3. Metadata block (`META`, 288 bytes in QSAFE007)

Prepended to the plaintext before payload encryption; little-endian.

```
offset  size    field
------  ------  ----------------------------------------
0       1       flags        (bit 0 = metadata present,
                              bit 1 = signature trailer present,
                              bit 2 = padding present)
1       1       reserved     (0)
2       2       name_len     (u16, <= 255)
4       256     name         (name_len valid bytes; remainder 0)
260     4       mode         (u32, st_mode & 0o777)
264     8       mtime        (u64, seconds since Unix epoch)
272     8       content_len  (u64; 0xFFFF…FF = unknown / streamed input)
280     8       pad_len      (u64, bytes of PADDING at the end of P)
```

Total `272 + 8 + 8 = 288`. **§3-v6:** in QSAFE006 and QSAFE005 the block ends
at offset 272 (no `content_len`/`pad_len`, flag bits 1–2 undefined).

Consistency rules a reader MUST enforce:
- bit 2 set requires `content_len != unknown` and `pad_len > 0`;
  bit 2 clear requires `pad_len == 0`.
- When `content_len` is known, the plaintext stream `P` MUST be exactly
  `288 + content_len + (bit1 ? 7221 : 0) + pad_len` bytes; any mismatch MUST
  be rejected.
- When `content_len` is unknown and bit 1 is set, `P` MUST be at least
  `288 + 7221` bytes and the trailer is the final 7221 bytes.

On decryption, `name` MUST be reduced to its final path component and a value of
`".."` MUST be discarded (directory-traversal defense). When `flags` bit 0 is
clear (e.g. data came from stdin), no name/mode/mtime are restored.

### 3.1 Embedded sender signature (`SIG_TRAILER`, 7221 bytes)

With `--sign-with`, the encryptor appends a fixed-size trailer after the file
contents, *inside* the encrypted payload (so the signer's identity is hidden
from anyone who cannot decrypt):

```
offset  size    field
------  ------  ----------------------------------------
0       2592    signer_pub    (raw ML-DSA-87 public key)
2592    2       sig_len       (u16, 1..4627)
2594    4627    signature     (sig_len valid bytes; remainder 0)
```

The signature is computed over the SHA-256 digest

```
digest = SHA-256("qsafe-v7-signed" ‖ H ‖ META ‖ file_contents)
```

where `H` is the container header (§2.1) — binding the signature to the exact
recipient set — and the ASCII context string provides domain separation from
detached signatures (§6). A reader MUST verify the signature whenever META flag
bit 1 is set and MUST reject the file if verification fails. The reader SHOULD
surface the signer (e.g. its SHA-256 fingerprint) and MAY additionally require
`signer_pub` to equal a caller-pinned key (`--signer`).

Note the trailer is itself covered by the payload AEAD, so an attacker without
a recipient key can neither strip nor substitute it. A *recipient* can re-encrypt
the contents without a signature, but cannot forge the original signer's
signature over new contents or a new recipient set.

### 3.2 Size-hiding padding (`PADDING`)

With `--pad`, `pad_len` random bytes are appended as the final section of `P`,
where `content_len + pad_len` is the [Padmé](https://petsymposium.org/2019/files/papers/issue4/popets-2019-0056.pdf)
bucket of `content_len`: with `E = ⌊log2 L⌋` and `S = ⌊log2 E⌋ + 1`, `L` is
rounded up to the next multiple of `2^(E-S)` (overhead ≤ ~12%, leaking only
`O(log log L)` bits of the true length). Padding bytes are random and MUST be
discarded by the reader. Padding requires a known `content_len`.

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

- The 8-byte magic identifies the format: `QSAFE007` (current), `QSAFE006` and
  `QSAFE005` (legacy, still readable) for files; `QSAFEK01` for secret-key
  files. A reader MUST reject an unrecognized magic.
- `qsafe encrypt` writes `QSAFE007`; `qsafe decrypt` accepts `QSAFE007`,
  `QSAFE006` and `QSAFE005`. All are intentionally incompatible with
  `QSAFE004` and earlier.
- Any change to a layout or construction in this document is a breaking change
  and MUST bump the corresponding magic. (`QSAFE006` added framing over
  `QSAFE005` to gain constant-memory verify-before-release; `QSAFE007`
  extended META to carry the embedded-signature and padding declarations.)
- Known-answer vectors for the deterministic primitives (SHA-256 fingerprint,
  HKDF-SHA256, scrypt) are in `tests/test_crypto_utils.c`.
