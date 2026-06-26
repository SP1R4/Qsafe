<p align="center">
  <h1 align="center">Qsafe</h1>
  <p align="center">
    Post-quantum file encryption built for the future.
    <br />
    <strong>X25519 + ML-KEM-1024 + AES-256-GCM + HKDF-SHA256 + scrypt + ML-DSA-87</strong>
  </p>
</p>

<p align="center">
  <img src="https://img.shields.io/badge/version-6.0.0-blue" alt="Version">
  <img src="https://img.shields.io/badge/license-MIT-green" alt="License">
  <img src="https://img.shields.io/badge/NIST-FIPS%20203-orange" alt="NIST FIPS 203">
  <img src="https://img.shields.io/badge/language-C-lightgrey" alt="C">
</p>

---

## Overview

Qsafe is a command-line file encryption tool that combines **post-quantum key encapsulation** with **classical authenticated encryption** to provide long-term data confidentiality against both classical and quantum adversaries.

It uses a **hybrid** key-establishment scheme — classical **X25519** Diffie–Hellman combined with post-quantum **ML-KEM-1024** (NIST FIPS 203, formerly CRYSTALS-Kyber) — so a file stays confidential unless an attacker breaks *both* layers. The two shared secrets are combined with **HKDF-SHA256** into a key that wraps a random content key; the payload is sealed with **AES-256-GCM**. Secret keys are protected at rest with a key derived from your passphrase using **scrypt**, a memory-hard KDF. Qsafe can also create and verify detached **ML-DSA-87** (Dilithium, Level 5) signatures.

Qsafe follows a true public-key workflow: you generate a keypair **once** with `keygen`, then encrypt to the public key (no passphrase needed) and decrypt with the passphrase-wrapped secret key. Encrypted files are durable — encrypting a second file never invalidates the first.

### Key Features

- **Hybrid quantum-resistant** — X25519 + ML-KEM-1024 (NIST FIPS 203, Level 5); break-one-stay-secure
- **Multi-recipient** — encrypt once to several public keys (`-r`); any one secret key decrypts
- **Detached signatures** — `sign` / `verify-sig` using ML-DSA-87 for sender authenticity
- **Durable public-key workflow** — generate a keypair once; encrypt with the public key, decrypt with the secret key. Encrypting never overwrites your keys.
- **Authenticated encryption** — AES-256-GCM provides confidentiality *and* integrity; the entire header (magic, recipient records, nonce) is authenticated as additional data (AAD)
- **Streaming architecture** — constant memory usage for both encryption and decryption via 4 KB chunked I/O
- **Pipe-friendly** — use `-` for stdin/stdout, so Qsafe composes with `tar`, `ssh`, and friends
- **Armored output** — `--armor` emits/consumes ASCII base64 for email and chat
- **Inspect & verify** — `inspect` reports a file's type without decrypting; `verify` / `--check` authenticate without writing plaintext
- **Key maintenance** — `rekey` changes a key's passphrase; `--scrypt-cost` tunes the KDF hardness
- **Metadata preservation** — the original filename, permission bits, and modification time are encrypted alongside the data and restored on decrypt
- **Smart defaults** — files vs. directories are auto-detected and output paths are inferred when omitted
- **Flexible passphrase entry** — interactive no-echo prompt, `$QSAFE_PASSPHRASE`, or `--passphrase-file` (never required on the command line)
- **Batch processing** — recursively encrypt or decrypt entire directory trees
- **Tamper detection** — any modification to the ciphertext, header, or recipient records is rejected
- **Cross-platform** — builds on Linux, macOS (Homebrew), and Windows (MSYS2/MinGW-w64)

---

## Table of Contents

- [Overview](#overview)
- [Architecture](#architecture)
- [Requirements](#requirements)
- [Installation](#installation)
- [Usage](#usage)
- [File Formats](#file-formats)
- [Key Management](#key-management)
- [Security Model](#security-model)
- [Project Structure](#project-structure)
- [Testing](#testing)
- [Compatibility](#compatibility)
- [License](#license)

---

## Architecture

### Cryptographic Primitives

| Component | Algorithm | Specification | Notes |
|:--|:--|:--|:--|
| Classical key exchange | X25519 | RFC 7748 | Hybrid classical layer |
| Key Encapsulation | ML-KEM-1024 | NIST FIPS 203 | Level 5 (AES-256 equivalent) |
| Signatures | ML-DSA-87 | NIST FIPS 204 | Dilithium Level 5, detached |
| Symmetric Encryption | AES-256-GCM | NIST SP 800-38D | 256-bit, authenticated |
| Shared-secret KDF | HKDF-SHA256 | RFC 5869 | (X25519 ‖ ML-KEM) → key-wrap key |
| Passphrase KDF | scrypt (N=2¹⁵ default, r=8, p=1) | RFC 7914 | Memory-hard key wrapping, tunable |
| Random Generation | OpenSSL `RAND_bytes` | CSPRNG | System entropy |

Encryption generates a random content-encryption key (CEK) that seals the
payload with AES-256-GCM. For each recipient the CEK is independently wrapped
under a key derived (via HKDF) from the combination of an ephemeral X25519 DH
and an ML-KEM-1024 encapsulation to that recipient — so one ciphertext can be
opened by any one of several secret keys, and only by breaking both the
classical and the post-quantum layer.

### Encryption Flow

> Keypair generation (the top portion of this diagram) happens once via
> `qsafe keygen`. Encryption itself only reads the public key — no passphrase
> is involved.

```
                        +-----------------+
                        |   Passphrase    |
                        +--------+--------+
                                 |
                          scrypt + salt
                                 |
                                 v
+-------------+         +-------+--------+         +----------------+
| ML-KEM-1024 |-------->| Secret Key     |-------->| secret_key.bin |
| Keypair Gen |         | (AES-GCM wrap) |         | (encrypted)    |
+------+------+         +----------------+         +----------------+
       |
       | Public Key
       v
+------+------+         +----------------+         +----------------+
| KEM         |-------->| Shared Secret  |--HKDF-->| AES-256 Key    |
| Encapsulate |         | (32 bytes)     |         | (32 bytes)     |
+------+------+         +----------------+         +-------+--------+
       |                                                    |
       | KEM Ciphertext                                     v
       |                                            +-------+--------+
       |                                            | AES-256-GCM    |
       |                                            | Encrypt        |
       |                                            | (4 KB chunks)  |
       |                                            +-------+--------+
       |                                                    |
       v                                                    v
+----------+-------+-----------+---------------------+----------------+-----+
| QSAFE005 | count | Nonce(12) | Recipient record(s) | AES Ciphertext | Tag |
+----------+-------+-----------+---------------------+----------------+-----+
 \________________ authenticated as GCM AAD __________________/

Each recipient record is: ephemeral X25519 pub (32) ‖ ML-KEM ciphertext (1568)
‖ wrap nonce (12) ‖ wrapped CEK (32) ‖ wrap tag (16). The AES ciphertext covers
a fixed 272-byte metadata block (original name, mode, mtime) followed by the
file contents. The payload nonce sits at the front so decryption can stream
straight from a pipe; the 16-byte payload tag is the trailing bytes.
```

### Decryption Flow

```
secret_key.bin + Passphrase --> scrypt --> AES-GCM Decrypt --> ML-KEM Secret Key
                                                                       |
Encrypted File --> Verify Header --> KEM Ciphertext -------------------+
                                                                       |
                                                 ML-KEM Decapsulate <--+
                                                         |
                                                   Shared Secret
                                                         |
                                                    HKDF-SHA256
                                                         |
                                                    AES-256 Key
                                                         |
                                      AES-GCM Decrypt (4 KB chunks, streamed)
                                                         |
                                                 Verify GCM Tag
                                                         |
                                                     Plaintext
```

---

## Requirements

| Dependency | Minimum Version | Purpose |
|:--|:--|:--|
| C compiler | C11 (GCC 7+, Clang) | Build |
| GNU Make | 3.81+ | Build system |
| CMake | 3.5+ | Build liboqs (Linux source build) |
| OpenSSL | 3.0+ | AES-256-GCM, HKDF, scrypt, CSPRNG |
| [liboqs](https://github.com/open-quantum-safe/liboqs) | 0.10+ | ML-KEM-1024 implementation |

---

## Installation

### Homebrew (macOS/Linux)

```bash
brew install SP1R4/qsafe/qsafe   # from a tap; see packaging/qsafe.rb
```

### Docker

```bash
docker build -t qsafe .
docker run --rm -e QSAFE_PASSPHRASE=secret -v "$PWD:/data" qsafe keygen --key-file /data/key.bin
```

### Automated (macOS or Ubuntu/Debian)

```bash
chmod +x scripts/setup.sh
./scripts/setup.sh
make
```

The script installs OpenSSL 3 and liboqs via Homebrew on macOS, or via apt +
a liboqs source build on Debian/Ubuntu.

### Manual — macOS (Homebrew)

```bash
brew install openssl@3 liboqs
make
```

The Makefile auto-discovers the Homebrew prefixes for `openssl@3` and `liboqs`.

### Manual — Linux

```bash
# Install build dependencies
sudo apt update && sudo apt install -y build-essential libssl-dev cmake git

# Build and install liboqs (0.10+ for ML-KEM)
git clone --depth 1 --branch 0.12.0 https://github.com/open-quantum-safe/liboqs.git
cmake -S liboqs -B liboqs/build -DCMAKE_BUILD_TYPE=Release -DOQS_BUILD_ONLY_LIB=ON
cmake --build liboqs/build -j"$(nproc)"
sudo cmake --install liboqs/build && sudo ldconfig

# Build Qsafe
make
```

The `qsafe` binary is placed in the project root. To install it system-wide:

```bash
sudo make install                # binary + man page (override with PREFIX=)
sudo make install-completions    # optional: bash + zsh completions
```

### Manual — Windows (MSYS2 / MinGW-w64)

From an **MSYS2 MINGW64** shell:

```bash
pacman -S --needed git make mingw-w64-x86_64-gcc mingw-w64-x86_64-openssl \
                   mingw-w64-x86_64-cmake mingw-w64-x86_64-ninja

# Build and install liboqs into the MinGW prefix
git clone --depth 1 --branch 0.12.0 https://github.com/open-quantum-safe/liboqs.git
cmake -S liboqs -B liboqs/build -G Ninja -DCMAKE_BUILD_TYPE=Release \
      -DOQS_BUILD_ONLY_LIB=ON -DCMAKE_INSTALL_PREFIX=/mingw64
cmake --build liboqs/build && cmake --install liboqs/build

# Build Qsafe -> qsafe.exe
make
```

The Makefile auto-detects MSYS2/MinGW and produces `qsafe.exe`.

### Verifying releases

Release tarballs (from the `Release` workflow on a `v*` tag) are signed with
[cosign](https://github.com/sigstore/cosign) using keyless signing — no
pre-shared key. To verify a downloaded artifact:

```bash
# Checksum
shasum -a 256 -c qsafe-v6.0.0-Linux-x86_64.tar.gz.sha256

# Signature
cosign verify-blob \
  --bundle qsafe-v6.0.0-Linux-x86_64.tar.gz.cosign.bundle \
  --certificate-identity-regexp "https://github.com/SP1R4/Qsafe/.github/workflows/release.yml@.*" \
  --certificate-oidc-issuer https://token.actions.githubusercontent.com \
  qsafe-v6.0.0-Linux-x86_64.tar.gz
```

### Verify Installation

```bash
./qsafe --help
```

---

## Usage

### Synopsis

```
qsafe keygen      [options]
qsafe encrypt     [options] <input> [output]
qsafe decrypt     [options] <input> [output]
qsafe verify      [options] <input>
qsafe rekey       [options]
qsafe inspect     <file>
qsafe sign-keygen [options]
qsafe sign        [options] <input> [signature]
qsafe verify-sig  [options] <input> [signature]
```

Files and directories are detected automatically — there is no `file|dir`
argument. When the output path is omitted, a sensible default is used
(`<name>.qsafe` for encrypt, the original name for decrypt). Use `-` for the
input or output to read from stdin / write to stdout.

### Commands

| Command | Description |
|:--|:--|
| `keygen` | Generate a hybrid X25519 + ML-KEM-1024 keypair (run once). Needs the passphrase. |
| `encrypt` | Encrypt a file or directory to one or more public keys. **No passphrase needed.** |
| `decrypt` | Decrypt a file or directory using the passphrase-wrapped secret key. |
| `verify` | Authenticate an encrypted file/directory without writing plaintext. |
| `rekey` | Change the passphrase protecting a secret key (keypair unchanged). |
| `inspect` | Report what a key or encrypted file is, without decrypting. |
| `sign-keygen` | Generate an ML-DSA-87 signing keypair (default `sign_key.bin`). |
| `sign` | Create a detached signature for a file (default `<input>.sig`). |
| `verify-sig` | Verify a detached signature against a file. |

### Options

| Option | Description |
|:--|:--|
| `--key-file <path>` | Secret key file (default: `secret_key.bin`; `sign_key.bin` for signing) |
| `--pub-file <path>` | Public key file (default: `<key-file>.pub`) |
| `-r, --recipient <path>` | Add a recipient public key when encrypting (repeatable) |
| `--passphrase <str>` | Passphrase (discouraged — visible to other users) |
| `--passphrase-file <path>` | Read the passphrase from the first line of a file |
| `--check` | decrypt/verify: authenticate only, write nothing |
| `--armor` | encrypt: ASCII base64 output; decrypt: base64 input |
| `--scrypt-cost <n>` | keygen/rekey: scrypt cost as log2(N), 14–22 (default 15) |
| `--verbose` | Print detailed information |
| `--force` | Overwrite existing output without prompting |
| `--help` | Display usage information |
| `--version` | Display version information |

> The passphrase protects the **secret key only**. If you don't pass one via
> `--passphrase`, `--passphrase-file`, or `$QSAFE_PASSPHRASE`, Qsafe prompts for
> it without echoing. Options may appear before or after the command.

### Examples

**Generate a keypair (once):**

```bash
qsafe keygen                      # prompts for a passphrase, writes secret_key.bin(+.pub)
```

**Encrypt / decrypt a file (defaults):**

```bash
qsafe encrypt report.pdf          # -> report.pdf.qsafe (no passphrase needed)
qsafe decrypt report.pdf.qsafe    # -> report.pdf (prompts for passphrase)
```

**Restore into a directory using the stored original name:**

```bash
qsafe decrypt report.pdf.qsafe ./restore/    # -> ./restore/report.pdf
```

**Encrypt / decrypt a directory (recursive, auto-detected):**

```bash
qsafe encrypt ./sensitive         # -> ./sensitive_qsafe/
qsafe decrypt ./sensitive_qsafe   # -> ./sensitive/
```

**Pipe through stdin/stdout:**

```bash
tar cf - ./project | qsafe encrypt - project.tar.qsafe
qsafe decrypt project.tar.qsafe - | tar xf -
```

**Custom key file and non-interactive passphrase:**

```bash
qsafe --key-file project.key keygen
export QSAFE_PASSPHRASE="…"
qsafe --key-file project.key encrypt data.csv
qsafe --key-file project.key decrypt data.csv.qsafe
```

> **Note:** passing `--passphrase` on the command line exposes it to other users
> via the process list and your shell history. Prefer the interactive prompt,
> `$QSAFE_PASSPHRASE`, or `--passphrase-file`.

---

## Library & Python bindings

Qsafe is also a library, so you can embed it instead of shelling out.

```bash
make lib        # -> libqsafe.so / libqsafe.dylib / libqsafe.dll
```

The C API is in [`include/libqsafe.h`](include/libqsafe.h) (`qsafe_keygen`,
`qsafe_encrypt`, `qsafe_decrypt`, `qsafe_sign`, `qsafe_verify_signature`, …).
The Python module wraps it with file and byte-buffer helpers:

```python
import qsafe   # python/qsafe.py; set QSAFE_LIB if the library isn't alongside it

qsafe.keygen("sk.bin", "pk.bin", "passphrase")
blob = qsafe.encrypt_bytes(b"secret", ["pk.bin"])      # bytes in, bytes out
assert qsafe.decrypt_bytes(blob, "sk.bin", "passphrase") == b"secret"
```

Errors raise `qsafe.QsafeError`. See `python/test_qsafe.py` for the full surface.

---

## age interoperability

Qsafe can read and write [age](https://age-encryption.org) v1 files for X25519
recipients, so it interoperates with the `age` tool and other v1 implementations:

```bash
qsafe age-keygen key.txt                       # age1… / AGE-SECRET-KEY-1…
qsafe age-encrypt -r age1q...  report.pdf report.pdf.age
qsafe age-decrypt -i key.txt   report.pdf.age report.pdf
# …and the files round-trip with the real `age` binary, both directions.
```

> **No post-quantum protection here.** age v1 is a *classical* X25519 format.
> These commands exist for ecosystem compatibility; for quantum-resistant
> encryption use Qsafe's native `encrypt`/`decrypt` (X25519 + ML-KEM-1024).

---

## File Formats

> The complete byte-level specification — every field, the key-wrap and AEAD
> construction, the secret-key and signature formats, and armor — lives in
> **[docs/FORMAT.md](docs/FORMAT.md)**. The summary below is informative.

### Encrypted File

`qsafe encrypt` writes the framed **QSAFE006** format; `qsafe decrypt` also
reads the legacy **QSAFE005** format. The full byte-level spec for both is in
[docs/FORMAT.md](docs/FORMAT.md).

```
Offset       Size          Field
-----------  ------------  ----------------------------
0x0000       8 bytes       Version header ("QSAFE006")
0x0008       1 byte        recipient count (1..16)
0x0009       N * 1660      recipient records (see below)
...          variable      frame[0..k-1]: each is ciphertext ‖ 16-byte tag
```

Each recipient record (1660 bytes) is:

```
ephemeral X25519 public key   32 bytes
ML-KEM-1024 ciphertext      1568 bytes
CEK wrap nonce                12 bytes
wrapped content key (CEK)     32 bytes
CEK wrap tag                  16 bytes
```

The payload (a 272-byte metadata block followed by the file contents) is
encrypted as a sequence of **64 KiB frames**, each its own AES-256-GCM segment
keyed by a random per-file content key. The header (magic, recipient count, and
every record) is authenticated as additional data on the first frame; each
frame's nonce carries a counter and a final-frame flag, so reordering and
truncation are detected. Every frame is verified before its plaintext is
released — constant memory, no buffering. The metadata block is:

```
Offset  Size       Field
------  ---------  ----------------------------
0x000   1 byte     flags (bit 0: metadata present)
0x001   1 byte     reserved
0x002   2 bytes    original name length (LE)
0x004   256 bytes  original filename
0x104   4 bytes    permission bits (mode & 0777, LE)
0x108   8 bytes    modification time (seconds, LE)
```

**Per-file overhead:** 9 + (N × 1660) + 272 + 16·(frames) bytes for N
recipients (a small single-recipient file is one frame: 9 + 1660 + 272 + 16 =
1957 bytes of overhead). Each additional 64 KiB frame adds a 16-byte tag.

### Secret Key File (`secret_key.bin`)

```
Offset       Size          Field
-----------  ------------  ----------------------------
0x0000       8 bytes       Key-file magic ("QSAFEK01")
0x0008       8 bytes       scrypt N (LE)
0x0010       4 bytes       scrypt r (LE)
0x0014       4 bytes       scrypt p (LE)
0x0018       12 bytes      AES-GCM nonce
0x0024       16 bytes      scrypt salt
0x0034       variable      Encrypted secret key (X25519 ‖ ML-KEM-1024)
EOF - 16     16 bytes      AES-GCM authentication tag
```

The magic and scrypt parameters are authenticated as additional data, so the
KDF cost is self-describing and tamper-evident. Written with `0600`
permissions. (Signing secret keys use the same wrapper format.)

### Public Key File (`secret_key.bin.pub`)

```
Offset       Size          Field
-----------  ------------  ----------------------------
0x0000       32 bytes      Raw X25519 public key
0x0020       1568 bytes    Raw ML-KEM-1024 public key
```

Stored in the clear — it contains no secret material and is all that
`encrypt` needs.

---

## Key Management

### Keyring (named identities)

Instead of juggling key-file paths, you can keep keys in a keyring under
`~/.qsafe` (override with `$QSAFE_HOME`):

```bash
qsafe keygen --identity me                 # ~/.qsafe/identities/me/
qsafe keys import alice alice_pub.bin       # save a recipient under a name
qsafe keys list                             # identities + recipients, with fingerprints

qsafe encrypt -r alice -r me report.pdf     # -r takes keyring names or paths
qsafe decrypt --identity me report.pdf.qsafe
qsafe keys remove alice
qsafe keys path                             # print the keyring location
```

Layout: `~/.qsafe/identities/<name>/{secret_key.bin,public_key.bin}` and
`~/.qsafe/recipients/<name>.pub`. For `-r`, a real file path always wins over a
keyring name. Names may not contain path separators.

### Generated Artifacts

| File | Size | Contents |
|:--|:--|:--|
| `secret_key.bin` | ~3.3 KB | Passphrase-encrypted X25519 + ML-KEM-1024 secret key (`0600`) |
| `secret_key.bin.pub` | 1600 bytes | Raw X25519 + ML-KEM-1024 public key (encryption only) |
| `<name>.qsafe` | input + ~2 KB/recipient | Recipient records + AES-GCM encrypted data + metadata |

### Best Practices

1. **Use a strong passphrase** — scrypt slows down guessing, but a weak passphrase is still the weakest link.
2. **Key file permissions** — `secret_key.bin` is created with `0600` automatically; keep it that way.
3. **Back up the secret key separately from encrypted data:**
   ```bash
   cp secret_key.bin /secure-backup/
   ```
4. **Use dedicated key files per project:**
   ```bash
   qsafe --key-file project_a.key keygen
   qsafe --key-file project_a.key encrypt ...
   ```
5. **The public key is safe to distribute** — anyone with it can encrypt *to* you, but only the secret key (and passphrase) can decrypt.
6. **Rotate keys periodically** — re-encrypt long-term data under a fresh keypair.

---

## Security Model

> **Qsafe has not been independently audited.** It is built on well-reviewed
> primitives (OpenSSL, liboqs) and backed by known-answer tests, sanitizer/
> Valgrind CI, and a fuzzing harness — but the surrounding code has not had a
> third-party review. For the full picture of what is and isn't protected, read
> the **[Threat Model](THREAT_MODEL.md)**. To report a vulnerability, see
> **[SECURITY.md](SECURITY.md)**.

| Threat | Mitigation |
|:--|:--|
| Quantum key recovery | ML-KEM-1024 (NIST Level 5), combined with X25519 — breaking one layer is not enough |
| Cryptanalytic break of one primitive | Hybrid X25519 + ML-KEM: an attacker must break *both* |
| Ciphertext / header tampering | AES-256-GCM authenticates the payload and the entire header (magic, recipient records, nonce) as AAD |
| File forgery / wrong sender | `sign` / `verify-sig` (ML-DSA-87) provide sender authenticity |
| Passphrase guessing on a stolen key file | scrypt (memory-hard, tunable cost) with a random salt slows brute force |
| Key file compromise without passphrase | Secret key is AES-256-GCM encrypted with a scrypt-derived key |
| Memory exposure | Key material is wiped (`OPENSSL_cleanse`) before deallocation |

### Failure Modes

- **Lost `secret_key.bin`** — encrypted files are permanently unrecoverable. There is no backdoor.
- **Forgotten passphrase** — the secret key cannot be decrypted. Data is permanently lost.
- **Modified ciphertext** — decryption fails with an integrity error; the partial output **file** is removed (but see the streaming caveat below).

### Known Limitations

See [THREAT_MODEL.md](THREAT_MODEL.md) for the complete list. The most important:

- **Metadata leakage:** Qsafe does not pad, so the approximate plaintext size and the recipient *count* are visible. The filename, mode, and mtime are encrypted.
- **No forward secrecy for long-term keys:** if a secret key (and passphrase) are later compromised, all past files encrypted to it can be decrypted.
- **Streaming and authentication:** QSAFE006 is framed — the payload is a sequence of 64 KiB frames, each authenticated independently, so every frame's plaintext is released only after that frame verifies, in constant memory for both files and pipes. Caveat: for a multi-frame file, earlier (authenticated) frames are released before a later corrupt frame is detected, so a verified *prefix* may already be emitted on failure — check the exit code. (Legacy QSAFE005 files buffer the whole pipe payload instead.)
- **`--passphrase` on the CLI** is visible in the process list / shell history; prefer the prompt, `$QSAFE_PASSPHRASE`, or `--passphrase-file`.

---

## Project Structure

```
Qsafe/
├── .github/
│   └── workflows/
│       └── ci.yml             # Build + test on every push / PR
├── src/
│   ├── main.c                 # CLI interface and argument parsing
│   └── crypto_utils.c         # Core cryptographic operations
├── include/
│   └── crypto_utils.h         # Public API, constants, and type definitions
├── tests/
│   ├── test_crypto_utils.c    # Unit tests
│   └── test.sh                # End-to-end integration tests
├── scripts/
│   └── setup.sh               # Dependency installer (macOS / Ubuntu / Debian)
├── docs/
│   └── encryption_flow.md     # Encryption pipeline diagram
├── Makefile                   # Build configuration
├── .gitignore                 # Git ignore rules
├── LICENSE                    # MIT License
└── README.md                  # This file
```

---

## Testing

```bash
make test
```

Runs the unit tests (`tests/test_crypto_utils.c`) and the end-to-end
integration tests (`tests/test.sh`), covering KDF behavior, key-file
round-trips, empty/single-chunk/multi-chunk files, recursive directories,
wrong-passphrase rejection, and tamper detection.

---

## Compatibility

Qsafe 6.0 changes the default encrypted-file format to the framed **QSAFE006**
(see [docs/FORMAT.md](docs/FORMAT.md)). This is **not** a breaking change for
reading: `decrypt` accepts both QSAFE006 and QSAFE005, so files produced by 5.0
still open. `encrypt` now writes QSAFE006, which 5.x builds cannot read — re-cut
any ciphertext you need older builds to open. Keys are unchanged across 5.x→6.0.

Qsafe 5.0 was a **breaking change** from 4.x. Key establishment is now hybrid
(X25519 + ML-KEM-1024) and the file format (`QSAFE005`) carries per-recipient
records, so keypairs and encrypted files must be regenerated: `QSAFE004` files
cannot be read by 5.0 — decrypt them with a 4.x build, then re-encrypt. Secret
key files also gained a self-describing scrypt-cost header (`QSAFEK01`); 4.x
keys without it are still accepted. New commands (`verify`, `rekey`, `inspect`,
`sign-keygen`, `sign`, `verify-sig`) and options (`-r/--recipient`, `--armor`,
`--check`, `--scrypt-cost`) are additive.

---

## License

Released under the [MIT License](LICENSE).
