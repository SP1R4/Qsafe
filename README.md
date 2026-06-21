<p align="center">
  <h1 align="center">Qsafe</h1>
  <p align="center">
    Post-quantum file encryption built for the future.
    <br />
    <strong>ML-KEM-1024 + AES-256-GCM + HKDF-SHA256 + scrypt</strong>
  </p>
</p>

<p align="center">
  <img src="https://img.shields.io/badge/version-4.0.0-blue" alt="Version">
  <img src="https://img.shields.io/badge/license-MIT-green" alt="License">
  <img src="https://img.shields.io/badge/NIST-FIPS%20203-orange" alt="NIST FIPS 203">
  <img src="https://img.shields.io/badge/language-C-lightgrey" alt="C">
</p>

---

## Overview

Qsafe is a command-line file encryption tool that combines **post-quantum key encapsulation** with **classical authenticated encryption** to provide long-term data confidentiality against both classical and quantum adversaries.

It uses **ML-KEM-1024** (NIST FIPS 203, formerly CRYSTALS-Kyber) for key encapsulation and **AES-256-GCM** for authenticated encryption. The KEM shared secret is expanded with **HKDF-SHA256**; the secret key is protected at rest with a key derived from your passphrase using **scrypt**, a memory-hard password KDF.

Qsafe follows a true public-key workflow: you generate a keypair **once** with `keygen`, then encrypt to the public key (no passphrase needed) and decrypt with the passphrase-wrapped secret key. Encrypted files are durable — encrypting a second file never invalidates the first.

### Key Features

- **Quantum-resistant** — ML-KEM-1024 (NIST FIPS 203, security Level 5)
- **Durable public-key workflow** — generate a keypair once; encrypt with the public key, decrypt with the secret key. Encrypting never overwrites your keys.
- **Authenticated encryption** — AES-256-GCM provides confidentiality *and* integrity; the file header, nonce, and KEM ciphertext are authenticated as additional data (AAD)
- **Streaming architecture** — constant memory usage for both encryption and decryption via 4 KB chunked I/O
- **Pipe-friendly** — use `-` for stdin/stdout, so Qsafe composes with `tar`, `ssh`, and friends
- **Metadata preservation** — the original filename, permission bits, and modification time are encrypted alongside the data and restored on decrypt
- **Smart defaults** — files vs. directories are auto-detected and output paths are inferred when omitted
- **Flexible passphrase entry** — interactive no-echo prompt, `$QSAFE_PASSPHRASE`, or `--passphrase-file` (never required on the command line)
- **Passphrase-protected keys** — secret keys are wrapped with a scrypt-derived key and a random salt
- **Batch processing** — recursively encrypt or decrypt entire directory trees
- **Tamper detection** — modified ciphertext, header, nonce, or KEM ciphertext is rejected
- **Cross-platform** — builds on Linux and macOS (Homebrew)

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
| Key Encapsulation | ML-KEM-1024 | NIST FIPS 203 | Level 5 (AES-256 equivalent) |
| Symmetric Encryption | AES-256-GCM | NIST SP 800-38D | 256-bit, authenticated |
| Shared-secret KDF | HKDF-SHA256 | RFC 5869 | KEM secret → AES key |
| Passphrase KDF | scrypt (N=2¹⁵, r=8, p=1) | RFC 7914 | Memory-hard key wrapping |
| Random Generation | OpenSSL `RAND_bytes` | CSPRNG | System entropy |

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
+------+----------------------------------------------------+------+
| QSAFE004 | Nonce (12 B) | KEM Ciphertext (1568 B) | AES Ciphertext | Tag |
+-----------+-------------+-------------------------+----------------+-----+
 \____________ authenticated as GCM AAD _______________/

The AES ciphertext covers a fixed 272-byte metadata block (original name,
mode, mtime) followed by the file contents. The nonce sits at the front so
decryption can stream straight from a pipe; the 16-byte tag is the trailing
bytes of the stream.
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
sudo make install           # installs to /usr/local/bin (override with PREFIX=)
```

### Verify Installation

```bash
./qsafe --help
```

---

## Usage

### Synopsis

```
qsafe keygen  [options]
qsafe encrypt [options] <input> [output]
qsafe decrypt [options] <input> [output]
```

Files and directories are detected automatically — there is no `file|dir`
argument. When the output path is omitted, a sensible default is used
(`<name>.qsafe` for encrypt, the original name for decrypt). Use `-` for the
input or output to read from stdin / write to stdout.

### Commands

| Command | Description |
|:--|:--|
| `keygen` | Generate an ML-KEM-1024 keypair (run once). Needs the passphrase. |
| `encrypt` | Encrypt a file or directory using the public key. **No passphrase needed.** |
| `decrypt` | Decrypt a file or directory using the passphrase-wrapped secret key. |

### Options

| Option | Description |
|:--|:--|
| `--key-file <path>` | Secret key file (default: `secret_key.bin`) |
| `--pub-file <path>` | Public key file (default: `<key-file>.pub`) |
| `--passphrase <str>` | Passphrase (discouraged — visible to other users) |
| `--passphrase-file <path>` | Read the passphrase from the first line of a file |
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

## File Formats

### Encrypted File

```
Offset       Size          Field
-----------  ------------  ----------------------------
0x0000       8 bytes       Version header ("QSAFE004")
0x0008       12 bytes      GCM nonce (IV)
0x0014       1568 bytes    ML-KEM-1024 KEM ciphertext
0x0634       variable      AES-256-GCM ciphertext (metadata + data)
EOF - 16     16 bytes      GCM authentication tag
```

The header, nonce, and KEM ciphertext are authenticated as GCM additional
data, so tampering with any of them is detected. The nonce sits at the front
so decryption can stream from a pipe without seeking; the tag is the final
16 bytes of the stream.

The AES ciphertext begins with a fixed **272-byte metadata block** (encrypted
and authenticated alongside the data) before the file contents:

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

**Per-file overhead:** 1876 bytes (8 + 12 + 1568 + 272 + 16)

### Secret Key File (`secret_key.bin`)

```
Offset       Size          Field
-----------  ------------  ----------------------------
0x0000       12 bytes      AES-GCM nonce
0x000C       16 bytes      scrypt salt
0x001C       3168 bytes    Encrypted ML-KEM-1024 secret key
0x0C7C       16 bytes      AES-GCM authentication tag
```

**Fixed size:** 3212 bytes (written with `0600` permissions)

### Public Key File (`secret_key.bin.pub`)

```
Offset       Size          Field
-----------  ------------  ----------------------------
0x0000       1568 bytes    Raw ML-KEM-1024 public key
```

Stored in the clear — it contains no secret material and is all that
`encrypt` needs.

---

## Key Management

### Generated Artifacts

| File | Size | Contents |
|:--|:--|:--|
| `secret_key.bin` | 3212 bytes | Passphrase-encrypted ML-KEM-1024 secret key (`0600`) |
| `secret_key.bin.pub` | 1568 bytes | Raw ML-KEM-1024 public key (encryption only) |
| `<name>.qsafe` | input size + 1876 bytes | KEM ciphertext + AES-GCM encrypted data + metadata |

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

| Threat | Mitigation |
|:--|:--|
| Quantum key recovery | ML-KEM-1024 (NIST Level 5) resists known quantum algorithms |
| Ciphertext / header tampering | AES-256-GCM authenticates the payload and the header + nonce + KEM ciphertext (AAD) |
| Passphrase guessing on a stolen key file | scrypt (memory-hard) with a random salt slows brute force |
| Key file compromise without passphrase | Secret key is AES-256-GCM encrypted with a scrypt-derived key |
| Memory exposure | Key material is wiped (`OPENSSL_cleanse`) before deallocation |

### Failure Modes

- **Lost `secret_key.bin`** — encrypted files are permanently unrecoverable. There is no backdoor.
- **Forgotten passphrase** — the secret key cannot be decrypted. Data is permanently lost.
- **Modified ciphertext** — decryption fails with an integrity error; the partial output file is removed.

### Known Limitations

- Filenames are padded to a fixed 256-byte field but the *length* of the plaintext (and thus the file size) is not otherwise hidden; Qsafe does not pad data to obscure file sizes.
- When `--passphrase` is used it is visible in the process list and shell history. The interactive prompt, `$QSAFE_PASSPHRASE`, and `--passphrase-file` avoid this.
- Anyone with your public key can produce valid ciphertexts for you; Qsafe provides confidentiality and integrity, not sender authentication.

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

Qsafe 4.0 is a **breaking change** from 3.x. The file format moved the nonce to
the front, added an encrypted metadata block, and adopted a true public-key
workflow (separate `keygen`). `QSAFE003` files cannot be read by 4.0 — decrypt
them with a 3.x build first. The CLI also changed: the trailing `file|dir`
argument is gone (types are auto-detected), output paths are optional, and the
binary is now `qsafe` (previously `crypto-v2`).

---

## License

Released under the [MIT License](LICENSE).
