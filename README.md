<p align="center">
  <h1 align="center">Qsafe</h1>
  <p align="center">
    Post-quantum file encryption built for the future.
    <br />
    <strong>ML-KEM-1024 + AES-256-GCM + HKDF-SHA256 + scrypt</strong>
  </p>
</p>

<p align="center">
  <img src="https://img.shields.io/badge/version-3.0.0-blue" alt="Version">
  <img src="https://img.shields.io/badge/license-MIT-green" alt="License">
  <img src="https://img.shields.io/badge/NIST-FIPS%20203-orange" alt="NIST FIPS 203">
  <img src="https://img.shields.io/badge/language-C-lightgrey" alt="C">
</p>

---

## Overview

Qsafe is a command-line file encryption tool that combines **post-quantum key encapsulation** with **classical authenticated encryption** to provide long-term data confidentiality against both classical and quantum adversaries.

It uses **ML-KEM-1024** (NIST FIPS 203, formerly CRYSTALS-Kyber) for key encapsulation and **AES-256-GCM** for authenticated encryption. The KEM shared secret is expanded with **HKDF-SHA256**; the secret key is protected at rest with a key derived from your passphrase using **scrypt**, a memory-hard password KDF.

### Key Features

- **Quantum-resistant** — ML-KEM-1024 (NIST FIPS 203, security Level 5)
- **Authenticated encryption** — AES-256-GCM provides confidentiality *and* integrity; the file header and KEM ciphertext are authenticated as additional data (AAD)
- **Streaming architecture** — constant memory usage for both encryption and decryption via 4 KB chunked I/O
- **Passphrase-protected keys** — secret keys are wrapped with a scrypt-derived key and a random salt
- **Batch processing** — recursively encrypt or decrypt entire directory trees
- **Tamper detection** — modified ciphertext, header, or KEM ciphertext is rejected

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
| QSAFE003 | KEM Ciphertext (1568 B) | AES Ciphertext | Nonce | Tag |
+-----------+-------------------------+----------------+-------+-----+
            \_________ authenticated as GCM AAD ______/
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
| GCC | 7+ | C compiler (C11) |
| GNU Make | 3.81+ | Build system |
| CMake | 3.5+ | Build liboqs |
| OpenSSL | 3.0+ | AES-256-GCM, HKDF, scrypt, CSPRNG |
| [liboqs](https://github.com/open-quantum-safe/liboqs) | 0.10+ | ML-KEM-1024 implementation |

---

## Installation

### Automated (Ubuntu/Debian)

```bash
chmod +x scripts/setup.sh
./scripts/setup.sh
make
```

### Manual

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

The `crypto-v2` binary will be placed in the project root.

### Verify Installation

```bash
./crypto-v2 --help
```

---

## Usage

### Synopsis

```
./crypto-v2 [OPTIONS] <encrypt|decrypt> <input> <output> <file|dir>
```

### Options

| Option | Description |
|:--|:--|
| `--passphrase <str>` | **(Required)** Passphrase to protect the ML-KEM secret key |
| `--key-file <path>` | Path to the secret key file (default: `secret_key.bin`) |
| `--verbose` | Print detailed cryptographic information |
| `--force` | Overwrite existing output files without prompting |
| `--help` | Display usage information |

> Options must precede the positional arguments. Without `--force`, Qsafe asks
> for confirmation before overwriting an existing output file.

### Examples

**Encrypt a file:**

```bash
./crypto-v2 --passphrase "strong-passphrase" encrypt document.pdf document.pdf.enc file
```

**Decrypt a file:**

```bash
./crypto-v2 --passphrase "strong-passphrase" decrypt document.pdf.enc document.pdf file
```

**Encrypt a directory (recursive):**

```bash
./crypto-v2 --passphrase "strong-passphrase" encrypt ./sensitive/ ./encrypted/ dir
```

**Decrypt a directory:**

```bash
./crypto-v2 --passphrase "strong-passphrase" decrypt ./encrypted/ ./decrypted/ dir
```

**Custom key file:**

```bash
./crypto-v2 --key-file project.key --passphrase "pass" encrypt data.csv data.csv.enc file
./crypto-v2 --key-file project.key --passphrase "pass" decrypt data.csv.enc data.csv file
```

> **Note:** passing `--passphrase` on the command line exposes it to other
> users via the process list and your shell history. For sensitive use, prefer
> a dedicated key file with restrictive permissions and a passphrase you do not
> reuse elsewhere.

---

## File Formats

### Encrypted File

```
Offset       Size          Field
-----------  ------------  ----------------------------
0x0000       8 bytes       Version header ("QSAFE003")
0x0008       1568 bytes    ML-KEM-1024 KEM ciphertext
0x0628       variable      AES-256-GCM ciphertext
EOF - 28     12 bytes      GCM nonce (IV)
EOF - 16     16 bytes      GCM authentication tag
```

The version header and KEM ciphertext are authenticated as GCM additional
data, so tampering with either is detected.

**Per-file overhead:** 1604 bytes (8 + 1568 + 12 + 16)

### Secret Key File (`secret_key.bin`)

```
Offset       Size          Field
-----------  ------------  ----------------------------
0x0000       12 bytes      AES-GCM nonce
0x000C       16 bytes      scrypt salt
0x001C       3168 bytes    Encrypted ML-KEM-1024 secret key
0x0C7C       16 bytes      AES-GCM authentication tag
```

**Fixed size:** 3212 bytes

---

## Key Management

### Generated Artifacts

| File | Size | Contents |
|:--|:--|:--|
| `secret_key.bin` | 3212 bytes | Passphrase-encrypted ML-KEM-1024 secret key |
| `<output>.enc` | input size + 1604 bytes | KEM ciphertext + AES-GCM encrypted data |

### Best Practices

1. **Use a strong passphrase** — scrypt slows down guessing, but a weak passphrase is still the weakest link.
2. **Restrict key file permissions:**
   ```bash
   chmod 600 secret_key.bin
   ```
3. **Back up key files separately from encrypted data:**
   ```bash
   cp secret_key.bin /secure-backup/
   ```
4. **Use dedicated key files per project:**
   ```bash
   ./crypto-v2 --key-file project_a.key --passphrase "pass-a" encrypt ...
   ./crypto-v2 --key-file project_b.key --passphrase "pass-b" encrypt ...
   ```
5. **Rotate keys periodically** — re-encrypt data with fresh keypairs for long-term storage.

---

## Security Model

| Threat | Mitigation |
|:--|:--|
| Quantum key recovery | ML-KEM-1024 (NIST Level 5) resists known quantum algorithms |
| Ciphertext / header tampering | AES-256-GCM authenticates the payload and the header + KEM ciphertext (AAD) |
| Passphrase guessing on a stolen key file | scrypt (memory-hard) with a random salt slows brute force |
| Key file compromise without passphrase | Secret key is AES-256-GCM encrypted with a scrypt-derived key |
| Memory exposure | Key material is wiped (`OPENSSL_cleanse`) before deallocation |

### Failure Modes

- **Lost `secret_key.bin`** — encrypted files are permanently unrecoverable. There is no backdoor.
- **Forgotten passphrase** — the secret key cannot be decrypted. Data is permanently lost.
- **Modified ciphertext** — decryption fails with an integrity error; the partial output file is removed.

### Known Limitations

- The passphrase is read from `--passphrase` and is therefore visible in the process list and shell history.
- Each encryption generates a fresh keypair and overwrites the key file; the public key is not retained, so a key file decrypts only files produced in the same run unless reused deliberately.

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
│   └── setup.sh               # Dependency installer (Ubuntu/Debian)
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

Qsafe 3.0 is a **breaking change** from 2.x: it switched the KEM to ML-KEM-1024
(FIPS 203) and the key-file format to scrypt + salt. Files and key files
produced by Qsafe 2.x (`CRYPTOv2`) cannot be read by 3.0. Decrypt any 2.x data
with a 2.x build before upgrading.

---

## License

Released under the [MIT License](LICENSE).
