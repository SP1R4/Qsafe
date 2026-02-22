<p align="center">
  <h1 align="center">Qsafe 2.0</h1>
  <p align="center">
    Post-quantum file encryption built for the future.
    <br />
    <strong>Kyber1024 (ML-KEM) + AES-256-GCM + HKDF-SHA256</strong>
  </p>
</p>

<p align="center">
  <img src="https://img.shields.io/badge/version-2.0.0-blue" alt="Version">
  <img src="https://img.shields.io/badge/license-MIT-green" alt="License">
  <img src="https://img.shields.io/badge/NIST-PQC%20Level%205-orange" alt="NIST PQC Level 5">
  <img src="https://img.shields.io/badge/language-C-lightgrey" alt="C">
</p>

---

## Overview

Qsafe 2.0 is a command-line file encryption tool that combines **post-quantum key encapsulation** with **classical symmetric encryption** to provide long-term data confidentiality against both classical and quantum adversaries.

It uses **CRYSTALS-Kyber (ML-KEM-1024)** for key encapsulation and **AES-256-GCM** for authenticated encryption, with **HKDF-SHA256** for key derivation. Secret keys are protected by a user-supplied passphrase.

### Key Features

- **Quantum-resistant** -- NIST FIPS 203 compliant Kyber1024 at security Level 5
- **Authenticated encryption** -- AES-256-GCM ensures both confidentiality and integrity
- **Streaming architecture** -- constant memory usage via 4 KB chunked I/O
- **Passphrase-protected keys** -- Kyber secret keys encrypted at rest with HKDF-derived keys
- **Batch processing** -- encrypt or decrypt entire directories in a single command
- **Tamper detection** -- GCM authentication tags reject any modified ciphertext

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
- [License](#license)

---

## Architecture

### Cryptographic Primitives

| Component | Algorithm | Specification | Security Level |
|:--|:--|:--|:--|
| Key Encapsulation | Kyber1024 (ML-KEM-1024) | NIST FIPS 203 | Level 5 (AES-256 equivalent) |
| Symmetric Encryption | AES-256-GCM | NIST SP 800-38D | 256-bit |
| Key Derivation | HKDF-SHA256 | RFC 5869 | 256-bit |
| Random Generation | OpenSSL `RAND_bytes` | CSPRNG | System entropy |

### Encryption Flow

```
                        +-----------------+
                        |   Passphrase    |
                        +--------+--------+
                                 |
                            HKDF-SHA256
                                 |
                                 v
+-------------+         +-------+--------+         +----------------+
| Kyber1024   |-------->| Secret Key     |-------->| secret_key.bin |
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
| CRYPTOv2 | KEM Ciphertext (1568 B) | AES Ciphertext | Nonce | Tag |
+-----------+-------------------------+----------------+-------+-----+
```

### Decryption Flow

```
secret_key.bin + Passphrase --> HKDF --> AES-GCM Decrypt --> Kyber Secret Key
                                                                    |
Encrypted File --> Parse Header --> KEM Ciphertext -----------------+
                                                                    |
                                              Kyber Decapsulate <---+
                                                      |
                                                Shared Secret
                                                      |
                                                 HKDF-SHA256
                                                      |
                                                 AES-256 Key
                                                      |
                                   AES-GCM Decrypt (4 KB chunks)
                                                      |
                                              Verify GCM Tag
                                                      |
                                                  Plaintext
```

---

## Requirements

| Dependency | Minimum Version | Purpose |
|:--|:--|:--|
| GCC | 7+ | C compiler |
| GNU Make | 3.81+ | Build system |
| CMake | 3.0+ | Build liboqs |
| OpenSSL | 3.0+ | AES-256-GCM, HKDF, CSPRNG |
| [liboqs](https://github.com/open-quantum-safe/liboqs) | 0.8+ | Kyber1024 KEM implementation |

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
sudo apt update && sudo apt install -y build-essential libssl-dev cmake

# Build and install liboqs
git clone https://github.com/open-quantum-safe/liboqs.git
cd liboqs && mkdir build && cd build
cmake -DCMAKE_BUILD_TYPE=Release ..
make -j$(nproc)
sudo make install && sudo ldconfig
cd ../..

# Build Qsafe 2.0
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
| `--passphrase <str>` | **(Required)** Passphrase to protect the Kyber secret key |
| `--key-file <path>` | Path to the secret key file (default: `secret_key.bin`) |
| `--verbose` | Print detailed cryptographic information |
| `--force` | Overwrite output files without confirmation |
| `--help` | Display usage information |

> Options must precede the positional arguments.

### Examples

**Encrypt a file:**

```bash
./crypto-v2 --passphrase "strong-passphrase" encrypt document.pdf document.pdf.enc file
```

**Decrypt a file:**

```bash
./crypto-v2 --passphrase "strong-passphrase" decrypt document.pdf.enc document.pdf file
```

**Encrypt a directory:**

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

**Verbose output:**

```bash
./crypto-v2 --verbose --passphrase "pass" encrypt file.txt file.enc file
```

---

## File Formats

### Encrypted File

```
Offset       Size          Field
-----------  ------------  ----------------------------
0x0000       8 bytes       Version header ("CRYPTOv2")
0x0008       1568 bytes    Kyber1024 KEM ciphertext
0x0628       variable      AES-256-GCM ciphertext
EOF - 28     12 bytes      GCM nonce (IV)
EOF - 16     16 bytes      GCM authentication tag
```

**Per-file overhead:** 1604 bytes (8 + 1568 + 12 + 16)

### Secret Key File (`secret_key.bin`)

```
Offset       Size          Field
-----------  ------------  ----------------------------
0x0000       12 bytes      AES-GCM nonce
0x000C       3168 bytes    Encrypted Kyber1024 secret key
0x0C6C       16 bytes      AES-GCM authentication tag
```

**Fixed size:** 3196 bytes

---

## Key Management

### Generated Artifacts

| File | Size | Contents |
|:--|:--|:--|
| `secret_key.bin` | 3196 bytes | Passphrase-encrypted Kyber1024 secret key |
| `<output>.enc` | input size + 1604 bytes | KEM ciphertext + AES-GCM encrypted data |

### Best Practices

1. **Use a strong passphrase** -- the passphrase is the sole protection for the Kyber secret key at rest.
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
5. **Rotate keys periodically** -- re-encrypt data with fresh keypairs for long-term storage.

---

## Security Model

| Threat | Mitigation |
|:--|:--|
| Quantum key recovery | Kyber1024 (NIST Level 5) is resistant to known quantum algorithms |
| Ciphertext tampering | AES-256-GCM authentication tag rejects any modification |
| Key file compromise without passphrase | Secret key is AES-GCM encrypted with HKDF-derived key |
| Memory exposure | All key material is zeroed (`memset`) before deallocation |

### Failure Modes

- **Lost `secret_key.bin`** -- encrypted files are permanently unrecoverable. There is no backdoor.
- **Forgotten passphrase** -- the secret key cannot be decrypted. Data is permanently lost.
- **Modified ciphertext** -- decryption fails with an integrity error (GCM tag mismatch).

---

## Project Structure

```
Qsafe2.0/
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
│   ├── ReadMe.md              # Extended documentation
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

Runs the full test suite including unit tests and end-to-end encryption/decryption verification.

---

## License

Released under the [MIT License](LICENSE).
