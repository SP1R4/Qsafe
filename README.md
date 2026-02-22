# Qsafe

A post-quantum file encryption CLI tool using **Kyber1024** (CRYSTALS-Kyber KEM) and **AES-256-GCM**, designed to protect data against both classical and quantum computer attacks.

---

## Table of Contents

- [How It Works](#how-it-works)
  - [Encryption Process](#encryption-process)
  - [Decryption Process](#decryption-process)
  - [Encrypted File Format](#encrypted-file-format)
  - [Secret Key Storage Format](#secret-key-storage-format)
  - [Cryptographic Primitives](#cryptographic-primitives)
- [Dependencies](#dependencies)
- [Installation](#installation)
- [Usage](#usage)
  - [Command Syntax](#command-syntax)
  - [Options Reference](#options-reference)
  - [Encrypting a Single File](#encrypting-a-single-file)
  - [Decrypting a Single File](#decrypting-a-single-file)
  - [Encrypting a Directory](#encrypting-a-directory)
  - [Decrypting a Directory](#decrypting-a-directory)
  - [Using Custom Key Files](#using-custom-key-files)
  - [Verbose Mode](#verbose-mode)
- [Key Management](#key-management)
- [Project Structure](#project-structure)
- [Testing](#testing)
- [License](#license)

---

## How It Works

Qsafe 2.0 uses a **hybrid encryption scheme** that combines post-quantum key encapsulation with classical symmetric encryption. This means your data is protected even if large-scale quantum computers become available in the future.

### Encryption Process

```
Step 1: Key Generation
  User passphrase ──► HKDF-SHA256 ──► Passphrase-derived key (32 bytes)
  Kyber1024 ──► Public key + Secret key (3168 bytes)
  Secret key ──► AES-256-GCM encrypt with passphrase key ──► secret_key.bin

Step 2: File Encryption
  Public key ──► Kyber encapsulation ──► KEM ciphertext (1568 bytes) + Shared secret (32 bytes)
  Shared secret ──► HKDF-SHA256 ──► AES key (32 bytes)
  Random ──► Nonce (12 bytes)
  Plaintext file ──► AES-256-GCM encrypt (streaming, 4KB chunks) ──► Ciphertext

Step 3: Output Assembly
  Write to output: [Version header] [KEM ciphertext] [AES ciphertext] [Nonce] [GCM Tag]
```

**Detailed walkthrough:**

1. **Kyber keypair generation** - A fresh Kyber1024 keypair (public key + 3168-byte secret key) is generated using liboqs. The secret key is encrypted with a key derived from your passphrase via HKDF-SHA256 and stored in `secret_key.bin`.

2. **Key encapsulation** - The Kyber public key is used to perform KEM encapsulation, producing a 1568-byte KEM ciphertext and a 32-byte shared secret. Only the holder of the Kyber secret key can recover this shared secret.

3. **AES key derivation** - The 32-byte Kyber shared secret is passed through HKDF-SHA256 to derive a 256-bit AES key. A random 12-byte nonce is generated via OpenSSL's `RAND_bytes`.

4. **Streaming encryption** - The input file is read in 4KB chunks and encrypted with AES-256-GCM. Each chunk is immediately written to the output file, keeping memory usage constant regardless of file size.

5. **Authentication** - After all chunks are processed, AES-GCM produces a 16-byte authentication tag. This tag is appended to the output along with the nonce, ensuring any tampering is detected during decryption.

### Decryption Process

```
Step 1: Key Recovery
  secret_key.bin ──► AES-256-GCM decrypt with passphrase key ──► Kyber secret key

Step 2: File Parsing
  Encrypted file ──► Parse [Header] [KEM ciphertext] [AES ciphertext] [Nonce] [Tag]

Step 3: Key Decapsulation
  KEM ciphertext + Kyber secret key ──► Kyber decapsulation ──► Shared secret
  Shared secret ──► HKDF-SHA256 ──► AES key (32 bytes)

Step 4: File Decryption
  AES ciphertext ──► AES-256-GCM decrypt (streaming, 4KB chunks) ──► Plaintext
  Verify GCM tag ──► Authentication check (reject if tampered)
```

**Detailed walkthrough:**

1. **Secret key recovery** - The encrypted secret key is loaded from `secret_key.bin`, and the passphrase-derived key is used to decrypt it via AES-256-GCM. If the passphrase is wrong or the key file is corrupted, authentication fails and decryption is refused.

2. **File format validation** - The encrypted file is opened and validated: the `CRYPTOv2` version header is checked, and the file size is verified to contain at least the header + KEM ciphertext + nonce + tag.

3. **Key decapsulation** - The KEM ciphertext is extracted and passed to Kyber decapsulation along with the secret key, recovering the original 32-byte shared secret. HKDF-SHA256 derives the same AES key used during encryption.

4. **Streaming decryption** - The AES ciphertext is decrypted in 4KB chunks and written to the output file. After all chunks are processed, the GCM authentication tag is verified. If verification fails (file was tampered with), the operation fails with an integrity error.

### Encrypted File Format

```
Offset    Size        Field
──────    ──────────  ─────────────────────────────────
0         8 bytes     Version header ("CRYPTOv2")
8         1568 bytes  Kyber1024 KEM ciphertext
1576      variable    AES-256-GCM encrypted data
EOF-28    12 bytes    AES-GCM nonce (IV)
EOF-16    16 bytes    AES-GCM authentication tag
```

- **Total overhead per file**: 1604 bytes (header + KEM ciphertext + nonce + tag)
- The encrypted file is always exactly `original_size + 1604` bytes

### Secret Key Storage Format

The `secret_key.bin` file stores the Kyber secret key encrypted with the user's passphrase:

```
Offset    Size        Field
──────    ──────────  ─────────────────────────────────
0         12 bytes    AES-GCM nonce
12        3168 bytes  Encrypted Kyber1024 secret key
3180      16 bytes    AES-GCM authentication tag
```

- **Total file size**: 3196 bytes (always fixed for Kyber1024)

### Cryptographic Primitives

| Component | Algorithm | Purpose | Security Level |
|---|---|---|---|
| Key Encapsulation | Kyber1024 (ML-KEM-1024) | Post-quantum key exchange | NIST Level 5 (equivalent to AES-256) |
| Symmetric Encryption | AES-256-GCM | Authenticated encryption | 256-bit |
| Key Derivation | HKDF-SHA256 | Derive AES key from shared secret | 256-bit |
| Random Generation | OpenSSL RAND_bytes | Nonce and key generation | CSPRNG |

**Why Kyber1024?** Kyber is the NIST-selected post-quantum KEM standard (FIPS 203 / ML-KEM). The 1024 parameter set provides the highest security level (Level 5), offering protection equivalent to AES-256 against both classical and quantum attacks.

**Why AES-256-GCM?** GCM mode provides both confidentiality (encryption) and integrity (authentication) in a single pass. The 16-byte authentication tag ensures any modification to the ciphertext, header, or KEM data is detected.

---

## Dependencies

| Dependency | Version | Purpose |
|---|---|---|
| GCC | any recent | C compiler |
| Make | any | Build system |
| CMake | 3.x+ | Build liboqs |
| OpenSSL | 3.x | AES-256-GCM, HKDF, CSPRNG |
| liboqs | latest | Kyber1024 KEM implementation |

---

## Installation

### Quick Setup (Ubuntu/Debian)

```bash
chmod +x scripts/setup.sh
./scripts/setup.sh
make
```

### Manual Setup

```bash
# 1. Install build tools and OpenSSL development headers
sudo apt update
sudo apt install -y build-essential libssl-dev cmake

# 2. Build and install liboqs
git clone https://github.com/open-quantum-safe/liboqs.git
cd liboqs
mkdir build && cd build
cmake -DCMAKE_BUILD_TYPE=Release ..
make -j$(nproc)
sudo make install
sudo ldconfig
cd ../..

# 3. Build Qsafe 2.0
make
```

After building, the `crypto-v2` executable is ready in the project root.

---

## Usage

### Command Syntax

```
./crypto-v2 [options] <operation> <input_path> <output_path> <type>
```

| Argument | Values | Description |
|---|---|---|
| `operation` | `encrypt` or `decrypt` | What to do |
| `input_path` | file or directory path | Source data |
| `output_path` | file or directory path | Destination |
| `type` | `file` or `dir` | Whether input is a single file or directory |

### Options Reference

| Option | Required | Default | Description |
|---|---|---|---|
| `--passphrase <str>` | Yes | none | Passphrase to protect the Kyber secret key |
| `--key-file <path>` | No | `secret_key.bin` | Path to the secret key file |
| `--verbose` | No | off | Print detailed info (key hex, chunk sizes, file sizes) |
| `--force` | No | off | Overwrite output files without prompting |
| `--help` | No | - | Show usage and exit |

**Important**: Options must come **before** the operation argument.

### Encrypting a Single File

```bash
./crypto-v2 --passphrase "my-secret-pass" encrypt plaintext.txt encrypted.bin file
```

**What happens:**
1. A new Kyber1024 keypair is generated
2. The secret key is encrypted with your passphrase and saved to `secret_key.bin`
3. `plaintext.txt` is encrypted and written to `encrypted.bin`
4. A progress bar shows encryption progress

**Output files:**
- `encrypted.bin` - your encrypted file
- `secret_key.bin` - encrypted Kyber secret key (keep this safe!)

### Decrypting a Single File

```bash
./crypto-v2 --passphrase "my-secret-pass" decrypt encrypted.bin decrypted.txt file
```

**What happens:**
1. The secret key is loaded from `secret_key.bin` and decrypted with your passphrase
2. The KEM ciphertext is decapsulated to recover the shared secret
3. The AES key is re-derived and the file is decrypted
4. The GCM tag is verified to ensure the file hasn't been tampered with

**Requirements:**
- The `secret_key.bin` file from the encryption step must be present
- The same passphrase used during encryption must be provided
- The encrypted file must not have been modified (integrity check)

### Encrypting a Directory

```bash
./crypto-v2 --passphrase "my-secret-pass" encrypt ./documents/ ./documents_enc/ dir
```

**What happens:**
- Each regular file in `./documents/` is individually encrypted
- Encrypted files are written to `./documents_enc/` (created if it doesn't exist)
- File names are preserved (but contents are encrypted)
- A single `secret_key.bin` is generated for the entire batch

**Note:** Only top-level files are processed. Subdirectories are skipped.

### Decrypting a Directory

```bash
./crypto-v2 --passphrase "my-secret-pass" decrypt ./documents_enc/ ./documents_dec/ dir
```

Each encrypted file in the directory is decrypted and written to the output directory.

### Using Custom Key Files

Use `--key-file` to specify a custom path for the secret key. This is useful when managing multiple encryption projects:

```bash
# Encrypt with a project-specific key
./crypto-v2 --key-file project_a.key --passphrase "pass-a" encrypt data.csv data.csv.enc file

# Decrypt with the same key
./crypto-v2 --key-file project_a.key --passphrase "pass-a" decrypt data.csv.enc data.csv file
```

### Verbose Mode

Use `--verbose` to see detailed cryptographic information during operation:

```bash
./crypto-v2 --verbose --passphrase "my-pass" encrypt file.txt file.enc file
```

Verbose output includes:
- Operation parameters (input, output, type, key file path)
- AES key and nonce in hexadecimal
- Encrypted/decrypted chunk sizes
- File size and KEM ciphertext length (during decryption)

---

## Key Management

### What Gets Generated

| File | Size | Contents | When Created |
|---|---|---|---|
| `secret_key.bin` | 3196 bytes | Encrypted Kyber1024 secret key | During encryption |
| `*.enc` (output) | input + 1604 bytes | Encrypted data with KEM ciphertext | During encryption |

### Security Model

- **If you lose `secret_key.bin`**: Your encrypted files are **permanently unrecoverable**. There is no backdoor.
- **If you forget the passphrase**: The secret key cannot be decrypted. Files are **permanently unrecoverable**.
- **If an encrypted file is modified**: Decryption will fail with an integrity error (GCM tag mismatch).
- **If an attacker has the encrypted file but not the key**: They cannot decrypt it, even with a quantum computer (Kyber1024 is quantum-resistant).

### Best Practices

1. **Use a strong passphrase** - The passphrase protects the Kyber secret key. Choose something long and unique.
2. **Restrict key file permissions**:
   ```bash
   chmod 600 secret_key.bin
   ```
3. **Back up the key file** - Store it separately from encrypted data:
   ```bash
   cp secret_key.bin /secure-backup/project_key.bin
   ```
4. **Use separate key files per project**:
   ```bash
   ./crypto-v2 --key-file project1.key --passphrase "pass1" encrypt ...
   ./crypto-v2 --key-file project2.key --passphrase "pass2" encrypt ...
   ```
5. **Rotate keys periodically** - Re-encrypt data with fresh keypairs for long-term storage.

---

## Project Structure

```
Qsafe2.0/
├── src/
│   ├── main.c              # CLI entry point, argument parsing, orchestration
│   └── crypto_utils.c      # Core cryptographic operations (KEM, AES, HKDF)
├── include/
│   └── crypto_utils.h      # Public API, constants, error codes, config struct
├── scripts/
│   └── setup.sh            # Automated dependency installer (Ubuntu/Debian)
├── docs/
│   ├── ReadMe.md           # Extended documentation
│   └── encryption_flow.md  # Mermaid flow diagram of the encryption pipeline
├── Makefile                # Build configuration (gcc, linking flags)
├── LICENCE.txt             # MIT License
└── README.md               # This file
```

### Source Code Overview

**`crypto_utils.h`** - Defines all constants, the `crypto_error_t` enum (6 error codes), the `crypto_config_t` struct, and function prototypes.

**`main.c`** (172 lines) - Handles CLI argument parsing, initializes the Kyber KEM, manages the keypair lifecycle (generate on encrypt, load on decrypt), dispatches to file or directory processing, and performs secure cleanup.

**`crypto_utils.c`** (664 lines) - Implements:
- `crypto_derive_aes_key()` - HKDF-SHA256 key derivation
- `crypto_save_secret_key()` / `crypto_load_secret_key()` - Passphrase-protected key storage
- `crypto_encrypt_file()` / `crypto_decrypt_file()` - Streaming AES-256-GCM with Kyber KEM
- `crypto_process_directory()` - Directory traversal and batch processing
- `crypto_print_progress_bar()` - Visual progress indicator

---

## Testing

```bash
make test
```

This runs the integration test suite including unit tests (`test_crypto_utils.c`) and end-to-end tests (`test.sh`).

---

## License

MIT License. See [LICENCE.txt](LICENCE.txt).
