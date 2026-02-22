Crypto-v2: Post-Quantum File Encryption Tool
Crypto-v2 is an enhanced command-line tool for encrypting and decrypting files and directories using Kyber1024 (post-quantum KEM) and AES-256-GCM (authenticated encryption). It offers improved security and performance over its predecessor, with features like HKDF key derivation, encrypted secret key storage, and direct streaming.
Features

Encrypt/decrypt files and directories with post-quantum security.
AES-256-GCM for authenticated encryption.
HKDF for secure AES key derivation.
Passphrase-protected secret key storage.
Direct streaming to output files, reducing disk I/O.
File format versioning for future compatibility.
Chunked processing for large files.
Verbose output, forced overwrites, and custom key files.

Installation

Install dependencies (Ubuntu/Debian):sudo apt update
sudo apt install build-essential libssl-dev cmake


Install liboqs:git clone https://github.com/open-quantum-safe/liboqs.git
cd liboqs
mkdir build && cd build
cmake -DCMAKE_BUILD_TYPE=Release ..
make -j$(nproc)
sudo make install
cd ../..


Clone and build Crypto-v2:git clone <repository_url>
cd crypto-v2
make



Usage
Encrypt a File
./crypto-v2 --force --verbose --passphrase mypass encrypt input.txt output.enc file


Creates output.enc and secret_key.bin (encrypted with passphrase).

Decrypt a File
./crypto-v2 --force --verbose --passphrase mypass decrypt output.enc decrypted.txt file


Requires secret_key.bin and correct passphrase.

Encrypt a Directory
./crypto-v2 --force --verbose --passphrase mypass encrypt input_dir output_dir dir

Decrypt a Directory
./crypto-v2 --force --verbose --passphrase mypass decrypt output_dir decrypted_dir dir

Options

--help: Display usage information.
--verbose: Show detailed output (keys, nonces, sizes).
--force: Overwrite output without prompting.
--key-file <path>: Specify secret key file (default: secret_key.bin).
--passphrase <str>: Passphrase for secret key encryption (required).

Key Management

Kyber Keypair:
Public Key: Used for encapsulation, not stored.
Secret Key: 3168 bytes, encrypted with AES-256-GCM using a passphrase, stored in secret_key.bin.
Security: Use a strong passphrase and protect the key file:chmod 600 secret_key.bin
mv secret_key.bin /secure/location/


Backup: Always back up the key:cp secret_key.bin /backup/project_key.bin




AES Key:
32 bytes, derived via HKDF from the Kyber shared secret.
Used for AES-256-GCM encryption/decryption.
Re-derived during decryption, not stored.



Best Practices:

Use unique passphrases and key files per project:./crypto-v2 --force --key-file project1_key.bin --passphrase mypass encrypt input_dir output_dir dir


Store keys securely and back them up.
Re-encrypt periodically with new keys.

Project Structure
crypto-v2/
├── include/
│   └── crypto_utils.h
├── src/
│   ├── main.c
│   └── crypto_utils.c
├── tests/
│   ├── test_crypto_utils.c
│   ├── test.sh
│   └── Makefile
├── docs/
│   ├── README.md
│   ├── CHANGELOG.md
│   ├── CONTRIBUTING.md
│   └── diagrams/
│       └── encryption_flow.md
├── scripts/
│   └── setup.sh
├── LICENSE
├── Makefile
└── .gitignore

Testing
Run integration tests:
make test

Contributing
See docs/CONTRIBUTING.md.
License
MIT License (see LICENSE).
