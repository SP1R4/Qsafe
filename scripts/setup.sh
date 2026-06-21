#!/bin/bash
# Qsafe dependency installer.
# Installs OpenSSL 3 and liboqs (>= 0.10, for ML-KEM-1024) on macOS (Homebrew)
# or Debian/Ubuntu Linux, after which you can run `make`.
set -euo pipefail

echo "Installing dependencies for Qsafe..."

OS="$(uname -s)"

if [ "$OS" = "Darwin" ]; then
    if ! command -v brew >/dev/null 2>&1; then
        echo "Homebrew is required. Install it from https://brew.sh and re-run."
        exit 1
    fi
    brew install openssl@3 liboqs
    echo "Dependencies installed via Homebrew. Run 'make' to build Qsafe."
    exit 0
fi

if [ -f /etc/debian_version ]; then
    sudo apt-get update
    sudo apt-get install -y build-essential libssl-dev cmake git

    if [ ! -d liboqs ]; then
        git clone --depth 1 --branch 0.12.0 https://github.com/open-quantum-safe/liboqs.git
    fi

    cmake -S liboqs -B liboqs/build -DCMAKE_BUILD_TYPE=Release -DOQS_BUILD_ONLY_LIB=ON
    cmake --build liboqs/build -j"$(nproc)"
    sudo cmake --install liboqs/build
    sudo ldconfig

    echo "Dependencies installed. Run 'make' to build Qsafe."
    exit 0
fi

echo "Unsupported OS. Please install liboqs (>= 0.10) and OpenSSL 3 manually,"
echo "then run 'make'."
exit 1
