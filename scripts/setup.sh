#!/bin/bash
# Qsafe dependency installer (Ubuntu/Debian).
# Installs OpenSSL/build tooling and builds liboqs (>= 0.10, for ML-KEM-1024).
set -euo pipefail

echo "Installing dependencies for Qsafe..."

if [ ! -f /etc/debian_version ]; then
    echo "Unsupported OS. Please install liboqs and OpenSSL manually."
    exit 1
fi

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
