#!/bin/bash
echo "Installing dependencies for Crypto-v2..."

# Check for Ubuntu/Debian
if [ -f /etc/debian_version ]; then
    sudo apt update
    sudo apt install -y build-essential libssl-dev cmake
    git clone https://github.com/open-quantum-safe/liboqs.git
    cd liboqs
    mkdir build && cd build
    cmake -DCMAKE_BUILD_TYPE=Release ..
    make -j$(nproc)
    sudo make install
    cd ../..
else
    echo "Unsupported OS. Please install liboqs and OpenSSL manually."
    exit 1
fi

echo "Dependencies installed!"