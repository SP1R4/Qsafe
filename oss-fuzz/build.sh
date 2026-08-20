#!/bin/bash -eu
# OSS-Fuzz build script for Qsafe: builds liboqs + OpenSSL with the
# sanitizer-instrumented toolchain, then links the decrypt-parser and
# vault-reader fuzzers.

# --- liboqs (static, instrumented) ---
# Built with $CC/$CFLAGS so the sanitizer instruments liboqs too: MemorySanitizer
# reports false positives on any uninstrumented linked code, and OQS_USE_CPU_EXTENSIONS
# pulls in hand-written asm MSan can't see — so disable it for a portable, fully
# instrumented, deterministic build across all three sanitizers.
cmake -S "$SRC/liboqs" -B "$SRC/liboqs/build" -GNinja \
  -DCMAKE_BUILD_TYPE=Release \
  -DCMAKE_C_COMPILER="$CC" \
  -DCMAKE_C_FLAGS="$CFLAGS" \
  -DOQS_USE_CPU_EXTENSIONS=OFF \
  -DOQS_BUILD_ONLY_LIB=ON \
  -DBUILD_SHARED_LIBS=OFF \
  -DOQS_USE_OPENSSL=OFF \
  -DCMAKE_INSTALL_PREFIX="$WORK/deps"
cmake --build "$SRC/liboqs/build"
cmake --install "$SRC/liboqs/build"

# --- OpenSSL (static, instrumented) ---
cd "$SRC/openssl"
./Configure --prefix="$WORK/deps" no-shared no-tests no-apps \
  no-asm linux-x86_64 "$CFLAGS"
make -j"$(nproc)" build_libs
make install_dev
cd "$SRC/qsafe"

# liboqs and OpenSSL each install their static lib to lib/ or lib64/ depending on
# the distro's GNUInstallDirs — resolve both rather than hardcoding a split.
find_lib() { for d in lib lib64; do [ -f "$WORK/deps/$d/$1" ] && { echo "$WORK/deps/$d/$1"; return 0; }; done; echo "ERROR: $1 not found under $WORK/deps/{lib,lib64}" >&2; return 1; }
LIBOQS_A="$(find_lib liboqs.a)"
LIBCRYPTO_A="$(find_lib libcrypto.a)"

# --- fuzz target: decrypt (QSAFE005/006/007 parser) ---
$CC $CFLAGS -Iinclude -I"$WORK/deps/include" \
  -c tests/fuzz_decrypt.c -o "$WORK/fuzz_decrypt.o" -DQSAFE_OSS_FUZZ
$CC $CFLAGS -Iinclude -I"$WORK/deps/include" \
  -c src/crypto_utils.c -o "$WORK/crypto_utils.o"
$CXX $CXXFLAGS "$WORK/fuzz_decrypt.o" "$WORK/crypto_utils.o" \
  -o "$OUT/fuzz_decrypt" \
  $LIB_FUZZING_ENGINE \
  "$LIBOQS_A" "$LIBCRYPTO_A" \
  -ldl -lpthread

# Seed corpus: the checked-in format fixtures.
zip -j "$OUT/fuzz_decrypt_seed_corpus.zip" tests/fixtures/*.qsafe

# --- fuzz target: vault (hidden-volume reader) ---
$CC $CFLAGS -Iinclude -I"$WORK/deps/include" \
  -c tests/fuzz_vault.c -o "$WORK/fuzz_vault.o" -DQSAFE_OSS_FUZZ
$CC $CFLAGS -Iinclude -I"$WORK/deps/include" \
  -c src/vault.c -o "$WORK/vault.o"
$CXX $CXXFLAGS "$WORK/fuzz_vault.o" "$WORK/vault.o" "$WORK/crypto_utils.o" \
  -o "$OUT/fuzz_vault" \
  $LIB_FUZZING_ENGINE \
  "$LIBOQS_A" "$LIBCRYPTO_A" \
  -ldl -lpthread

# Seed corpus: the frozen vault fixture container — real ciphertext at the
# harness's fixed (offset=0, capacity=140000) for the mutator to perturb,
# rather than starting from nothing but random bytes.
zip -j "$OUT/fuzz_vault_seed_corpus.zip" tests/fixtures/vault/container.bin

# --- fuzz target: vault v2 directory parser ---
$CC $CFLAGS -Iinclude -I"$WORK/deps/include" \
  -c tests/fuzz_vault_dir.c -o "$WORK/fuzz_vault_dir.o" -DQSAFE_OSS_FUZZ
$CXX $CXXFLAGS "$WORK/fuzz_vault_dir.o" "$WORK/vault.o" "$WORK/crypto_utils.o" \
  -o "$OUT/fuzz_vault_dir" \
  $LIB_FUZZING_ENGINE \
  "$LIBOQS_A" "$LIBCRYPTO_A" \
  -ldl -lpthread
