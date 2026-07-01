#!/bin/bash -eu
# OSS-Fuzz build script for Qsafe: builds liboqs + OpenSSL with the
# sanitizer-instrumented toolchain, then links the decrypt-parser fuzzer.

# --- liboqs (static) ---
cmake -S "$SRC/liboqs" -B "$SRC/liboqs/build" -GNinja \
  -DCMAKE_BUILD_TYPE=Release \
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

# --- fuzz target ---
$CC $CFLAGS -Iinclude -I"$WORK/deps/include" \
  -c tests/fuzz_decrypt.c -o "$WORK/fuzz_decrypt.o" -DQSAFE_OSS_FUZZ
$CC $CFLAGS -Iinclude -I"$WORK/deps/include" \
  -c src/crypto_utils.c -o "$WORK/crypto_utils.o"
$CXX $CXXFLAGS "$WORK/fuzz_decrypt.o" "$WORK/crypto_utils.o" \
  -o "$OUT/fuzz_decrypt" \
  $LIB_FUZZING_ENGINE \
  "$WORK/deps/lib/liboqs.a" "$WORK/deps/lib64/libcrypto.a" \
  -ldl -lpthread

# Seed corpus: the checked-in format fixtures.
zip -j "$OUT/fuzz_decrypt_seed_corpus.zip" tests/fixtures/*.qsafe
