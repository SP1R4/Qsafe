# OSS-Fuzz build container for Qsafe (see oss-fuzz/README.md).
FROM gcr.io/oss-fuzz-base/base-builder

RUN apt-get update && apt-get install -y make cmake ninja-build

# liboqs, built static so the fuzzer is self-contained.
RUN git clone --depth 1 --branch 0.12.0 \
    https://github.com/open-quantum-safe/liboqs.git $SRC/liboqs

# OpenSSL, built with the sanitizer toolchain (system libssl-dev is not
# instrumented, which MemorySanitizer in particular requires).
RUN git clone --depth 1 --branch openssl-3.3.1 \
    https://github.com/openssl/openssl.git $SRC/openssl

RUN git clone --depth 1 https://github.com/SP1R4/Qsafe.git $SRC/qsafe
WORKDIR $SRC/qsafe
COPY build.sh $SRC/
