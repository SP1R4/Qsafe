# Qsafe container image — zero-dependency way to try the tool.
#
#   docker build -t qsafe .
#   docker run --rm -e QSAFE_PASSPHRASE=secret -v "$PWD:/data" qsafe keygen --key-file /data/key.bin
#
# Multi-stage: build liboqs + qsafe, then ship a slim runtime with just the
# shared libraries it needs.

ARG LIBOQS_VERSION=0.12.0

# ---- build stage ----
FROM ubuntu:24.04 AS build
ARG LIBOQS_VERSION
RUN apt-get update && apt-get install -y --no-install-recommends \
        build-essential git cmake ninja-build libssl-dev ca-certificates \
    && rm -rf /var/lib/apt/lists/*

# liboqs (pinned)
RUN git clone --depth 1 --branch ${LIBOQS_VERSION} https://github.com/open-quantum-safe/liboqs.git /tmp/liboqs \
    && cmake -S /tmp/liboqs -B /tmp/liboqs/build -GNinja \
        -DCMAKE_BUILD_TYPE=Release -DOQS_BUILD_ONLY_LIB=ON \
        -DCMAKE_INSTALL_PREFIX=/usr/local \
    && cmake --build /tmp/liboqs/build \
    && cmake --install /tmp/liboqs/build

# qsafe
COPY . /src
WORKDIR /src
RUN make && make test && make PREFIX=/usr/local install

# ---- runtime stage ----
FROM ubuntu:24.04
RUN apt-get update && apt-get install -y --no-install-recommends \
        libssl3 ca-certificates \
    && rm -rf /var/lib/apt/lists/*
COPY --from=build /usr/local/bin/qsafe /usr/local/bin/qsafe
COPY --from=build /usr/local/lib/liboqs.so* /usr/local/lib/
RUN ldconfig
# Run as a non-root user; mount your files at /data.
RUN useradd --create-home --uid 1000 qsafe
USER qsafe
WORKDIR /data
ENTRYPOINT ["qsafe"]
CMD ["--help"]
