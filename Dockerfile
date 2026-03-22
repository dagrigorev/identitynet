# ============================================================================
# Dockerfile — Identity Network
# Multi-stage build: builder → runtime
# Final image: ~50MB (Ubuntu minimal + OpenSSL runtime only)
# ============================================================================

# ── Stage 1: Builder ─────────────────────────────────────────────────────────
FROM ubuntu:24.04 AS builder

LABEL maintainer="identitynet"
LABEL description="Identity Network — cryptographic identity-native network stack"

# Avoid interactive prompts
ENV DEBIAN_FRONTEND=noninteractive

# Install build dependencies
# libssl-dev provides /usr/include/openssl/*.h and -lssl -lcrypto symlinks
RUN apt-get update && apt-get install -y --no-install-recommends \
        g++ \
        make \
        libssl-dev \
    && rm -rf /var/lib/apt/lists/*

# Copy source tree
WORKDIR /src
COPY . .

# Build all binaries (verbose output for debugging)
RUN make all

# Verify binaries exist — explicit paths, no bash brace expansion (/bin/sh safe)
RUN ls -la build/identitynet-discovery \
           build/identitynet-server    \
           build/identitynet-client    \
           build/identitynet-tests     \
           build/identitynet-demo

# ── Stage 2: Runtime ─────────────────────────────────────────────────────────
FROM ubuntu:24.04 AS runtime

ENV DEBIAN_FRONTEND=noninteractive

# Only runtime OpenSSL (no dev headers needed)
RUN apt-get update && apt-get install -y --no-install-recommends \
        libssl3 \
        ca-certificates \
    && rm -rf /var/lib/apt/lists/*

# Copy compiled binaries from builder
COPY --from=builder /src/build/identitynet-discovery /usr/local/bin/
COPY --from=builder /src/build/identitynet-server    /usr/local/bin/
COPY --from=builder /src/build/identitynet-client    /usr/local/bin/
COPY --from=builder /src/build/identitynet-tests     /usr/local/bin/
COPY --from=builder /src/build/identitynet-demo      /usr/local/bin/

# Data directory for key files and ACL configs
RUN mkdir -p /data
WORKDIR /data

# Default: run demo (all-in-one verification)
CMD ["identitynet-demo"]

# Expose standard ports
# 7700 = discovery server
# 7701 = identity server (default)
EXPOSE 7700 7701
