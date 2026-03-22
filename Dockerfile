# ============================================================================
# Dockerfile — Identity Network (with Proxy support)
# Multi-stage build: builder → runtime
# ============================================================================
FROM ubuntu:24.04 AS builder
ENV DEBIAN_FRONTEND=noninteractive

RUN apt-get update && apt-get install -y --no-install-recommends \
        g++ make libssl-dev \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /src
COPY . .
RUN make all proxy-tests

RUN ls -la \
    build/identitynet-discovery \
    build/identitynet-server \
    build/identitynet-client \
    build/identitynet-tests \
    build/identitynet-demo \
    build/identitynet-proxy-server \
    build/identitynet-proxy-client \
    build/identitynet-proxy-tests

# ── Runtime ──────────────────────────────────────────────────────────────────
FROM ubuntu:24.04 AS runtime
ENV DEBIAN_FRONTEND=noninteractive

RUN apt-get update && apt-get install -y --no-install-recommends \
        libssl3 ca-certificates \
    && rm -rf /var/lib/apt/lists/*

COPY --from=builder /src/build/identitynet-discovery     /usr/local/bin/
COPY --from=builder /src/build/identitynet-server        /usr/local/bin/
COPY --from=builder /src/build/identitynet-client        /usr/local/bin/
COPY --from=builder /src/build/identitynet-tests         /usr/local/bin/
COPY --from=builder /src/build/identitynet-demo          /usr/local/bin/
COPY --from=builder /src/build/identitynet-proxy-server  /usr/local/bin/
COPY --from=builder /src/build/identitynet-proxy-client  /usr/local/bin/
COPY --from=builder /src/build/identitynet-proxy-tests   /usr/local/bin/

RUN mkdir -p /data
WORKDIR /data
CMD ["identitynet-demo"]
EXPOSE 7700 7701 1080
