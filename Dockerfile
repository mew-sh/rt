# ============================================================================
# Multi-stage build for rt
# ============================================================================
# Stage 1: Build -- use latest stable Rust to avoid edition2024 issues
# ============================================================================
FROM rust:latest AS builder

RUN apt-get update && \
    apt-get install -y --no-install-recommends \
        pkg-config libssl-dev && \
    rm -rf /var/lib/apt/lists/*

WORKDIR /usr/src/rt

COPY Cargo.toml Cargo.lock ./
COPY src/ src/
COPY tests/ tests/

RUN cargo build --release

# ============================================================================
# Stage 2: Runtime
# ============================================================================
FROM debian:bookworm-slim

RUN apt-get update && \
    apt-get install -y --no-install-recommends \
        ca-certificates \
        iproute2 \
        iptables \
    && rm -rf /var/lib/apt/lists/*

COPY --from=builder /usr/src/rt/target/release/rt /usr/local/bin/rt

RUN mkdir -p /etc/rt

EXPOSE 8080 1080 8338 8443

ENTRYPOINT ["rt"]
CMD ["-L", ":8080"]
