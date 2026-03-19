# ── Stage 1: Build the Rust binary ──────────────────────────────────────────
FROM rust:1.88-slim-bookworm AS builder

WORKDIR /build

# Install minimal deps for linking (openssl for reqwest TLS)
RUN apt-get update && \
    apt-get install -y --no-install-recommends pkg-config libssl-dev && \
    rm -rf /var/lib/apt/lists/*

# Cache dependency layer: copy manifests, create dummy src, build deps first
COPY Cargo.toml Cargo.lock* ./
RUN mkdir src && echo 'fn main() {}' > src/main.rs && \
    cargo build --release 2>/dev/null || true && \
    rm -rf src && \
    rm -f target/release/navil-proxy target/release/deps/navil_proxy*

# Now copy actual source and build
COPY src/ ./src/
RUN touch src/main.rs && cargo build --release

# ── Stage 2: Lean runtime ──────────────────────────────────────────────────
FROM debian:bookworm-slim

RUN apt-get update && \
    apt-get install -y --no-install-recommends ca-certificates libssl3 curl && \
    rm -rf /var/lib/apt/lists/* && \
    useradd --system --no-create-home navil

COPY --from=builder /build/target/release/navil-proxy /usr/local/bin/navil-proxy

USER navil

EXPOSE 8080

HEALTHCHECK --interval=10s --timeout=3s --retries=3 \
    CMD curl -f http://localhost:8080/health || exit 1

ENTRYPOINT ["navil-proxy"]
