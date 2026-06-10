# Build Stage
FROM rust:1.85-slim-bookworm AS builder

# Install build dependencies
RUN apt-get update && apt-get install -y --no-install-recommends \
    pkg-config \
    libssl-dev \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /usr/src/oxidized-wall

# Copy manifest files
COPY Cargo.toml Cargo.lock ./

# Copy source code and build (No dummy build to avoid cache issues)
COPY src ./src
RUN cargo build --release

# Runtime Stage
FROM debian:bookworm-slim

# Install runtime dependencies
RUN apt-get update && apt-get install -y --no-install-recommends \
    ca-certificates \
    tzdata \
    && rm -rf /var/lib/apt/lists/*

# Security: Create non-root user
RUN groupadd -g 1001 appuser && \
    useradd -u 1001 -g appuser -s /bin/sh appuser

WORKDIR /app

# Copy the actual binary from builder
COPY --from=builder /usr/src/oxidized-wall/target/release/oxidized-wall /usr/local/bin/oxidized-wall

# Setup directory permissions
RUN mkdir -p /app/certs && chown -R appuser:appuser /app
USER appuser

# Execution
CMD ["oxidized-wall"]
