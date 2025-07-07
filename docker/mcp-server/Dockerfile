FROM rust:latest AS builder

# Install dependencies for building
RUN apt-get update && apt-get install -y \
    git \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app

# Copy manifests
COPY Cargo.toml ./

# Create dummy main to cache dependencies
RUN mkdir src && echo "fn main() {}" > src/main.rs
RUN cargo update && cargo build --release
RUN rm -rf src

# Copy source code
COPY src ./src

# Build for release
RUN touch src/main.rs && cargo update && cargo build --release

# Runtime stage
FROM debian:bookworm-slim

RUN apt-get update && apt-get install -y \
    ca-certificates \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app

# Copy the binary
COPY --from=builder /app/target/release/mcp-server /app/mcp-server

EXPOSE 8080

CMD ["./mcp-server"]