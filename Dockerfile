# syntax=docker/dockerfile:1.7

# --- Web UI build ---
FROM node:22-bookworm-slim AS web-builder
WORKDIR /web

RUN corepack enable pnpm

COPY web/package.json web/pnpm-lock.yaml ./
RUN pnpm install --frozen-lockfile

COPY web/ ./
RUN pnpm build

# --- Rust build ---
FROM rust:1.88-bookworm AS builder
WORKDIR /app

COPY . .
COPY --from=web-builder /web/dist/ /app/crates/api/assets/
ENV SQLX_OFFLINE=true
RUN cargo build --locked --release \
    -p betterbase-accounts-server \
    -p betterbase-accounts-keygen \
    -p betterbase-accounts-oauth-client

FROM debian:bookworm-slim AS runtime
RUN apt-get update \
    && apt-get install -y --no-install-recommends ca-certificates wget \
    && rm -rf /var/lib/apt/lists/* \
    && groupadd --gid 65532 nonroot \
    && useradd --uid 65532 --gid 65532 --no-create-home --shell /usr/sbin/nologin nonroot \
    && mkdir -p /app \
    && chown -R nonroot:nonroot /app

WORKDIR /app

COPY --from=builder /app/target/release/betterbase-accounts-server /app/server
COPY --from=builder /app/target/release/betterbase-accounts-keygen /app/keygen
COPY --from=builder /app/target/release/betterbase-accounts-oauth-client /app/oauth-client
COPY docker/entrypoint.sh /usr/local/bin/betterbase-accounts-entrypoint
RUN chmod +x /usr/local/bin/betterbase-accounts-entrypoint

USER nonroot
EXPOSE 5377

ENTRYPOINT ["/usr/local/bin/betterbase-accounts-entrypoint"]
