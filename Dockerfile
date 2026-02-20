# syntax=docker/dockerfile:1.7

FROM rust:1.88-bookworm AS builder
WORKDIR /app

COPY . .
ENV SQLX_OFFLINE=true
RUN cargo build --locked --release \
    -p less-accounts-server \
    -p less-accounts-keygen \
    -p less-accounts-oauth-client

FROM debian:bookworm-slim AS runtime
RUN apt-get update \
    && apt-get install -y --no-install-recommends ca-certificates wget \
    && rm -rf /var/lib/apt/lists/* \
    && groupadd --gid 65532 nonroot \
    && useradd --uid 65532 --gid 65532 --no-create-home --shell /usr/sbin/nologin nonroot \
    && mkdir -p /app \
    && chown -R nonroot:nonroot /app

WORKDIR /app

COPY --from=builder /app/target/release/less-accounts-server /app/server
COPY --from=builder /app/target/release/less-accounts-keygen /app/keygen
COPY --from=builder /app/target/release/less-accounts-oauth-client /app/oauth-client
COPY docker/entrypoint.sh /usr/local/bin/less-accounts-entrypoint
RUN chmod +x /usr/local/bin/less-accounts-entrypoint

USER nonroot
EXPOSE 5377

ENTRYPOINT ["/usr/local/bin/less-accounts-entrypoint"]
