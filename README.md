# betterbase-accounts

[![License](https://img.shields.io/badge/license-Apache--2.0-blue.svg)](LICENSE)

Password authentication and OAuth 2.0 authorization server for [Betterbase](https://github.com/BetterbaseHQ/betterbase-dev). **Passwords never leave the client** -- the server uses the [OPAQUE protocol](https://www.ietf.org/rfc/rfc9497.html) so it never sees, stores, or transmits user passwords in any form.

## Quick Start

### As part of betterbase-dev (recommended)

```bash
# From the betterbase-dev root
just setup    # Clone repos, generate keys, create .env
just dev      # Start all services with hot reload
```

Once running, visit **http://localhost:5377** for the login and registration UI.

### Standalone

1. Generate OPAQUE server setup:
   ```bash
   cargo run -p betterbase-accounts-keygen
   ```

2. Set required environment variables:
   ```bash
   export DATABASE_URL="postgres://user:pass@localhost:5432/accounts"
   export OPAQUE_SERVER_SETUP="<hex from step 1>"
   export OAUTH_ISSUER="http://localhost:5377"
   export IDENTITY_HASH_KEY="<64 hex chars = 32 bytes>"
   ```

3. Run the server:
   ```bash
   cargo run -p betterbase-accounts-server
   ```

4. Register an OAuth client:
   ```bash
   cargo run -p betterbase-accounts-oauth-client -- create \
     --name "My App" \
     --redirect-uri "http://localhost:3000/callback"
   ```

The server listens on port 5377 by default. Database migrations run automatically on startup -- just point `DATABASE_URL` at an empty PostgreSQL database and the schema will be created for you.

## Features

- **OPAQUE authentication** (RFC 9497) -- zero-knowledge password proof using `opaque-ke` with Ristretto255 cipher suite.
- **OAuth 2.0 + PKCE** -- authorization code flow for public clients with extended PKCE for scoped key delivery via JWE.
- **ES256 JWTs** -- access tokens signed with P-256 keys, exposed via a JWKS endpoint.
- **Key management** -- per-user key storage, root key wrapping (AES-KW), and root key rotation with batch grant updates.
- **Account recovery** -- encrypted recovery blobs with rate-limited retrieval.
- **Email verification** -- 6-digit codes with attempt limits and send rate limiting.
- **CAP proof-of-work** -- optional bot protection via proof-of-work CAPTCHA service.
- **WebFinger and discovery** -- `/.well-known/betterbase` and `/.well-known/webfinger` endpoints for federation.
- **Embedded web UI** -- React SPA (Vite + Tailwind) served from the binary via `rust-embed`.

## Architecture

```
betterbase-accounts/
├── bins/
│   ├── server/          # Main HTTP server entry point
│   ├── keygen/          # OPAQUE ServerSetup generator
│   └── oauth-client/    # CLI for OAuth client management
├── crates/
│   ├── core/            # Domain types, validation, API protocol types
│   ├── auth/            # OPAQUE, JWT (5 types), ES256, auth middleware
│   ├── storage/         # Storage traits + PostgreSQL impl (sqlx)
│   ├── email/           # Mailer trait (SMTP + dev mode)
│   ├── cap/             # CAP proof-of-work client
│   ├── api/             # Axum HTTP handlers, router, embedded web UI
│   └── app/             # Config, startup, background tasks, shutdown
├── web/                 # React frontend (Vite + Tailwind)
└── docker/              # Entrypoint scripts
```

**Crate dependency graph:** `bins/server` -> `app` -> `api` -> `{ auth, storage, email, cap, core }`. `bins/keygen` is standalone. `bins/oauth-client` depends on `storage`. All crates enforce `#![forbid(unsafe_code)]`.

The storage layer is trait-based with 16+ async traits organized by domain. The PostgreSQL implementation uses sqlx with compile-time checked queries.

## Configuration

### Required Environment Variables

| Variable | Description |
|---|---|
| `DATABASE_URL` | PostgreSQL connection string |
| `OPAQUE_SERVER_SETUP` | Hex-encoded OPAQUE ServerSetup (from `keygen`) |
| `OAUTH_ISSUER` | Stable issuer URL for JWTs and federation |
| `IDENTITY_HASH_KEY` | Hex-encoded 32-byte HMAC key for rate limit privacy |

### Optional Environment Variables

`LISTEN_ADDR` (default `0.0.0.0:5377`), `LOG_FORMAT` (`text`/`json`), `WEB_BASE_URL`, `SYNC_ENDPOINT`, `FEDERATION_WS_ENDPOINT`, `CAP_KEY_ID` + `CAP_SECRET` + `CAP_VERIFY_URL` (enables proof-of-work), `SMTP_DEV_MODE` (logs emails instead of sending), `SMTP_HOST`/`SMTP_PORT`/`SMTP_USERNAME`/`SMTP_PASSWORD`/`SMTP_FROM`.

## Development

### Prerequisites

- Rust 1.88+
- PostgreSQL 17 (or Docker for `just test-db`)
- Node.js 22+ and pnpm (for web UI)

### Commands

```bash
just check          # Format + lint + test + check web (run before committing)
just test           # Run tests (DB tests skip without DATABASE_URL)
just test-db        # Spin up Postgres, run all tests including DB, tear down
just build-web      # Build React UI into crates/api/assets/
just check-web      # Lint and typecheck web UI
```

`just test-db` starts a PostgreSQL container on port 15433, runs all tests, then removes the container.

### Docker

```bash
# Production (multi-stage: Node 22 + Rust 1.88 -> debian:bookworm-slim)
docker build -t betterbase-accounts .

# Dev with hot reload
docker build -f Dockerfile.dev -t betterbase-accounts-dev .
```

## API Overview

All v1 routes are immutable contracts. Every response includes `X-Protocol-Version: 1`.

- **Authentication** -- OPAQUE registration (`/v1/accounts/password/init`, `finalize`), login (`/v1/auth/login/init`, `finalize`), validation, and account deletion.
- **Key management** -- Per-user key CRUD (`/v1/keys/...`), root key get/set/rotation, and grant-wrapped key updates.
- **Password change** -- Three-step flow: init, verify old password, complete (`/v1/accounts/password/change/...`).
- **Recovery** -- Store and fetch encrypted recovery blobs, initiate and finalize account recovery (`/v1/accounts/recover/...`).
- **OAuth 2.0** -- Authorization (`/oauth/authorize`), consent, token exchange (PKCE), userinfo, mailbox registration, and grant keypairs.
- **Discovery** -- JWKS (`/.well-known/jwks.json`), server metadata (`/.well-known/betterbase`), WebFinger, user public key lookup, and health check.

## Related

- [betterbase-dev](https://github.com/BetterbaseHQ/betterbase-dev) -- Platform orchestration
- [betterbase-sync](../betterbase-sync/) -- Encrypted blob sync service
- [betterbase-inference](../betterbase-inference/) -- E2EE inference proxy
- [@betterbase/sdk](../betterbase/) -- Client SDK (auth, crypto, discovery, sync, db)

## License

Apache-2.0
