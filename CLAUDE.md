# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Overview

betterbase-accounts is an OPAQUE-based password authentication and OAuth 2.0 authorization server for the Betterbase platform. It is a Rust Axum service that provides user registration, login, token issuance, key management, and account recovery. A React web UI is embedded into the binary via `rust-embed`.

Part of the [betterbase-dev](https://github.com/BetterbaseHQ/betterbase-dev) orchestration repo.

## Commands

```bash
just check            # fmt + lint + test + check-web (standard workflow check)
just fmt              # cargo fmt --all
just lint             # cargo clippy --workspace --all-targets -- -D warnings
just test             # cargo test --workspace (DB tests auto-skip without DATABASE_URL)
just test-v           # cargo test --workspace -- --nocapture
just test-db          # Spin up Postgres container, run tests with DATABASE_URL, tear down
just build            # cargo build --workspace
just build-release    # cargo build --workspace --release
just build-web        # Build React UI into crates/api/assets/
just check-web        # pnpm install + pnpm check for web UI
just db-start         # Start test Postgres on port 15433
just db-down          # Stop test Postgres
just db-shell         # psql into test database
```

Run a single test: `cargo test --workspace -p betterbase-accounts-storage -- test_name`

## Workspace Structure

**Binaries** (`bins/`):
- `server` -- Main HTTP server (Axum). Entry point calls `app::run()`.
- `keygen` -- Generates hex-encoded OPAQUE `ServerSetup` blob.
- `oauth-client` -- CLI for managing OAuth clients in the database.

**Library crates** (`crates/`), in dependency order:
- `core` -- Shared domain types, validation (email, username, handle, DID key), API request/response types (`protocol.rs`), verification purpose constants
- `auth` -- OPAQUE registration/login (`opaque-ke` with Ristretto255), JWT creation/validation (5 token types: auth/state/access/oauth-state/verification), ES256 key management, auth middleware
- `storage` -- Storage traits (16+ async traits organized by domain) + PostgreSQL implementation (sqlx). Migrations in `crates/storage/migrations/`.
- `email` -- Mailer trait with SMTP (`lettre`) and dev-mode implementations
- `cap` -- CAP proof-of-work verification client
- `api` -- Axum HTTP handlers and router. Depends on all other crates. Embeds web UI assets via `rust-embed`.
- `app` -- Application bootstrap: `AppConfig` (env-based), startup sequence, background cleanup tasks, graceful shutdown

## Key Dependency Chain

```
bins/server → app → api → { auth, storage, email, cap, core }
bins/keygen → (standalone: hex, rand)
bins/oauth-client → storage
```

## Architecture

### OPAQUE Authentication
Uses `opaque-ke` crate (Ristretto255 cipher suite, RFC 9497). Config uses a single `OPAQUE_SERVER_SETUP` hex blob. The server never sees user passwords.

### JWT Tokens
5 token types with different signing algorithms and lifetimes:
- **HS256** (internal): auth (14d), state (60s), oauth-state (10m), verification (15m)
- **ES256** (OAuth): access tokens (15m)
- JWKS endpoint exposes ES256 public keys at `/.well-known/jwks.json`

### Storage Layer
Trait-based with 16+ async traits organized by domain: accounts, registration, login, JWT keys, user keys, OAuth entities (clients, codes, grants, refresh tokens, signing keys), recovery, verification, rate limits, cleanup, composite operations. A `Storage` supertrait combines all traits. PostgreSQL implementation uses sqlx with compile-time checked queries.

### Web UI
React SPA (Vite + Tailwind) built into `crates/api/assets/` and embedded via `rust-embed`. SPA fallback serves `index.html` for non-file paths.

### Background Tasks
60-second cleanup loop purges expired: registration/login states, OAuth codes, refresh tokens, used refresh tokens (>7 days), verification codes, verification token JTIs.

### Middleware
- CORS (permissive: any origin, standard methods/headers)
- Request body limit: 64 KB
- `X-Protocol-Version: 1` header on all responses (immutable v1 contract)

## API Routes

All routes are immutable v1 contracts -- paths must not change without a versioned migration.

| Group | Routes |
|---|---|
| Health | `GET /health` |
| Verification | `POST /v1/accounts/verify/{send,confirm}` |
| Registration | `POST /v1/accounts/password/{init,finalize}` |
| Login | `POST /v1/auth/login/{init,finalize}` |
| Auth ops | `GET /v1/auth/validate`, `DELETE /v1/accounts` |
| User keys | `GET /v1/keys`, `PUT/GET /v1/keys/{service}/{key_name}` |
| Root key | `GET/PUT /v1/accounts/root-key`, `GET/PUT /v1/accounts/grants/wrapped-keys`, `POST /v1/accounts/rotate-root-key` |
| Password change | `POST /v1/accounts/password/change/{init,verify,complete}` |
| Recovery | `POST /v1/accounts/recovery-blob`, `POST /v1/accounts/recovery-blob/fetch`, `POST /v1/accounts/recover/{init,finalize}` |
| OAuth | `GET /oauth/authorize`, `POST /oauth/{consent,token}`, `GET /oauth/userinfo`, `POST /oauth/mailbox`, `GET /oauth/grant-keypair` |
| JWKS | `GET /.well-known/jwks.json` |
| User lookups | `GET /v1/users/{username}/keys/{client_id}`, `GET /v1/users/by-thumbprint/{thumbprint}` |
| Discovery | `GET /.well-known/betterbase`, `GET /.well-known/webfinger` |
| Web UI | Fallback SPA catch-all |

## Configuration (Environment Variables)

**Required:**
- `DATABASE_URL` -- PostgreSQL connection string
- `OPAQUE_SERVER_SETUP` -- Hex-encoded OPAQUE ServerSetup blob (generate with `keygen` binary)
- `OAUTH_ISSUER` -- Stable issuer URL for JWTs and federation identity
- `IDENTITY_HASH_KEY` -- Hex-encoded 32-byte HMAC key for privacy-hashing emails in rate limits

**Optional:**
- `LISTEN_ADDR` (default `0.0.0.0:5377`)
- `LOG_FORMAT` (`text` or `json`, default `text`)
- `WEB_BASE_URL` -- Base URL for web UI links
- `SYNC_ENDPOINT` -- Sync service URL
- `FEDERATION_WS_ENDPOINT` -- Federation WebSocket endpoint
- `CAP_KEY_ID`, `CAP_SECRET`, `CAP_VERIFY_URL` -- CAP proof-of-work (enabled when `CAP_KEY_ID` is set)
- `SMTP_DEV_MODE` -- `true` to log emails instead of sending
- `SMTP_HOST`, `SMTP_PORT` (default 587), `SMTP_USERNAME`, `SMTP_PASSWORD`, `SMTP_FROM`

## Conventions

- All crates enforce `#![forbid(unsafe_code)]`
- Error handling: `thiserror` for domain errors (`StorageError`), `anyhow` for startup/infallible paths
- Async traits use `async-trait` crate
- Tests: `#[cfg(test)] mod tests` inline, DB tests skip without `DATABASE_URL`
- Workspace edition: 2021, MSRV: 1.88

## Docker

- `Dockerfile` -- Multi-stage production build: Node 22 (web UI) + Rust 1.88 (binaries) -> debian:bookworm-slim, nonroot user, port 5377
- `Dockerfile.dev` -- Dev build with `cargo-watch` hot reload
