# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Overview

Rust port of `less-accounts` (Go) — an OPAQUE-based password authentication and OAuth 2.0 server for the Less platform. Follows the architecture established in `less-sync-rs`. Currently at scaffold phase (Phase 1 complete); all crates compile but contain empty stubs.

See `PLAN.md` for the full implementation plan.

## Porting Guidelines

This is a **faithful port** of the Go `less-accounts` server. The Go source of truth lives at:
`/Users/nchapman/Code/lessisbetter/less-platform/less-accounts`

- **Always cross-reference the Go implementation** before writing or reviewing code. When in doubt, read the Go source. Don't take liberties — match behavior exactly.
- **Use idiomatic Rust.** Newtypes, enums, `From`/`Into`, `thiserror`, exhaustive matches, builder patterns where appropriate. This should be a project Rustaceans admire.
- **Test-driven development.** Write failing tests first, then implement. Every module should have thorough unit tests. Prefer `#[cfg(test)] mod tests` inline. Test edge cases, error paths, and empty inputs.
- **Commit as you go.** Small, focused commits with clear descriptions of what was done. Never reference milestone names, phase numbers, or plan sections in commit messages.

## Commands

```bash
just check            # fmt + lint + test (use this as the standard workflow check)
just fmt              # cargo fmt --all
just lint             # cargo clippy --workspace --all-targets -- -D warnings
just test             # cargo test --workspace (DB tests auto-skip without DATABASE_URL)
just test-v           # cargo test --workspace -- --nocapture
just test-db          # Spins up Postgres container, runs tests with DATABASE_URL, tears down
just build            # cargo build --workspace
just build-release    # cargo build --workspace --release
just db-start         # Start test Postgres on port 15433
just db-down          # Stop test Postgres
just db-shell         # psql into test database
```

Run a single test: `cargo test --workspace -p less-accounts-storage -- test_name`

## Workspace Structure

**Binaries** (`bins/`):
- `server` — Main HTTP server (Axum). Entry point calls `app::run()`.
- `keygen` — Generates hex-encoded OPAQUE `ServerSetup` blob.
- `oauth-client` — CLI for managing OAuth clients in the database.

**Library crates** (`crates/`), in dependency order:
- `core` — Shared domain types, validation (email, username, handle, DID key), API request/response types (`protocol.rs`)
- `auth` — OPAQUE registration/login (`opaque-ke` with Ristretto255), JWT creation/validation (5 token types: auth/state/access/oauth-state/verification), ES256 key management, auth middleware
- `storage` — Storage traits (16+ trait types organized by domain) + PostgreSQL implementation (sqlx). Migrations live in `crates/storage/migrations/`.
- `email` — Mailer trait with SMTP and dev-mode implementations
- `cap` — CAP proof-of-work verification client
- `api` — Axum HTTP handlers and router. Depends on all other crates.
- `app` — Application bootstrap, `AppConfig` (env-based), startup sequence, graceful shutdown

## Key Dependency Chain

```
bins/server → app → api → { auth, storage, email, cap, core }
bins/keygen → (standalone: hex, rand)
bins/oauth-client → storage
```

## Architecture Notes

**OPAQUE**: Uses `opaque-ke` crate (Ristretto255 cipher suite). Wire format is **incompatible** with the Go server's `bytemare/opaque` — existing registrations cannot migrate; users must re-register via recovery. Config uses a single `OPAQUE_SERVER_SETUP` hex blob (replaces Go's separate key + public key + DB-stored OPRF seeds).

**JWT tokens**: 5 types with different signing/lifetime. HS256 for internal tokens (auth 14d, state 60s, oauth-state 10m, verification 15m). ES256 for OAuth access tokens (15m). JWKS endpoint exposes ES256 public keys.

**Storage layer**: Trait-based with 16+ async traits organized by domain (accounts, registration, login, JWT keys, user keys, OAuth entities, recovery, verification, rate limits, cleanup). PostgreSQL impl uses sqlx with compile-time checked queries. 17 tables.

**Web UI**: React SPA from `less-accounts/web/` embedded via `rust-embed`. SPA fallback serves `index.html` for non-file paths.

**Background tasks**: 60-second cleanup loop purges expired registration/login states, OAuth codes, refresh tokens, verification codes/JTIs.

**All crates enforce `#![forbid(unsafe_code)]`.**

## Configuration (Environment Variables)

Required: `DATABASE_URL`, `OPAQUE_SERVER_SETUP` (hex), `OAUTH_ISSUER`, `IDENTITY_HASH_KEY` (hex, 32 bytes).

Optional: `LISTEN_ADDR` (default `0.0.0.0:5377`), `LOG_FORMAT` (`text`/`json`), `WEB_BASE_URL`, `SYNC_ENDPOINT`, `CAP_KEY_ID`/`CAP_SECRET`/`CAP_VERIFY_URL`, `SMTP_*` vars, `SMTP_DEV_MODE`.

## API Routes

All routes are under `/v1/` (auth, registration, verification, recovery, keys, password change) and `/oauth/` (authorize, consent, token, userinfo, mailbox, grant-keypair). JWKS at `/.well-known/jwks.json`. Discovery at `/.well-known/less-platform` and `/.well-known/webfinger`. Health at `/health`.

These are immutable v1 contracts — route paths must not change without a versioned migration.

## Docker

- `Dockerfile` — Multi-stage production build (rust:1.88 → debian:bookworm-slim), nonroot user, port 5377
- `Dockerfile.dev` — Dev build with `cargo-watch` hot reload
