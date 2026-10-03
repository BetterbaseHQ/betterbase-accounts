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

Configuration is validated before database initialization. Invalid OPAQUE setup or
identity-hash keys, malformed listen addresses, invalid SMTP ports, and enabled CAP
without a key ID, secret, or HTTP(S) verification URL fail startup. `OAUTH_ISSUER`
must be an HTTP(S) URL without userinfo, query, or fragment; an issuer with a path
requires an explicit bare `ACCOUNTS_PUBLIC_URL` for discovery.

## Deployment compatibility

Temporary authentication state tokens are bound to their registration, login,
password-change, or recovery flow and credential version. When upgrading from a
build without these bindings, replace all server instances together. In-progress
flows using older state tokens must restart; existing auth sessions are unchanged.
These temporary tokens have a 60-second lifetime. Migrations 0004–0005 store
credential and root-key snapshots on the server and run automatically at startup.

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
just check-web      # Format, typecheck, test, and enforce web coverage
```

`just test-db` starts a PostgreSQL container on port 15433, runs all tests, then removes the container.

### Property tests

JWT, OPAQUE, and OAuth key-validation property tests run in the normal Rust suite
and CI. They generate inputs, check successful authentication before tampering,
and exercise malformed messages and key material. Each property runs 256 cases
by default; no database or external E2E suite is needed for this subset.

```bash
just test-properties
PROPTEST_CASES=1024 just test-properties # A longer local run
PROPTEST_RNG_SEED=42 just test-properties # Reproduce a generation sequence
```

Proptest shrinks failures and saves regression seeds under each crate's
`proptest-regressions/` directory. Commit these files when fixing a discovered
failure so normal runs continue to replay the minimized case. Seeds reproduce
generated inputs; cryptographic key generation and protocol nonces still use
OS randomness. Property tests complement the example-based tests and coverage
floors; passing generated cases does not prove that every input is safe.

### Security mutations

The Rust CI job also runs ten reviewed security mutations: it disables ownership,
credential/root-version, and PKCE guards, and replaces consuming reads with ordinary
reads to test replay protection. The runner copies the current Rust sources and
embedded UI assets into a temporary directory, checks the unmodified API baseline
against PostgreSQL, then builds each mutation and runs its exact regression test.
It never edits the working source. Compilation errors, missing tests, infrastructure
failures, timeouts, and surviving mutations fail the gate.

```bash
just test-mutations-db # Disposable PostgreSQL, retained on failure
# With DATABASE_URL pointing to a test database:
just test-mutations
just test-mutations --only login-proof-replay # Investigate one mutation
```

On a fresh checkout, run `just build-web` first to populate embedded assets.
Reports and build/test logs are in `target/security-mutations/reports/`; CI uploads
them as `rust-security-mutations`. Mutation anchors and exact test names live in
`scripts/test-security-mutations.py`; review them when refactoring a guard. This
focused gate covers only those ten reviewed changes.

### Coverage

Coverage runs locally and in both CI jobs. CI enforces checked-in minimums,
adds totals to the job summary, and retains HTML, LCOV, and JSON reports as
`rust-coverage` and `web-coverage` artifacts for 30 days. No external coverage
service or token is required.

```bash
just coverage-setup # Once: install cargo-llvm-cov 0.9.1 and llvm-tools-preview
just build-web      # On a fresh checkout: install web dependencies and build embedded assets
just coverage-db    # Both suites with disposable PostgreSQL; enforce coverage floors
just coverage-web   # Web only
# With DATABASE_URL pointing to a test database:
just coverage-rust  # Rust only; fails if DATABASE_URL is missing or unreachable
```

Open `target/coverage/rust/html/index.html` and `web/coverage/index.html` for
per-file coverage. Machine-readable totals are in
`target/coverage/rust/summary.json` and `web/coverage/coverage-summary.json`;
LCOV reports are `lcov.info` in those directories. Generated reports are ignored
by Git and formatting checks. Rust coverage explicitly cleans workspace binaries
and execution profiles before each run, so deleted code and earlier runs cannot
affect the results. Instrumented third-party dependencies remain cached.
The disposable database is removed on success and kept on failure for debugging
(`just db-down` removes it).

| Suite | Lines | Branches | Functions | Statements / regions |
| --- | ---: | ---: | ---: | ---: |
| Web minimum | 84% | 71% | 78% | 82% statements |
| Rust minimum | 88% | Not measured | 77% | 86% regions |

Web coverage includes all `src` files, including untouched components; only the
TypeScript declaration file is excluded. The recovery form and auth context each
require 100% lines, branches, functions, and statements. Thresholds live in
`web/vite.config.ts`; `pnpm test:coverage` and `just check-web` enforce them.

Rust uses stable LLVM instrumentation across the workspace, with PostgreSQL
required so storage and API tests cannot silently skip. Reports exclude dedicated
test files and test-support files. Rust tests live in dedicated `*_tests.rs` files,
so totals measure production code only, including the binaries. The coverage gate
checks that no inline test modules return and no test files enter the report.
Stable Rust does not measure branch coverage here. The Rust thresholds live in
`scripts/coverage-rust.sh`.

The production-only baseline is 88.67% lines, 77.53% functions, and 86.89% regions.
These totals replace the old 92.62% line figure, which included inline test bodies:
the measured line count changed from 7,898 to 3,876. The new floors reflect this
measurement change; all production files remain included.

These floors prevent drops below the recorded baseline, not every small decrease.
Review the per-file reports and raise the floors as tests improve; do not lower
thresholds or exclude production files simply to make a check pass. External E2E
coverage is separate and is not merged into these reports.

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
- [betterbase](../betterbase/) -- Client SDK (auth, crypto, discovery, sync, db)

## License

Apache-2.0
