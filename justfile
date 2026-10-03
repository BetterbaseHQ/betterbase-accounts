# List available recipes
default:
    @just --list

# Run all checks (format, lint, test, web)
check: fmt lint test check-web

# Format code
fmt:
    cargo fmt --all

# Run clippy linter
lint:
    cargo clippy --workspace --all-targets -- -D warnings

# Run tests (DB-backed storage tests skip without DATABASE_URL; use test-db for the enforced real-PostgreSQL gate)
test *args:
    cargo test --workspace {{args}}

# Generated security-input tests; no database or external E2E suite required.
test-properties:
    SQLX_OFFLINE=true cargo test --workspace property_tests

# Deliberately disable selected security guards in a temporary source copy.
test-mutations *args:
    python3 scripts/test-security-mutations.py {{args}}

# Enforce mutation detection with disposable PostgreSQL; keep DB on failure.
test-mutations-db *args:
    #!/usr/bin/env bash
    set -euo pipefail
    just db-start
    DATABASE_URL="{{_db_url}}" just test-mutations {{args}}
    just db-down

# Run tests with verbose output
test-v *args:
    cargo test --workspace {{args}} -- --nocapture

# Build all targets
build:
    cargo build --workspace

# Build release
build-release:
    cargo build --workspace --release

# Build web UI (output to crates/api/assets/)
build-web:
    cd web && pnpm install && pnpm build
    rm -rf crates/api/assets
    cp -r web/dist crates/api/assets

# Run web quality checks
check-web:
    cd web && pnpm install && pnpm check

# Clean build artifacts
clean:
    cargo clean
    rm -rf crates/api/assets

# Docker settings for test database
_db_container := "betterbase-accounts-test-db"
_db_port      := "15433"
_db_user      := "accounts"
_db_pass      := "accounts"
_db_name      := "accounts_test"
_db_url       := "postgres://" + _db_user + ":" + _db_pass + "@localhost:" + _db_port + "/" + _db_name + "?sslmode=disable"

# Start a PostgreSQL container for tests
[private]
db-start:
    #!/usr/bin/env bash
    set -e
    if docker ps --format '{{{{.Names}}' | grep -q '^{{_db_container}}$'; then
        echo "Test database already running"
    elif docker ps -a --format '{{{{.Names}}' | grep -q '^{{_db_container}}$'; then
        echo "Starting stopped test database..."
        docker start {{_db_container}}
    else
        echo "Creating test database..."
        docker run -d \
            --name {{_db_container}} \
            -p {{_db_port}}:5432 \
            -e POSTGRES_USER={{_db_user}} \
            -e POSTGRES_PASSWORD={{_db_pass}} \
            -e POSTGRES_DB={{_db_name}} \
            postgres:17-alpine
    fi
    echo "Waiting for PostgreSQL to accept connections..."
    # The initialization server only opens a Unix socket; wait for the final TCP server.
    until docker exec {{_db_container}} pg_isready -h 127.0.0.1 -U {{_db_user}} -d {{_db_name}} > /dev/null 2>&1; do
        sleep 0.2
    done
    echo "Test database ready on port {{_db_port}}"

# Stop and remove the test database container
db-down:
    docker rm -f {{_db_container}} 2>/dev/null || true

# Run tests against a real PostgreSQL database (spins up, tests, tears down on success)
# On failure the container is kept for debugging via `just db-shell`; run `just db-down` to remove.
# SQLX_OFFLINE compiles via the committed .sqlx metadata (queries still execute
# live at test time); BB_TEST_REQUIRE_DB makes DB-backed tests fail instead of skip.
test-db *args:
    #!/usr/bin/env bash
    set -e
    just db-start
    echo "Running tests with DATABASE_URL..."
    SQLX_OFFLINE=true BB_TEST_REQUIRE_DB=1 DATABASE_URL="{{_db_url}}" cargo test --workspace {{args}}
    just db-down

# PostgreSQL shell for the test database (must be running)
db-shell:
    docker exec -it {{_db_container}} psql -U {{_db_user}} -d {{_db_name}}

# Install the pinned Rust coverage tool and compiler-matched LLVM tools.
coverage-setup:
    rustup component add llvm-tools-preview
    cargo install cargo-llvm-cov --version 0.9.1 --locked

# Measure all Rust targets against an existing DATABASE_URL and enforce floors.
coverage-rust:
    bash scripts/coverage-rust.sh

# Web coverage, including untouched source files, with threshold enforcement.
coverage-web:
    cd web && pnpm test:coverage

# Both coverage reports; DATABASE_URL must point to a test database.
coverage: coverage-rust coverage-web

# Full coverage using disposable PostgreSQL; retained on failure for debugging.
coverage-db:
    #!/usr/bin/env bash
    set -euo pipefail
    just db-start
    DATABASE_URL="{{_db_url}}" just coverage
    just db-down
