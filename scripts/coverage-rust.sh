#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")/.."

# Never publish misleading coverage from silently skipped database tests.
: "${DATABASE_URL:?Set DATABASE_URL, or use just coverage-db for disposable PostgreSQL}"
export BB_TEST_REQUIRE_DB=1
export SQLX_OFFLINE=true

report_dir=target/coverage/rust
# Do not leave a previous report available if this run fails before reporting.
rm -rf "$report_dir"
mkdir -p "$report_dir"
ignore_files='(^|/)([^/]*_tests|tests|[^/]*test_support)\.rs$'

# --no-report preserves previous profiles and binaries. Explicitly clean the
# workspace artifacts first, while retaining instrumented third-party dependencies.
cargo llvm-cov clean --workspace
cargo llvm-cov --workspace --all-targets --no-report
cargo llvm-cov report --ignore-filename-regex "$ignore_files" --html --output-dir "$report_dir"
cargo llvm-cov report --ignore-filename-regex "$ignore_files" --lcov --output-path "$report_dir/lcov.info"
cargo llvm-cov report --ignore-filename-regex "$ignore_files" --json --summary-only --output-path "$report_dir/summary.json"
python3 scripts/check-rust-coverage.py "$report_dir/summary.json"
# Generate artifacts before checking floors so failed gates remain inspectable.
# Raise these checked-in floors as coverage improves.
cargo llvm-cov report --ignore-filename-regex "$ignore_files" \
    --fail-under-lines 88 --fail-under-functions 77 --fail-under-regions 86
