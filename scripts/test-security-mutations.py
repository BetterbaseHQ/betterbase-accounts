"""Check selected security regressions in an isolated copy of the working tree.

These reviewed mutations include storage-call substitutions, which ordinary
operator mutation tools don't generate. A compile error, timeout, skipped test,
or infrastructure failure never counts as a detected mutation.
"""

import argparse
import json
import os
import re
import shutil
import subprocess
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
API = "crates/api/src/handlers/"
FLOW = "credential_flow_tests::"
OAUTH = "handlers::oauth::"
MUTATIONS = [
    (
        "password-change-login-owner",
        API + "password_change.rs",
        "if login_state.account_id != Some(auth_ctx.account_id) {",
        "if false {",
        FLOW + "password_change_verification_rejects_another_accounts_login_state",
    ),
    (
        "password-change-completion-owner",
        API + "password_change.rs",
        "if reg_state.account_id != auth_ctx.account_id {",
        "if false {",
        FLOW + "password_change_completion_rejects_another_accounts_registration_state",
    ),
    (
        "session-credential-version",
        API + "auth.rs",
        "if claims.cred_ver != current_version {",
        "if false {",
        FLOW + "password_change_flow_revokes_old_session_and_returns_a_usable_session",
    ),
    (
        "login-credential-version",
        API + "auth.rs",
        "if state.storage.get_credentials_version(account_id).await? != Some(credentials_version) {",
        "if false {",
        FLOW + "login_started_before_credential_replacement_cannot_create_a_new_session",
    ),
    (
        "replacement-credential-version",
        "crates/storage/src/postgres/composite.rs",
        "if i64::from(snapshot.credentials_version) != expected_credentials_version {",
        "if false {",
        FLOW + "recovery_started_before_a_credential_change_cannot_overwrite_it",
    ),
    (
        "replacement-root-version",
        "crates/storage/src/postgres/composite.rs",
        "if i64::from(snapshot.root_key_version) != expected_root_key_version {",
        "if false {",
        FLOW + "credential_completion_cannot_overwrite_a_rotated_root",
    ),
    (
        "standard-pkce",
        API + "oauth.rs",
        "verify_pkce(&req.code_verifier, &code.code_challenge)",
        "true",
        "security_boundary_tests::authorization_code_exchange_binds_pkce_client_redirect_and_expiry",
    ),
    (
        "recipient-bound-pkce",
        API + "oauth.rs",
        "verify_pkce_with_thumbprint(&req.code_verifier, thumbprint, &code.code_challenge)",
        "true",
        OAUTH + "validation_tests::extended_pkce_binds_verifier_and_recipient_and_delivers_keys_once",
    ),
    (
        "authorization-code-replay",
        API + "oauth.rs",
        "state.storage.consume_oauth_code(&req.code)",
        "state.storage.get_oauth_code(&req.code)",
        OAUTH + "validation_tests::concurrent_code_exchanges_issue_only_one_session",
    ),
    (
        "login-proof-replay",
        API + "auth.rs",
        "state.storage.consume_login_state(state_id)",
        "state.storage.get_login_state(state_id)",
        "registration_tests::signup_through_http_returns_a_session_and_credentials_that_can_log_in",
    ),
]


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--only", nargs="+", choices=[m[0] for m in MUTATIONS])
    args = parser.parse_args()
    if not os.environ.get("DATABASE_URL"):
        raise SystemExit("Set DATABASE_URL, or use just test-mutations-db.")
    mutations = [m for m in MUTATIONS if not args.only or m[0] in args.only]
    report_dir = ROOT / "target/security-mutations/reports"
    report_dir.mkdir(parents=True, exist_ok=True)
    report = {"baseline": "not-run", "mutations": []}

    def save():
        (report_dir / "summary.json").write_text(json.dumps(report, indent=2) + "\n")

    save()  # Never leave a successful summary from an earlier run.
    env = dict(os.environ, SQLX_OFFLINE="true", BB_TEST_REQUIRE_DB="1",
               CARGO_TARGET_DIR=str(ROOT / "target"), CARGO_TERM_COLOR="never")
    with tempfile.TemporaryDirectory(prefix="security-mutations-") as temporary:
        checkout = Path(temporary)
        for name in ("Cargo.toml", "Cargo.lock", "rust-toolchain.toml", "rust-toolchain"):
            if (ROOT / name).exists():
                shutil.copy2(ROOT / name, checkout / name)
        for name in ("crates", "bins", ".sqlx", ".cargo"):
            if (ROOT / name).exists():
                shutil.copytree(ROOT / name, checkout / name)

        def run(arguments, log_name):
            try:
                result = subprocess.run(
                    ["cargo", "test", "--locked", "-p", "betterbase-accounts-api", "--lib", *arguments],
                    cwd=checkout, env=env, capture_output=True, text=True, timeout=300,
                )
            except subprocess.TimeoutExpired as error:
                output = (error.stdout or b"") + (error.stderr or b"")
                (report_dir / log_name).write_bytes(output)
                raise RuntimeError(f"Timed out; inspect {report_dir / log_name}") from error
            output = result.stdout + result.stderr
            (report_dir / log_name).write_text(output)
            return result.returncode, output

        print("Running unmodified API baseline against PostgreSQL...", flush=True)
        code, output = run([], "baseline.log")
        if code or not re.search(r"test result: ok\. [1-9]\d* passed", output):
            report["baseline"] = "failed"
            save()
            raise RuntimeError(f"Baseline failed; inspect {report_dir / 'baseline.log'}")
        report["baseline"] = "passed"
        save()
        for name, filename, original, replacement, test in mutations:
            print(f"Checking {name}...", flush=True)
            outcome = {"name": name, "test": test, "status": "invalid"}
            report["mutations"].append(outcome)
            path = checkout / filename
            source = path.read_text()
            if source.count(original) != 1:
                outcome["reason"] = "Mutation anchor must match exactly once; review it after refactoring."
                save()
                continue
            try:
                path.write_text(source.replace(original, replacement, 1))
                code, _ = run(["--no-run"], name + "-build.log")
                if code:
                    outcome["reason"] = "Mutated code did not compile."
                    continue
                code, output = run([test, "--", "--exact"], name + "-test.log")
                if "running 1 test\n" not in output:
                    outcome["reason"] = "Expected exactly one regression test to run."
                elif code == 0 and "test result: ok. 1 passed" in output:
                    outcome["status"] = "survived"
                elif (code == 101 and f"test {test} ... FAILED" in output
                      and "assertion" in output and "test result: FAILED. 0 passed; 1 failed" in output):
                    outcome["status"] = "detected"
                else:
                    outcome["reason"] = "Failure was not a regression assertion (check infrastructure and logs)."
            finally:
                path.write_text(source)
                save()
            print(f"  {outcome['status']}", flush=True)
    detected = sum(m["status"] == "detected" for m in report["mutations"])
    print(f"Detected {detected}/{len(mutations)} security mutations. Reports: {report_dir}")
    if detected != len(mutations):
        raise SystemExit(1)


if __name__ == "__main__":
    main()
