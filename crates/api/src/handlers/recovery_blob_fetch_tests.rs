use base64::engine::general_purpose::STANDARD as B64;
use betterbase_accounts_auth::opaque::test_registration_start;
use serde_json::json;

use crate::test_support::{post_json, test_app, TEST_ISSUER};

use super::*;

#[tokio::test]
async fn blob_fetch_does_not_consume_the_one_use_token() {
    // AUD-007: the recovery page fetches the encrypted blob before
    // calling recover/init. The fetch must not consume the one-use
    // verification token — single use belongs at the state-changing
    // boundary (init). Pre-fix, the real UI sequence could never pass
    // init, and a wrong-phrase decrypt burned the token.
    let Some(app) = test_app().await else {
        return;
    };
    let account = app
        .storage
        .get_or_create_account(TEST_ISSUER, "recoverer", "recoverer@example.test")
        .await
        .expect("create account");
    app.storage
        .finalize_registration(account.id, b"record")
        .await
        .expect("finalize");
    app.storage
        .store_recovery_blob(account.id, b"encrypted-blob")
        .await
        .expect("store blob");

    let token = app
        .jwt
        .create_verification_token(
            "recoverer@example.test",
            betterbase_accounts_core::purpose::RECOVERY,
        )
        .expect("token");

    // The real page sequence: fetch the blob (readable, re-readable
    // while the token is unused — the blob itself stays encrypted).
    for _ in 0..2 {
        let (status, body) = post_json(
            &app,
            "/v1/accounts/recovery-blob/fetch",
            Some(&token),
            &json!(null),
        )
        .await;
        assert_eq!(status, StatusCode::OK, "body: {body}");
        assert_eq!(body["blob"], "encrypted-blob");
    }

    // init still accepts the token and starts recovery.
    let ke1 = test_registration_start(b"new-password").expect("ke1");
    let (status, body) = post_json(
        &app,
        "/v1/accounts/recover/init",
        None,
        &json!({
            "email": "recoverer@example.test",
            "verification_token": token,
            "opaque_request": B64.encode(&ke1),
            "cap_token": "",
        }),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "body: {body}");
    assert!(body["opaque_response"]
        .as_str()
        .is_some_and(|s| !s.is_empty()));

    // Single use is enforced at init: a replayed init is rejected.
    let ke1b = test_registration_start(b"new-password").expect("ke1");
    let (status, body) = post_json(
        &app,
        "/v1/accounts/recover/init",
        None,
        &json!({
            "email": "recoverer@example.test",
            "verification_token": token,
            "opaque_request": B64.encode(&ke1b),
            "cap_token": "",
        }),
    )
    .await;
    assert_eq!(status, StatusCode::BAD_REQUEST, "body: {body}");
    assert_eq!(body["error"], "verification token already used");
}
