use base64::engine::general_purpose::STANDARD as B64;
use serde_json::json;

use crate::test_support::{post_json, test_app, TEST_ISSUER};

use super::*;

async fn victim(app: &crate::test_support::TestApp) -> betterbase_accounts_storage::Account {
    let account = app
        .storage
        .get_or_create_account(TEST_ISSUER, "victim", "victim@example.test")
        .await
        .expect("create victim");
    app.storage
        .finalize_registration(account.id, b"victim-opaque-record")
        .await
        .expect("register victim");
    app.storage
        .get_account_by_id(account.id)
        .await
        .expect("reload victim")
}

#[tokio::test]
async fn recover_init_rejects_malformed_email_with_bad_request() {
    // Unauthenticated endpoint: a missing "@" must produce a clean 400,
    // never a panic (worker-killing DoS vector).
    let Some(app) = test_app().await else {
        return;
    };
    let token = app
        .jwt
        .create_verification_token(
            "someone@example.test",
            betterbase_accounts_core::purpose::RECOVERY,
        )
        .expect("token");

    let (status, body) = post_json(
        &app,
        "/v1/accounts/recover/init",
        None,
        &json!({
            "email": "no-at-sign-example",
            "verification_token": token,
            "opaque_request": B64.encode(b"junk"),
            "cap_token": "",
        }),
    )
    .await;

    assert_eq!(status, StatusCode::BAD_REQUEST);
    assert_eq!(body["error"], "invalid email");
}

#[tokio::test]
async fn recover_init_rejects_token_issued_for_a_different_email() {
    let Some(app) = test_app().await else {
        return;
    };
    let victim = victim(&app).await;
    // Attacker controls a verification token for their own email...
    let attacker_token = app
        .jwt
        .create_verification_token(
            "attacker@example.test",
            betterbase_accounts_core::purpose::RECOVERY,
        )
        .expect("token");

    // ...and submits the victim's email in the request body.
    let (status, body) = post_json(
        &app,
        "/v1/accounts/recover/init",
        None,
        &json!({
            "email": victim.email,
            "verification_token": attacker_token,
            "opaque_request": B64.encode(b"junk"),
            "cap_token": "",
        }),
    )
    .await;

    assert_eq!(status, StatusCode::BAD_REQUEST);
    assert_eq!(
        body["error"],
        "verification token is not valid for this email"
    );

    // The victim's credentials are untouched.
    let reloaded = app
        .storage
        .get_account_by_id(victim.id)
        .await
        .expect("reload victim");
    assert_eq!(
        reloaded.opaque_record.as_deref(),
        Some(b"victim-opaque-record".as_slice())
    );
}

#[tokio::test]
async fn rejected_binding_does_not_consume_the_verification_token() {
    let Some(app) = test_app().await else {
        return;
    };
    // The attacker's email must resolve to a real account so the honest
    // retry can progress past the account lookup (it then fails at OPAQUE
    // decoding of junk bytes, proving the binding passed and the JTI was
    // consumed by this attempt, not the rejected one).
    app.storage
        .get_or_create_account(TEST_ISSUER, "attacker", "attacker@example.test")
        .await
        .expect("create attacker account");
    let attacker_token = app
        .jwt
        .create_verification_token(
            "attacker@example.test",
            betterbase_accounts_core::purpose::RECOVERY,
        )
        .expect("token");

    // First attempt claims a different email and must be rejected...
    let (status, _) = post_json(
        &app,
        "/v1/accounts/recover/init",
        None,
        &json!({
            "email": "someone-else@example.test",
            "verification_token": attacker_token,
            "opaque_request": B64.encode(b"junk"),
            "cap_token": "",
        }),
    )
    .await;
    assert_eq!(status, StatusCode::BAD_REQUEST);

    // ...and a second, honestly-paired attempt still passes the binding
    // (it fails later at OPAQUE decoding, proving progression past the
    // binding and JTI consumption).
    let (status, body) = post_json(
        &app,
        "/v1/accounts/recover/init",
        None,
        &json!({
            "email": "attacker@example.test",
            "verification_token": attacker_token,
            "opaque_request": B64.encode(b"junk"),
            "cap_token": "",
        }),
    )
    .await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
    assert_eq!(body["error"], "invalid OPAQUE request");
}

#[tokio::test]
async fn recover_init_rejects_non_recovery_purpose_tokens() {
    let Some(app) = test_app().await else {
        return;
    };
    let registration_token = app
        .jwt
        .create_verification_token(
            "attacker@example.test",
            betterbase_accounts_core::purpose::REGISTRATION,
        )
        .expect("token");

    let (status, body) = post_json(
        &app,
        "/v1/accounts/recover/init",
        None,
        &json!({
            "email": "attacker@example.test",
            "verification_token": registration_token,
            "opaque_request": B64.encode(b"junk"),
            "cap_token": "",
        }),
    )
    .await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
    assert_eq!(body["error"], "invalid verification token purpose");
}
