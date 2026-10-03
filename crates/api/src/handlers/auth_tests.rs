use base64::engine::general_purpose::STANDARD as B64;
use serde_json::json;

use crate::test_support::{post_json, test_app, TEST_ISSUER};

use super::*;

#[tokio::test]
async fn password_init_rejects_verified_email_claiming_an_existing_username() {
    let Some(app) = test_app().await else {
        return;
    };
    // Victim already registered their username.
    let victim = app
        .storage
        .get_or_create_account(TEST_ISSUER, "victim", "victim@example.test")
        .await
        .expect("create victim");
    app.storage
        .finalize_registration_with_root_key(victim.id, b"victim-record", &[0xAA; 41])
        .await
        .expect("register victim");

    // Attacker verifies their own fresh email but submits the victim's username.
    let attacker_token = app
        .jwt
        .create_verification_token(
            "attacker@example.test",
            betterbase_accounts_core::purpose::REGISTRATION,
        )
        .expect("token");

    let (status, body) = post_json(
        &app,
        "/v1/accounts/password/init",
        None,
        &json!({
            "username": "victim",
            "email": "attacker@example.test",
            "verification_token": attacker_token,
            "opaque_request": B64.encode(b"junk"),
            "cap_token": "",
        }),
    )
    .await;

    assert_eq!(status, StatusCode::CONFLICT);
    assert_eq!(body["error"], "username already taken");

    // The victim's credentials and root key are untouched.
    let reloaded = app
        .storage
        .get_account_by_id(victim.id)
        .await
        .expect("reload victim");
    assert_eq!(
        reloaded.opaque_record.as_deref(),
        Some(b"victim-record".as_slice())
    );
    assert_eq!(reloaded.wrapped_root_key.as_deref(), Some(&[0xAA; 41][..]));

    // The rejection did not consume the verification token: retrying
    // with a fresh username passes the reservation checks (and fails at
    // OPAQUE decoding of junk bytes, proving progression).
    let (status, body) = post_json(
        &app,
        "/v1/accounts/password/init",
        None,
        &json!({
            "username": "attacker",
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
async fn password_init_allows_resuming_an_unfinished_signup() {
    let Some(app) = test_app().await else {
        return;
    };
    // A first init pre-created the account but never finalized it.
    app.storage
        .get_or_create_account(TEST_ISSUER, "newuser", "new@example.test")
        .await
        .expect("pre-create");

    let token = app
        .jwt
        .create_verification_token(
            "new@example.test",
            betterbase_accounts_core::purpose::REGISTRATION,
        )
        .expect("token");

    // Retry with the same email/username: passes the reservation checks
    // and fails only at OPAQUE decoding of junk bytes.
    let (status, body) = post_json(
        &app,
        "/v1/accounts/password/init",
        None,
        &json!({
            "username": "newuser",
            "email": "new@example.test",
            "verification_token": token,
            "opaque_request": B64.encode(b"junk"),
            "cap_token": "",
        }),
    )
    .await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
    assert_eq!(body["error"], "invalid OPAQUE request");
}

#[tokio::test]
async fn password_init_rejects_token_issued_for_a_different_email() {
    let Some(app) = test_app().await else {
        return;
    };
    let token = app
        .jwt
        .create_verification_token(
            "other@example.test",
            betterbase_accounts_core::purpose::REGISTRATION,
        )
        .expect("token");

    let (status, body) = post_json(
        &app,
        "/v1/accounts/password/init",
        None,
        &json!({
            "username": "freshuser",
            "email": "fresh@example.test",
            "verification_token": token,
            "opaque_request": B64.encode(b"junk"),
            "cap_token": "",
        }),
    )
    .await;
    assert_eq!(status, StatusCode::UNAUTHORIZED);
    assert_eq!(body["error"], "invalid verification token");
}

#[tokio::test]
async fn password_init_matches_the_verification_email_across_casing() {
    // The token/email comparison is canonical (domain casing normalized;
    // Gmail local-part folding): a user verifying "mixed@EXAMPLE.test"
    // must be able to submit the lowercase form — and a genuinely
    // different email must still reject.
    let Some(app) = test_app().await else {
        return;
    };
    let token = app
        .jwt
        .create_verification_token(
            "mixed@EXAMPLE.test",
            betterbase_accounts_core::purpose::REGISTRATION,
        )
        .expect("token");

    let (status, body) = post_json(
        &app,
        "/v1/accounts/password/init",
        None,
        &json!({
            "username": "mixedcase",
            "email": "mixed@example.test",
            "verification_token": token,
            "opaque_request": B64.encode(b"junk"),
            "cap_token": "",
        }),
    )
    .await;
    // Canonical match: passes binding and reservation checks, fails
    // only at OPAQUE decoding of junk bytes.
    assert_eq!(status, StatusCode::BAD_REQUEST);
    assert_eq!(body["error"], "invalid OPAQUE request");

    // A genuinely different email still fails binding.
    let token2 = app
        .jwt
        .create_verification_token(
            "mixed@example.test",
            betterbase_accounts_core::purpose::REGISTRATION,
        )
        .expect("token2");
    let (status, body) = post_json(
        &app,
        "/v1/accounts/password/init",
        None,
        &json!({
            "username": "mixedcase2",
            "email": "other@example.test",
            "verification_token": token2,
            "opaque_request": B64.encode(b"junk"),
            "cap_token": "",
        }),
    )
    .await;
    assert_eq!(status, StatusCode::UNAUTHORIZED);
    assert_eq!(body["error"], "invalid verification token");
}
