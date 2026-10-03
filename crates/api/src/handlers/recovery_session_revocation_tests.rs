use base64::engine::general_purpose::STANDARD as B64;
use betterbase_accounts_auth::opaque::test_registration_upload;
use serde_json::json;

use crate::test_support::{get_json, post_form, post_json, test_app};

use betterbase_accounts_storage::{
    AccountStorage, OAuthClientStorage, OAuthGrantStorage, OAuthRefreshTokenStorage,
};

use super::*;

#[tokio::test]
async fn recover_finalize_revokes_prior_sessions() {
    let Some(app) = test_app().await else {
        return;
    };
    let account = app
        .storage
        .get_or_create_account(
            crate::test_support::TEST_ISSUER,
            "revoked",
            "revoked@example.test",
        )
        .await
        .expect("create account");

    // A pre-existing session: an auth JWT and an active refresh family.
    let old_auth = app.auth_token(&account.id.to_string());
    let client_id = uuid::Uuid::new_v4();
    app.storage
        .create_oauth_client(&betterbase_accounts_storage::OAuthClient {
            id: client_id,
            name: "victim app".to_owned(),
            secret_hash: None,
            redirect_uris: vec!["http://localhost:5381/".to_owned()],
            allowed_scopes: vec!["openid".to_owned()],
            created_at: chrono::Utc::now(),
        })
        .await
        .expect("create client");
    let grant = app
        .storage
        .get_or_create_oauth_grant(client_id, account.id, "openid")
        .await
        .expect("create grant");
    let mut token_bytes = [0u8; 32];
    use rand::RngExt as _;
    rand::rng().fill(&mut token_bytes);
    let raw_refresh = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(token_bytes);
    let now = chrono::Utc::now();
    app.storage
        .create_refresh_token(&betterbase_accounts_storage::OAuthRefreshToken {
            id: uuid::Uuid::new_v4(),
            grant_id: grant.id,
            token_hash: crate::handlers::oauth::sha256_hash(raw_refresh.as_bytes()),
            created_at: now,
            expires_at: now + chrono::Duration::days(1),
        })
        .await
        .expect("seed refresh token");

    // The old session works before recovery.
    let (status, _) = get_json(&app, "/v1/auth/validate", Some(&old_auth)).await;
    assert_eq!(status, axum::http::StatusCode::OK);

    // Drive a full recovery finalize: registration state + a real
    // OPAQUE registration upload (the handler runs registration_finish).
    let state_id = uuid::Uuid::new_v4();
    let now2 = chrono::Utc::now();
    app.storage
        .create_registration_state(&RegistrationState {
            root_key_version: account.root_key_version,
            id: state_id,
            account_id: account.id,
            username: account.username.clone(),
            created_at: now2,
            expires_at: now2 + chrono::Duration::seconds(60),
        })
        .await
        .expect("create state");
    let state_token = app
        .jwt
        .create_state_token(
            &state_id.to_string(),
            StatePurpose::Recovery,
            account.credentials_version,
        )
        .expect("state token");
    let upload = test_registration_upload(&app.opaque, b"new-password", account.id.as_bytes())
        .expect("registration upload");

    let (status, body) = post_json(
        &app,
        "/v1/accounts/recover/finalize",
        None,
        &json!({
            "state_token": state_token,
            "opaque_record": B64.encode(&upload),
            "wrapped_root_key": "",
            "new_blob": "",
        }),
    )
    .await;
    assert_eq!(status, axum::http::StatusCode::OK, "body: {body}");
    let new_auth = body["auth_token"].as_str().expect("auth token").to_owned();

    // AUD-011: the pre-recovery auth JWT is fenced...
    let (status, body) = get_json(&app, "/v1/auth/validate", Some(&old_auth)).await;
    assert_eq!(status, axum::http::StatusCode::UNAUTHORIZED, "body: {body}");
    assert!(
        body["error"]
            .as_str()
            .unwrap_or_default()
            .contains("credentials"),
        "body: {body}"
    );

    // ...the completion token (minted under the new version) works...
    let (status, _) = get_json(&app, "/v1/auth/validate", Some(&new_auth)).await;
    assert_eq!(status, axum::http::StatusCode::OK);

    // ...and the pre-recovery refresh family is dead.
    let (status, body) = post_form(
        &app,
        "/oauth/token",
        None,
        &format!("grant_type=refresh_token&refresh_token={raw_refresh}&client_id={client_id}"),
    )
    .await;
    assert_eq!(status, axum::http::StatusCode::BAD_REQUEST, "body: {body}");
    assert_eq!(body["error"], "invalid_grant");
}
