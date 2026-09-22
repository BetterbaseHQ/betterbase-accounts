//! Regression coverage for flow binding and credential revocation.
use axum::http::StatusCode;
use base64::{engine::general_purpose::STANDARD as B64, Engine as _};
use betterbase_accounts_auth::{
    jwt::StatePurpose,
    opaque::{test_registration_start, test_registration_upload, TestLogin},
};
use betterbase_accounts_storage::{
    Account, AccountStorage, CompositeStorage, RegistrationState, RegistrationStateStorage,
};
use serde_json::json;
use uuid::Uuid;

use crate::test_support::{get_json, post_json, test_app, TestApp, TEST_ISSUER};

const PASSWORD: &[u8] = b"original-password";

async fn registered_account(app: &TestApp) -> Account {
    let account = app
        .storage
        .get_or_create_account(TEST_ISSUER, "alice", "alice@example.test")
        .await
        .expect("create account");
    let upload = test_registration_upload(&app.opaque, PASSWORD, account.id.as_bytes()).unwrap();
    let record = app.opaque.registration_finish(&upload).unwrap();
    app.storage
        .finalize_registration_with_root_key(account.id, &record, &[1; 41])
        .await
        .expect("register account");
    app.storage.get_account_by_id(account.id).await.unwrap()
}

async fn registration_state(
    app: &TestApp,
    account: &Account,
    purpose: StatePurpose,
) -> (Uuid, String) {
    let now = chrono::Utc::now();
    let id = Uuid::new_v4();
    app.storage
        .create_registration_state(&RegistrationState {
            root_key_version: account.root_key_version,
            id,
            account_id: account.id,
            username: account.username.clone(),
            created_at: now,
            expires_at: now + chrono::Duration::seconds(60),
        })
        .await
        .unwrap();
    let token = app
        .jwt
        .create_state_token(&id.to_string(), purpose, account.credentials_version)
        .unwrap();
    (id, token)
}

#[tokio::test]
async fn registration_and_password_change_tokens_cannot_recover_an_account() {
    let Some(app) = test_app().await else {
        return;
    };
    let account = registered_account(&app).await;
    let upload =
        test_registration_upload(&app.opaque, b"replacement", account.id.as_bytes()).unwrap();
    for purpose in [StatePurpose::Registration, StatePurpose::PasswordChange] {
        let (id, token) = registration_state(&app, &account, purpose).await;
        let (status, body) = post_json(
            &app,
            "/v1/accounts/recover/finalize",
            None,
            &json!({
                "state_token": token, "opaque_record": B64.encode(&upload),
                "wrapped_root_key": B64.encode([2; 41]),
            }),
        )
        .await;
        assert_eq!(status, StatusCode::UNAUTHORIZED, "{body}");
        // A rejected cross-flow request must not even consume the legitimate state.
        assert!(app.storage.get_registration_state(id).await.is_ok());
        let unchanged = app.storage.get_account_by_id(account.id).await.unwrap();
        assert_eq!(unchanged.opaque_record, account.opaque_record);
        assert_eq!(unchanged.credentials_version, 0);
    }
}

async fn start_login(app: &TestApp, account: &Account) -> (String, Vec<u8>) {
    let (client, ke1) = TestLogin::start(PASSWORD);
    let (status, body) = post_json(
        app,
        "/v1/auth/login/init",
        None,
        &json!({
            "username": account.username, "opaque_ke1": B64.encode(ke1), "cap_token": "",
        }),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{body}");
    let ke3 = client.finish(
        PASSWORD,
        &B64.decode(body["opaque_ke2"].as_str().unwrap()).unwrap(),
    );
    (body["login_token"].as_str().unwrap().to_owned(), ke3)
}

#[tokio::test]
async fn login_started_before_credential_replacement_cannot_create_a_new_session() {
    let Some(app) = test_app().await else {
        return;
    };
    let account = registered_account(&app).await;
    // Control: a normal OPAQUE login issues a usable session.
    let (token, ke3) = start_login(&app, &account).await;
    let (status, body) = post_json(
        &app,
        "/v1/auth/login/finalize",
        None,
        &json!({
            "login_token": token, "opaque_ke3": B64.encode(ke3),
        }),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{body}");
    let old_auth = body["auth_token"].as_str().unwrap();

    let (token, ke3) = start_login(&app, &account).await;
    let upload =
        test_registration_upload(&app.opaque, b"replacement", account.id.as_bytes()).unwrap();
    let record = app.opaque.registration_finish(&upload).unwrap();
    app.storage
        .update_credentials_and_revoke_sessions(account.id, &record, Some(&[2; 41]), 0, 0, None)
        .await
        .unwrap();
    let (status, body) = post_json(
        &app,
        "/v1/auth/login/finalize",
        None,
        &json!({
            "login_token": token, "opaque_ke3": B64.encode(ke3),
        }),
    )
    .await;
    assert_eq!(status, StatusCode::UNAUTHORIZED, "{body}");
    assert_eq!(
        get_json(&app, "/v1/auth/validate", Some(old_auth)).await.0,
        StatusCode::UNAUTHORIZED
    );
}

#[tokio::test]
async fn password_change_flow_revokes_old_session_and_returns_a_usable_session() {
    let Some(app) = test_app().await else {
        return;
    };
    let account = registered_account(&app).await;
    let old_auth = app.auth_token(&account.id.to_string());
    let (client, ke1) = TestLogin::start(PASSWORD);
    let (status, init) = post_json(
        &app,
        "/v1/accounts/password/change/init",
        Some(&old_auth),
        &json!({
            "username": account.username, "opaque_ke1": B64.encode(ke1),
        }),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{init}");
    let ke3 = client.finish(
        PASSWORD,
        &B64.decode(init["opaque_ke2"].as_str().unwrap()).unwrap(),
    );
    // The same valid proof must not complete an ordinary login.
    let (status, _) = post_json(
        &app,
        "/v1/auth/login/finalize",
        None,
        &json!({
            "login_token": init["login_token"], "opaque_ke3": B64.encode(&ke3),
        }),
    )
    .await;
    assert_eq!(status, StatusCode::UNAUTHORIZED);
    let request = test_registration_start(b"replacement").unwrap();
    let (status, verified) = post_json(
        &app,
        "/v1/accounts/password/change/verify",
        Some(&old_auth),
        &json!({
            "login_token": init["login_token"], "opaque_ke3": B64.encode(ke3),
            "opaque_request": B64.encode(request),
        }),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{verified}");
    let upload =
        test_registration_upload(&app.opaque, b"replacement", account.id.as_bytes()).unwrap();
    let (status, completed) = post_json(
        &app,
        "/v1/accounts/password/change/complete",
        Some(&old_auth),
        &json!({
            "state_token": verified["state_token"], "opaque_record": B64.encode(upload),
            "wrapped_root_key": B64.encode([2; 41]),
        }),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{completed}");
    assert_eq!(
        get_json(&app, "/v1/auth/validate", Some(&old_auth)).await.0,
        StatusCode::UNAUTHORIZED
    );
    assert_eq!(
        get_json(&app, "/v1/auth/validate", completed["auth_token"].as_str())
            .await
            .0,
        StatusCode::OK
    );
    let account = app.storage.get_account_by_id(account.id).await.unwrap();
    assert_eq!(account.credentials_version, 1);
    assert_eq!(account.wrapped_root_key, Some(vec![2; 41]));
}

#[tokio::test]
async fn recovery_started_before_a_credential_change_cannot_overwrite_it() {
    let Some(app) = test_app().await else {
        return;
    };
    let account = registered_account(&app).await;
    let (_, stale_token) = registration_state(&app, &account, StatePurpose::Recovery).await;
    app.storage
        .revoke_account_sessions(account.id)
        .await
        .unwrap();
    let upload =
        test_registration_upload(&app.opaque, b"replacement", account.id.as_bytes()).unwrap();
    let (status, body) = post_json(
        &app,
        "/v1/accounts/recover/finalize",
        None,
        &json!({
            "state_token": stale_token, "opaque_record": B64.encode(upload),
            "wrapped_root_key": B64.encode([2; 41]),
        }),
    )
    .await;
    assert_eq!(status, StatusCode::UNAUTHORIZED, "{body}");
    let unchanged = app.storage.get_account_by_id(account.id).await.unwrap();
    assert_eq!(unchanged.opaque_record, account.opaque_record);
    assert_eq!(unchanged.wrapped_root_key, account.wrapped_root_key);
    assert_eq!(unchanged.credentials_version, 1);
}

#[tokio::test]
async fn login_state_does_not_reveal_credential_changes() {
    let Some(app) = test_app().await else {
        return;
    };
    let account = registered_account(&app).await;
    for expected_version in [0, 1] {
        if expected_version > 0 {
            app.storage
                .revoke_account_sessions(account.id)
                .await
                .unwrap();
        }
        let (token, ke3) = start_login(&app, &account).await;
        let claims = app
            .jwt
            .validate_state_token(&token, StatePurpose::Login)
            .unwrap();
        // A caller sees the same public value before and after a password change.
        assert_eq!(claims.cred_ver, 0);
        let (status, body) = post_json(
            &app,
            "/v1/auth/login/finalize",
            None,
            &json!({
                "login_token": token, "opaque_ke3": B64.encode(ke3),
            }),
        )
        .await;
        assert_eq!(status, StatusCode::OK, "{body}");
        let session = body["auth_token"].as_str().unwrap();
        // Only the authenticated session receives the real version.
        assert_eq!(
            app.jwt.validate_auth_token(session).unwrap().cred_ver,
            expected_version
        );
        assert_eq!(
            get_json(&app, "/v1/auth/validate", Some(session)).await.0,
            StatusCode::OK
        );
    }
    let (_, ke1) = TestLogin::start(PASSWORD);
    let (status, body) = post_json(
        &app,
        "/v1/auth/login/init",
        None,
        &json!({
            "username": "nobody", "opaque_ke1": B64.encode(ke1), "cap_token": "",
        }),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{body}");
    let claims = app
        .jwt
        .validate_state_token(body["login_token"].as_str().unwrap(), StatePurpose::Login)
        .unwrap();
    assert_eq!(claims.cred_ver, 0);
}

#[tokio::test]
async fn credential_completion_cannot_overwrite_a_rotated_root() {
    for purpose in [StatePurpose::PasswordChange, StatePurpose::Recovery] {
        let Some(app) = test_app().await else {
            return;
        };
        let account = registered_account(&app).await;
        let auth = app.auth_token(&account.id.to_string());
        let (_, state_token) = registration_state(&app, &account, purpose).await;
        app.storage
            .rotate_root_key(account.id, 0, &[3; 41], &[], &[])
            .await
            .unwrap();
        let upload =
            test_registration_upload(&app.opaque, b"replacement", account.id.as_bytes()).unwrap();
        let path = if purpose == StatePurpose::Recovery {
            "/v1/accounts/recover/finalize"
        } else {
            "/v1/accounts/password/change/complete"
        };
        let (status, body) = post_json(
            &app,
            path,
            Some(&auth),
            &json!({
                "state_token": state_token, "opaque_record": B64.encode(&upload),
                "wrapped_root_key": B64.encode([2; 41]),
            }),
        )
        .await;
        assert_eq!(status, StatusCode::CONFLICT, "{body}");
        let unchanged = app.storage.get_account_by_id(account.id).await.unwrap();
        assert_eq!(unchanged.opaque_record, account.opaque_record);
        assert_eq!(unchanged.credentials_version, 0);
        assert_eq!(unchanged.root_key_version, 1);
        assert_eq!(unchanged.wrapped_root_key, Some(vec![3; 41]));
        // A fresh exchange based on the current root can still complete.
        let (_, fresh_token) = registration_state(&app, &unchanged, purpose).await;
        let (status, body) = post_json(
            &app,
            path,
            Some(&auth),
            &json!({
                "state_token": fresh_token, "opaque_record": B64.encode(&upload),
                "wrapped_root_key": B64.encode([4; 41]),
            }),
        )
        .await;
        assert_eq!(status, StatusCode::OK, "{body}");
    }
}

#[tokio::test]
async fn recovery_rejects_a_blob_snapshot_rotated_before_init_without_consuming_proof() {
    use betterbase_accounts_storage::RecoveryStorage;
    let Some(app) = test_app().await else {
        return;
    };
    let account = registered_account(&app).await;
    app.storage
        .store_recovery_blob(account.id, b"old blob")
        .await
        .unwrap();
    let verification = app
        .jwt
        .create_verification_token(&account.email, "recovery")
        .unwrap();
    let (status, fetched) = post_json(
        &app,
        "/v1/accounts/recovery-blob/fetch",
        Some(&verification),
        &json!({}),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{fetched}");
    assert_eq!(fetched["root_key_version"], 0);
    app.storage
        .rotate_root_key(account.id, 0, &[3; 41], &[], b"new blob")
        .await
        .unwrap();
    let request = test_registration_start(b"replacement").unwrap();
    let mut body = json!({
        "email": account.email, "verification_token": verification,
        "opaque_request": B64.encode(&request), "expected_root_version": fetched["root_key_version"],
    });
    let (status, response) = post_json(&app, "/v1/accounts/recover/init", None, &body).await;
    assert_eq!(status, StatusCode::CONFLICT, "{response}");
    let (status, fetched) = post_json(
        &app,
        "/v1/accounts/recovery-blob/fetch",
        Some(&verification),
        &json!({}),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{fetched}");
    assert_eq!(fetched["blob"], "new blob");
    assert_eq!(fetched["root_key_version"], 1);
    body["expected_root_version"] = fetched["root_key_version"].clone();
    let (status, response) = post_json(&app, "/v1/accounts/recover/init", None, &body).await;
    assert_eq!(status, StatusCode::OK, "{response}");
}
