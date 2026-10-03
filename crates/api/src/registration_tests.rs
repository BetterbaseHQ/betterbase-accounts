use crate::test_support::{get_json, post_json, test_app, TestApp};
use axum::http::StatusCode;
use base64::{engine::general_purpose::STANDARD as B64, Engine as _};
use betterbase_accounts_auth::{
    jwt::StatePurpose,
    opaque::{TestLogin, TestRegistration},
};
use betterbase_accounts_storage::{AccountStorage, RegistrationStateStorage, StorageError};
use serde_json::{json, Value};
use uuid::Uuid;

const PASSWORD: &[u8] = b"signup-password";
const INIT: &str = "/v1/accounts/password/init";
const FINALIZE: &str = "/v1/accounts/password/finalize";

async fn start(app: &TestApp) -> (Value, Value, Value) {
    let (client, request) = TestRegistration::start(PASSWORD);
    let verification = app
        .jwt
        .create_verification_token("signup@example.test", "registration")
        .unwrap();
    let init_request = json!({
        "username": "signup", "email": "signup@example.test", "cap_token": "",
        "verification_token": verification, "opaque_request": B64.encode(request),
    });
    let (status, init) = post_json(app, INIT, None, &init_request).await;
    assert_eq!(status, StatusCode::OK, "{init}");
    let upload = client.finish(
        PASSWORD,
        &B64.decode(init["opaque_response"].as_str().unwrap())
            .unwrap(),
    );
    let finalize = json!({ "state_token": init["state_token"],
        "opaque_record": B64.encode(upload), "wrapped_root_key": B64.encode([1; 41]) });
    (init, finalize, init_request)
}

#[tokio::test]
async fn signup_through_http_returns_a_session_and_credentials_that_can_log_in() {
    let Some(app) = test_app().await else { return };
    let (init, finalize, init_request) = start(&app).await;
    // Verification proof is one-use even while signup is unfinished.
    let (status, _) = post_json(&app, INIT, None, &init_request).await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
    let (status, completed) = post_json(&app, FINALIZE, None, &finalize).await;
    assert_eq!(status, StatusCode::OK, "{completed}");
    assert_eq!(completed["user_id"], init["user_id"]);
    assert_eq!(
        get_json(&app, "/v1/auth/validate", completed["auth_token"].as_str())
            .await
            .0,
        StatusCode::OK
    );
    let id: Uuid = init["user_id"].as_str().unwrap().parse().unwrap();
    let account = app.storage.get_account_by_id(id).await.unwrap();
    assert!(account.opaque_record.is_some());
    assert_eq!(account.wrapped_root_key, Some(vec![1; 41]));
    let (status, _) = post_json(&app, FINALIZE, None, &finalize).await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
    let (client, ke1) = TestLogin::start(PASSWORD);
    let (status, login) = post_json(
        &app,
        "/v1/auth/login/init",
        None,
        &json!({"username": "signup", "opaque_ke1": B64.encode(ke1), "cap_token": ""}),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{login}");
    let proof = client.finish(
        PASSWORD,
        &B64.decode(login["opaque_ke2"].as_str().unwrap()).unwrap(),
    );
    let login_finalize =
        json!({"login_token": login["login_token"], "opaque_ke3": B64.encode(proof)});
    let (status, session) = post_json(&app, "/v1/auth/login/finalize", None, &login_finalize).await;
    assert_eq!(status, StatusCode::OK, "{session}");
    assert_eq!(session["user_id"], init["user_id"]);
    let (status, replay) = post_json(&app, "/v1/auth/login/finalize", None, &login_finalize).await;
    assert_eq!(
        status,
        StatusCode::BAD_REQUEST,
        "login proof was reusable: {replay}"
    );
    assert!(replay.get("auth_token").is_none());
    assert_eq!(
        get_json(&app, "/v1/auth/validate", session["auth_token"].as_str())
            .await
            .0,
        StatusCode::OK
    );
}

#[tokio::test]
async fn malformed_signup_uploads_do_not_register_an_account_and_consume_state_once() {
    let Some(app) = test_app().await else { return };
    for (field, value, message) in [
        (
            "opaque_record",
            "!".to_owned(),
            "invalid opaque_record encoding",
        ),
        ("opaque_record", B64.encode([0; 3]), "invalid OPAQUE record"),
        (
            "wrapped_root_key",
            "!".to_owned(),
            "invalid wrapped_root_key encoding",
        ),
        (
            "wrapped_root_key",
            B64.encode([]),
            "wrapped_root_key must be 41 bytes",
        ),
        (
            "wrapped_root_key",
            B64.encode([0; 40]),
            "wrapped_root_key must be 41 bytes",
        ),
        (
            "wrapped_root_key",
            B64.encode([0; 42]),
            "wrapped_root_key must be 41 bytes",
        ),
    ] {
        let (init, valid, _) = start(&app).await;
        let mut malformed = valid.clone();
        malformed[field] = value.into();
        let (status, error) = post_json(&app, FINALIZE, None, &malformed).await;
        assert_eq!(status, StatusCode::BAD_REQUEST, "{field}: {error}");
        assert_eq!(error["error"], message);
        let id = init["user_id"].as_str().unwrap().parse().unwrap();
        let account = app.storage.get_account_by_id(id).await.unwrap();
        assert!(account.opaque_record.is_none());
        assert!(account.wrapped_root_key.is_none());
        let (status, _) = post_json(&app, FINALIZE, None, &valid).await;
        assert_eq!(status, StatusCode::BAD_REQUEST);
    }
    // Restarting the exchange after a malformed completion remains possible.
    let (_, valid, _) = start(&app).await;
    assert_eq!(
        post_json(&app, FINALIZE, None, &valid).await.0,
        StatusCode::OK
    );
}

#[tokio::test]
async fn expired_signup_state_cannot_write_credentials() {
    let Some(app) = test_app().await else { return };
    let (init, finalize, _) = start(&app).await;
    let claims = app
        .jwt
        .validate_state_token(
            init["state_token"].as_str().unwrap(),
            StatePurpose::Registration,
        )
        .unwrap();
    let state_id: Uuid = claims.sub.parse().unwrap();
    sqlx::query(
        "UPDATE registration_states SET expires_at = NOW() - INTERVAL '1 second' WHERE id = $1",
    )
    .bind(state_id)
    .execute(app.storage.pool())
    .await
    .unwrap();
    let (status, body) = post_json(&app, FINALIZE, None, &finalize).await;
    assert_eq!(status, StatusCode::BAD_REQUEST, "{body}");
    assert!(matches!(
        app.storage.get_registration_state(state_id).await,
        Err(StorageError::StateNotFound)
    ));
    let account = app
        .storage
        .get_account_by_id(init["user_id"].as_str().unwrap().parse().unwrap())
        .await
        .unwrap();
    assert!(account.opaque_record.is_none());
    assert!(account.wrapped_root_key.is_none());
}
