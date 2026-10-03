use base64::engine::general_purpose::STANDARD as B64;
use serde_json::json;

use crate::test_support::{get_json, post_json, test_app, TEST_ISSUER};

use super::*;

use betterbase_accounts_storage::{
    AccountStorage, OAuthClient, OAuthClientStorage, OAuthGrantStorage, RecoveryStorage,
};

async fn seed() -> Option<crate::test_support::TestApp> {
    let app = test_app().await?;
    let account = app
        .storage
        .get_or_create_account(TEST_ISSUER, "rotator", "rotator@example.test")
        .await
        .expect("create account");
    let client_id = Uuid::new_v4();
    app.storage
        .create_oauth_client(&OAuthClient {
            id: client_id,
            name: "rot client".to_owned(),
            secret_hash: None,
            redirect_uris: vec!["http://localhost:5381/".to_owned()],
            allowed_scopes: vec!["openid".to_owned()],
            created_at: chrono::Utc::now(),
        })
        .await
        .expect("create client");
    app.storage
        .get_or_create_oauth_grant(client_id, account.id, "openid")
        .await
        .expect("create grant");
    app.storage
        .store_recovery_blob(account.id, b"old-recovery-blob")
        .await
        .expect("store recovery blob");
    Some(app)
}

fn rotate_body(version: i64, grant_ids: &[String]) -> serde_json::Value {
    json!({
        "wrapped_root_key": B64.encode(vec![9u8; WRAPPED_KEY_SIZE]),
        "expected_root_version": version,
        "grants": grant_ids.iter().map(|id| json!({
            "grant_id": id,
            "wrapped_scoped_key": B64.encode(vec![8u8; WRAPPED_KEY_SIZE]),
        })).collect::<Vec<_>>(),
        "recovery_blob": B64.encode(crate::test_support::recovery_blob(9)),
    })
}

#[tokio::test]
async fn rotation_with_current_version_and_full_grant_set_succeeds() {
    let Some(app) = seed().await else {
        return;
    };
    let account = app
        .storage
        .get_account_by_email(TEST_ISSUER, "rotator@example.test")
        .await
        .expect("account");
    let token = app.auth_token(&account.id.to_string());

    let (_, root) = get_json(&app, "/v1/accounts/root-key", Some(&token)).await;
    assert_eq!(root["root_key_version"], 0);
    let grants = app
        .storage
        .list_grants_for_account(account.id)
        .await
        .expect("grants");
    let ids: Vec<String> = grants.iter().map(|g| g.id.to_string()).collect();

    let (status, body) = post_json(
        &app,
        "/v1/accounts/rotate-root-key",
        Some(&token),
        &rotate_body(0, &ids),
    )
    .await;
    assert_eq!(status, StatusCode::NO_CONTENT, "body: {body}");

    // Version advanced, root replaced, recovery blob replaced.
    let (_, root) = get_json(&app, "/v1/accounts/root-key", Some(&token)).await;
    assert_eq!(root["root_key_version"], 1);
    assert_eq!(
        root["wrapped_root_key"],
        B64.encode(vec![9u8; WRAPPED_KEY_SIZE])
    );
    let blob = app
        .storage
        .get_recovery_blob_by_email(TEST_ISSUER, "rotator@example.test")
        .await
        .expect("blob");
    assert_eq!(blob, crate::test_support::recovery_blob(9).as_bytes());
}

#[tokio::test]
async fn rotation_prepared_against_stale_version_is_rejected() {
    let Some(app) = seed().await else {
        return;
    };
    let account = app
        .storage
        .get_account_by_email(TEST_ISSUER, "rotator@example.test")
        .await
        .expect("account");
    let token = app.auth_token(&account.id.to_string());
    let grants = app
        .storage
        .list_grants_for_account(account.id)
        .await
        .expect("grants");
    let ids: Vec<String> = grants.iter().map(|g| g.id.to_string()).collect();

    // First rotation wins and bumps the version to 1.
    let (status, _) = post_json(
        &app,
        "/v1/accounts/rotate-root-key",
        Some(&token),
        &rotate_body(0, &ids),
    )
    .await;
    assert_eq!(status, StatusCode::NO_CONTENT);

    // A concurrent rotation prepared against version 0 must be
    // rejected, not overwrite the newer root (AUD-009 CAS).
    let (status, body) = post_json(
        &app,
        "/v1/accounts/rotate-root-key",
        Some(&token),
        &rotate_body(0, &ids),
    )
    .await;
    assert_eq!(status, StatusCode::CONFLICT, "body: {body}");
    assert!(
        body["error"]
            .as_str()
            .unwrap_or_default()
            .contains("root key changed"),
        "body: {body}"
    );
    let (_, root) = get_json(&app, "/v1/accounts/root-key", Some(&token)).await;
    assert_eq!(root["root_key_version"], 1);
}

#[tokio::test]
async fn rotation_missing_a_grant_is_rejected_unchanged() {
    let Some(app) = seed().await else {
        return;
    };
    let account = app
        .storage
        .get_account_by_email(TEST_ISSUER, "rotator@example.test")
        .await
        .expect("account");
    let token = app.auth_token(&account.id.to_string());

    // A second grant appears after the client snapshotted the set —
    // submitting only the snapshotted (empty) list must be rejected:
    // committing it would strand every grant under the old root.
    let client_id = Uuid::new_v4();
    app.storage
        .create_oauth_client(&OAuthClient {
            id: client_id,
            name: "late client".to_owned(),
            secret_hash: None,
            redirect_uris: vec!["http://localhost:5381/".to_owned()],
            allowed_scopes: vec!["openid".to_owned()],
            created_at: chrono::Utc::now(),
        })
        .await
        .expect("create late client");
    app.storage
        .get_or_create_oauth_grant(client_id, account.id, "openid")
        .await
        .expect("create late grant");

    let (status, body) = post_json(
        &app,
        "/v1/accounts/rotate-root-key",
        Some(&token),
        &rotate_body(0, &[]),
    )
    .await;
    assert_eq!(status, StatusCode::CONFLICT, "body: {body}");
    assert!(
        body["error"]
            .as_str()
            .unwrap_or_default()
            .contains("every grant"),
        "body: {body}"
    );

    // Nothing changed: version still 0, root untouched.
    let (_, root) = get_json(&app, "/v1/accounts/root-key", Some(&token)).await;
    assert_eq!(root["root_key_version"], 0);
}

#[tokio::test]
async fn rotation_without_recovery_blob_deletes_the_stale_one() {
    let Some(app) = seed().await else {
        return;
    };
    let account = app
        .storage
        .get_account_by_email(TEST_ISSUER, "rotator@example.test")
        .await
        .expect("account");
    let token = app.auth_token(&account.id.to_string());
    let grants = app
        .storage
        .list_grants_for_account(account.id)
        .await
        .expect("grants");
    let ids: Vec<String> = grants.iter().map(|g| g.id.to_string()).collect();

    let mut body = rotate_body(0, &ids);
    body["recovery_blob"] = json!("");
    let (status, body_resp) =
        post_json(&app, "/v1/accounts/rotate-root-key", Some(&token), &body).await;
    assert_eq!(status, StatusCode::NO_CONTENT, "body: {body_resp}");

    // The old blob decrypts to the retired root — it must not survive
    // as a false recovery path.
    let blob = app
        .storage
        .get_recovery_blob_by_email(TEST_ISSUER, "rotator@example.test")
        .await;
    assert!(blob.is_err(), "stale recovery blob must be deleted");
}
#[tokio::test]
async fn wrapped_key_batch_enforces_version_ownership_and_validation() {
    use axum::{body::Body, http::Request};
    use tower::ServiceExt;
    let Some(app) = seed().await else {
        return;
    };
    let account = app
        .storage
        .get_account_by_email(TEST_ISSUER, "rotator@example.test")
        .await
        .unwrap();
    let grant = app
        .storage
        .list_grants_for_account(account.id)
        .await
        .unwrap()
        .remove(0);
    let other = app
        .storage
        .get_or_create_account(TEST_ISSUER, "other", "other@example.test")
        .await
        .unwrap();
    let foreign = app
        .storage
        .get_or_create_oauth_grant(grant.client_id, other.id, "openid")
        .await
        .unwrap();
    let token = app.auth_token(&account.id.to_string());
    for (id, key, version, expected) in [
        (
            grant.id.to_string(),
            B64.encode([1; 41]),
            1,
            StatusCode::CONFLICT,
        ),
        (
            foreign.id.to_string(),
            B64.encode([1; 41]),
            0,
            StatusCode::FORBIDDEN,
        ),
        (
            "invalid".into(),
            B64.encode([1; 41]),
            0,
            StatusCode::BAD_REQUEST,
        ),
        (
            grant.id.to_string(),
            "invalid-base64".into(),
            0,
            StatusCode::BAD_REQUEST,
        ),
        (
            grant.id.to_string(),
            B64.encode([1; 40]),
            0,
            StatusCode::BAD_REQUEST,
        ),
        (
            grant.id.to_string(),
            B64.encode([1; 41]),
            0,
            StatusCode::NO_CONTENT,
        ),
    ] {
        let request = Request::builder().method("PUT").uri("/v1/accounts/grants/wrapped-keys")
            .header("authorization", format!("Bearer {token}"))
            .header("content-type", "application/json")
            .body(Body::from(json!({"expected_root_version": version, "grants": [{"grant_id": id, "wrapped_scoped_key": key}]}).to_string())).unwrap();
        let response = app.router.clone().oneshot(request).await.unwrap();
        assert_eq!(response.status(), expected);
        assert_eq!(
            app.storage
                .get_oauth_grant(grant.id)
                .await
                .unwrap()
                .wrapped_scoped_key,
            if expected == StatusCode::NO_CONTENT {
                Some(vec![1; 41])
            } else {
                None
            }
        );
        assert!(app
            .storage
            .get_oauth_grant(foreign.id)
            .await
            .unwrap()
            .wrapped_scoped_key
            .is_none());
    }
}
