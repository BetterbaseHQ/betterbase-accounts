use base64::engine::general_purpose::STANDARD as B64;
use serde_json::json;

use crate::test_support::{get_json, post_json, test_app};

use super::*;

const REDIRECT_URI: &str = "http://localhost:5381/";

#[tokio::test]
async fn malformed_key_bundles_preserve_existing_grant_and_issue_no_code() {
    let Some((app, client_id, token)) = seed().await else {
        return;
    };
    let state = state_for(&app, &client_id);
    let valid = consent_body(&state, &[7; WRAPPED_SCOPED_KEY_SIZE], "existing-blob");
    let (status, response) = post_json(&app, "/oauth/consent", Some(&token), &valid).await;
    assert_eq!(status, StatusCode::OK, "{response}");
    let account = app
        .storage
        .get_account_by_email(crate::test_support::TEST_ISSUER, "bundle@example.test")
        .await
        .unwrap();
    let existing = app
        .storage
        .get_oauth_grant_by_account_and_client(account.id, client_id.parse().unwrap())
        .await
        .unwrap();
    let mut cases = Vec::new();
    for field in [
        "app_public_key_jwk",
        "wrapped_scoped_key",
        "root_key_version",
    ] {
        let mut body = valid.clone();
        body.as_object_mut().unwrap().remove(field);
        cases.push(body);
    }
    let mut private_key: serde_json::Value =
        serde_json::from_str(valid["app_public_key_jwk"].as_str().unwrap()).unwrap();
    private_key["d"] = "private-key".into();
    for (field, value) in [
        (
            "app_keypair_blob",
            json!("x".repeat(MAX_KEYPAIR_BLOB_SIZE + 1)),
        ),
        ("app_public_key_jwk", json!("not JSON")),
        ("app_public_key_jwk", json!("null")),
        ("app_public_key_jwk", json!(private_key.to_string())),
        ("wrapped_scoped_key", json!("!")),
        ("wrapped_scoped_key", json!(B64.encode([7; 40]))),
        ("wrapped_scoped_key", json!(B64.encode([7; 42]))),
    ] {
        let mut body = valid.clone();
        body[field] = value;
        cases.push(body);
    }
    for body in cases {
        let (status, error) = post_json(&app, "/oauth/consent", Some(&token), &body).await;
        assert_eq!(status, StatusCode::BAD_REQUEST, "{body}: {error}");
        assert_eq!(error["error"], "invalid_request");
        assert!(error.get("redirect_uri").is_none());
        let current = app
            .storage
            .get_oauth_grant_by_account_and_client(account.id, client_id.parse().unwrap())
            .await
            .unwrap();
        assert_eq!(current.wrapped_scoped_key, existing.wrapped_scoped_key);
        assert_eq!(current.app_public_key, existing.app_public_key);
        assert_eq!(current.app_keypair_blob, existing.app_keypair_blob);
        assert_eq!(current.scope, existing.scope);
        let codes: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM oauth_codes")
            .fetch_one(app.storage.pool())
            .await
            .unwrap();
        assert_eq!(codes, 1, "rejected consent issued an authorization code");
    }
}

#[tokio::test]
async fn malformed_wrapper_only_consent_creates_no_grant_or_code() {
    let Some((app, client_id, token)) = seed().await else {
        return;
    };
    let state = state_for(&app, &client_id);
    for (wrapper, version) in [
        ("!".into(), Some(0)),
        (B64.encode([7; 40]), Some(0)),
        (B64.encode([7; 42]), Some(0)),
        (B64.encode([7; 41]), None),
    ] {
        let mut body =
            json!({"oauth_state": state, "approved": true, "wrapped_scoped_key": wrapper});
        if let Some(version) = version {
            body["root_key_version"] = json!(version);
        }
        let (status, error) = post_json(&app, "/oauth/consent", Some(&token), &body).await;
        assert_eq!(status, StatusCode::BAD_REQUEST, "{error}");
        assert_eq!(error["error"], "invalid_request");
        let counts: (i64, i64) = sqlx::query_as(
            "SELECT (SELECT COUNT(*) FROM oauth_grants), (SELECT COUNT(*) FROM oauth_codes)",
        )
        .fetch_one(app.storage.pool())
        .await
        .unwrap();
        assert_eq!(counts, (0, 0));
    }
    // The same signed state still works once the malformed input is corrected.
    let (status, body) = post_json(&app, "/oauth/consent", Some(&token),
        &json!({"oauth_state": state, "approved": true, "wrapped_scoped_key": B64.encode([7; 41]), "root_key_version": 0})).await;
    assert_eq!(status, StatusCode::OK, "{body}");
}

async fn seed() -> Option<(crate::test_support::TestApp, String, String)> {
    let app = test_app().await?;
    let client_id = Uuid::new_v4();
    app.storage
        .create_oauth_client(&OAuthClient {
            id: client_id,
            name: "bundle client".to_owned(),
            secret_hash: None,
            redirect_uris: vec![REDIRECT_URI.to_owned()],
            allowed_scopes: vec!["openid".to_owned(), "sync".to_owned()],
            created_at: chrono::Utc::now(),
        })
        .await
        .expect("create client");
    let account = app
        .storage
        .get_or_create_account(
            crate::test_support::TEST_ISSUER,
            "bundle",
            "bundle@example.test",
        )
        .await
        .expect("create account");
    let token = app.auth_token(&account.id.to_string());
    Some((app, client_id.to_string(), token))
}

fn consent_body(state: &str, wrapped: &[u8], blob: &str) -> serde_json::Value {
    consent_body_with_root_version(state, wrapped, blob, 0)
}

fn consent_body_with_root_version(
    state: &str,
    wrapped: &[u8],
    blob: &str,
    root_key_version: i64,
) -> serde_json::Value {
    json!({
        "oauth_state": state,
        "approved": true,
        "wrapped_scoped_key": B64.encode(wrapped),
        "app_keypair_blob": blob,
        "root_key_version": root_key_version,
        // Real P-256 point (validate_p256_public_key checks on-curve).
        "app_public_key_jwk": json!({
            "kty": "EC",
            "crv": "P-256",
            "x": "-fdJbZAPB-1JvgW0Z-yAicImzBmEkhx396ojqztJHFw",
            "y": "DZagJ-DypVyEsBj3y3CdosboodfJAP9u9Z4hItYM4NM",
        }).to_string(),
    })
}

fn state_for(app: &crate::test_support::TestApp, client_id: &str) -> String {
    app.jwt
        .create_oauth_state_token(OAuthStateClaims::new(
            client_id.to_owned(),
            REDIRECT_URI.to_owned(),
            "openid".to_owned(),
            "client-state".to_owned(),
            "challenge".to_owned(),
            "S256".to_owned(),
            None,
        ))
        .expect("state token")
}

#[tokio::test]
async fn consent_bundle_installs_atomically_on_empty_grant() {
    let Some((app, client_id, token)) = seed().await else {
        return;
    };
    let state = state_for(&app, &client_id);
    let wrapped = vec![7u8; WRAPPED_SCOPED_KEY_SIZE];
    let (status, body) = post_json(
        &app,
        "/oauth/consent",
        Some(&token),
        &consent_body(&state, &wrapped, "blob-v1"),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "body: {body}");

    // The bundle landed together.
    let (status, body) = get_json(
        &app,
        &format!("/oauth/grant-keypair?client_id={client_id}"),
        Some(&token),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(body["app_keypair_blob"], "blob-v1");
    assert_eq!(body["wrapped_scoped_key"], B64.encode(&wrapped));
}

#[tokio::test]
async fn consent_bundle_rejects_material_derived_under_rotated_root() {
    let Some((app, client_id, token)) = seed().await else {
        return;
    };
    let state = state_for(&app, &client_id);
    let wrapped = vec![7u8; WRAPPED_SCOPED_KEY_SIZE];

    // AUD-008/009 residual: the account's root key rotated (bump the
    // committed version) after this client derived its key material.
    // Installing the bundle would strand the grant under a root
    // nobody holds anymore.
    // The interleaving under test only needs the committed version to
    // have moved; bump it directly (a full API rotation needs valid
    // wrapped material unrelated to this check).
    sqlx::query("UPDATE accounts SET root_key_version = 1 WHERE email = 'bundle@example.test'")
        .execute(app.storage.pool())
        .await
        .expect("bump root version");

    let (status, body) = post_json(
        &app,
        "/oauth/consent",
        Some(&token),
        &consent_body_with_root_version(&state, &wrapped, "blob-stale", 0),
    )
    .await;
    assert_eq!(status, StatusCode::CONFLICT, "body: {body}");
    assert!(body["error"]
        .as_str()
        .unwrap_or("")
        .contains("invalid_grant_state"));

    // Nothing was written for this grant.
    let (status, body) = get_json(
        &app,
        &format!("/oauth/grant-keypair?client_id={client_id}"),
        Some(&token),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(body["app_keypair_blob"], "");

    // A client that re-derived under the CURRENT root succeeds.
    let state = state_for(&app, &client_id);
    let (status, body) = post_json(
        &app,
        "/oauth/consent",
        Some(&token),
        &consent_body_with_root_version(&state, &wrapped, "blob-fresh", 1),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "body: {body}");
    assert_eq!(body_text(&body), "");
}

fn body_text(body: &serde_json::Value) -> String {
    body.as_str().unwrap_or("").to_string()
}

#[tokio::test]
async fn consent_bundle_rejects_stale_read_overwriting_keypair() {
    let Some((app, client_id, token)) = seed().await else {
        return;
    };
    // First consent installs W1 + keypair-v1.
    let state = state_for(&app, &client_id);
    let w1 = vec![1u8; WRAPPED_SCOPED_KEY_SIZE];
    let (status, body) = post_json(
        &app,
        "/oauth/consent",
        Some(&token),
        &consent_body(&state, &w1, "keypair-v1"),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "body: {body}");

    // AUD-008: a client whose grant read failed generates a fresh
    // scoped key and submits W2 + keypair-v2. The server must reject:
    // overwriting the keypair under a different wrapper strands the
    // existing key material.
    let state2 = state_for(&app, &client_id);
    let w2 = vec![2u8; WRAPPED_SCOPED_KEY_SIZE];
    let (status, body) = post_json(
        &app,
        "/oauth/consent",
        Some(&token),
        &consent_body(&state2, &w2, "keypair-v2"),
    )
    .await;
    assert_eq!(status, StatusCode::CONFLICT, "body: {body}");
    assert_eq!(body["error"], "invalid_grant_state");

    // Stored state unchanged: W1 + keypair-v1 intact.
    let (status, body) = get_json(
        &app,
        &format!("/oauth/grant-keypair?client_id={client_id}"),
        Some(&token),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(body["app_keypair_blob"], "keypair-v1");
    assert_eq!(body["wrapped_scoped_key"], B64.encode(&w1));

    // A consistent resubmission (same wrapper) replaces the keypair.
    let state3 = state_for(&app, &client_id);
    let (status, body) = post_json(
        &app,
        "/oauth/consent",
        Some(&token),
        &consent_body(&state3, &w1, "keypair-v1b"),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "body: {body}");
    let (_, body) = get_json(
        &app,
        &format!("/oauth/grant-keypair?client_id={client_id}"),
        Some(&token),
    )
    .await;
    assert_eq!(body["app_keypair_blob"], "keypair-v1b");
    assert_eq!(body["wrapped_scoped_key"], B64.encode(&w1));
}

#[tokio::test]
async fn consent_keypair_without_wrapped_key_is_rejected() {
    let Some((app, client_id, token)) = seed().await else {
        return;
    };
    let state = state_for(&app, &client_id);
    let mut body = consent_body(&state, &[0u8; WRAPPED_SCOPED_KEY_SIZE], "blob");
    body.as_object_mut().unwrap().remove("wrapped_scoped_key");
    let (status, body) = post_json(&app, "/oauth/consent", Some(&token), &body).await;
    assert_eq!(status, StatusCode::BAD_REQUEST, "body: {body}");
    assert!(
        body["error_description"]
            .as_str()
            .unwrap_or_default()
            .contains("atomically"),
        "body: {body}"
    );
}

#[tokio::test]
async fn wrapper_only_consent_retries_are_idempotent_and_conflicts_are_reported() {
    for existing_bundle in [false, true] {
        let Some((app, client_id, token)) = seed().await else {
            return;
        };
        let state = state_for(&app, &client_id);
        if existing_bundle {
            let (status, body) = post_json(
                &app,
                "/oauth/consent",
                Some(&token),
                &consent_body(&state, &[2; 41], "bundle-for-key-2"),
            )
            .await;
            assert_eq!(status, StatusCode::OK, "{body}");
        }
        for (key, version, expected) in [
            (2, 0, StatusCode::OK),
            (2, 0, StatusCode::OK),
            (1, 0, StatusCode::CONFLICT),
            (2, 1, StatusCode::CONFLICT),
        ] {
            let (status, body) = post_json(
                &app,
                "/oauth/consent",
                Some(&token),
                &json!({
                    "oauth_state": state, "approved": true,
                    "wrapped_scoped_key": B64.encode([key; 41]), "root_key_version": version,
                }),
            )
            .await;
            assert_eq!(status, expected, "{body}");
            if expected == StatusCode::CONFLICT {
                assert_eq!(body["error"], "invalid_grant_state");
            }
            let account = app
                .storage
                .get_account_by_email(crate::test_support::TEST_ISSUER, "bundle@example.test")
                .await
                .unwrap();
            let grant = app
                .storage
                .get_oauth_grant_by_account_and_client(account.id, client_id.parse().unwrap())
                .await
                .unwrap();
            assert_eq!(grant.wrapped_scoped_key, Some(vec![2; 41]));
            assert_eq!(
                grant.app_keypair_blob.as_deref(),
                if existing_bundle {
                    Some("bundle-for-key-2")
                } else {
                    None
                }
            );
        }
    }
}
