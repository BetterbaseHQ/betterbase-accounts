use crate::test_support::{test_app, test_app_with_config, TestApp, TEST_ISSUER};
use axum::{
    body::{to_bytes, Body},
    http::{Request, StatusCode},
};
use betterbase_accounts_storage::AccountStorage;
use tower::ServiceExt;

async fn request(app: &TestApp, uri: &str) -> (StatusCode, axum::http::HeaderMap, Vec<u8>) {
    let response = app
        .router
        .clone()
        .oneshot(Request::builder().uri(uri).body(Body::empty()).unwrap())
        .await
        .unwrap();
    let status = response.status();
    let headers = response.headers().clone();
    let body = to_bytes(response.into_body(), 65536)
        .await
        .unwrap()
        .to_vec();
    assert_eq!(headers["x-protocol-version"], "1");
    (status, headers, body)
}

#[tokio::test]
async fn webfinger_rejects_malformed_foreign_and_missing_resources() {
    let Some(app) = test_app().await else {
        return;
    };
    for (query, expected) in [
        ("", StatusCode::BAD_REQUEST),
        ("?resource=", StatusCode::BAD_REQUEST),
        (
            "?resource=https%3A%2F%2Fexample.test",
            StatusCode::BAD_REQUEST,
        ),
        ("?resource=acct%3Aalice", StatusCode::BAD_REQUEST),
        (
            "?resource=acct%3Aalice%40foreign.test",
            StatusCode::NOT_FOUND,
        ),
        (
            "?resource=acct%3Aalice%40accounts.example.test",
            StatusCode::NOT_FOUND,
        ),
        (
            "?resource=acct%3A%40accounts.example.test",
            StatusCode::NOT_FOUND,
        ),
        (
            "?resource=acct%3Aalice%40accounts.example.test%40evil.test",
            StatusCode::NOT_FOUND,
        ),
    ] {
        let (status, _, _) = request(&app, &format!("/.well-known/webfinger{query}")).await;
        assert_eq!(status, expected, "{query}");
    }
}

#[tokio::test]
async fn discovery_preserves_identity_and_advertises_configured_services() {
    for enabled in [false, true] {
        let Some(app) = test_app_with_config(|config| {
            config.accounts_public_url = "https://api.example.test".into();
            if enabled {
                config.sync_endpoint = Some("https://sync.example.test".into());
                config.federation_ws_endpoint = Some("wss://federation.example.test".into());
                config.cap_enabled = true;
                config.cap_key_id = "public-cap-key".into();
            }
        })
        .await
        else {
            return;
        };
        app.storage
            .get_or_create_account(TEST_ISSUER, "alice", "alice@example.test")
            .await
            .unwrap();
        let (status, headers, body) = request(
            &app,
            "/.well-known/webfinger?resource=acct%3Aalice%40accounts.example.test",
        )
        .await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(headers["content-type"], "application/jrd+json");
        assert_eq!(headers["cache-control"], "public, max-age=300");
        let body: serde_json::Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(body["subject"], "acct:alice@accounts.example.test");
        assert_eq!(
            body["links"][0]["href"],
            "https://api.example.test/v1/users/alice"
        );
        assert_eq!(
            body["links"].as_array().unwrap().len(),
            if enabled { 2 } else { 1 }
        );
        if enabled {
            assert_eq!(body["links"][1]["href"], "https://sync.example.test");
        }
        let (status, headers, body) = request(&app, "/.well-known/betterbase").await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(headers["content-type"], "application/json");
        assert_eq!(
            headers["cache-control"],
            "public, max-age=3600, stale-while-revalidate=86400"
        );
        let body: serde_json::Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(body["version"], 1);
        assert_eq!(body["accounts_endpoint"], "https://api.example.test");
        assert_eq!(
            body["jwks_uri"],
            "https://api.example.test/.well-known/jwks.json"
        );
        assert_eq!(
            body["webfinger"],
            "https://api.example.test/.well-known/webfinger"
        );
        assert_eq!(body["federation"], enabled);
        assert_eq!(body["pow_required"], enabled);
        if enabled {
            assert_eq!(body["cap_key_id"], "public-cap-key");
            assert_eq!(body["federation_ws"], "wss://federation.example.test");
        } else {
            assert!(body["cap_key_id"].is_null());
        }
    }
}

#[tokio::test]
async fn webfinger_sanitizes_database_failures() {
    let Some(app) = test_app().await else {
        return;
    };
    sqlx::query("ALTER TABLE accounts RENAME TO unavailable_accounts")
        .execute(app.storage.pool())
        .await
        .unwrap();
    let (status, _, body) = request(
        &app,
        "/.well-known/webfinger?resource=acct%3Aalice%40accounts.example.test",
    )
    .await;
    assert_eq!(status, StatusCode::INTERNAL_SERVER_ERROR);
    assert_eq!(body, b"internal error");
}
